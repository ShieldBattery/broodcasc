//! CDN ("online") storage: read files straight from Blizzard's CDN, no
//! local install required.
//!
//! The pipeline mirrors [`crate::storage::Storage`] above the EKey layer
//! (encoding table, root catalog, BLTE, CKey verification are identical);
//! what differs is how encoded bytes are obtained:
//!
//! 1. Discovery: `http://<region>.patch.battle.net:1119/<product>/versions`
//!    and `/cdns` name the build config, CDN config, hosts, and path prefix
//!    (see [`crate::tact`]).
//! 2. The CDN config's `archives` list names archive files; each has a
//!    `.index` mapping full EKeys to `(offset, size)` within it (see
//!    [`crate::cdnindex`]).
//! 3. Reading an EKey: archive-index hit → HTTP Range request into the
//!    archive; miss → loose GET of `data/<xx>/<yy>/<ekey>`.
//!
//! CDN-served data is **bare BLTE** — unlike local `data.###` archives there
//! is no 30-byte span header. Integrity still holds end to end: BLTE chunk
//! MD5s are verified during decode and whole files are verified against
//! their CKey.
//!
//! All fetching goes through the [`CdnTransport`] trait so the core stays
//! HTTP-library-free (and WASM-compatible); the `cdn-http` feature provides
//! the ureq-based [`HttpTransport`], and `fs` additionally provides
//! [`CachingTransport`] for a persistent local cache.

use md5::{Digest, Md5};

use crate::blte::ReadLimits;
use crate::cdnindex::{ArchiveIndex, CdnIndex};
use crate::config::BuildConfig;
use crate::encoding::EncodingTable;
use crate::error::{CascError, Result};
use crate::keys::{ContentKey, EncodingKey};
use crate::object::{ExpectedObject, read_verified};
use crate::root::RootFile;
use crate::storage::StorageOptions;
use crate::tact::{
    CdnPathKind, Cdns, Versions, cdn_file_url, cdns_url, validate_cdn_location,
    validate_discovery_identifier, versions_url,
};

/// Fetches resources from a CDN by URL.
///
/// Implementations should return [`CascError::NotFound`] for a clean HTTP
/// 404 (the storage layer uses this to fall back from "not archived" to
/// "doesn't exist") and [`CascError::Transport`] for other failures.
pub trait CdnTransport: Send + Sync {
    /// Fetches the entire resource at `url`, retaining at most `max_bytes`.
    /// Implementations must reject an oversized response before allocating or
    /// buffering beyond that bound.
    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>>;

    /// Fetches exactly `len` bytes starting at byte `offset` of the resource
    /// at `url` (an HTTP Range request). Must fail rather than silently
    /// return a different amount of data.
    fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>>;

    /// Best-effort invalidation hook used when bytes fail verification above
    /// the transport layer. Stateless transports can keep the default no-op;
    /// persistent caches should evict the exact whole or range entry.
    fn invalidate(&self, _url: &str, _range: Option<(u64, u64)>) {}
}

impl<T: CdnTransport + ?Sized> CdnTransport for &T {
    fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
        (**self).get(url, max_bytes)
    }

    fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        (**self).get_range(url, offset, len)
    }

    fn invalidate(&self, url: &str, range: Option<(u64, u64)>) {
        (**self).invalidate(url, range);
    }
}

struct AcquiredEncoded {
    bytes: Vec<u8>,
    url: String,
    range: Option<(u64, u64)>,
    index_key: Option<EncodingKey>,
    next_host: usize,
}

/// The EKey-addressed lower half of a CDN storage: hosts, archive list, and
/// merged archive index. Separate from [`CdnStorage`] so the bootstrap can
/// fetch the encoding table before the CKey layer exists (same shape as the
/// local storage's internal split).
struct CdnFetcher<T: CdnTransport> {
    transport: T,
    limits: ReadLimits,
    /// CDN hosts in preference order; later hosts are tried when earlier
    /// ones fail with transport errors (a 404 is authoritative and not
    /// retried — the CDN is content-addressed, so all hosts serve the same
    /// objects).
    hosts: Vec<String>,
    cdn_path: String,
    /// Archive hashes (lowercase hex) from the CDN config, in order; the
    /// merged index refers to archives by position in this list.
    archives: Vec<EncodingKey>,
    index: CdnIndex,
}

impl<T: CdnTransport> CdnFetcher<T> {
    /// Fetches a CDN file (`config/` or `data/` addressing), trying each
    /// host in order on transport failures.
    fn get_config(
        &self,
        key: &ContentKey,
        max_bytes: usize,
        what: &'static str,
    ) -> Result<Vec<u8>> {
        let mut last_err = None;
        for host in &self.hosts {
            let url = cdn_file_url(
                host,
                &self.cdn_path,
                CdnPathKind::Config,
                &key.to_string(),
                false,
            )?;
            match self.transport.get(&url, max_bytes) {
                Ok(bytes) => match verify_raw_ckey(&bytes, key, what) {
                    Ok(()) => return Ok(bytes),
                    Err(err) => {
                        self.transport.invalidate(&url, None);
                        last_err = Some(err);
                    }
                },
                Err(err @ CascError::NotFound(_)) => return Err(err),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| CascError::Transport {
            url: String::new(),
            reason: "no CDN hosts available".to_string(),
        }))
    }

    fn get_index(&self, key: &EncodingKey, max_bytes: usize) -> Result<(usize, ArchiveIndex)> {
        let mut last_err = None;
        for host in &self.hosts {
            let url = cdn_file_url(
                host,
                &self.cdn_path,
                CdnPathKind::Data,
                &key.to_string(),
                true,
            )?;
            match self.transport.get(&url, max_bytes) {
                Ok(bytes) => match ArchiveIndex::parse(&bytes) {
                    Ok(parsed) => return Ok((bytes.len(), parsed)),
                    Err(err) => {
                        self.transport.invalidate(&url, None);
                        last_err = Some(err);
                    }
                },
                Err(err @ CascError::NotFound(_)) => return Err(err),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| CascError::Transport {
            url: String::new(),
            reason: "no CDN hosts available".to_string(),
        }))
    }

    fn invalidate_config(&self, key: &ContentKey) {
        for host in &self.hosts {
            if let Ok(url) = cdn_file_url(
                host,
                &self.cdn_path,
                CdnPathKind::Config,
                &key.to_string(),
                false,
            ) {
                self.transport.invalidate(&url, None);
            }
        }
    }

    fn invalidate_index(&self, key: &EncodingKey) {
        for host in &self.hosts {
            if let Ok(url) = cdn_file_url(
                host,
                &self.cdn_path,
                CdnPathKind::Data,
                &key.to_string(),
                true,
            ) {
                self.transport.invalidate(&url, None);
            }
        }
    }

    /// Fetches and BLTE-decodes the content for `ekey`: a Range request into
    /// the owning archive when indexed, otherwise a loose-file GET. Verifies
    /// the decoded bytes against `expected_ckey` when given.
    fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
        decoded_size: Option<u64>,
    ) -> Result<Vec<u8>> {
        let mut host_start = 0usize;
        loop {
            let mut acquired_source = None;
            let result = read_verified(
                ExpectedObject {
                    ckey: expected_ckey,
                    decoded_size,
                },
                self.limits,
                |encoded_limit| {
                    let acquired = self.acquire_encoded(ekey, encoded_limit, host_start)?;
                    acquired_source = Some((
                        acquired.url,
                        acquired.range,
                        acquired.index_key,
                        acquired.next_host,
                    ));
                    Ok(acquired.bytes)
                },
            );
            let verification_failed = matches!(
                result,
                Err(CascError::Malformed { .. } | CascError::ChecksumMismatch(_))
            );
            if verification_failed && let Some((url, range, index_key, next_host)) = acquired_source
            {
                self.transport.invalidate(&url, range);
                if let Some(index_key) = index_key {
                    self.invalidate_index(&index_key);
                }
                if next_host < self.hosts.len() {
                    host_start = next_host;
                    continue;
                }
            }
            return result;
        }
    }

    fn acquire_encoded(
        &self,
        ekey: &EncodingKey,
        encoded_limit: usize,
        host_start: usize,
    ) -> Result<AcquiredEncoded> {
        match self.index.lookup(ekey) {
            Some(entry) => {
                let archive = self.archives.get(entry.archive as usize).ok_or_else(|| {
                    CascError::malformed("CDN index", "archive number out of range")
                })?;
                let encoded_size =
                    usize::try_from(entry.encoded_size).map_err(|_| CascError::LimitExceeded {
                        what: "CDN encoded object",
                        limit: encoded_limit,
                    })?;
                if encoded_size > encoded_limit {
                    return Err(CascError::LimitExceeded {
                        what: "CDN encoded object",
                        limit: encoded_limit,
                    });
                }
                let offset = u64::from(entry.offset);
                let len = u64::from(entry.encoded_size);
                self.acquire_from_hosts(
                    archive,
                    encoded_limit,
                    Some((offset, len)),
                    Some(*archive),
                    host_start,
                )
            }
            None => match self.acquire_from_hosts(ekey, encoded_limit, None, None, host_start) {
                Ok(acquired) => Ok(acquired),
                Err(CascError::NotFound(_)) => Err(CascError::NotFound(ekey.to_string())),
                Err(err) => Err(err),
            },
        }
    }

    fn acquire_from_hosts(
        &self,
        key: &EncodingKey,
        max_bytes: usize,
        range: Option<(u64, u64)>,
        index_key: Option<EncodingKey>,
        host_start: usize,
    ) -> Result<AcquiredEncoded> {
        let mut last_err = None;
        for (host_index, host) in self.hosts.iter().enumerate().skip(host_start) {
            let url = cdn_file_url(
                host,
                &self.cdn_path,
                CdnPathKind::Data,
                &key.to_string(),
                false,
            )?;
            let fetched = match range {
                Some((offset, len)) => self.transport.get_range(&url, offset, len),
                None => self.transport.get(&url, max_bytes),
            };
            match fetched {
                Ok(bytes) => {
                    return Ok(AcquiredEncoded {
                        bytes,
                        url,
                        range,
                        index_key,
                        next_host: host_index + 1,
                    });
                }
                Err(err @ CascError::NotFound(_)) => return Err(err),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| CascError::Transport {
            url: String::new(),
            reason: "no CDN hosts available".to_string(),
        }))
    }
}

const MAX_CDN_ARCHIVES: usize = 256;
const MAX_CDN_INDEX_ENTRIES: usize = 1_000_000;
const MAX_CDN_INDEX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CDN_INDEX_BYTES: usize = 128 * 1024 * 1024;

fn merge_archive_index(
    merged: &mut CdnIndex,
    archive: usize,
    downloaded_bytes: usize,
    parsed: &ArchiveIndex,
    total_bytes: &mut usize,
    total_entries: &mut usize,
) -> Result<()> {
    let next_bytes = total_bytes
        .checked_add(downloaded_bytes)
        .ok_or(CascError::LimitExceeded {
            what: "aggregate CDN archive index bytes",
            limit: MAX_CDN_INDEX_BYTES,
        })?;
    if next_bytes > MAX_CDN_INDEX_BYTES {
        return Err(CascError::LimitExceeded {
            what: "aggregate CDN archive index bytes",
            limit: MAX_CDN_INDEX_BYTES,
        });
    }

    let next_entries = total_entries
        .checked_add(parsed.len())
        .ok_or(CascError::LimitExceeded {
            what: "aggregate CDN archive index entries",
            limit: MAX_CDN_INDEX_ENTRIES,
        })?;
    if next_entries > MAX_CDN_INDEX_ENTRIES {
        return Err(CascError::LimitExceeded {
            what: "aggregate CDN archive index entries",
            limit: MAX_CDN_INDEX_ENTRIES,
        });
    }

    let archive = u32::try_from(archive)
        .map_err(|_| CascError::malformed("CDN config", "archive list exceeds u32::MAX entries"))?;
    merged.try_add_archive(archive, parsed, MAX_CDN_INDEX_ENTRIES)?;
    *total_bytes = next_bytes;
    *total_entries = next_entries;
    Ok(())
}

fn load_archive_indexes<T: CdnTransport>(
    fetcher: &CdnFetcher<T>,
    archives: &[EncodingKey],
    max_bytes: usize,
) -> Result<CdnIndex> {
    if archives.len() > MAX_CDN_ARCHIVES {
        return Err(CascError::LimitExceeded {
            what: "CDN archive count",
            limit: MAX_CDN_ARCHIVES,
        });
    }

    load_archive_indexes_impl(fetcher, archives, max_bytes)
}

#[cfg(not(target_arch = "wasm32"))]
fn load_archive_indexes_impl<T: CdnTransport>(
    fetcher: &CdnFetcher<T>,
    archives: &[EncodingKey],
    max_bytes: usize,
) -> Result<CdnIndex> {
    const WORKERS: usize = MAX_CDN_INDEX_BYTES / MAX_CDN_INDEX_FILE_BYTES;
    // A true per-index limit keeps native and WASM behavior identical while
    // ensuring a complete native worker batch fits the aggregate policy.
    let per_index_max = max_bytes.min(MAX_CDN_INDEX_FILE_BYTES);

    let mut merged = CdnIndex::new();
    let mut total_bytes = 0usize;
    let mut total_entries = 0usize;
    let mut archive = 0usize;
    for chunk in archives.chunks(WORKERS) {
        let chunk_results = std::thread::scope(|scope| {
            let handles = chunk
                .iter()
                .map(|hash| scope.spawn(move || fetcher.get_index(hash, per_index_max)))
                .collect::<Vec<_>>();

            // Join every worker before propagating an error. This prevents a
            // panicking worker from escaping `scope` through an unjoined
            // handle, and retaining handle order preserves archive order.
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(result) => result,
                    Err(_) => Err(CascError::malformed(
                        "CDN archive index",
                        "loader worker panicked",
                    )),
                })
                .collect::<Vec<_>>()
        });

        // All workers in the batch have been joined, so propagating the first
        // archive-ordered error cannot leave an unjoined panic behind. Merge
        // each result immediately so only one bounded batch is retained.
        for result in chunk_results {
            let (downloaded_bytes, parsed) = result?;
            merge_archive_index(
                &mut merged,
                archive,
                downloaded_bytes,
                &parsed,
                &mut total_bytes,
                &mut total_entries,
            )?;
            archive += 1;
        }
    }

    Ok(merged)
}

#[cfg(target_arch = "wasm32")]
fn load_archive_indexes_impl<T: CdnTransport>(
    fetcher: &CdnFetcher<T>,
    archives: &[EncodingKey],
    max_bytes: usize,
) -> Result<CdnIndex> {
    let per_index_max = max_bytes.min(MAX_CDN_INDEX_FILE_BYTES);
    let mut merged = CdnIndex::new();
    let mut total_bytes = 0usize;
    let mut total_entries = 0usize;
    for (archive, hash) in archives.iter().enumerate() {
        let (downloaded_bytes, parsed) = fetcher.get_index(hash, per_index_max)?;
        merge_archive_index(
            &mut merged,
            archive,
            downloaded_bytes,
            &parsed,
            &mut total_bytes,
            &mut total_entries,
        )?;
    }
    Ok(merged)
}

/// An opened CDN storage, ready to read files. The read API mirrors
/// [`crate::storage::Storage`].
pub struct CdnStorage<T: CdnTransport> {
    fetcher: CdnFetcher<T>,
    build_config: BuildConfig,
    encoding: EncodingTable,
    root: RootFile,
    version_name: Option<String>,
}

impl<T: CdnTransport> CdnStorage<T> {
    /// Opens the current live build of `product` (e.g. `"s1"`) for `region`
    /// (e.g. `"us"`), discovering the version and CDN via
    /// `patch.battle.net`.
    ///
    /// This performs a substantial amount of up-front fetching (build/CDN
    /// configs, every archive's `.index`, the encoding table, the root
    /// catalog — tens of MB); wrap the transport in [`CachingTransport`] to
    /// make reopening cheap.
    pub fn open(product: &str, region: &str, transport: T) -> Result<Self> {
        Self::open_with_options(product, region, transport, StorageOptions::default())
    }

    /// Opens the current live build with an explicit resource policy.
    pub fn open_with_options(
        product: &str,
        region: &str,
        transport: T,
        options: StorageOptions,
    ) -> Result<Self> {
        validate_discovery_identifier(product, "product")?;
        validate_discovery_identifier(region, "region")?;
        let versions_bytes =
            transport.get(&versions_url(region, product), options.max_metadata_bytes())?;
        let versions = Versions::parse(&String::from_utf8_lossy(&versions_bytes))?;
        let version = versions
            .region(region)
            .ok_or_else(|| CascError::NotFound(format!("region {region} in {product} versions")))?;
        let (build_config, cdn_config) = (version.build_config, version.cdn_config);
        let version_name = version.versions_name.clone();
        Self::open_inner(
            product,
            region,
            build_config,
            cdn_config,
            version_name,
            transport,
            options,
        )
    }

    /// Opens a specific pinned build instead of whatever `versions`
    /// currently advertises: `build_config` and `cdn_config` are the hashes
    /// a `versions` response (current or historical) listed for it. CDN
    /// hosts and path are still discovered via `cdns`. Useful for pinning a
    /// known build regardless of live updates — note Blizzard's CDN only
    /// retains builds for a limited time.
    pub fn open_pinned(
        product: &str,
        region: &str,
        build_config: ContentKey,
        cdn_config: ContentKey,
        transport: T,
    ) -> Result<Self> {
        Self::open_pinned_with_options(
            product,
            region,
            build_config,
            cdn_config,
            transport,
            StorageOptions::default(),
        )
    }

    /// Opens a pinned CDN build with an explicit resource policy.
    pub fn open_pinned_with_options(
        product: &str,
        region: &str,
        build_config: ContentKey,
        cdn_config: ContentKey,
        transport: T,
        options: StorageOptions,
    ) -> Result<Self> {
        validate_discovery_identifier(product, "product")?;
        validate_discovery_identifier(region, "region")?;
        Self::open_inner(
            product,
            region,
            build_config,
            cdn_config,
            None,
            transport,
            options,
        )
    }

    fn open_inner(
        product: &str,
        region: &str,
        build_config_key: ContentKey,
        cdn_config_key: ContentKey,
        version_name: Option<String>,
        transport: T,
        options: StorageOptions,
    ) -> Result<Self> {
        let cdns_bytes = transport.get(&cdns_url(region, product), options.max_metadata_bytes())?;
        let cdns = Cdns::parse(&String::from_utf8_lossy(&cdns_bytes))?;
        let cdn = cdns
            .region(region)
            .ok_or_else(|| CascError::NotFound(format!("region {region} in {product} cdns")))?;
        validate_cdn_location(&cdn.hosts, &cdn.path)?;

        let mut fetcher = CdnFetcher {
            transport,
            limits: options.metadata_read_limits(),
            hosts: cdn.hosts.clone(),
            cdn_path: cdn.path.clone(),
            archives: Vec::new(),
            index: CdnIndex::new(),
        };

        let build_config_bytes = fetcher.get_config(
            &build_config_key,
            options.max_metadata_bytes(),
            "build config",
        )?;
        let build_config = BuildConfig::parse(&String::from_utf8_lossy(&build_config_bytes))
            .inspect_err(|_| {
                fetcher.invalidate_config(&build_config_key);
            })?;

        // The CDN config shares the build config's key=value format; its
        // `archives` line lists the archive hashes this build's data spans.
        let cdn_config_bytes =
            fetcher.get_config(&cdn_config_key, options.max_metadata_bytes(), "CDN config")?;
        let cdn_config = BuildConfig::parse(&String::from_utf8_lossy(&cdn_config_bytes))
            .inspect_err(|_| {
                fetcher.invalidate_config(&cdn_config_key);
            })?;
        let archive_tokens = cdn_config
            .get("archives")
            .ok_or_else(|| CascError::malformed("CDN config", "missing 'archives'"))?
            .split_whitespace();
        let mut archives = Vec::new();
        archives
            .try_reserve(MAX_CDN_ARCHIVES.min(64))
            .map_err(|_| CascError::LimitExceeded {
                what: "CDN archive count",
                limit: MAX_CDN_ARCHIVES,
            })?;
        for token in archive_tokens {
            if archives.len() >= MAX_CDN_ARCHIVES {
                return Err(CascError::LimitExceeded {
                    what: "CDN archive count",
                    limit: MAX_CDN_ARCHIVES,
                });
            }
            archives.push(EncodingKey::from_hex(token).map_err(|_| {
                CascError::malformed("CDN config", "invalid archive content address")
            })?);
        }

        let index = load_archive_indexes(&fetcher, &archives, options.max_metadata_bytes())?;
        fetcher.archives = archives;
        fetcher.index = index;

        // The encoding table's EKey comes straight from the build config —
        // the one fetch that can't go through encoding itself.
        let (encoding_ckey, encoding_ekey) = build_config.encoding()?;
        let encoding_size = build_config.encoding_size().map(|(decoded, _)| decoded);
        let encoding_bytes =
            fetcher.read_by_ekey(&encoding_ekey, Some(&encoding_ckey), encoding_size)?;
        let encoding = EncodingTable::parse(&encoding_bytes)?;

        let root_ckey = build_config.root()?;
        let root_enc = encoding
            .lookup(&root_ckey)
            .ok_or_else(|| CascError::malformed("root file", "root CKey not in encoding table"))?;
        let root_bytes =
            fetcher.read_by_ekey(&root_enc.ekey, Some(&root_ckey), Some(root_enc.size))?;
        let root = RootFile::parse(&root_bytes)?;
        fetcher.limits = options.read_limits();

        Ok(CdnStorage {
            fetcher,
            build_config,
            encoding,
            root,
            version_name,
        })
    }

    /// Downloads a file by its root-catalog path (case-insensitive, `/` or
    /// `\` separators). Returns [`CascError::NotFound`] for unknown paths.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let entry = self
            .root
            .lookup(path)
            .ok_or_else(|| CascError::NotFound(path.to_string()))?;
        self.read_by_ckey(&entry.ckey).map_err(|e| match e {
            CascError::NotFound(_) => CascError::NotFound(path.to_string()),
            other => other,
        })
    }

    /// The decoded size of a file, without downloading it.
    pub fn file_size(&self, path: &str) -> Result<u64> {
        let entry = self
            .root
            .lookup(path)
            .ok_or_else(|| CascError::NotFound(path.to_string()))?;
        let enc = self
            .encoding
            .lookup(&entry.ckey)
            .ok_or_else(|| CascError::NotFound(path.to_string()))?;
        Ok(enc.size)
    }

    /// Whether `path` exists in the root catalog.
    pub fn contains(&self, path: &str) -> bool {
        self.root.lookup(path).is_some()
    }

    /// All file paths in the root catalog, in catalog order.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.root.entries().iter().map(|e| e.path.as_str())
    }

    /// Downloads and decodes content by CKey, verifying the result's MD5.
    pub fn read_by_ckey(&self, ckey: &ContentKey) -> Result<Vec<u8>> {
        let enc = self
            .encoding
            .lookup(ckey)
            .ok_or_else(|| CascError::NotFound(ckey.to_string()))?;
        self.fetcher
            .read_by_ekey(&enc.ekey, Some(ckey), Some(enc.size))
    }

    /// Downloads and decodes content selected by EKey. When `expected_ckey`
    /// is given, the decoded bytes' MD5 is verified against it. Without a
    /// CKey, archive/range addressing and BLTE chunk corruption checks still
    /// apply, but decoded content identity cannot be established.
    pub fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
    ) -> Result<Vec<u8>> {
        self.fetcher.read_by_ekey(ekey, expected_ckey, None)
    }

    /// The parsed root catalog.
    pub fn root(&self) -> &RootFile {
        &self.root
    }

    /// The parsed encoding (CKey → EKey) table.
    pub fn encoding(&self) -> &EncodingTable {
        &self.encoding
    }

    /// The build config this storage was opened from.
    pub fn build_config(&self) -> &BuildConfig {
        &self.build_config
    }

    /// The version name from discovery (e.g. `"1.23.10.13515"`), when the
    /// storage was opened via [`CdnStorage::open`].
    pub fn version_name(&self) -> Option<&str> {
        self.version_name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Condvar, Mutex};

    use md5::{Digest, Md5};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Get {
            url: String,
            max_bytes: usize,
        },
        Range {
            url: String,
            offset: u64,
            len: u64,
        },
        Invalidate {
            url: String,
            range: Option<(u64, u64)>,
        },
    }

    struct ScriptTransport {
        bodies: HashMap<String, Vec<u8>>,
        range_body: Option<Vec<u8>>,
        calls: Mutex<Vec<Call>>,
    }

    impl ScriptTransport {
        fn new(bodies: HashMap<String, Vec<u8>>) -> Self {
            Self {
                bodies,
                range_body: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CdnTransport for ScriptTransport {
        fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
            self.calls.lock().unwrap().push(Call::Get {
                url: url.to_string(),
                max_bytes,
            });
            let bytes = self
                .bodies
                .get(url)
                .cloned()
                .ok_or_else(|| CascError::NotFound(url.to_string()))?;
            if bytes.len() > max_bytes {
                return Err(CascError::LimitExceeded {
                    what: "scripted response",
                    limit: max_bytes,
                });
            }
            Ok(bytes)
        }

        fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
            self.calls.lock().unwrap().push(Call::Range {
                url: url.to_string(),
                offset,
                len,
            });
            let bytes = self
                .range_body
                .clone()
                .ok_or_else(|| CascError::NotFound(url.to_string()))?;
            if bytes.len() as u64 != len {
                return Err(CascError::Transport {
                    url: url.to_string(),
                    reason: "scripted range length mismatch".to_string(),
                });
            }
            Ok(bytes)
        }

        fn invalidate(&self, url: &str, range: Option<(u64, u64)>) {
            self.calls.lock().unwrap().push(Call::Invalidate {
                url: url.to_string(),
                range,
            });
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    struct ReorderedIndexTransport {
        bodies: HashMap<String, Vec<u8>>,
        first_url: String,
        second_url: String,
        second_finished: (Mutex<bool>, Condvar),
        completion_order: Mutex<Vec<String>>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl CdnTransport for ReorderedIndexTransport {
        fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
            let bytes = self
                .bodies
                .get(url)
                .cloned()
                .ok_or_else(|| CascError::NotFound(url.to_string()))?;
            if bytes.len() > max_bytes {
                return Err(CascError::LimitExceeded {
                    what: "scripted response",
                    limit: max_bytes,
                });
            }

            if url == self.first_url {
                let (finished, wake) = &self.second_finished;
                let mut second_finished = finished.lock().unwrap();
                while !*second_finished {
                    second_finished = wake.wait(second_finished).unwrap();
                }
                self.completion_order
                    .lock()
                    .unwrap()
                    .push(self.first_url.clone());
            } else if url == self.second_url {
                self.completion_order
                    .lock()
                    .unwrap()
                    .push(self.second_url.clone());
                let (finished, wake) = &self.second_finished;
                *finished.lock().unwrap() = true;
                wake.notify_all();
            }

            Ok(bytes)
        }

        fn get_range(&self, url: &str, _offset: u64, _len: u64) -> Result<Vec<u8>> {
            Err(CascError::NotFound(url.to_string()))
        }
    }

    fn single_raw(payload: &[u8]) -> Vec<u8> {
        let mut out = b"BLTE\0\0\0\0N".to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn content_key(bytes: &[u8]) -> ContentKey {
        ContentKey::from(<[u8; 16]>::from(Md5::digest(bytes)))
    }

    fn expect_error<T>(result: Result<T>) -> CascError {
        match result {
            Ok(_) => panic!("operation unexpectedly succeeded"),
            Err(err) => err,
        }
    }

    fn archive_index_bytes(ekey: EncodingKey, encoded_size: u32, offset: u32) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0..16].copy_from_slice(ekey.as_bytes());
        data[16..20].copy_from_slice(&encoded_size.to_be_bytes());
        data[20..24].copy_from_slice(&offset.to_be_bytes());
        let mut footer = [0u8; 36];
        footer[16] = 1;
        footer[19] = 1;
        footer[20] = 4;
        footer[21] = 4;
        footer[22] = 16;
        footer[23] = 8;
        footer[24..28].copy_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&footer);
        data
    }

    fn archive_index(ekey: EncodingKey, encoded_size: u32, offset: u32) -> ArchiveIndex {
        ArchiveIndex::parse(&archive_index_bytes(ekey, encoded_size, offset)).unwrap()
    }

    fn fetcher(
        transport: ScriptTransport,
        limits: ReadLimits,
        archives: Vec<EncodingKey>,
        index: CdnIndex,
    ) -> CdnFetcher<ScriptTransport> {
        CdnFetcher {
            transport,
            limits,
            hosts: vec!["cdn.example".to_string()],
            cdn_path: "tpr/sc1live".to_string(),
            archives,
            index,
        }
    }

    #[test]
    fn loose_object_uses_verified_boundary_and_propagates_encoded_cap() {
        let ekey = EncodingKey::from([2; 16]);
        let payload = b"hello";
        let encoded = single_raw(payload);
        let url = cdn_file_url(
            "cdn.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &ekey.to_string(),
            false,
        )
        .unwrap();
        let transport = ScriptTransport::new(HashMap::from([(url.clone(), encoded)]));
        let limits = ReadLimits {
            max_encoded_bytes: 123,
            ..ReadLimits::default()
        };
        let fetcher = fetcher(transport, limits, Vec::new(), CdnIndex::new());
        let ckey = content_key(payload);

        let decoded = fetcher
            .read_by_ekey(&ekey, Some(&ckey), Some(payload.len() as u64))
            .unwrap();

        assert_eq!(decoded, payload);
        assert_eq!(
            fetcher.transport.calls(),
            vec![Call::Get {
                url,
                max_bytes: 123
            }]
        );
    }

    #[test]
    fn indexed_object_routes_to_range_request() {
        let ekey = EncodingKey::from([3; 16]);
        let archive = EncodingKey::from([4; 16]);
        let payload = b"archive";
        let encoded = single_raw(payload);
        let parsed = archive_index(ekey, encoded.len() as u32, 77);
        let mut index = CdnIndex::new();
        index.add_archive(0, &parsed);
        let mut transport = ScriptTransport::new(HashMap::new());
        transport.range_body = Some(encoded.clone());
        let fetcher = fetcher(transport, ReadLimits::default(), vec![archive], index);

        assert_eq!(fetcher.read_by_ekey(&ekey, None, None).unwrap(), payload);
        assert!(matches!(
            fetcher.transport.calls().as_slice(),
            [Call::Range { offset: 77, len, .. }] if *len == encoded.len() as u64
        ));
    }

    #[test]
    fn archive_count_limit_is_checked_before_transport() {
        let fetcher = fetcher(
            ScriptTransport::new(HashMap::new()),
            ReadLimits::default(),
            Vec::new(),
            CdnIndex::new(),
        );
        let archives = vec![EncodingKey::from([8; 16]); 257];

        let err = load_archive_indexes(&fetcher, &archives, 1024).unwrap_err();

        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "CDN archive count",
                limit: 256
            }
        ));
        assert!(fetcher.transport.calls().is_empty());
    }

    #[test]
    fn aggregate_index_limits_are_checked_before_insertion() {
        let ekey = EncodingKey::from([13; 16]);
        let parsed = archive_index(ekey, 1, 0);
        let mut merged = CdnIndex::new();
        let mut total_bytes = MAX_CDN_INDEX_BYTES;
        let mut total_entries = 0;

        let bytes_err = merge_archive_index(
            &mut merged,
            0,
            1,
            &parsed,
            &mut total_bytes,
            &mut total_entries,
        )
        .unwrap_err();
        assert!(matches!(
            bytes_err,
            CascError::LimitExceeded {
                what: "aggregate CDN archive index bytes",
                limit: MAX_CDN_INDEX_BYTES
            }
        ));
        assert_eq!(merged.len(), 0);

        total_bytes = 0;
        total_entries = MAX_CDN_INDEX_ENTRIES;
        let entries_err = merge_archive_index(
            &mut merged,
            0,
            1,
            &parsed,
            &mut total_bytes,
            &mut total_entries,
        )
        .unwrap_err();
        assert!(matches!(
            entries_err,
            CascError::LimitExceeded {
                what: "aggregate CDN archive index entries",
                limit: MAX_CDN_INDEX_ENTRIES
            }
        ));
        assert_eq!(merged.len(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn parallel_index_loading_preserves_later_archive_wins_order() {
        let shared_ekey = EncodingKey::from([9; 16]);
        let first_archive = EncodingKey::from([10; 16]);
        let second_archive = EncodingKey::from([11; 16]);
        let first_url = cdn_file_url(
            "cdn.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &first_archive.to_string(),
            true,
        )
        .unwrap();
        let second_url = cdn_file_url(
            "cdn.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &second_archive.to_string(),
            true,
        )
        .unwrap();
        let transport = ReorderedIndexTransport {
            bodies: HashMap::from([
                (first_url.clone(), archive_index_bytes(shared_ekey, 100, 10)),
                (
                    second_url.clone(),
                    archive_index_bytes(shared_ekey, 200, 20),
                ),
            ]),
            first_url: first_url.clone(),
            second_url: second_url.clone(),
            second_finished: (Mutex::new(false), Condvar::new()),
            completion_order: Mutex::new(Vec::new()),
        };
        let fetcher = CdnFetcher {
            transport,
            limits: ReadLimits::default(),
            hosts: vec!["cdn.example".to_string()],
            cdn_path: "tpr/sc1live".to_string(),
            archives: Vec::new(),
            index: CdnIndex::new(),
        };

        let merged =
            load_archive_indexes(&fetcher, &[first_archive, second_archive], 2 * 1024).unwrap();
        assert_eq!(
            *fetcher.transport.completion_order.lock().unwrap(),
            vec![second_url, first_url],
            "the transport should complete out of archive order"
        );

        let entry = merged.lookup(&shared_ekey).unwrap();
        assert_eq!(entry.archive, 1);
        assert_eq!(entry.offset, 20);
        assert_eq!(entry.encoded_size, 200);
    }

    #[test]
    fn oversized_indexed_object_is_rejected_before_transport() {
        let ekey = EncodingKey::from([5; 16]);
        let archive = EncodingKey::from([6; 16]);
        let parsed = archive_index(ekey, 11, 0);
        let mut index = CdnIndex::new();
        index.add_archive(0, &parsed);
        let limits = ReadLimits {
            max_encoded_bytes: 10,
            ..ReadLimits::default()
        };
        let fetcher = fetcher(
            ScriptTransport::new(HashMap::new()),
            limits,
            vec![archive],
            index,
        );

        let err = fetcher.read_by_ekey(&ekey, None, None).unwrap_err();
        assert!(matches!(err, CascError::LimitExceeded { .. }));
        assert!(fetcher.transport.calls().is_empty());
    }

    #[test]
    fn malformed_object_invalidates_its_transport_entry() {
        let ekey = EncodingKey::from([9; 16]);
        let url = cdn_file_url(
            "cdn.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &ekey.to_string(),
            false,
        )
        .unwrap();
        let transport = ScriptTransport::new(HashMap::from([(
            url.clone(),
            b"not a BLTE object".to_vec(),
        )]));
        let fetcher = fetcher(
            transport,
            ReadLimits::default(),
            Vec::new(),
            CdnIndex::new(),
        );

        assert!(matches!(
            fetcher.read_by_ekey(&ekey, None, None),
            Err(CascError::Malformed { .. })
        ));
        assert!(
            fetcher
                .transport
                .calls()
                .contains(&Call::Invalidate { url, range: None })
        );
    }

    #[test]
    fn corrupt_first_host_is_invalidated_then_next_host_is_tried() {
        let ekey = EncodingKey::from([10; 16]);
        let payload = b"healthy";
        let first_url = cdn_file_url(
            "first.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &ekey.to_string(),
            false,
        )
        .unwrap();
        let second_url = cdn_file_url(
            "second.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &ekey.to_string(),
            false,
        )
        .unwrap();
        let transport = ScriptTransport::new(HashMap::from([
            (first_url.clone(), b"corrupt".to_vec()),
            (second_url.clone(), single_raw(payload)),
        ]));
        let mut fetcher = fetcher(
            transport,
            ReadLimits::default(),
            Vec::new(),
            CdnIndex::new(),
        );
        fetcher.hosts = vec!["first.example".to_string(), "second.example".to_string()];

        assert_eq!(
            fetcher
                .read_by_ekey(&ekey, Some(&content_key(payload)), None)
                .unwrap(),
            payload
        );
        let calls = fetcher.transport.calls();
        assert!(calls.contains(&Call::Invalidate {
            url: first_url,
            range: None,
        }));
        assert!(calls.iter().any(|call| matches!(
            call,
            Call::Get { url, .. } if url == &second_url
        )));
    }

    #[test]
    fn corrupt_index_host_is_invalidated_then_next_host_is_tried() {
        let archive = EncodingKey::from([11; 16]);
        let first_url = cdn_file_url(
            "first.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &archive.to_string(),
            true,
        )
        .unwrap();
        let second_url = cdn_file_url(
            "second.example",
            "tpr/sc1live",
            CdnPathKind::Data,
            &archive.to_string(),
            true,
        )
        .unwrap();
        let mut empty_index = vec![0; 36];
        empty_index[16] = 1;
        empty_index[19] = 1;
        empty_index[20] = 4;
        empty_index[21] = 4;
        empty_index[22] = 16;
        empty_index[23] = 8;
        let transport = ScriptTransport::new(HashMap::from([
            (first_url.clone(), b"corrupt".to_vec()),
            (second_url, empty_index),
        ]));
        let mut fetcher = fetcher(
            transport,
            ReadLimits::default(),
            Vec::new(),
            CdnIndex::new(),
        );
        fetcher.hosts = vec!["first.example".to_string(), "second.example".to_string()];

        assert!(fetcher.get_index(&archive, 1024).unwrap().1.is_empty());
        assert!(fetcher.transport.calls().contains(&Call::Invalidate {
            url: first_url,
            range: None,
        }));
    }

    #[test]
    fn corrupt_config_host_is_invalidated_then_next_host_is_tried() {
        let body = b"archives =\n";
        let key = content_key(body);
        let first_url = cdn_file_url(
            "first.example",
            "tpr/sc1live",
            CdnPathKind::Config,
            &key.to_string(),
            false,
        )
        .unwrap();
        let second_url = cdn_file_url(
            "second.example",
            "tpr/sc1live",
            CdnPathKind::Config,
            &key.to_string(),
            false,
        )
        .unwrap();
        let transport = ScriptTransport::new(HashMap::from([
            (first_url.clone(), b"forged".to_vec()),
            (second_url, body.to_vec()),
        ]));
        let mut fetcher = fetcher(
            transport,
            ReadLimits::default(),
            Vec::new(),
            CdnIndex::new(),
        );
        fetcher.hosts = vec!["first.example".to_string(), "second.example".to_string()];

        assert_eq!(fetcher.get_config(&key, 1024, "test config").unwrap(), body);
        assert!(fetcher.transport.calls().contains(&Call::Invalidate {
            url: first_url,
            range: None,
        }));
    }

    #[test]
    fn pinned_open_bounds_discovery_metadata() {
        let url = cdns_url("us", "s1");
        let transport = ScriptTransport::new(HashMap::from([(url.clone(), vec![0; 9])]));
        let options = StorageOptions::new().with_max_metadata_bytes(8);

        let err = expect_error(CdnStorage::open_pinned_with_options(
            "s1",
            "us",
            ContentKey::from([1; 16]),
            ContentKey::from([2; 16]),
            transport,
            options,
        ));

        assert!(matches!(err, CascError::LimitExceeded { .. }));
    }

    #[test]
    fn pinned_open_rejects_forged_build_config_before_parsing() {
        let cdns = b"Name!STRING:0|Path!STRING:0|Hosts!STRING:0\nus|tpr/sc1live|cdn.blizzard.com\n"
            .to_vec();
        let build_key = content_key(b"authentic build config");
        let cdn_key = content_key(b"authentic CDN config");
        let build_url = cdn_file_url(
            "cdn.blizzard.com",
            "tpr/sc1live",
            CdnPathKind::Config,
            &build_key.to_string(),
            false,
        )
        .unwrap();
        let transport = ScriptTransport::new(HashMap::from([
            (cdns_url("us", "s1"), cdns),
            (build_url, b"forged".to_vec()),
        ]));

        let err = expect_error(CdnStorage::open_pinned(
            "s1", "us", build_key, cdn_key, transport,
        ));
        assert!(matches!(err, CascError::ChecksumMismatch("build config")));
    }

    #[test]
    fn cdn_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ScriptTransport>();
        assert_send_sync::<CdnStorage<ScriptTransport>>();
    }
}

fn verify_raw_ckey(bytes: &[u8], expected: &ContentKey, what: &'static str) -> Result<()> {
    let actual: [u8; 16] = Md5::digest(bytes).into();
    if actual == *expected.as_bytes() {
        Ok(())
    } else {
        Err(CascError::ChecksumMismatch(what))
    }
}

#[cfg(feature = "cdn-http")]
mod http_impl {
    use std::time::Duration;

    use super::CdnTransport;
    use crate::error::{CascError, Result};

    /// [`CdnTransport`] over plain HTTP using [`ureq`].
    ///
    /// The default agent does not follow redirects: discovery-derived URLs
    /// are restricted to Blizzard hosts, and following an unvalidated
    /// redirect could otherwise reintroduce SSRF. Integrity is enforced by
    /// the verification layer above for CKey-addressed reads; plain HTTP is
    /// not itself an authentication boundary.
    pub struct HttpTransport {
        agent: ureq::Agent,
    }

    impl HttpTransport {
        pub fn new() -> Self {
            HttpTransport {
                agent: ureq::config::Config::builder()
                    .max_redirects(0)
                    .timeout_global(Some(Duration::from_secs(5 * 60)))
                    .timeout_resolve(Some(Duration::from_secs(10)))
                    .timeout_connect(Some(Duration::from_secs(10)))
                    .timeout_recv_response(Some(Duration::from_secs(30)))
                    .build()
                    .into(),
            }
        }

        /// Uses a caller-configured agent (timeouts, proxies, ...). Callers
        /// should keep redirects disabled; enabling them can bypass the CDN
        /// host validation performed by [`crate::cdn::CdnStorage`].
        pub fn with_agent(agent: ureq::Agent) -> Self {
            HttpTransport { agent }
        }
    }

    impl Default for HttpTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    fn request_err(url: &str, err: ureq::Error) -> CascError {
        match err {
            ureq::Error::StatusCode(404) => CascError::NotFound(url.to_string()),
            other => CascError::Transport {
                url: url.to_string(),
                reason: other.to_string(),
            },
        }
    }

    fn body_err(url: &str, err: ureq::Error) -> CascError {
        CascError::Transport {
            url: url.to_string(),
            reason: format!("reading body: {err}"),
        }
    }

    fn bounded_body_err(
        url: &str,
        err: ureq::Error,
        what: &'static str,
        limit: usize,
    ) -> CascError {
        match err {
            ureq::Error::BodyExceedsLimit(_) => CascError::LimitExceeded { what, limit },
            other => body_err(url, other),
        }
    }

    fn content_range_matches(value: &str, offset: u64, end: u64) -> bool {
        let Some((unit, remainder)) = value.split_once(' ') else {
            return false;
        };
        let Some((range, total)) = remainder.split_once('/') else {
            return false;
        };
        if !unit.eq_ignore_ascii_case("bytes") || range != format!("{offset}-{end}") {
            return false;
        }
        total == "*" || total.parse::<u64>().is_ok_and(|length| end < length)
    }

    impl CdnTransport for HttpTransport {
        fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
            let max_u64 = u64::try_from(max_bytes).map_err(|_| CascError::LimitExceeded {
                what: "CDN response body",
                limit: max_bytes,
            })?;
            // ureq reports an error when the response reaches the configured
            // limit, so one byte of slack permits exactly `max_bytes` while
            // still preventing a larger body from being retained.
            let read_limit = max_u64.saturating_add(1);
            let mut response = self
                .agent
                .get(url)
                .call()
                .map_err(|e| request_err(url, e))?;
            let body = response
                .body_mut()
                .with_config()
                .limit(read_limit)
                .read_to_vec()
                .map_err(|e| bounded_body_err(url, e, "CDN response body", max_bytes))?;
            if body.len() > max_bytes {
                return Err(CascError::LimitExceeded {
                    what: "CDN response body",
                    limit: max_bytes,
                });
            }
            Ok(body)
        }

        fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
            if len == 0 {
                return Ok(Vec::new());
            }
            // HTTP Range ends are inclusive.
            let end = offset
                .checked_add(len - 1)
                .ok_or_else(|| CascError::Transport {
                    url: url.to_string(),
                    reason: "range end overflows u64".to_string(),
                })?;
            let response_limit = len.checked_add(1).ok_or_else(|| CascError::Transport {
                url: url.to_string(),
                reason: "range response limit overflows u64".to_string(),
            })?;
            let mut response = self
                .agent
                .get(url)
                .header("Range", format!("bytes={offset}-{end}"))
                .call()
                .map_err(|e| request_err(url, e))?;
            if response.status().as_u16() != 206 {
                // A 200 here means the server ignored the Range header; for
                // a 1 GiB archive that must be an error, not a fallback.
                return Err(CascError::Transport {
                    url: url.to_string(),
                    reason: format!("expected 206 Partial Content, got {}", response.status()),
                });
            }
            let valid_content_range = response
                .headers()
                .get("Content-Range")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| content_range_matches(value, offset, end));
            if !valid_content_range {
                return Err(CascError::Transport {
                    url: url.to_string(),
                    reason: "missing or inconsistent Content-Range header".to_string(),
                });
            }
            // Slack on the limit: ureq errors when a body *reaches* the
            // limit, and we want the exact-length check below to produce the
            // clearer error for small overruns anyway.
            let body = response
                .body_mut()
                .with_config()
                .limit(response_limit)
                .read_to_vec()
                .map_err(|e| body_err(url, e))?;
            if body.len() as u64 != len {
                return Err(CascError::Transport {
                    url: url.to_string(),
                    reason: format!("range response returned {} bytes, wanted {len}", body.len()),
                });
            }
            Ok(body)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn range_end_overflow_is_rejected_before_request() {
            let err = HttpTransport::new()
                .get_range("http://127.0.0.1:1/archive", u64::MAX, 2)
                .unwrap_err();
            assert!(
                matches!(err, CascError::Transport { reason, .. } if reason.contains("range end overflows"))
            );
        }

        #[test]
        fn range_limit_overflow_is_rejected_before_request() {
            let err = HttpTransport::new()
                .get_range("http://127.0.0.1:1/archive", 0, u64::MAX)
                .unwrap_err();
            assert!(
                matches!(err, CascError::Transport { reason, .. } if reason.contains("range response limit overflows"))
            );
        }

        #[test]
        fn content_range_must_identify_the_requested_interval() {
            assert!(content_range_matches("bytes 10-19/100", 10, 19));
            assert!(content_range_matches("Bytes 10-19/*", 10, 19));
            assert!(!content_range_matches("bytes 0-9/100", 10, 19));
            assert!(!content_range_matches("bytes 10-19/19", 10, 19));
            assert!(!content_range_matches("garbage", 10, 19));
        }
    }
}

#[cfg(feature = "cdn-http")]
pub use http_impl::HttpTransport;

#[cfg(feature = "fs")]
mod cache_impl {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::CdnTransport;
    use crate::error::{CascError, Result};

    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy)]
    enum CacheKind {
        Whole,
        Range { offset: u64, len: u64 },
    }

    /// Wraps a [`CdnTransport`] with a persistent on-disk cache.
    ///
    /// Only content-addressed resources are cached (URLs whose last segment
    /// is a 32-char hex hash, optionally `.index`) — those are immutable, so
    /// entries never need invalidation. Discovery endpoints (`versions`,
    /// `cdns`) change over time and always pass through. Cache writes are
    /// best-effort: a failed write degrades to a plain fetch, never an
    /// error.
    pub struct CachingTransport<T> {
        inner: T,
        dir: PathBuf,
    }

    impl<T: CdnTransport> CachingTransport<T> {
        pub fn new(inner: T, dir: impl Into<PathBuf>) -> Self {
            CachingTransport {
                inner,
                dir: dir.into(),
            }
        }

        pub fn cache_dir(&self) -> &Path {
            &self.dir
        }

        /// The cache file for `url`, or `None` if its final segment is not a
        /// validated content address. No other URL component reaches the
        /// filesystem path: hosts and CDN paths come from mutable discovery
        /// documents and must be treated as untrusted.
        fn cache_path(&self, url: &str, kind: CacheKind) -> Option<PathBuf> {
            let last = url.rsplit('/').next()?;
            let stem = last.strip_suffix(".index").unwrap_or(last);
            if stem.len() != 32 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let hash = stem.to_ascii_lowercase();
            let is_index = last.ends_with(".index");
            let (subdir, file_name) = match kind {
                CacheKind::Whole if is_index => ("indices", format!("{hash}.index")),
                CacheKind::Whole => ("content", hash.clone()),
                CacheKind::Range { .. } if is_index => return None,
                CacheKind::Range { offset, len } => ("ranges", format!("{hash}.r{offset}-{len}")),
            };
            Some(
                self.dir
                    .join(subdir)
                    .join(&hash[0..2])
                    .join(&hash[2..4])
                    .join(file_name),
            )
        }

        /// Publishes a complete cache entry with a same-directory rename so
        /// readers never observe a partially-written file. Cache writes are
        /// best-effort by design; a racing writer may win publication.
        fn publish(path: &Path, bytes: &[u8]) {
            let Some(parent) = path.parent() else {
                return;
            };
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }

            let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let Some(file_name) = path.file_name() else {
                return;
            };
            let mut temporary_name = file_name.to_os_string();
            temporary_name.push(format!(".tmp-{}-{sequence}", std::process::id()));
            let temporary = path.with_file_name(temporary_name);

            // Exclusive creation prevents a writable shared cache directory
            // from turning the predictable temporary name into a symlink
            // target. A collision simply degrades this best-effort cache
            // write to a miss.
            let Ok(mut file) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            else {
                return;
            };
            if file.write_all(bytes).is_err() {
                drop(file);
                let _ = std::fs::remove_file(&temporary);
                return;
            }
            drop(file);
            if std::fs::rename(&temporary, path).is_err() {
                let _ = std::fs::remove_file(temporary);
            }
        }

        /// Reads at most `max_bytes + 1` from a cache file. Metadata is
        /// checked first to avoid `std::fs::read` reserving directly from an
        /// attacker-controlled file length, while `take` handles a file that
        /// grows after the metadata check.
        fn read_cached(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
            let file = std::fs::File::open(path).ok()?;
            let file_len = usize::try_from(file.metadata().ok()?.len()).ok()?;
            if file_len > max_bytes {
                return None;
            }
            let read_limit = u64::try_from(max_bytes).ok()?.saturating_add(1);
            let mut bytes = Vec::with_capacity(file_len);
            file.take(read_limit).read_to_end(&mut bytes).ok()?;
            (bytes.len() <= max_bytes).then_some(bytes)
        }

        fn fetch_through(
            &self,
            url: &str,
            max_bytes: usize,
            fetch: impl FnOnce() -> Result<Vec<u8>>,
        ) -> Result<Vec<u8>> {
            let Some(path) = self.cache_path(url, CacheKind::Whole) else {
                return fetch();
            };
            if let Some(bytes) = Self::read_cached(&path, max_bytes) {
                return Ok(bytes);
            }
            let _ = std::fs::remove_file(&path);
            let bytes = fetch()?;
            if bytes.len() > max_bytes {
                return Err(CascError::LimitExceeded {
                    what: "CDN response body",
                    limit: max_bytes,
                });
            }
            Self::publish(&path, &bytes);
            Ok(bytes)
        }

        fn fetch_range(
            &self,
            url: &str,
            offset: u64,
            len: u64,
            fetch: impl FnOnce() -> Result<Vec<u8>>,
        ) -> Result<Vec<u8>> {
            let Some(path) = self.cache_path(url, CacheKind::Range { offset, len }) else {
                return fetch();
            };
            let range_limit = usize::try_from(len).map_err(|_| CascError::LimitExceeded {
                what: "CDN range response",
                limit: usize::MAX,
            })?;
            match Self::read_cached(&path, range_limit) {
                Some(bytes) if bytes.len() as u64 == len => return Ok(bytes),
                Some(_) | None => {
                    // Do not let a truncated file become a permanent cache
                    // hit. Removing it also lets atomic publication repair it
                    // on platforms where rename does not replace files.
                    let _ = std::fs::remove_file(&path);
                }
            }

            let bytes = fetch()?;
            if bytes.len() as u64 != len {
                return Err(CascError::Transport {
                    url: url.to_string(),
                    reason: format!(
                        "range transport returned {} bytes, wanted {len}",
                        bytes.len()
                    ),
                });
            }
            Self::publish(&path, &bytes);
            Ok(bytes)
        }
    }

    impl<T: CdnTransport> CdnTransport for CachingTransport<T> {
        fn get(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
            self.fetch_through(url, max_bytes, || self.inner.get(url, max_bytes))
        }

        fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
            self.fetch_range(url, offset, len, || self.inner.get_range(url, offset, len))
        }

        fn invalidate(&self, url: &str, range: Option<(u64, u64)>) {
            let kind = match range {
                Some((offset, len)) => CacheKind::Range { offset, len },
                None => CacheKind::Whole,
            };
            if let Some(path) = self.cache_path(url, kind) {
                let _ = std::fs::remove_file(path);
            }
            self.inner.invalidate(url, range);
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use super::*;

        const HASH: &str = "864772b9ff94f6d372aa4ee90ee2f8ab";

        struct TestTransport {
            whole_bytes: Vec<u8>,
            whole_calls: AtomicUsize,
            range_bytes: Vec<u8>,
            range_calls: AtomicUsize,
        }

        impl CdnTransport for TestTransport {
            fn get(&self, _url: &str, _max_bytes: usize) -> Result<Vec<u8>> {
                self.whole_calls.fetch_add(1, Ordering::Relaxed);
                Ok(self.whole_bytes.clone())
            }

            fn get_range(&self, _url: &str, _offset: u64, _len: u64) -> Result<Vec<u8>> {
                self.range_calls.fetch_add(1, Ordering::Relaxed);
                Ok(self.range_bytes.clone())
            }
        }

        struct TestDir(PathBuf);

        impl TestDir {
            fn new(name: &str) -> Self {
                let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "broodcasc-{name}-{}-{sequence}",
                    std::process::id()
                ));
                std::fs::create_dir_all(&path).unwrap();
                TestDir(path)
            }
        }

        impl Drop for TestDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn transport(bytes: Vec<u8>, dir: &Path) -> CachingTransport<TestTransport> {
            CachingTransport::new(
                TestTransport {
                    whole_bytes: bytes.clone(),
                    whole_calls: AtomicUsize::new(0),
                    range_bytes: bytes,
                    range_calls: AtomicUsize::new(0),
                },
                dir,
            )
        }

        #[test]
        fn cache_path_ignores_hostile_url_components() {
            let cache = transport(Vec::new(), Path::new("cache-root"));
            let hostile = format!("http://host/../../../../escape/data/86/47/{HASH}");

            let path = cache
                .cache_path(&hostile, CacheKind::Whole)
                .expect("content-addressed URL should be cacheable");

            assert_eq!(
                path,
                Path::new("cache-root")
                    .join("content")
                    .join("86")
                    .join("47")
                    .join(HASH)
            );
            assert!(
                !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            );
        }

        #[test]
        fn truncated_range_cache_entry_is_refetched_and_repaired() {
            let dir = TestDir::new("range-repair");
            let cache = transport(vec![7, 8, 9], &dir.0);
            let url = format!("http://host/cdn/data/86/47/{HASH}");
            let path = cache
                .cache_path(&url, CacheKind::Range { offset: 4, len: 3 })
                .unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, [1]).unwrap();

            assert_eq!(cache.get_range(&url, 4, 3).unwrap(), [7, 8, 9]);
            assert_eq!(cache.inner.range_calls.load(Ordering::Relaxed), 1);
            assert_eq!(std::fs::read(&path).unwrap(), [7, 8, 9]);

            assert_eq!(cache.get_range(&url, 4, 3).unwrap(), [7, 8, 9]);
            assert_eq!(cache.inner.range_calls.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn oversized_whole_cache_entry_is_refetched_without_unbounded_read() {
            let dir = TestDir::new("whole-limit");
            let cache = transport(vec![7, 8, 9], &dir.0);
            let url = format!("http://host/cdn/data/86/47/{HASH}");
            let path = cache.cache_path(&url, CacheKind::Whole).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, [0; 4]).unwrap();

            assert_eq!(cache.get(&url, 3).unwrap(), [7, 8, 9]);
            assert_eq!(cache.inner.whole_calls.load(Ordering::Relaxed), 1);
            assert_eq!(std::fs::read(path).unwrap(), [7, 8, 9]);
        }

        #[test]
        fn wrong_length_range_response_is_not_cached() {
            let dir = TestDir::new("range-length");
            let cache = transport(vec![7, 8], &dir.0);
            let url = format!("http://host/cdn/data/86/47/{HASH}");
            let path = cache
                .cache_path(&url, CacheKind::Range { offset: 4, len: 3 })
                .unwrap();

            let err = cache.get_range(&url, 4, 3).unwrap_err();
            assert!(matches!(err, CascError::Transport { .. }));
            assert!(!path.exists());
        }
    }
}

#[cfg(feature = "fs")]
pub use cache_impl::CachingTransport;
