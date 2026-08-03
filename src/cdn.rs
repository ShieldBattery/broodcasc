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

use crate::blte;
use crate::cdnindex::{ArchiveIndex, CdnIndex};
use crate::config::BuildConfig;
use crate::encoding::EncodingTable;
use crate::error::{CascError, Result};
use crate::keys::{ContentKey, EncodingKey};
use crate::root::RootFile;
use crate::tact::{CdnPathKind, Cdns, Versions, cdn_file_url, cdns_url, versions_url};

/// Fetches resources from a CDN by URL.
///
/// Implementations should return [`CascError::NotFound`] for a clean HTTP
/// 404 (the storage layer uses this to fall back from "not archived" to
/// "doesn't exist") and [`CascError::Transport`] for other failures.
pub trait CdnTransport {
    /// Fetches the entire resource at `url`.
    fn get(&self, url: &str) -> Result<Vec<u8>>;

    /// Fetches exactly `len` bytes starting at byte `offset` of the resource
    /// at `url` (an HTTP Range request). Must fail rather than silently
    /// return a different amount of data.
    fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>>;
}

impl<T: CdnTransport + ?Sized> CdnTransport for &T {
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        (**self).get(url)
    }

    fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        (**self).get_range(url, offset, len)
    }
}

/// The EKey-addressed lower half of a CDN storage: hosts, archive list, and
/// merged archive index. Separate from [`CdnStorage`] so the bootstrap can
/// fetch the encoding table before the CKey layer exists (same shape as the
/// local storage's internal split).
struct CdnFetcher<T: CdnTransport> {
    transport: T,
    /// CDN hosts in preference order; later hosts are tried when earlier
    /// ones fail with transport errors (a 404 is authoritative and not
    /// retried — the CDN is content-addressed, so all hosts serve the same
    /// objects).
    hosts: Vec<String>,
    cdn_path: String,
    /// Archive hashes (lowercase hex) from the CDN config, in order; the
    /// merged index refers to archives by position in this list.
    archives: Vec<String>,
    index: CdnIndex,
}

impl<T: CdnTransport> CdnFetcher<T> {
    /// Fetches a CDN file (`config/` or `data/` addressing), trying each
    /// host in order on transport failures.
    fn get(&self, kind: CdnPathKind, hash_hex: &str, index: bool) -> Result<Vec<u8>> {
        self.try_hosts(|host| {
            let url = cdn_file_url(host, &self.cdn_path, kind, hash_hex, index);
            self.transport.get(&url)
        })
    }

    fn get_range(&self, hash_hex: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.try_hosts(|host| {
            let url = cdn_file_url(host, &self.cdn_path, CdnPathKind::Data, hash_hex, false);
            self.transport.get_range(&url, offset, len)
        })
    }

    fn try_hosts(&self, mut fetch: impl FnMut(&str) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
        let mut last_err = None;
        for host in &self.hosts {
            match fetch(host) {
                Ok(bytes) => return Ok(bytes),
                err @ Err(CascError::NotFound(_)) => return err,
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| CascError::Transport {
            url: String::new(),
            reason: "no CDN hosts available".to_string(),
        }))
    }

    /// Fetches and BLTE-decodes the content for `ekey`: a Range request into
    /// the owning archive when indexed, otherwise a loose-file GET. Verifies
    /// the decoded bytes against `expected_ckey` when given.
    fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
    ) -> Result<Vec<u8>> {
        let encoded = match self.index.lookup(ekey) {
            Some(entry) => {
                let archive = self.archives.get(entry.archive as usize).ok_or_else(|| {
                    CascError::malformed("CDN index", "archive number out of range")
                })?;
                self.get_range(
                    archive,
                    u64::from(entry.offset),
                    u64::from(entry.encoded_size),
                )?
            }
            None => match self.get(CdnPathKind::Data, &ekey.to_string(), false) {
                Ok(bytes) => bytes,
                Err(CascError::NotFound(_)) => {
                    return Err(CascError::NotFound(ekey.to_string()));
                }
                Err(err) => return Err(err),
            },
        };

        // CDN data is bare BLTE: no 30-byte span header to strip or verify.
        let decoded = blte::decode(&encoded)?;
        if let Some(ckey) = expected_ckey {
            let actual: [u8; 16] = Md5::digest(&decoded).into();
            if &actual != ckey.as_bytes() {
                return Err(CascError::ChecksumMismatch("decoded content (CKey)"));
            }
        }
        Ok(decoded)
    }
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
        let versions_bytes = transport.get(&versions_url(region, product))?;
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
        Self::open_inner(product, region, build_config, cdn_config, None, transport)
    }

    fn open_inner(
        product: &str,
        region: &str,
        build_config_key: ContentKey,
        cdn_config_key: ContentKey,
        version_name: Option<String>,
        transport: T,
    ) -> Result<Self> {
        let cdns_bytes = transport.get(&cdns_url(region, product))?;
        let cdns = Cdns::parse(&String::from_utf8_lossy(&cdns_bytes))?;
        let cdn = cdns
            .region(region)
            .ok_or_else(|| CascError::NotFound(format!("region {region} in {product} cdns")))?;

        let mut fetcher = CdnFetcher {
            transport,
            hosts: cdn.hosts.clone(),
            cdn_path: cdn.path.clone(),
            archives: Vec::new(),
            index: CdnIndex::new(),
        };

        let build_config_bytes =
            fetcher.get(CdnPathKind::Config, &build_config_key.to_string(), false)?;
        let build_config = BuildConfig::parse(&String::from_utf8_lossy(&build_config_bytes))?;

        // The CDN config shares the build config's key=value format; its
        // `archives` line lists the archive hashes this build's data spans.
        let cdn_config_bytes =
            fetcher.get(CdnPathKind::Config, &cdn_config_key.to_string(), false)?;
        let cdn_config = BuildConfig::parse(&String::from_utf8_lossy(&cdn_config_bytes))?;
        let archives: Vec<String> = cdn_config
            .get("archives")
            .ok_or_else(|| CascError::malformed("CDN config", "missing 'archives'"))?
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();

        let mut index = CdnIndex::new();
        for (i, hash) in archives.iter().enumerate() {
            let index_bytes = fetcher.get(CdnPathKind::Data, hash, true)?;
            let parsed = ArchiveIndex::parse(&index_bytes)?;
            index.add_archive(i as u32, &parsed);
        }
        fetcher.archives = archives;
        fetcher.index = index;

        // The encoding table's EKey comes straight from the build config —
        // the one fetch that can't go through encoding itself.
        let (encoding_ckey, encoding_ekey) = build_config.encoding()?;
        let encoding_bytes = fetcher.read_by_ekey(&encoding_ekey, Some(&encoding_ckey))?;
        let encoding = EncodingTable::parse(&encoding_bytes)?;

        let root_ckey = build_config.root()?;
        let root_enc = encoding
            .lookup(&root_ckey)
            .ok_or_else(|| CascError::malformed("root file", "root CKey not in encoding table"))?;
        let root_bytes = fetcher.read_by_ekey(&root_enc.ekey, Some(&root_ckey))?;
        let root = RootFile::parse(&root_bytes)?;

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
        self.fetcher.read_by_ekey(&enc.ekey, Some(ckey))
    }

    /// Downloads and decodes content by EKey. When `expected_ckey` is given,
    /// the decoded bytes' MD5 is verified against it.
    pub fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
    ) -> Result<Vec<u8>> {
        self.fetcher.read_by_ekey(ekey, expected_ckey)
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

#[cfg(feature = "cdn-http")]
mod http_impl {
    use super::CdnTransport;
    use crate::error::{CascError, Result};

    /// Cap on response bodies, as a guard against a misbehaving server
    /// streaming unbounded data. CDN archives are ≤ 1 GiB by construction.
    const BODY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

    /// [`CdnTransport`] over plain HTTP using [`ureq`].
    ///
    /// Blizzard's CDN content is content-addressed (URLs contain the MD5 of
    /// what they serve) and every read is checksum-verified above this
    /// layer, so plain HTTP is not an integrity concern.
    pub struct HttpTransport {
        agent: ureq::Agent,
    }

    impl HttpTransport {
        pub fn new() -> Self {
            HttpTransport {
                agent: ureq::Agent::new_with_defaults(),
            }
        }

        /// Uses a caller-configured agent (timeouts, proxies, ...).
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

    impl CdnTransport for HttpTransport {
        fn get(&self, url: &str) -> Result<Vec<u8>> {
            let mut response = self
                .agent
                .get(url)
                .call()
                .map_err(|e| request_err(url, e))?;
            response
                .body_mut()
                .with_config()
                .limit(BODY_LIMIT)
                .read_to_vec()
                .map_err(|e| body_err(url, e))
        }

        fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
            if len == 0 {
                return Ok(Vec::new());
            }
            // HTTP Range ends are inclusive.
            let end = offset + (len - 1);
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
            // Slack on the limit: ureq errors when a body *reaches* the
            // limit, and we want the exact-length check below to produce the
            // clearer error for small overruns anyway.
            let body = response
                .body_mut()
                .with_config()
                .limit(len + 1024)
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
}

#[cfg(feature = "cdn-http")]
pub use http_impl::HttpTransport;

#[cfg(feature = "fs")]
mod cache_impl {
    use std::path::{Path, PathBuf};

    use super::CdnTransport;
    use crate::error::Result;

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

        /// The cache file for `url` (plus a `suffix` distinguishing range
        /// requests), or `None` if the resource isn't cacheable.
        fn cache_path(&self, url: &str, suffix: &str) -> Option<PathBuf> {
            let rel = url
                .strip_prefix("http://")
                .or_else(|| url.strip_prefix("https://"))?;
            let last = rel.rsplit('/').next()?;
            let stem = last.strip_suffix(".index").unwrap_or(last);
            let content_addressed = stem.len() == 32 && stem.bytes().all(|b| b.is_ascii_hexdigit());
            if !content_addressed {
                return None;
            }
            let mut path = self.dir.clone();
            path.extend(rel.split('/').filter(|s| !s.is_empty()));
            if !suffix.is_empty() {
                path.set_file_name(format!("{last}{suffix}"));
            }
            Some(path)
        }

        fn fetch_through(
            &self,
            url: &str,
            suffix: &str,
            fetch: impl FnOnce() -> Result<Vec<u8>>,
        ) -> Result<Vec<u8>> {
            let Some(path) = self.cache_path(url, suffix) else {
                return fetch();
            };
            if let Ok(bytes) = std::fs::read(&path) {
                return Ok(bytes);
            }
            let bytes = fetch()?;
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&path, &bytes);
            Ok(bytes)
        }
    }

    impl<T: CdnTransport> CdnTransport for CachingTransport<T> {
        fn get(&self, url: &str) -> Result<Vec<u8>> {
            self.fetch_through(url, "", || self.inner.get(url))
        }

        fn get_range(&self, url: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
            let suffix = format!(".r{offset}-{len}");
            self.fetch_through(url, &suffix, || self.inner.get_range(url, offset, len))
        }
    }
}

#[cfg(feature = "fs")]
pub use cache_impl::CachingTransport;
