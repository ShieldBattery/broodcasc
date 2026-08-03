//! The top-level [`Storage`] type: opens a CASC install and reads files.
//!
//! Opening follows the bootstrap pipeline from `docs/casc-format.md` §7:
//! `.build.info` → build config → merged `.idx` index → encoding table
//! (found by EKey directly, the one file that can be) → root catalog. After
//! that, reading a file is `path → CKey → EKey → (archive, offset) → BLTE`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};

use crate::blte::ReadLimits;
use crate::config::{BuildConfig, BuildInfo};
use crate::encoding::EncodingTable;
use crate::error::{CascError, Result};
use crate::idx::{IdxEntry, LocalIndex};
use crate::io::{ReadAt, StorageProvider};
use crate::jenkins::hashlittle2;
use crate::keys::{ContentKey, EncodingKey};
use crate::object::{ExpectedObject, read_verified_prefixed};
use crate::root::RootFile;

/// Size of the span header preceding every BLTE stream in a `data.###`
/// archive.
const SPAN_HEADER_SIZE: u64 = 30;
/// Seed used by CASC's `BLTE_ENCODED_HEADER::JenkinsHash` calculation.
const SPAN_JENKINS_SEED: u32 = 0x3D6B_E971;

/// Resource policy used while opening and reading local CASC storage.
///
/// Metadata files are bounded separately from encoded content because they
/// are parsed before the encoding table can establish content identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageOptions {
    read_limits: ReadLimits,
    max_metadata_bytes: usize,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            read_limits: ReadLimits::default(),
            max_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}

impl StorageOptions {
    /// Creates the default secure resource policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Limits for encoded CASC objects and BLTE decoding.
    pub fn read_limits(&self) -> ReadLimits {
        self.read_limits
    }

    /// Maximum bytes read for each bootstrap metadata file.
    pub fn max_metadata_bytes(&self) -> usize {
        self.max_metadata_bytes
    }

    /// Replaces the encoded-object and BLTE limits.
    pub fn with_read_limits(mut self, read_limits: ReadLimits) -> Self {
        self.read_limits = read_limits;
        self
    }

    /// Replaces the per-file bootstrap metadata limit.
    pub fn with_max_metadata_bytes(mut self, max_metadata_bytes: usize) -> Self {
        self.max_metadata_bytes = max_metadata_bytes;
        self
    }

    /// Applies the metadata cap to both encoded and decoded bootstrap
    /// objects. Encoding and root files are BLTE objects, so bounding only
    /// the text configs and index files would still allow oversized parser
    /// inputs during open.
    pub(crate) fn metadata_read_limits(&self) -> ReadLimits {
        let mut limits = self.read_limits;
        limits.max_encoded_bytes = limits.max_encoded_bytes.min(self.max_metadata_bytes);
        limits.max_decoded_bytes = limits.max_decoded_bytes.min(self.max_metadata_bytes);
        limits.max_chunk_decoded_bytes =
            limits.max_chunk_decoded_bytes.min(self.max_metadata_bytes);
        limits.initial_reserve_bytes = limits.initial_reserve_bytes.min(self.max_metadata_bytes);
        limits
    }
}

/// The EKey-addressed lower half of a storage: the merged local index plus
/// lazily-opened archive handles. This exists separately from [`Storage`] so
/// the bootstrap can read the encoding table before the CKey layer is up.
struct SpanReader<P: StorageProvider> {
    provider: P,
    index: LocalIndex,
    limits: ReadLimits,
    /// Lazily-opened `data.###` archive handles, keyed by archive number.
    archives: Mutex<HashMap<u16, Arc<P::File>>>,
}

impl<P: StorageProvider> SpanReader<P> {
    /// Reads and BLTE-decodes the span for `ekey`. When `expected_ckey` is
    /// given, the decoded bytes' MD5 is verified against it.
    fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
        decoded_size: Option<u64>,
    ) -> Result<Vec<u8>> {
        let entry = *self
            .index
            .lookup(ekey)
            .ok_or_else(|| CascError::NotFound(ekey.to_string()))?;
        read_verified_prefixed(
            ExpectedObject {
                ckey: expected_ckey,
                decoded_size,
            },
            self.limits,
            SPAN_HEADER_SIZE as usize,
            |encoded_limit| self.read_span(ekey, &entry, encoded_limit),
        )
    }

    /// Acquires a complete span (30-byte header plus BLTE stream),
    /// sanity-checking the header against the index entry. The verification
    /// boundary decodes only the suffix without copying it.
    fn read_span(
        &self,
        ekey: &EncodingKey,
        entry: &IdxEntry,
        encoded_limit: usize,
    ) -> Result<Vec<u8>> {
        if entry.encoded_size as u64 <= SPAN_HEADER_SIZE {
            // Placeholder spans are filtered at idx parse time; seeing one
            // here means the index and archives disagree.
            return Err(CascError::malformed("span", "span has no BLTE payload"));
        }
        let encoded_size = u64::from(entry.encoded_size) - SPAN_HEADER_SIZE;
        if encoded_size > encoded_limit as u64 {
            return Err(CascError::LimitExceeded {
                what: "local encoded span",
                limit: encoded_limit,
            });
        }
        let span_size =
            usize::try_from(entry.encoded_size).map_err(|_| CascError::LimitExceeded {
                what: "local span",
                limit: encoded_limit,
            })?;
        entry
            .offset
            .checked_add(
                u64::try_from(span_size).map_err(|_| CascError::LimitExceeded {
                    what: "local span",
                    limit: encoded_limit,
                })?,
            )
            .ok_or_else(|| CascError::malformed("span", "span offset overflows u64"))?;

        let archive = self.archive(entry.archive)?;
        // A single positioned read avoids a header read followed by a second
        // payload read for every object. The shared verification boundary
        // decodes the suffix directly, without shifting this allocation.
        let span = archive.read_vec_at(entry.offset, span_size)?;
        let header = span
            .get(..SPAN_HEADER_SIZE as usize)
            .ok_or_else(|| CascError::malformed("span", "truncated span header"))?;

        // The span header EKey is stored byte-reversed, and is sometimes
        // truncated to 9 bytes (+ zero padding) — compare only the first 9
        // bytes of the logical key (docs/casc-format.md §3.2).
        let matches = header[0..16]
            .iter()
            .rev()
            .take(9)
            .eq(ekey.as_bytes()[..9].iter());
        if !matches {
            return Err(CascError::malformed(
                "span",
                "span header EKey does not match index entry",
            ));
        }
        let size = u32::from_le_bytes(header[16..20].try_into().unwrap());
        if size != entry.encoded_size {
            return Err(CascError::malformed(
                "span",
                format!(
                    "span header size {size} disagrees with index entry {}",
                    entry.encoded_size
                ),
            ));
        }

        // `JenkinsHash` is the first (`pc`) word returned by Jenkins'
        // `hashlittle2` over bytes 0x00..0x15, seeded as CascLib's
        // `VerifyHeaderSpan` does. The final four header bytes use a
        // separate, offset-dependent checksum algorithm that is deliberately
        // left unverified until it is independently documented here.
        let expected_jenkins_hash = u32::from_le_bytes(header[0x16..0x1A].try_into().unwrap());
        let actual_jenkins_hash = hashlittle2(&header[..0x16], SPAN_JENKINS_SEED, 0).0;
        if actual_jenkins_hash != expected_jenkins_hash {
            return Err(CascError::ChecksumMismatch(
                "local span header Jenkins hash",
            ));
        }
        Ok(span)
    }

    /// Returns the (lazily-opened, cached) handle for `data.<archive>`.
    fn archive(&self, archive: u16) -> Result<Arc<P::File>> {
        {
            let archives = self
                .archives
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(handle) = archives.get(&archive) {
                return Ok(Arc::clone(handle));
            }
        }

        // Do not serialize a slow first `open` behind the archive-cache
        // mutex. Concurrent misses may open a duplicate handle; only one is
        // retained and all handles remain immutable/read-only.
        let opened = Arc::new(
            self.provider
                .open(&format!("Data/data/data.{archive:03}"))?,
        );
        let mut archives = self
            .archives
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(Arc::clone(archives.entry(archive).or_insert(opened)))
    }
}

/// An opened CASC storage, ready to read files.
///
/// All read methods take `&self`; a `Storage` can be shared across threads
/// when the provider's file handles allow it (the bundled `FsProvider` does).
pub struct Storage<P: StorageProvider> {
    spans: SpanReader<P>,
    build_info: BuildInfo,
    build_config: BuildConfig,
    encoding: EncodingTable,
    root: RootFile,
}

impl<P: StorageProvider> Storage<P> {
    /// Opens the storage reachable through `provider` (rooted at the install
    /// directory containing `.build.info`).
    ///
    /// This reads and parses `.build.info`, the active build's config, all
    /// local index files, the encoding table, and the root catalog — a few MB
    /// of parsing in total; everything needed for fast lookups afterwards.
    pub fn open_with_provider(provider: P) -> Result<Self> {
        Self::open_with_provider_and_options(provider, StorageOptions::default())
    }

    /// Opens storage with an explicit resource policy.
    pub fn open_with_provider_and_options(provider: P, options: StorageOptions) -> Result<Self> {
        let build_info_text = read_metadata(&provider, ".build.info", options.max_metadata_bytes)?;
        let build_info = BuildInfo::parse(&String::from_utf8_lossy(&build_info_text))?;
        let record = build_info
            .active_record()
            .or_else(|| build_info.records().first())
            .ok_or_else(|| CascError::malformed("build info", "no build records"))?;
        let build_key = record.build_key()?;
        let build_key_hex = build_key.to_string();

        let config_path = format!(
            "Data/config/{}/{}/{}",
            &build_key_hex[0..2],
            &build_key_hex[2..4],
            build_key_hex
        );
        let config_text = read_metadata(&provider, &config_path, options.max_metadata_bytes)?;
        verify_raw_ckey(&config_text, &build_key, "build config")?;
        let build_config = BuildConfig::parse(&String::from_utf8_lossy(&config_text))?;

        // Merge all bucket .idx files into one EKey → span map. Only
        // Data/data is a real v7 index set; other directories (s1, ecache)
        // hold indices for storages we don't read.
        let names = provider.list_dir("Data/data")?;
        let idx_names = LocalIndex::select_files(&names);
        if idx_names.is_empty() {
            return Err(CascError::malformed(
                "local index",
                "no .idx files found under Data/data",
            ));
        }
        let mut index = LocalIndex::default();
        for name in &idx_names {
            let bytes = read_metadata(
                &provider,
                &format!("Data/data/{name}"),
                options.max_metadata_bytes,
            )?;
            index.add_file(&bytes)?;
        }

        let mut spans = SpanReader {
            provider,
            index,
            limits: options.metadata_read_limits(),
            archives: Mutex::new(HashMap::new()),
        };

        // The encoding table is the one file whose EKey the build config
        // states directly; everything else resolves CKey → EKey through it.
        let (encoding_ckey, encoding_ekey) = build_config.encoding()?;
        let encoding_size = build_config.encoding_size().map(|(decoded, _)| decoded);
        let encoding_bytes =
            spans.read_by_ekey(&encoding_ekey, Some(&encoding_ckey), encoding_size)?;
        let encoding = EncodingTable::parse(&encoding_bytes)?;

        let root_ckey = build_config.root()?;
        let root_enc = encoding
            .lookup(&root_ckey)
            .ok_or_else(|| CascError::malformed("root file", "root CKey not in encoding table"))?;
        let root_bytes =
            spans.read_by_ekey(&root_enc.ekey, Some(&root_ckey), Some(root_enc.size))?;
        let root = RootFile::parse(&root_bytes)?;

        // Bootstrap metadata is deliberately tighter than ordinary content.
        // Restore the caller's content policy for subsequent file reads.
        spans.limits = options.read_limits;

        Ok(Storage {
            spans,
            build_info,
            build_config,
            encoding,
            root,
        })
    }

    /// Reads a file by its root-catalog path (case-insensitive, `/` or `\`
    /// separators).
    ///
    /// Returns [`CascError::NotFound`] for paths not in the catalog and
    /// [`CascError::NotInstalled`] for cataloged files whose content isn't
    /// present locally (normal for unselected locales).
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let entry = self
            .root
            .lookup(path)
            .ok_or_else(|| CascError::NotFound(path.to_string()))?;
        self.read_by_ckey(&entry.ckey).map_err(|e| match e {
            CascError::NotFound(_) => CascError::NotInstalled(path.to_string()),
            other => other,
        })
    }

    /// The decoded size of a file, without reading it (from the encoding
    /// table).
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

    /// Whether `path` exists in the root catalog (it may still not be
    /// installed locally; see [`Storage::is_installed`]).
    pub fn contains(&self, path: &str) -> bool {
        self.root.lookup(path).is_some()
    }

    /// Whether `path` is in the catalog *and* its content is present in the
    /// local archives.
    pub fn is_installed(&self, path: &str) -> bool {
        self.root
            .lookup(path)
            .and_then(|e| self.encoding.lookup(&e.ckey))
            .and_then(|e| self.spans.index.lookup(&e.ekey))
            .is_some()
    }

    /// All file paths in the root catalog, in catalog order.
    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.root.entries().iter().map(|e| e.path.as_str())
    }

    /// Reads and decodes content by CKey, verifying the result's MD5 matches.
    pub fn read_by_ckey(&self, ckey: &ContentKey) -> Result<Vec<u8>> {
        let enc = self
            .encoding
            .lookup(ckey)
            .ok_or_else(|| CascError::NotFound(ckey.to_string()))?;
        self.spans
            .read_by_ekey(&enc.ekey, Some(ckey), Some(enc.size))
    }

    /// Reads and decodes content selected by EKey. When `expected_ckey` is
    /// given, the decoded bytes' MD5 is verified against it. Without a CKey,
    /// BLTE chunk checks and the span/index addressing checks still apply.
    pub fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
    ) -> Result<Vec<u8>> {
        self.spans.read_by_ekey(ekey, expected_ckey, None)
    }

    /// The parsed root catalog.
    pub fn root(&self) -> &RootFile {
        &self.root
    }

    /// The parsed encoding (CKey → EKey) table.
    pub fn encoding(&self) -> &EncodingTable {
        &self.encoding
    }

    /// The merged local index (EKey → archive location).
    pub fn index(&self) -> &LocalIndex {
        &self.spans.index
    }

    /// The active build's config.
    pub fn build_config(&self) -> &BuildConfig {
        &self.build_config
    }

    /// The parsed `.build.info`.
    pub fn build_info(&self) -> &BuildInfo {
        &self.build_info
    }
}

fn read_metadata<P: StorageProvider>(
    provider: &P,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let file = provider.open(path)?;
    let len = file.len()?;
    let len = usize::try_from(len).map_err(|_| CascError::LimitExceeded {
        what: "storage metadata file",
        limit: max_bytes,
    })?;
    if len > max_bytes {
        return Err(CascError::LimitExceeded {
            what: "storage metadata file",
            limit: max_bytes,
        });
    }
    file.read_vec_at(0, len)
}

fn verify_raw_ckey(bytes: &[u8], expected: &ContentKey, what: &'static str) -> Result<()> {
    let actual: [u8; 16] = Md5::digest(bytes).into();
    if actual == *expected.as_bytes() {
        Ok(())
    } else {
        Err(CascError::ChecksumMismatch(what))
    }
}

#[cfg(feature = "fs")]
impl Storage<crate::io::FsProvider> {
    /// Opens a CASC storage from a local install directory (the one
    /// containing `.build.info`, e.g. `C:\Program Files (x86)\StarCraft`).
    pub fn open(dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::open_with_provider(crate::io::FsProvider::new(dir))
    }

    /// Opens a CASC install with an explicit resource policy.
    pub fn open_with_options(
        dir: impl Into<std::path::PathBuf>,
        options: StorageOptions,
    ) -> Result<Self> {
        Self::open_with_provider_and_options(crate::io::FsProvider::new(dir), options)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use md5::{Digest, Md5};

    use super::*;

    #[derive(Clone)]
    struct MemoryFile {
        bytes: Vec<u8>,
        positioned_reads: Arc<AtomicUsize>,
    }

    impl ReadAt for MemoryFile {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.positioned_reads.fetch_add(1, Ordering::Relaxed);
            self.bytes.as_slice().read_exact_at(offset, buf)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.bytes.len() as u64)
        }
    }

    struct MemoryProvider {
        files: HashMap<String, MemoryFile>,
    }

    impl MemoryProvider {
        fn one(path: &str, bytes: Vec<u8>) -> (Self, Arc<AtomicUsize>) {
            let positioned_reads = Arc::new(AtomicUsize::new(0));
            let mut files = HashMap::new();
            files.insert(
                path.to_string(),
                MemoryFile {
                    bytes,
                    positioned_reads: positioned_reads.clone(),
                },
            );
            (Self { files }, positioned_reads)
        }
    }

    impl StorageProvider for MemoryProvider {
        type File = MemoryFile;

        fn open(&self, path: &str) -> Result<Self::File> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| CascError::NotFound(path.to_string()))
        }

        fn read(&self, _path: &str) -> Result<Vec<u8>> {
            panic!("storage bootstrap must use bounded positioned reads")
        }

        fn list_dir(&self, _path: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    fn raw_blte(payload: &[u8]) -> Vec<u8> {
        let mut out = b"BLTE\0\0\0\0N".to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn metadata_reads_are_bounded_and_bypass_provider_read_override() {
        let (provider, positioned_reads) = MemoryProvider::one("metadata", b"small".to_vec());
        assert_eq!(read_metadata(&provider, "metadata", 5).unwrap(), b"small");
        assert_eq!(positioned_reads.load(Ordering::Relaxed), 1);

        let err = read_metadata(&provider, "metadata", 4).unwrap_err();
        assert!(matches!(err, CascError::LimitExceeded { .. }));
        assert_eq!(positioned_reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn raw_build_config_ckey_is_verified() {
        let bytes = b"root = test\n";
        let good = ContentKey::from(<[u8; 16]>::from(Md5::digest(bytes)));
        assert!(verify_raw_ckey(bytes, &good, "build config").is_ok());
        let err = verify_raw_ckey(bytes, &ContentKey::from([0; 16]), "build config").unwrap_err();
        assert!(matches!(err, CascError::ChecksumMismatch("build config")));
    }

    #[test]
    fn span_reader_uses_one_positioned_read_and_enforces_encoded_limit() {
        let payload = raw_blte(b"ok");
        let ekey = EncodingKey::from(<[u8; 16]>::from(Md5::digest(&payload)));
        let entry = IdxEntry {
            archive: 0,
            offset: 0,
            encoded_size: (SPAN_HEADER_SIZE as usize + payload.len()) as u32,
        };
        let mut span = vec![0u8; SPAN_HEADER_SIZE as usize];
        for (dst, src) in span[..16].iter_mut().zip(ekey.as_bytes().iter().rev()) {
            *dst = *src;
        }
        span[16..20].copy_from_slice(&entry.encoded_size.to_le_bytes());
        let jenkins_hash = hashlittle2(&span[..0x16], SPAN_JENKINS_SEED, 0).0;
        span[0x16..0x1A].copy_from_slice(&jenkins_hash.to_le_bytes());
        span.extend_from_slice(&payload);
        let expected_span = span.clone();
        let mut corrupt_hash_span = span.clone();
        corrupt_hash_span[0x15] ^= 1;

        let (provider, positioned_reads) = MemoryProvider::one("Data/data/data.000", span);
        let reader = SpanReader {
            provider,
            index: LocalIndex::default(),
            limits: ReadLimits::default(),
            archives: Mutex::new(HashMap::new()),
        };
        assert_eq!(
            reader.read_span(&ekey, &entry, payload.len()).unwrap(),
            expected_span
        );
        assert_eq!(positioned_reads.load(Ordering::Relaxed), 1);

        let err = reader
            .read_span(&ekey, &entry, payload.len() - 1)
            .unwrap_err();
        assert!(matches!(err, CascError::LimitExceeded { .. }));
        assert_eq!(positioned_reads.load(Ordering::Relaxed), 1);

        let (provider, _) = MemoryProvider::one("Data/data/data.000", corrupt_hash_span);
        let reader = SpanReader {
            provider,
            index: LocalIndex::default(),
            limits: ReadLimits::default(),
            archives: Mutex::new(HashMap::new()),
        };
        let err = reader.read_span(&ekey, &entry, payload.len()).unwrap_err();
        assert!(matches!(
            err,
            CascError::ChecksumMismatch("local span header Jenkins hash")
        ));
    }

    #[test]
    fn storage_options_and_storage_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<StorageOptions>();
        assert_send_sync::<Storage<MemoryProvider>>();
    }
}
