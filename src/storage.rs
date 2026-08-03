//! The top-level [`Storage`] type: opens a CASC install and reads files.
//!
//! Opening follows the bootstrap pipeline from `docs/casc-format.md` §7:
//! `.build.info` → build config → merged `.idx` index → encoding table
//! (found by EKey directly, the one file that can be) → root catalog. After
//! that, reading a file is `path → CKey → EKey → (archive, offset) → BLTE`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use md5::{Digest, Md5};

use crate::blte;
use crate::config::{BuildConfig, BuildInfo};
use crate::encoding::EncodingTable;
use crate::error::{CascError, Result};
use crate::idx::{IdxEntry, LocalIndex};
use crate::io::{ReadAt, StorageProvider};
use crate::keys::{ContentKey, EncodingKey};
use crate::root::RootFile;

/// Size of the span header preceding every BLTE stream in a `data.###`
/// archive.
const SPAN_HEADER_SIZE: u64 = 30;

/// The EKey-addressed lower half of a storage: the merged local index plus
/// lazily-opened archive handles. This exists separately from [`Storage`] so
/// the bootstrap can read the encoding table before the CKey layer is up.
struct SpanReader<P: StorageProvider> {
    provider: P,
    index: LocalIndex,
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
    ) -> Result<Vec<u8>> {
        let entry = *self
            .index
            .lookup(ekey)
            .ok_or_else(|| CascError::NotFound(ekey.to_string()))?;
        let encoded = self.read_span(ekey, &entry)?;
        let decoded = blte::decode(&encoded)?;
        if let Some(ckey) = expected_ckey {
            let actual: [u8; 16] = Md5::digest(&decoded).into();
            if &actual != ckey.as_bytes() {
                return Err(CascError::ChecksumMismatch("decoded content (CKey)"));
            }
        }
        Ok(decoded)
    }

    /// Reads a span's complete BLTE stream (past the 30-byte span header),
    /// sanity-checking the header against the index entry.
    fn read_span(&self, ekey: &EncodingKey, entry: &IdxEntry) -> Result<Vec<u8>> {
        if entry.encoded_size as u64 <= SPAN_HEADER_SIZE {
            // Placeholder spans are filtered at idx parse time; seeing one
            // here means the index and archives disagree.
            return Err(CascError::malformed("span", "span has no BLTE payload"));
        }
        let archive = self.archive(entry.archive)?;

        let mut header = [0u8; SPAN_HEADER_SIZE as usize];
        archive.read_exact_at(entry.offset, &mut header)?;

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

        archive.read_vec_at(
            entry.offset + SPAN_HEADER_SIZE,
            (entry.encoded_size as u64 - SPAN_HEADER_SIZE) as usize,
        )
    }

    /// Returns the (lazily-opened, cached) handle for `data.<archive>`.
    fn archive(&self, archive: u16) -> Result<Arc<P::File>> {
        let mut archives = self.archives.lock().expect("archive cache poisoned");
        if let Some(handle) = archives.get(&archive) {
            return Ok(Arc::clone(handle));
        }
        let handle = Arc::new(
            self.provider
                .open(&format!("Data/data/data.{archive:03}"))?,
        );
        archives.insert(archive, Arc::clone(&handle));
        Ok(handle)
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
        let build_info_text = provider.read(".build.info")?;
        let build_info = BuildInfo::parse(&String::from_utf8_lossy(&build_info_text))?;
        let record = build_info
            .active_record()
            .or_else(|| build_info.records().first())
            .ok_or_else(|| CascError::malformed("build info", "no build records"))?;
        let build_key_hex = record.build_key()?.to_string();

        let config_path = format!(
            "Data/config/{}/{}/{}",
            &build_key_hex[0..2],
            &build_key_hex[2..4],
            build_key_hex
        );
        let config_text = provider.read(&config_path)?;
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
        let mut idx_contents = Vec::with_capacity(idx_names.len());
        for name in &idx_names {
            idx_contents.push(provider.read(&format!("Data/data/{name}"))?);
        }
        let index = LocalIndex::from_files(idx_contents.iter().map(Vec::as_slice))?;

        let spans = SpanReader {
            provider,
            index,
            archives: Mutex::new(HashMap::new()),
        };

        // The encoding table is the one file whose EKey the build config
        // states directly; everything else resolves CKey → EKey through it.
        let (encoding_ckey, encoding_ekey) = build_config.encoding()?;
        let encoding_bytes = spans.read_by_ekey(&encoding_ekey, Some(&encoding_ckey))?;
        let encoding = EncodingTable::parse(&encoding_bytes)?;

        let root_ckey = build_config.root()?;
        let root_enc = encoding
            .lookup(&root_ckey)
            .ok_or_else(|| CascError::malformed("root file", "root CKey not in encoding table"))?;
        let root_bytes = spans.read_by_ekey(&root_enc.ekey, Some(&root_ckey))?;
        let root = RootFile::parse(&root_bytes)?;

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
        self.spans.read_by_ekey(&enc.ekey, Some(ckey))
    }

    /// Reads and decodes content by EKey. When `expected_ckey` is given, the
    /// decoded bytes' MD5 is verified against it.
    pub fn read_by_ekey(
        &self,
        ekey: &EncodingKey,
        expected_ckey: Option<&ContentKey>,
    ) -> Result<Vec<u8>> {
        self.spans.read_by_ekey(ekey, expected_ckey)
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

#[cfg(feature = "fs")]
impl Storage<crate::io::FsProvider> {
    /// Opens a CASC storage from a local install directory (the one
    /// containing `.build.info`, e.g. `C:\Program Files (x86)\StarCraft`).
    pub fn open(dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::open_with_provider(crate::io::FsProvider::new(dir))
    }
}
