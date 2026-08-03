//! Backend-agnostic wrapper over the two storage kinds `broodcasc` exposes,
//! so subcommands don't need to care whether they're reading from a local
//! install or Blizzard's CDN.

use std::path::PathBuf;

use anyhow::{Context, Result};
use broodcasc::cdn::{CachingTransport, CdnStorage, HttpTransport};
use broodcasc::io::FsProvider;
use broodcasc::{CascError, ContentKey, Storage};

use crate::args::{Cli, DEFAULT_LOCAL_DIR};

/// The concrete CDN transport this CLI always uses: HTTP, wrapped in a
/// persistent on-disk cache so re-running the CLI doesn't re-download.
pub type Transport = CachingTransport<HttpTransport>;

pub enum Source {
    Local {
        storage: Storage<FsProvider>,
        dir: PathBuf,
    },
    Cdn {
        storage: CdnStorage<Transport>,
        product: String,
        region: String,
    },
}

impl Source {
    /// Reads a file's decoded bytes by catalog path.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, CascError> {
        match self {
            Source::Local { storage, .. } => storage.read_file(path),
            Source::Cdn { storage, .. } => storage.read_file(path),
        }
    }

    /// The decoded size of a catalog file, without reading it.
    pub fn file_size(&self, path: &str) -> Result<u64, CascError> {
        match self {
            Source::Local { storage, .. } => storage.file_size(path),
            Source::Cdn { storage, .. } => storage.file_size(path),
        }
    }

    /// Whether `path` is cataloged *and* its content is actually available
    /// without further downloading. Always `true` for CDN storage, which
    /// fetches on demand; meaningful only for local (partial) installs.
    pub fn is_installed(&self, path: &str) -> bool {
        match self {
            Source::Local { storage, .. } => storage.is_installed(path),
            Source::Cdn { .. } => true,
        }
    }

    /// All catalog paths, in catalog order.
    pub fn file_names(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Source::Local { storage, .. } => Box::new(storage.file_names()),
            Source::Cdn { storage, .. } => Box::new(storage.file_names()),
        }
    }

    /// Total number of cataloged files.
    pub fn file_count(&self) -> usize {
        match self {
            Source::Local { storage, .. } => storage.root().len(),
            Source::Cdn { storage, .. } => storage.root().len(),
        }
    }

    /// A short human-readable description of where this storage came from.
    pub fn label(&self) -> String {
        match self {
            Source::Local { dir, .. } => format!("local install at {}", dir.display()),
            Source::Cdn {
                product, region, ..
            } => format!("CDN ({product}, region {region})"),
        }
    }

    /// The build/version name to show in `info`: the live version name for
    /// CDN storage when discovery provided one, otherwise (and always for
    /// local) the build config's `build-name`.
    pub fn version_label(&self) -> Option<&str> {
        match self {
            Source::Local { storage, .. } => storage.build_config().build_name(),
            Source::Cdn { storage, .. } => storage
                .version_name()
                .or_else(|| storage.build_config().build_name()),
        }
    }
}

/// Opens whichever storage backend `args` selected: a local install (the
/// default when neither `--local` nor `--cdn` is given) or Blizzard's CDN.
pub fn open_source(args: &Cli) -> Result<Source> {
    if args.source.cdn {
        open_cdn(args)
    } else {
        open_local(args)
    }
}

fn open_local(args: &Cli) -> Result<Source> {
    let dir = args
        .source
        .local
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCAL_DIR));
    let storage = Storage::open(&dir)
        .with_context(|| format!("opening local CASC storage at {}", dir.display()))?;
    Ok(Source::Local { storage, dir })
}

fn open_cdn(args: &Cli) -> Result<Source> {
    let region = args.source.region.clone();
    let product = args.source.product.clone();
    let cache_dir = args.source.cache.clone().unwrap_or_else(default_cache_dir);
    let transport = CachingTransport::new(HttpTransport::new(), cache_dir);

    let storage = match (&args.source.build_config, &args.source.cdn_config) {
        (Some(build_hex), Some(cdn_hex)) => {
            let build_config = ContentKey::from_hex(build_hex)
                .with_context(|| format!("invalid --build-config hash: {build_hex:?}"))?;
            let cdn_config = ContentKey::from_hex(cdn_hex)
                .with_context(|| format!("invalid --cdn-config hash: {cdn_hex:?}"))?;
            CdnStorage::open_pinned(&product, &region, build_config, cdn_config, transport)
                .with_context(|| {
                    format!("opening pinned CDN build for product {product:?}, region {region:?}")
                })?
        }
        (None, None) => CdnStorage::open(&product, &region, transport).with_context(|| {
            format!("opening CDN storage for product {product:?}, region {region:?}")
        })?,
        _ => unreachable!("clap enforces --build-config and --cdn-config together"),
    };

    Ok(Source::Cdn {
        storage,
        product,
        region,
    })
}

/// Default CDN cache directory: `broodcasc-cache` under the OS temp dir.
fn default_cache_dir() -> PathBuf {
    std::env::temp_dir().join("broodcasc-cache")
}
