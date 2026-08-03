//! Storage access abstractions.
//!
//! All reads from the underlying CASC storage go through [`ReadAt`] and
//! [`StorageProvider`], so the core library never touches the filesystem
//! directly. Native users get a `std::fs` implementation via the `fs` feature
//! ([`FsProvider`]); WASM users can implement these traits over whatever byte
//! source they have (OPFS sync access handles, in-memory buffers, ...).

use crate::error::{CascError, Result};

/// Positioned reads from an immutable byte source.
///
/// Implementations must be usable through `&self` (concurrent readers may
/// share one handle), which is why this is not `std::io::Read`.
pub trait ReadAt: Send + Sync {
    /// Reads exactly `buf.len()` bytes starting at `offset`, failing if the
    /// source ends first.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Total length of the source in bytes.
    fn len(&self) -> Result<u64>;

    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Reads `len` bytes at `offset` into a new `Vec`.
    fn read_vec_at(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len).map_err(|_| {
            CascError::malformed(
                "positioned read",
                "requested buffer is too large for memory",
            )
        })?;
        buf.resize(len, 0);
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).ok().filter(|&o| o <= self.len());
        let end = start
            .and_then(|s| s.checked_add(buf.len()))
            .filter(|&e| e <= self.len());
        match (start, end) {
            (Some(start), Some(end)) => {
                buf.copy_from_slice(&self[start..end]);
                Ok(())
            }
            _ => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
        }
    }

    fn len(&self) -> Result<u64> {
        Ok(<[u8]>::len(self) as u64)
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.as_slice().read_exact_at(offset, buf)
    }

    fn len(&self) -> Result<u64> {
        Ok(Vec::len(self) as u64)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_exact_at(offset, buf)
    }

    fn len(&self) -> Result<u64> {
        (**self).len()
    }
}

/// Provides access to the files that make up a CASC storage.
///
/// Paths are relative to the storage's install root (the directory containing
/// `.build.info`) and always use `/` as the separator (e.g. `".build.info"`,
/// `"Data/data/000000001b.idx"`, `"Data/config/86/47/864772b9..."`).
pub trait StorageProvider: Send + Sync {
    type File: ReadAt;

    /// Opens a file for positioned reads (used for the large `data.###`
    /// archives).
    fn open(&self, path: &str) -> Result<Self::File>;

    /// Reads an entire file into memory (used for configs and indices, which
    /// are small).
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let file = self.open(path)?;
        let len = file.len()?;
        let len = usize::try_from(len).map_err(|_| {
            CascError::malformed("storage file", "file is too large for address space")
        })?;
        file.read_vec_at(0, len)
    }

    /// Lists the file names (not full paths) in a directory. Returns an empty
    /// list if the directory doesn't exist.
    fn list_dir(&self, path: &str) -> Result<Vec<String>>;
}

#[cfg(feature = "fs")]
mod fs_impl {
    use std::fs::File;
    use std::path::{Component, Path, PathBuf};

    use super::{ReadAt, StorageProvider};
    use crate::error::{CascError, Result};

    const MAX_DIRECTORY_ENTRIES: usize = 100_000;
    const MAX_DIRECTORY_NAME_BYTES: usize = 16 * 1024 * 1024;

    impl ReadAt for File {
        #[cfg(windows)]
        fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
            use std::os::windows::fs::FileExt;
            while !buf.is_empty() {
                match self.seek_read(buf, offset) {
                    Ok(0) => {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                    }
                    Ok(n) => {
                        buf = &mut buf[n..];
                        offset += n as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        }

        #[cfg(unix)]
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            use std::os::unix::fs::FileExt;
            FileExt::read_exact_at(self, buf, offset).map_err(Into::into)
        }

        fn len(&self) -> Result<u64> {
            Ok(self.metadata()?.len())
        }
    }

    /// [`StorageProvider`] over a local directory using `std::fs`.
    pub struct FsProvider {
        root: PathBuf,
    }

    impl FsProvider {
        /// Creates a provider rooted at a CASC install directory (the
        /// directory containing `.build.info` and `Data/`, e.g.
        /// `C:\Program Files (x86)\StarCraft`).
        pub fn new(root: impl Into<PathBuf>) -> Self {
            FsProvider { root: root.into() }
        }

        fn resolve(&self, path: &str) -> Result<PathBuf> {
            if path.is_empty() {
                return Err(CascError::malformed("storage path", "path is empty"));
            }
            if path.contains('\\') {
                return Err(CascError::malformed(
                    "storage path",
                    "backslash separators are not allowed",
                ));
            }
            if path.contains('\0') {
                return Err(CascError::malformed(
                    "storage path",
                    "NUL bytes are not allowed",
                ));
            }
            if path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(CascError::malformed(
                    "storage path",
                    "path contains an empty, current-directory, or parent-directory component",
                ));
            }

            let relative = Path::new(path);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(CascError::malformed(
                    "storage path",
                    "path is not a plain relative path",
                ));
            }

            let mut out = self.root.clone();
            out.push(relative);
            Ok(out)
        }

        fn resolve_existing(&self, path: &str) -> Result<PathBuf> {
            let root = std::fs::canonicalize(&self.root)?;
            let resolved = std::fs::canonicalize(self.resolve(path)?)?;
            if !resolved.starts_with(&root) {
                return Err(CascError::malformed(
                    "storage path",
                    "resolved path escapes the storage root",
                ));
            }
            Ok(resolved)
        }

        pub fn root(&self) -> &Path {
            &self.root
        }
    }

    impl StorageProvider for FsProvider {
        type File = File;

        fn open(&self, path: &str) -> Result<File> {
            Ok(File::open(self.resolve_existing(path)?)?)
        }

        fn list_dir(&self, path: &str) -> Result<Vec<String>> {
            let dir = self.resolve(path)?;
            if !dir.is_dir() {
                return Ok(Vec::new());
            }
            let dir = self.resolve_existing(path)?;
            let mut out = Vec::new();
            let mut name_bytes = 0usize;
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                if let Ok(name) = entry.file_name().into_string() {
                    if out.len() >= MAX_DIRECTORY_ENTRIES {
                        return Err(CascError::LimitExceeded {
                            what: "storage directory entries",
                            limit: MAX_DIRECTORY_ENTRIES,
                        });
                    }
                    name_bytes =
                        name_bytes
                            .checked_add(name.len())
                            .ok_or(CascError::LimitExceeded {
                                what: "storage directory names",
                                limit: MAX_DIRECTORY_NAME_BYTES,
                            })?;
                    if name_bytes > MAX_DIRECTORY_NAME_BYTES {
                        return Err(CascError::LimitExceeded {
                            what: "storage directory names",
                            limit: MAX_DIRECTORY_NAME_BYTES,
                        });
                    }
                    out.push(name);
                }
            }
            Ok(out)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn resolve_accepts_documented_relative_paths() {
            let provider = FsProvider::new("install-root");
            assert_eq!(
                provider.resolve(".build.info").unwrap(),
                Path::new("install-root").join(".build.info")
            );
            assert_eq!(
                provider
                    .resolve("Data/config/86/47/864772b9ff94f6d372aa4ee90ee2f8ab")
                    .unwrap(),
                Path::new("install-root")
                    .join("Data/config/86/47/864772b9ff94f6d372aa4ee90ee2f8ab")
            );
        }

        #[test]
        fn resolve_rejects_root_escape_and_ambiguous_components() {
            let provider = FsProvider::new("install-root");
            for path in [
                "",
                "/absolute",
                "../outside",
                "Data/../outside",
                "Data/./data",
                "Data//data",
                "Data/data/",
                r"..\outside",
                r"Data\data\file.idx",
                "Data/data/\0file.idx",
            ] {
                assert!(provider.resolve(path).is_err(), "accepted {path:?}");
            }
        }

        #[cfg(unix)]
        #[test]
        fn resolve_existing_rejects_symlink_escape() {
            use std::os::unix::fs::symlink;
            use std::time::{SystemTime, UNIX_EPOCH};

            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let base = std::env::temp_dir().join(format!(
                "broodcasc-provider-test-{}-{nonce}",
                std::process::id()
            ));
            let root = base.join("root");
            let outside = base.join("outside");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("secret"), b"outside root").unwrap();
            symlink(&outside, root.join("escape")).unwrap();

            let provider = FsProvider::new(&root);
            assert!(provider.resolve_existing("escape/secret").is_err());

            std::fs::remove_dir_all(&base).unwrap();
        }
    }
}

#[cfg(feature = "fs")]
pub use fs_impl::FsProvider;

#[cfg(test)]
mod tests {
    use super::*;

    struct HugeFile;

    impl ReadAt for HugeFile {
        fn read_exact_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<()> {
            panic!("oversized reads must fail before attempting I/O")
        }

        fn len(&self) -> Result<u64> {
            Ok(u64::MAX)
        }
    }

    struct HugeProvider;

    impl StorageProvider for HugeProvider {
        type File = HugeFile;

        fn open(&self, _path: &str) -> Result<Self::File> {
            Ok(HugeFile)
        }

        fn list_dir(&self, _path: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn slice_read_at() {
        let data: &[u8] = &[1, 2, 3, 4, 5];
        let mut buf = [0u8; 3];
        data.read_exact_at(1, &mut buf).unwrap();
        assert_eq!(buf, [2, 3, 4]);
        assert!(data.read_exact_at(3, &mut buf).is_err());
        assert!(data.read_exact_at(u64::MAX, &mut buf).is_err());
        assert_eq!(ReadAt::len(data).unwrap(), 5);
    }

    #[test]
    fn oversized_default_read_returns_error_without_allocating() {
        assert!(HugeProvider.read("huge").is_err());
    }

    #[test]
    fn public_io_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_read_at<T: ReadAt>() {}
        fn assert_provider<T: StorageProvider>() {}

        assert_send_sync::<Vec<u8>>();
        assert_read_at::<Vec<u8>>();
        assert_provider::<HugeProvider>();

        #[cfg(feature = "fs")]
        {
            assert_send_sync::<FsProvider>();
            assert_read_at::<std::fs::File>();
            assert_provider::<FsProvider>();
        }
    }
}
