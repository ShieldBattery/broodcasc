//! Storage access abstractions.
//!
//! All reads from the underlying CASC storage go through [`ReadAt`] and
//! [`StorageProvider`], so the core library never touches the filesystem
//! directly. Native users get a `std::fs` implementation via the `fs` feature
//! ([`FsProvider`]); WASM users can implement these traits over whatever byte
//! source they have (OPFS sync access handles, in-memory buffers, ...).

use crate::error::Result;

/// Positioned reads from an immutable byte source.
///
/// Implementations must be usable through `&self` (concurrent readers may
/// share one handle), which is why this is not `std::io::Read`.
pub trait ReadAt {
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
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).ok().filter(|&o| o <= self.len());
        let end = start.and_then(|s| s.checked_add(buf.len())).filter(|&e| e <= self.len());
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
/// Paths are relative to the storage's `Data` directory and always use `/` as
/// the separator (e.g. `"data/000000001b.idx"`,
/// `"config/86/47/864772b9..."`).
pub trait StorageProvider {
    type File: ReadAt;

    /// Opens a file for positioned reads (used for the large `data.###`
    /// archives).
    fn open(&self, path: &str) -> Result<Self::File>;

    /// Reads an entire file into memory (used for configs and indices, which
    /// are small).
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let file = self.open(path)?;
        let len = file.len()?;
        file.read_vec_at(0, len.try_into().expect("file too large for memory"))
    }

    /// Lists the file names (not full paths) in a directory. Returns an empty
    /// list if the directory doesn't exist.
    fn list_dir(&self, path: &str) -> Result<Vec<String>>;
}

#[cfg(feature = "fs")]
mod fs_impl {
    use std::fs::File;
    use std::path::{Path, PathBuf};

    use super::{ReadAt, StorageProvider};
    use crate::error::Result;

    impl ReadAt for File {
        #[cfg(windows)]
        fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
            use std::os::windows::fs::FileExt;
            while !buf.is_empty() {
                match self.seek_read(buf, offset) {
                    Ok(0) => {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into())
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
        /// Creates a provider rooted at a CASC data directory (the directory
        /// containing `config/` and `data/`, e.g.
        /// `C:\Program Files (x86)\StarCraft\Data`).
        pub fn new(root: impl Into<PathBuf>) -> Self {
            FsProvider { root: root.into() }
        }

        fn resolve(&self, path: &str) -> PathBuf {
            let mut out = self.root.clone();
            out.extend(path.split('/'));
            out
        }

        pub fn root(&self) -> &Path {
            &self.root
        }
    }

    impl StorageProvider for FsProvider {
        type File = File;

        fn open(&self, path: &str) -> Result<File> {
            Ok(File::open(self.resolve(path))?)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>> {
            Ok(std::fs::read(self.resolve(path))?)
        }

        fn list_dir(&self, path: &str) -> Result<Vec<String>> {
            let dir = self.resolve(path);
            if !dir.is_dir() {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                if let Ok(name) = entry.file_name().into_string() {
                    out.push(name);
                }
            }
            Ok(out)
        }
    }
}

#[cfg(feature = "fs")]
pub use fs_impl::FsProvider;

#[cfg(test)]
mod tests {
    use super::*;

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
}
