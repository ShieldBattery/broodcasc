//! A pure-Rust reader for CASC archives, targeting the StarCraft: Remastered
//! featureset.
//!
//! The usual entry point is [`Storage`]:
//!
//! ```ignore
//! # fn main() -> Result<(), broodcasc::CascError> {
//! let storage = broodcasc::Storage::open(r"C:\Program Files (x86)\StarCraft")?;
//! let bytes = storage.read_file("SD/campaign/Starcraft/SWAR/staredit/scenario.chk")?;
//! # Ok(())
//! # }
//! ```
//!
//! See the README for goals and usage; `docs/casc-format.md` documents the
//! on-disk format this implementation follows.

pub mod blte;
#[cfg(feature = "cdn")]
pub mod cdn;
#[cfg(feature = "cdn")]
pub mod cdnindex;
pub mod config;
pub mod encoding;
pub mod error;
pub mod idx;
pub mod io;
mod jenkins;
pub mod keys;
mod object;
pub mod root;
pub mod storage;
#[cfg(feature = "cdn")]
pub mod tact;

pub use blte::ReadLimits;
#[cfg(feature = "cdn")]
pub use cdn::CdnStorage;
pub use error::CascError;
pub use keys::{ContentKey, EncodingKey, TruncatedKey};
pub use storage::{Storage, StorageOptions};
