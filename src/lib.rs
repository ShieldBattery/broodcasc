//! A pure-Rust reader for CASC archives, targeting the StarCraft: Remastered
//! featureset.
//!
//! The usual entry point is [`Storage`]:
//!
//! ```no_run
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
pub mod keys;
pub mod root;
pub mod storage;
#[cfg(feature = "cdn")]
pub mod tact;

#[cfg(feature = "cdn")]
pub use cdn::CdnStorage;
pub use error::CascError;
pub use keys::{ContentKey, EncodingKey, TruncatedKey};
pub use storage::Storage;
