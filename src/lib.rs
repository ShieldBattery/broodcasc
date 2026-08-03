//! A pure-Rust reader for CASC archives, targeting the StarCraft: Remastered
//! featureset.
//!
//! See the README for goals and usage; `docs/casc-format.md` documents the
//! on-disk format this implementation follows.

pub mod blte;
pub mod config;
pub mod encoding;
pub mod error;
pub mod io;
pub mod keys;
pub mod root;

pub use error::CascError;
pub use keys::{ContentKey, EncodingKey, TruncatedKey};
