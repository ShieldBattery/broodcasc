//! A pure-Rust reader for CASC archives, targeting the StarCraft: Remastered
//! featureset.
//!
//! See the README for goals and usage; `docs/casc-format.md` documents the
//! on-disk format this implementation follows.

pub mod error;

pub use error::CascError;
