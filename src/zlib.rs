//! zlib inflate backends for BLTE `Z` chunks.
//!
//! Two interchangeable implementations behind one tiny interface:
//!
//! - `fast-inflate` (default): [`zlib-rs`](https://docs.rs/zlib-rs), roughly
//!   30% faster than `miniz_oxide` on SC:R data natively, with runtime SIMD
//!   detection, at the cost of more code.
//! - otherwise: [`miniz_oxide`], the smallest option; this is what
//!   `--no-default-features` (e.g. wasm32) gets.
//!
//! Both are pure Rust, verify the zlib Adler-32 trailer, and report the same
//! error shapes, so `blte` doesn't care which is in use.

use crate::error::CascError;

fn size_mismatch(written: usize, expected: usize) -> CascError {
    CascError::malformed(
        "BLTE chunk",
        format!(
            "mode 'Z' decompressed length {written} does not match declared decompressed_size {expected}"
        ),
    )
}

fn past_declared_size(expected: usize) -> CascError {
    CascError::malformed(
        "BLTE chunk",
        format!("mode 'Z' decompresses past declared decompressed_size {expected}"),
    )
}

fn zlib_error(what: impl std::fmt::Debug) -> CascError {
    CascError::malformed("BLTE chunk", format!("zlib inflate failed: {what:?}"))
}

#[cfg(feature = "fast-inflate")]
pub(crate) use fast::{Inflater, inflate_exact, inflate_to_vec};
#[cfg(not(feature = "fast-inflate"))]
pub(crate) use small::{Inflater, inflate_exact, inflate_to_vec};

#[cfg(feature = "fast-inflate")]
mod fast {
    use zlib_rs::{Inflate, InflateFlush, Status};

    use super::{past_declared_size, size_mismatch, zlib_error};
    use crate::error::{CascError, Result};

    /// A reusable inflate state, created on first use. Its window and tables
    /// are allocated once per top-level decode instead of once per chunk.
    #[derive(Default)]
    pub(crate) struct Inflater(Option<Inflate>);

    impl Inflater {
        /// A state ready to start a new zlib stream.
        fn fresh(&mut self) -> &mut Inflate {
            let inflate = self.0.get_or_insert_with(|| Inflate::new(true, 15));
            inflate.reset(true);
            inflate
        }
    }

    /// Inflates a zlib stream that must produce exactly `out.len()` bytes.
    pub(crate) fn inflate_exact(
        inflater: &mut Inflater,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let expected = out.len();
        let inflate = inflater.fresh();
        let status = inflate.decompress(payload, out, InflateFlush::Finish);
        let written = inflate.total_out() as usize;
        match status {
            Ok(Status::StreamEnd) if written == expected => Ok(()),
            Ok(Status::StreamEnd) => Err(size_mismatch(written, expected)),
            // The output filled up with the stream still going.
            Ok(_) if written == expected => Err(past_declared_size(expected)),
            Ok(_) => Err(zlib_error("truncated stream")),
            Err(e) => Err(zlib_error(e.as_str())),
        }
    }

    /// Inflates a zlib stream of unknown decoded size, failing if it would
    /// exceed `limit` bytes.
    pub(crate) fn inflate_to_vec(
        inflater: &mut Inflater,
        payload: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>> {
        let inflate = inflater.fresh();
        let mut out = vec![0u8; payload.len().saturating_mul(4).max(4096).min(limit.max(1))];
        loop {
            let consumed = inflate.total_in() as usize;
            let produced = inflate.total_out() as usize;
            let status = inflate.decompress(
                payload.get(consumed..).unwrap_or_default(),
                &mut out[produced..],
                InflateFlush::NoFlush,
            );
            let produced = inflate.total_out() as usize;
            match status {
                Ok(Status::StreamEnd) => {
                    out.truncate(produced);
                    return Ok(out);
                }
                Err(e) => return Err(zlib_error(e.as_str())),
                Ok(_) if produced < out.len() => return Err(zlib_error("truncated stream")),
                Ok(_) if out.len() >= limit => {
                    return Err(CascError::malformed(
                        "BLTE chunk",
                        format!("zlib inflate failed: output exceeds limit of {limit} bytes"),
                    ));
                }
                Ok(_) => out.resize(out.len().saturating_mul(2).min(limit), 0),
            }
        }
    }
}

#[cfg(not(feature = "fast-inflate"))]
mod small {
    use core::iter;

    use miniz_oxide::inflate::{
        TINFLStatus, decompress_slice_iter_to_slice, decompress_to_vec_zlib_with_limit,
    };

    use super::{past_declared_size, size_mismatch, zlib_error};
    use crate::error::Result;

    /// `miniz_oxide` keeps no reusable state across calls.
    #[derive(Default)]
    pub(crate) struct Inflater(());

    /// Inflates a zlib stream that must produce exactly `out.len()` bytes.
    pub(crate) fn inflate_exact(
        _inflater: &mut Inflater,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let expected = out.len();
        match decompress_slice_iter_to_slice(out, iter::once(payload), true, false) {
            Ok(written) if written == expected => Ok(()),
            Ok(written) => Err(size_mismatch(written, expected)),
            Err(TINFLStatus::HasMoreOutput) => Err(past_declared_size(expected)),
            Err(status) => Err(zlib_error(status)),
        }
    }

    /// Inflates a zlib stream of unknown decoded size, failing if it would
    /// exceed `limit` bytes.
    pub(crate) fn inflate_to_vec(
        _inflater: &mut Inflater,
        payload: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>> {
        decompress_to_vec_zlib_with_limit(payload, limit).map_err(|e| zlib_error(e.status))
    }
}
