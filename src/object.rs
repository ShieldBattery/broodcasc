//! Verification boundary for complete encoded CASC objects.
//!
//! Byte acquisition remains owned by local spans and CDN transports. This
//! module owns the invariant shared by both: no decoded bytes leave the
//! boundary until their BLTE framing, optional decoded length, and optional
//! CKey have all been verified. EKeys select encoded representations, but are
//! not the MD5 of the stored bare BLTE bytes in SC:R and therefore cannot be
//! recomputed at this boundary.

use md5::{Digest, Md5};

use crate::blte::{self, ChunkRead, ChunkStream, ReadLimits};
use crate::error::{CascError, Result};
use crate::keys::ContentKey;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpectedObject<'a> {
    pub(crate) ckey: Option<&'a ContentKey>,
    pub(crate) decoded_size: Option<u64>,
}

/// Acquires and verifies one encoded CASC object.
///
/// The acquisition callback receives the maximum accepted encoded byte count
/// and must enforce it before allocating. The returned length is checked a
/// second time defensively.
#[cfg(any(feature = "cdn", test))]
pub(crate) fn read_verified(
    expected: ExpectedObject<'_>,
    limits: ReadLimits,
    acquire: impl FnOnce(usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    read_verified_prefixed(expected, limits, 0, acquire)
}

/// What an acquisition callback hands back: either a complete encoded object
/// or a validated chunk stream that fetches (and verifies) chunk data lazily.
pub(crate) enum Acquired<R> {
    Whole(Vec<u8>),
    Streamed(ChunkStream<R>),
}

/// Placeholder reader type for acquisitions that never stream.
#[cfg(any(feature = "cdn", test))]
type NoStream = fn(u64, &mut [u8]) -> Result<()>;

/// Variant for containers such as local CASC spans where a small framing
/// prefix is acquired together with the BLTE bytes. Keeping the prefix in the
/// same allocation avoids a second positioned read without shifting the
/// entire encoded object in memory.
#[cfg(any(feature = "cdn", test))]
pub(crate) fn read_verified_prefixed(
    expected: ExpectedObject<'_>,
    limits: ReadLimits,
    prefix_len: usize,
    acquire: impl FnOnce(usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    read_verified_streaming::<NoStream>(expected, limits, prefix_len, |max| {
        acquire(max).map(Acquired::Whole)
    })
}

/// Like [`read_verified_prefixed`], but the callback may instead return a
/// [`ChunkStream`], which is decoded chunk-by-chunk straight into the output
/// allocation without ever holding the whole encoded object. All of the same
/// checks apply.
pub(crate) fn read_verified_streaming<R: ChunkRead>(
    expected: ExpectedObject<'_>,
    limits: ReadLimits,
    prefix_len: usize,
    acquire: impl FnOnce(usize) -> Result<Acquired<R>>,
) -> Result<Vec<u8>> {
    let decoded_size = expected
        .decoded_size
        .map(|size| check_decoded_size(size, limits))
        .transpose()?;

    let acquired = acquire(limits.max_encoded_bytes)?;
    // Expected sizes come from verified metadata (encoding table, build
    // config), so the output is allocated once at its final size rather
    // than grown from `initial_reserve_bytes`.
    let decoded = match acquired {
        Acquired::Whole(acquired) => {
            let encoded = encoded_suffix(&acquired, prefix_len, limits)?;
            match decoded_size {
                Some(size) => {
                    let mut decoded = alloc_output(size, limits)?;
                    blte::decode_into(encoded, &mut decoded, limits)?;
                    decoded
                }
                None => blte::decode_with_limits(encoded, limits)?,
            }
        }
        Acquired::Streamed(stream) => {
            let size = check_decoded_size(stream.decoded_size() as u64, limits)?;
            if let Some(expected_size) = decoded_size
                && expected_size != size
            {
                return Err(CascError::malformed(
                    "BLTE chunk table",
                    format!(
                        "declared decoded size {size} does not match expected size {expected_size}"
                    ),
                ));
            }
            let mut decoded = alloc_output(size, limits)?;
            stream.decode_into(&mut decoded)?;
            decoded
        }
    };
    verify_ckey(&decoded, expected.ckey)?;
    Ok(decoded)
}

/// Variant of [`read_verified_streaming`] that decodes into caller-provided
/// memory. `out.len()` is the expected decoded size; it is checked against
/// the limits before anything is acquired.
pub(crate) fn read_verified_into_streaming<R: ChunkRead>(
    ckey: Option<&ContentKey>,
    out: &mut [u8],
    limits: ReadLimits,
    prefix_len: usize,
    acquire: impl FnOnce(usize) -> Result<Acquired<R>>,
) -> Result<()> {
    check_decoded_size(out.len() as u64, limits)?;
    match acquire(limits.max_encoded_bytes)? {
        Acquired::Whole(acquired) => {
            let encoded = encoded_suffix(&acquired, prefix_len, limits)?;
            blte::decode_into(encoded, out, limits)?;
        }
        Acquired::Streamed(stream) => stream.decode_into(out)?,
    }
    verify_ckey(out, ckey)
}

fn alloc_output(size: usize, limits: ReadLimits) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(size)
        .map_err(|_| CascError::LimitExceeded {
            what: "decoded object allocation",
            limit: limits.max_decoded_bytes,
        })?;
    decoded.resize(size, 0);
    Ok(decoded)
}

fn check_decoded_size(size: u64, limits: ReadLimits) -> Result<usize> {
    usize::try_from(size)
        .ok()
        .filter(|&size| size <= limits.max_decoded_bytes)
        .ok_or(CascError::LimitExceeded {
            what: "decoded object",
            limit: limits.max_decoded_bytes,
        })
}

fn encoded_suffix(acquired: &[u8], prefix_len: usize, limits: ReadLimits) -> Result<&[u8]> {
    let encoded = acquired.get(prefix_len..).ok_or_else(|| {
        CascError::malformed("encoded object", "framing prefix exceeds acquired bytes")
    })?;
    if encoded.len() > limits.max_encoded_bytes {
        return Err(CascError::LimitExceeded {
            what: "encoded object",
            limit: limits.max_encoded_bytes,
        });
    }
    Ok(encoded)
}

fn verify_ckey(decoded: &[u8], ckey: Option<&ContentKey>) -> Result<()> {
    if let Some(ckey) = ckey {
        let actual_ckey: [u8; 16] = Md5::digest(decoded).into();
        if actual_ckey != *ckey.as_bytes() {
            return Err(CascError::ChecksumMismatch("decoded content (CKey)"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use md5::{Digest, Md5};

    use super::*;

    fn read_verified_into_prefixed(
        ckey: Option<&ContentKey>,
        out: &mut [u8],
        limits: ReadLimits,
        prefix_len: usize,
        acquire: impl FnOnce(usize) -> Result<Vec<u8>>,
    ) -> Result<()> {
        read_verified_into_streaming::<NoStream>(ckey, out, limits, prefix_len, |max| {
            acquire(max).map(Acquired::Whole)
        })
    }

    fn single_raw(payload: &[u8]) -> Vec<u8> {
        let mut out = b"BLTE\0\0\0\0N".to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn ckey(bytes: &[u8]) -> ContentKey {
        ContentKey::from(<[u8; 16]>::from(Md5::digest(bytes)))
    }

    #[test]
    fn known_oversize_rejects_before_acquisition() {
        let encoded = single_raw(b"ok");
        let called = std::cell::Cell::new(false);
        let err = read_verified(
            ExpectedObject {
                ckey: None,
                decoded_size: Some(ReadLimits::default().max_decoded_bytes as u64 + 1),
            },
            ReadLimits::default(),
            |_| {
                called.set(true);
                Ok(encoded.clone())
            },
        )
        .unwrap_err();
        assert!(matches!(err, CascError::LimitExceeded { .. }));
        assert!(!called.get());
    }

    #[test]
    fn malformed_blte_is_rejected_before_decoded_checks() {
        let encoded = b"not BLTE".to_vec();
        let err = read_verified(
            ExpectedObject {
                ckey: None,
                decoded_size: None,
            },
            ReadLimits::default(),
            |_| Ok(encoded),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CascError::Malformed {
                what: "BLTE header",
                ..
            }
        ));
    }

    #[test]
    fn decoded_size_is_checked_before_ckey() {
        let encoded = single_raw(b"ok");
        let wrong_ckey = ContentKey::from([0; 16]);
        let err = read_verified(
            ExpectedObject {
                ckey: Some(&wrong_ckey),
                decoded_size: Some(3),
            },
            ReadLimits::default(),
            |_| Ok(encoded),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CascError::Malformed {
                what: "BLTE chunk",
                ..
            }
        ));
    }

    #[test]
    fn oversized_output_buffer_rejects_before_acquisition() {
        let limits = ReadLimits {
            max_decoded_bytes: 1,
            ..ReadLimits::default()
        };
        let called = std::cell::Cell::new(false);
        let mut out = [0u8; 2];
        let err = read_verified_into_prefixed(None, &mut out, limits, 0, |_| {
            called.set(true);
            Ok(single_raw(b"ok"))
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "decoded object",
                ..
            }
        ));
        assert!(!called.get());
    }

    #[test]
    fn verified_object_is_decoded_into_buffer() {
        let payload = b"ok";
        let mut out = [0u8; 2];
        read_verified_into_prefixed(
            Some(&ckey(payload)),
            &mut out,
            ReadLimits::default(),
            1,
            |_| {
                let mut acquired = vec![0xAA];
                acquired.extend_from_slice(&single_raw(payload));
                Ok(acquired)
            },
        )
        .unwrap();
        assert_eq!(&out, payload);

        let err = read_verified_into_prefixed(
            Some(&ContentKey::from([0; 16])),
            &mut out,
            ReadLimits::default(),
            0,
            |_| Ok(single_raw(payload)),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CascError::ChecksumMismatch("decoded content (CKey)")
        ));
    }

    #[test]
    fn ckey_is_checked_after_successful_decode() {
        let encoded = single_raw(b"ok");
        let wrong_ckey = ContentKey::from([0; 16]);
        let err = read_verified(
            ExpectedObject {
                ckey: Some(&wrong_ckey),
                decoded_size: Some(2),
            },
            ReadLimits::default(),
            |_| Ok(encoded),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CascError::ChecksumMismatch("decoded content (CKey)")
        ));
    }

    #[test]
    fn verified_object_is_returned() {
        let encoded = single_raw(b"ok");
        let payload = b"ok";
        let expected_ckey = ckey(payload);
        let decoded = read_verified(
            ExpectedObject {
                ckey: Some(&expected_ckey),
                decoded_size: Some(payload.len() as u64),
            },
            ReadLimits::default(),
            |_| Ok(encoded),
        )
        .unwrap();
        assert_eq!(decoded, payload);
    }
}
