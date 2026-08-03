//! Verification boundary for complete encoded CASC objects.
//!
//! Byte acquisition remains owned by local spans and CDN transports. This
//! module owns the invariant shared by both: no decoded bytes leave the
//! boundary until their BLTE framing, optional decoded length, and optional
//! CKey have all been verified. EKeys select encoded representations, but are
//! not the MD5 of the stored bare BLTE bytes in SC:R and therefore cannot be
//! recomputed at this boundary.

use md5::{Digest, Md5};

use crate::blte::{self, ReadLimits};
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

/// Variant for containers such as local CASC spans where a small framing
/// prefix is acquired together with the BLTE bytes. Keeping the prefix in the
/// same allocation avoids a second positioned read without shifting the
/// entire encoded object in memory.
pub(crate) fn read_verified_prefixed(
    expected: ExpectedObject<'_>,
    limits: ReadLimits,
    prefix_len: usize,
    acquire: impl FnOnce(usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if let Some(size) = expected.decoded_size {
        usize::try_from(size)
            .ok()
            .filter(|&size| size <= limits.max_decoded_bytes)
            .ok_or(CascError::LimitExceeded {
                what: "decoded object",
                limit: limits.max_decoded_bytes,
            })?;
    }

    let acquired = acquire(limits.max_encoded_bytes)?;
    let encoded = acquired.get(prefix_len..).ok_or_else(|| {
        CascError::malformed("encoded object", "framing prefix exceeds acquired bytes")
    })?;
    if encoded.len() > limits.max_encoded_bytes {
        return Err(CascError::LimitExceeded {
            what: "encoded object",
            limit: limits.max_encoded_bytes,
        });
    }

    let decoded = blte::decode_with_limits(encoded, limits)?;
    if let Some(expected_size) = expected.decoded_size
        && decoded.len() as u64 != expected_size
    {
        return Err(CascError::malformed(
            "decoded content",
            format!(
                "length {} does not match expected size {expected_size}",
                decoded.len()
            ),
        ));
    }
    if let Some(ckey) = expected.ckey {
        let actual_ckey: [u8; 16] = Md5::digest(&decoded).into();
        if actual_ckey != *ckey.as_bytes() {
            return Err(CascError::ChecksumMismatch("decoded content (CKey)"));
        }
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use md5::{Digest, Md5};

    use super::*;

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
                what: "decoded content",
                ..
            }
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
