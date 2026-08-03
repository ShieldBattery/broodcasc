//! BLTE decoder.
//!
//! BLTE ("Block Table Encoded") is the container format every file stored in
//! a CASC data archive is wrapped in. A BLTE buffer has an optional chunk
//! table header followed by one or more chunks, each independently encoded
//! (raw, zlib-compressed, or a nested BLTE stream) and individually
//! checksummed.
//!
//! Layout (all multi-byte integers are big-endian):
//!
//! ```text
//! 0x00  magic            b"BLTE"
//! 0x04  header_size      u32
//! ```
//!
//! If `header_size == 0`, there is no chunk table: the rest of the input is a
//! single chunk (mode byte + payload) of unknown decompressed size.
//!
//! If `header_size > 0`, it is followed by a chunk table:
//!
//! ```text
//! 0x08  flags            u8      (must be 0x0F)
//! 0x09  chunk_count      u24
//! 0x0c  chunk_count entries of:
//!         compressed_size    u32  (includes the 1-byte mode)
//!         decompressed_size  u32
//!         md5                [u8; 16]  (of the compressed chunk data)
//! ```
//!
//! `header_size` must equal `8 + 4 + 24 * chunk_count`. Chunk data follows
//! immediately after the header, chunks back-to-back.
//!
//! Each chunk is a 1-byte mode followed by a payload:
//! - `N`: raw data, copied through.
//! - `Z`: a zlib stream.
//! - `F`: a nested BLTE stream (recursed into).
//! - `E`: Salsa20/ARC4-encrypted data (unsupported here).

use md5::{Digest, Md5};
use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;

use crate::error::{CascError, Result};

const MAGIC: &[u8; 4] = b"BLTE";
/// Size of one chunk table entry: compressed_size(4) + decompressed_size(4) + md5(16).
const CHUNK_ENTRY_SIZE: usize = 24;
/// Maximum recursion depth for nested (`F`-mode) BLTE chunks.
const MAX_NEST_DEPTH: u32 = 4;
/// Cap on decompressed size when it isn't known up front (header_size == 0,
/// mode `Z`), to bound zlib-bomb style inputs.
const UNKNOWN_SIZE_LIMIT: usize = 1 << 30; // 1 GiB

/// Metadata for a single chunk from a BLTE chunk table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInfo {
    /// Size in bytes of the chunk's encoded data (mode byte included).
    pub compressed_size: u32,
    /// Size in bytes of the chunk's decoded data.
    pub decompressed_size: u32,
    /// MD5 of the chunk's encoded data (mode byte included).
    pub md5: [u8; 16],
    /// Absolute offset of this chunk's encoded data within the original
    /// input buffer.
    pub offset: usize,
}

/// A parsed BLTE header: where each chunk lives in the input and how big it
/// decodes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlteHeader {
    chunks: Vec<ChunkInfo>,
    /// Offset of the start of chunk data (end of the header). Equal to the
    /// start of the single implicit chunk when there is no chunk table.
    data_start: usize,
}

impl BlteHeader {
    /// Parses the header (magic + optional chunk table) of a BLTE buffer.
    ///
    /// Only the header bytes are required to be present; chunk data itself
    /// is not validated here.
    pub fn parse(data: &[u8]) -> Result<BlteHeader> {
        if data.len() < 8 {
            return Err(CascError::malformed(
                "BLTE header",
                "input shorter than 8 bytes",
            ));
        }
        if &data[0..4] != MAGIC {
            return Err(CascError::malformed("BLTE header", "bad magic"));
        }
        let header_size = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;

        if header_size == 0 {
            return Ok(BlteHeader {
                chunks: Vec::new(),
                data_start: 8,
            });
        }

        if data.len() < header_size {
            return Err(CascError::malformed(
                "BLTE header",
                "input shorter than declared header_size",
            ));
        }
        if data.len() < 9 {
            return Err(CascError::malformed(
                "BLTE header",
                "input too short for chunk table",
            ));
        }

        let flags = data[8];
        if flags != 0x0F {
            return Err(CascError::malformed(
                "BLTE header",
                format!("unexpected chunk table flags 0x{flags:02x}"),
            ));
        }
        if data.len() < 12 {
            return Err(CascError::malformed(
                "BLTE header",
                "input too short for chunk count",
            ));
        }
        let chunk_count = u32::from_be_bytes([0, data[9], data[10], data[11]]) as usize;
        if chunk_count == 0 {
            return Err(CascError::malformed("BLTE header", "chunk_count is zero"));
        }

        let expected_header_size = 8 + 4 + CHUNK_ENTRY_SIZE * chunk_count;
        if header_size != expected_header_size {
            return Err(CascError::malformed(
                "BLTE header",
                format!(
                    "header_size {header_size} does not match chunk_count {chunk_count} \
                     (expected {expected_header_size})"
                ),
            ));
        }

        let mut chunks = Vec::with_capacity(chunk_count);
        let mut offset = header_size;
        let mut entry_pos = 12;
        for _ in 0..chunk_count {
            let entry = &data[entry_pos..entry_pos + CHUNK_ENTRY_SIZE];
            let compressed_size = u32::from_be_bytes(entry[0..4].try_into().unwrap());
            let decompressed_size = u32::from_be_bytes(entry[4..8].try_into().unwrap());
            let mut md5 = [0u8; 16];
            md5.copy_from_slice(&entry[8..24]);

            chunks.push(ChunkInfo {
                compressed_size,
                decompressed_size,
                md5,
                offset,
            });

            offset = offset
                .checked_add(compressed_size as usize)
                .ok_or_else(|| CascError::malformed("BLTE header", "chunk size overflow"))?;
            entry_pos += CHUNK_ENTRY_SIZE;
        }

        Ok(BlteHeader {
            chunks,
            data_start: header_size,
        })
    }

    /// Total decompressed size of all chunks combined, or `None` if the
    /// input has no chunk table (`header_size == 0`), in which case the
    /// decompressed size isn't known without decoding.
    pub fn total_decompressed_size(&self) -> Option<u64> {
        if self.chunks.is_empty() {
            return None;
        }
        Some(self.chunks.iter().map(|c| c.decompressed_size as u64).sum())
    }

    /// The chunk table entries, in order. Empty when `header_size == 0`.
    pub fn chunks(&self) -> &[ChunkInfo] {
        &self.chunks
    }

    /// Offset in the input at which chunk data begins (i.e. the end of the
    /// header).
    pub fn data_start(&self) -> usize {
        self.data_start
    }
}

/// Decodes a single chunk's encoded data (mode byte + payload).
///
/// `expected_size`, when known (chunk-table case), is used both to bound the
/// inflate output and to validate the result. `expected_md5`, when provided,
/// is checked against the MD5 of `encoded` before decoding.
pub fn decode_chunk(
    encoded: &[u8],
    expected_size: Option<u32>,
    expected_md5: Option<&[u8; 16]>,
) -> Result<Vec<u8>> {
    decode_chunk_inner(encoded, expected_size, expected_md5, 0)
}

fn decode_chunk_inner(
    encoded: &[u8],
    expected_size: Option<u32>,
    expected_md5: Option<&[u8; 16]>,
    depth: u32,
) -> Result<Vec<u8>> {
    if let Some(expected) = expected_md5 {
        let actual: [u8; 16] = Md5::digest(encoded).into();
        if &actual != expected {
            return Err(CascError::ChecksumMismatch("BLTE chunk"));
        }
    }

    let Some((&mode, payload)) = encoded.split_first() else {
        return Err(CascError::malformed(
            "BLTE chunk",
            "empty chunk (missing mode byte)",
        ));
    };

    match mode {
        b'N' => {
            if let Some(expected) = expected_size {
                if payload.len() as u32 != expected {
                    return Err(CascError::malformed(
                        "BLTE chunk",
                        format!(
                            "mode 'N' payload length {} does not match declared decompressed_size {expected}",
                            payload.len()
                        ),
                    ));
                }
            }
            Ok(payload.to_vec())
        }
        b'Z' => {
            let limit = expected_size.map_or(UNKNOWN_SIZE_LIMIT, |s| s as usize);
            let decoded = decompress_to_vec_zlib_with_limit(payload, limit).map_err(|e| {
                CascError::malformed("BLTE chunk", format!("zlib inflate failed: {e:?}"))
            })?;
            if let Some(expected) = expected_size {
                if decoded.len() as u32 != expected {
                    return Err(CascError::malformed(
                        "BLTE chunk",
                        format!(
                            "mode 'Z' decompressed length {} does not match declared decompressed_size {expected}",
                            decoded.len()
                        ),
                    ));
                }
            }
            Ok(decoded)
        }
        b'F' => {
            if depth >= MAX_NEST_DEPTH {
                return Err(CascError::malformed(
                    "BLTE chunk",
                    format!("nested BLTE recursion exceeds max depth {MAX_NEST_DEPTH}"),
                ));
            }
            decode_inner(payload, depth + 1)
        }
        b'E' => Err(CascError::Unsupported {
            what: "BLTE chunk",
            reason: "encrypted (Salsa20/ARC4) chunks are not supported".to_string(),
        }),
        other => Err(CascError::Unsupported {
            what: "BLTE chunk",
            reason: format!("mode 0x{other:02x}"),
        }),
    }
}

/// Decodes a complete BLTE-encoded buffer into its decoded contents.
pub fn decode(data: &[u8]) -> Result<Vec<u8>> {
    decode_inner(data, 0)
}

fn decode_inner(data: &[u8], depth: u32) -> Result<Vec<u8>> {
    let header = BlteHeader::parse(data)?;

    if header.chunks.is_empty() {
        // header_size == 0: entire remainder is a single chunk of unknown size.
        let encoded = &data[header.data_start..];
        return decode_chunk_inner(encoded, None, None, depth);
    }

    // Cap the preallocation: total_decompressed_size comes from the (as yet
    // unverified) header, so don't let a hostile one force a giant alloc.
    let capacity = header
        .total_decompressed_size()
        .unwrap_or(0)
        .min(UNKNOWN_SIZE_LIMIT as u64) as usize;
    let mut out = Vec::with_capacity(capacity);
    for chunk in &header.chunks {
        let end = chunk
            .offset
            .checked_add(chunk.compressed_size as usize)
            .ok_or_else(|| CascError::malformed("BLTE chunk", "chunk extends past end of input"))?;
        let encoded = data
            .get(chunk.offset..end)
            .ok_or_else(|| CascError::malformed("BLTE chunk", "chunk extends past end of input"))?;
        let decoded = decode_chunk_inner(
            encoded,
            Some(chunk.decompressed_size),
            Some(&chunk.md5),
            depth,
        )?;
        out.extend_from_slice(&decoded);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Builds a BLTE buffer with a chunk table from `(mode, payload)` pairs,
    /// where `payload` is the pre-mode-byte data (raw bytes for `N`, already
    /// zlib-compressed bytes for `Z`, a full nested BLTE buffer for `F`).
    fn build_blte(chunks: &[(u8, &[u8], u32)]) -> Vec<u8> {
        // (mode, payload, decompressed_size)
        let chunk_count = chunks.len() as u32;
        let header_size = 8 + 4 + CHUNK_ENTRY_SIZE * chunks.len();

        let mut chunk_datas: Vec<Vec<u8>> = Vec::new();
        for &(mode, payload, _) in chunks {
            let mut d = Vec::with_capacity(1 + payload.len());
            d.push(mode);
            d.extend_from_slice(payload);
            chunk_datas.push(d);
        }

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(header_size as u32).to_be_bytes());
        out.push(0x0F);
        out.extend_from_slice(&chunk_count.to_be_bytes()[1..4]);
        for (&(_, _, decompressed_size), data) in chunks.iter().zip(&chunk_datas) {
            let md5: [u8; 16] = Md5::digest(data).into();
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&decompressed_size.to_be_bytes());
            out.extend_from_slice(&md5);
        }
        for data in &chunk_datas {
            out.extend_from_slice(data);
        }
        out
    }

    fn build_single_chunk(mode: u8, payload: &[u8]) -> Vec<u8> {
        // header_size == 0: magic + header_size(0) + mode byte + payload
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(mode);
        out.extend_from_slice(payload);
        out
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
    }

    /// Builds a valid chunk-table BLTE buffer from `(is_z, raw_payload)`
    /// pairs, compressing the raw payload for `Z`-mode chunks. Used by the
    /// property tests below to get a realistic, always-valid starting point.
    fn build_valid_blte(raws: &[(bool, Vec<u8>)]) -> Vec<u8> {
        let owned: Vec<Vec<u8>> = raws
            .iter()
            .map(|(is_z, raw)| if *is_z { zlib(raw) } else { raw.clone() })
            .collect();
        let chunks: Vec<(u8, &[u8], u32)> = raws
            .iter()
            .zip(&owned)
            .map(|((is_z, raw), payload)| {
                let mode = if *is_z { b'Z' } else { b'N' };
                (mode, payload.as_slice(), raw.len() as u32)
            })
            .collect();
        build_blte(&chunks)
    }

    #[test]
    fn header_size_zero_raw() {
        let data = b"hello world";
        let blte = build_single_chunk(b'N', data);
        let decoded = decode(&blte).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn header_size_zero_zlib() {
        let data = b"hello world, this is compressible compressible compressible data";
        let compressed = zlib(data);
        let blte = build_single_chunk(b'Z', &compressed);
        let decoded = decode(&blte).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn multi_chunk_mixed_n_and_z() {
        let raw = b"raw chunk data";
        let text = b"compressible compressible compressible compressible text";
        let compressed = zlib(text);
        let blte = build_blte(&[
            (b'N', raw, raw.len() as u32),
            (b'Z', &compressed, text.len() as u32),
        ]);
        let decoded = decode(&blte).unwrap();
        let mut expected = raw.to_vec();
        expected.extend_from_slice(text);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn md5_mismatch_is_detected() {
        let raw = b"raw chunk data";
        let mut blte = build_blte(&[(b'N', raw, raw.len() as u32)]);
        // Corrupt a byte of the chunk data (after the header) so the MD5 no
        // longer matches the table entry.
        let last = blte.len() - 1;
        blte[last] ^= 0xFF;
        let err = decode(&blte).unwrap_err();
        assert!(matches!(err, CascError::ChecksumMismatch("BLTE chunk")));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut blte = build_single_chunk(b'N', b"data");
        blte[0] = b'X';
        assert!(decode(&blte).is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(decode(b"BLT").is_err());
        assert!(decode(b"").is_err());

        let blte = build_blte(&[(b'N', b"hello", 5)]);
        let truncated = &blte[..blte.len() - 2];
        assert!(decode(truncated).is_err());
    }

    #[test]
    fn header_size_disagreeing_with_chunk_count_is_rejected() {
        let mut blte = build_blte(&[(b'N', b"hello", 5), (b'N', b"world", 5)]);
        // Corrupt header_size to no longer match 2 chunks worth of table.
        let bad_header_size = (8 + 4 + CHUNK_ENTRY_SIZE) as u32; // only 1 entry's worth
        blte[4..8].copy_from_slice(&bad_header_size.to_be_bytes());
        let err = decode(&blte).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn encrypted_mode_is_unsupported() {
        let blte = build_single_chunk(b'E', b"whatever");
        let err = decode(&blte).unwrap_err();
        assert!(matches!(
            err,
            CascError::Unsupported {
                what: "BLTE chunk",
                ..
            }
        ));
    }

    #[test]
    fn unknown_mode_is_unsupported() {
        let blte = build_single_chunk(0x34, b"whatever");
        let err = decode(&blte).unwrap_err();
        match err {
            CascError::Unsupported { what, reason } => {
                assert_eq!(what, "BLTE chunk");
                assert!(reason.contains("0x34"), "reason was: {reason}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn nested_f_mode_works() {
        let inner_data = b"deeply nested payload";
        let inner_blte = build_blte(&[(b'N', inner_data, inner_data.len() as u32)]);
        let outer = build_blte(&[(b'F', &inner_blte, inner_data.len() as u32)]);
        let decoded = decode(&outer).unwrap();
        assert_eq!(decoded, inner_data);
    }

    #[test]
    fn nested_f_mode_recursion_depth_limit() {
        // Build a chain of nested BLTE buffers deeper than MAX_NEST_DEPTH.
        let leaf = b"leaf";
        let mut current = build_blte(&[(b'N', leaf, leaf.len() as u32)]);
        for _ in 0..(MAX_NEST_DEPTH + 2) {
            current = build_blte(&[(b'F', &current, leaf.len() as u32)]);
        }
        let err = decode(&current).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn decompressed_size_mismatch_is_an_error() {
        let raw = b"raw chunk data";
        // Declare a decompressed_size that doesn't match the actual payload length.
        let blte = build_blte(&[(b'N', raw, raw.len() as u32 + 1)]);
        assert!(decode(&blte).is_err());
    }

    #[test]
    fn zlib_decompressed_size_mismatch_is_an_error() {
        let text = b"compressible compressible compressible compressible text";
        let compressed = zlib(text);
        let blte = build_blte(&[(b'Z', &compressed, text.len() as u32 - 1)]);
        assert!(decode(&blte).is_err());
    }

    #[test]
    fn header_parse_reports_chunk_table() {
        let blte = build_blte(&[(b'N', b"hello", 5), (b'N', b"world", 5)]);
        let header = BlteHeader::parse(&blte).unwrap();
        assert_eq!(header.chunks().len(), 2);
        assert_eq!(header.total_decompressed_size(), Some(10));
        assert_eq!(header.chunks()[0].decompressed_size, 5);
        assert_eq!(header.chunks()[1].decompressed_size, 5);
    }

    #[test]
    fn header_parse_no_chunk_table_has_unknown_size() {
        let blte = build_single_chunk(b'N', b"hello");
        let header = BlteHeader::parse(&blte).unwrap();
        assert!(header.chunks().is_empty());
        assert_eq!(header.total_decompressed_size(), None);
    }

    #[test]
    fn decode_chunk_standalone() {
        let raw = b"standalone chunk";
        let mut encoded = vec![b'N'];
        encoded.extend_from_slice(raw);
        let decoded = decode_chunk(&encoded, Some(raw.len() as u32), None).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn chunk_count_zero_is_rejected() {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        // header_size = 8 + 4 + 0 entries = 12
        out.extend_from_slice(&12u32.to_be_bytes());
        out.push(0x0F);
        out.extend_from_slice(&[0, 0, 0]); // chunk_count = 0
        assert!(decode(&out).is_err());
    }

    #[test]
    fn bad_flags_byte_is_rejected() {
        let mut blte = build_blte(&[(b'N', b"hello", 5)]);
        blte[8] = 0x00;
        assert!(decode(&blte).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Building a multi-chunk BLTE buffer from arbitrary raw/zlib chunks
        /// and decoding it must reproduce the concatenation of the original
        /// (uncompressed) payloads.
        #[test]
        fn prop_roundtrip_blte_chunk_table(
            raws in proptest::collection::vec(
                (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..64)),
                1..8,
            )
        ) {
            let blte = build_valid_blte(&raws);
            let decoded = decode(&blte).unwrap();
            let mut expected = Vec::new();
            for (_, raw) in &raws {
                expected.extend_from_slice(raw);
            }
            prop_assert_eq!(decoded, expected);
        }

        /// Same, but for the `header_size == 0` single-implicit-chunk form.
        #[test]
        fn prop_roundtrip_blte_single_chunk(
            is_z in any::<bool>(),
            raw in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let blte = if is_z {
                build_single_chunk(b'Z', &zlib(&raw))
            } else {
                build_single_chunk(b'N', &raw)
            };
            let decoded = decode(&blte).unwrap();
            prop_assert_eq!(decoded, raw);
        }

        /// Neither `decode` nor `BlteHeader::parse` should ever panic, no
        /// matter what bytes they're fed.
        #[test]
        fn prop_no_panic_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = decode(&data);
            let _ = BlteHeader::parse(&data);
        }

        /// Flipping a handful of bytes in an otherwise-valid BLTE buffer
        /// should never panic, even though it usually breaks the checksum or
        /// header invariants.
        #[test]
        fn prop_no_panic_flipped_bytes(
            raws in proptest::collection::vec(
                (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..32)),
                1..4,
            ),
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..4),
        ) {
            let mut blte = build_valid_blte(&raws);
            for (pos, xor) in &flips {
                if !blte.is_empty() {
                    let idx = pos % blte.len();
                    blte[idx] ^= xor | 1;
                }
            }
            let _ = decode(&blte);
        }

        /// Truncating an otherwise-valid BLTE buffer to an arbitrary length
        /// should never panic.
        #[test]
        fn prop_no_panic_truncated(
            raws in proptest::collection::vec(
                (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..32)),
                1..4,
            ),
            trunc_len in any::<usize>(),
        ) {
            let blte = build_valid_blte(&raws);
            let len = trunc_len % (blte.len() + 1);
            let _ = decode(&blte[..len]);
        }
    }
}
