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

use crate::zlib::{Inflater, inflate_exact, inflate_to_vec};
use md5::{Digest, Md5};

use crate::error::{CascError, Result};
#[cfg(not(target_arch = "wasm32"))]
use crate::md5lanes::hash_many;

const MAGIC: &[u8; 4] = b"BLTE";
/// Size of one chunk table entry: compressed_size(4) + decompressed_size(4) + md5(16).
const CHUNK_ENTRY_SIZE: usize = 24;

/// Resource limits for a complete encoded CASC object.
///
/// These limits apply before allocating from attacker-controlled metadata and
/// while expanding compressed data. [`Default`] is deliberately conservative
/// for StarCraft: Remastered; callers that need different limits can use
/// [`decode_with_limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLimits {
    /// Largest accepted encoded BLTE object.
    pub max_encoded_bytes: usize,
    /// Largest final decoded object, including nested `F` chunks.
    pub max_decoded_bytes: usize,
    /// Largest decoded output of a single BLTE chunk.
    pub max_chunk_decoded_bytes: usize,
    /// Largest number of entries in one BLTE chunk table.
    pub max_chunk_count: usize,
    /// Largest nesting depth of `F` chunks.
    pub max_nesting: u32,
    /// Largest up-front output reservation when the decoded size isn't known
    /// from verified metadata. Actual growth remains bounded by
    /// `max_decoded_bytes`. Reads with a known size (CKey-addressed reads,
    /// [`decode_into`]) allocate exactly once and ignore this.
    pub initial_reserve_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 256 * 1024 * 1024,
            max_decoded_bytes: 512 * 1024 * 1024,
            max_chunk_decoded_bytes: 64 * 1024 * 1024,
            max_chunk_count: 16_384,
            max_nesting: 4,
            initial_reserve_bytes: 8 * 1024 * 1024,
        }
    }
}

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
        parse_with_limits(data, ReadLimits::default())
    }

    /// Total decompressed size of all chunks combined, or `None` if the
    /// input has no chunk table (`header_size == 0`), in which case the
    /// decompressed size isn't known without decoding.
    pub fn total_decompressed_size(&self) -> Option<u64> {
        if self.chunks.is_empty() {
            return None;
        }
        self.chunks.iter().try_fold(0u64, |sum, chunk| {
            sum.checked_add(chunk.decompressed_size as u64)
        })
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

fn parse_with_limits(data: &[u8], limits: ReadLimits) -> Result<BlteHeader> {
    if data.len() > limits.max_encoded_bytes {
        return Err(limit("BLTE encoded input", limits.max_encoded_bytes));
    }
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
    if data.len() < 12 {
        return Err(CascError::malformed(
            "BLTE header",
            "input too short for chunk count",
        ));
    }
    let flags = data[8];
    if flags != 0x0F {
        return Err(CascError::malformed(
            "BLTE header",
            format!("unexpected chunk table flags 0x{flags:02x}"),
        ));
    }
    let chunk_count = u32::from_be_bytes([0, data[9], data[10], data[11]]) as usize;
    if chunk_count == 0 {
        return Err(CascError::malformed("BLTE header", "chunk_count is zero"));
    }
    if chunk_count > limits.max_chunk_count {
        return Err(limit("BLTE chunk count", limits.max_chunk_count));
    }

    let expected_header_size = 12usize
        .checked_add(
            CHUNK_ENTRY_SIZE
                .checked_mul(chunk_count)
                .ok_or_else(|| CascError::malformed("BLTE header", "chunk count overflow"))?,
        )
        .ok_or_else(|| CascError::malformed("BLTE header", "header size overflow"))?;
    if header_size != expected_header_size {
        return Err(CascError::malformed(
            "BLTE header",
            format!(
                "header_size {header_size} does not match chunk_count {chunk_count} \
                     (expected {expected_header_size})"
            ),
        ));
    }

    let mut chunks = Vec::new();
    chunks
        .try_reserve_exact(chunk_count)
        .map_err(|_| limit("BLTE chunk table allocation", limits.max_chunk_count))?;
    let mut offset = header_size;
    let mut entry_pos: usize = 12;
    for _ in 0..chunk_count {
        let entry_end = entry_pos
            .checked_add(CHUNK_ENTRY_SIZE)
            .ok_or_else(|| CascError::malformed("BLTE header", "chunk entry overflow"))?;
        let entry = data
            .get(entry_pos..entry_end)
            .ok_or_else(|| CascError::malformed("BLTE header", "truncated chunk table"))?;
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
        entry_pos = entry_end;
    }

    Ok(BlteHeader {
        chunks,
        data_start: header_size,
    })
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
    let limits = ReadLimits::default();
    if encoded.len() > limits.max_encoded_bytes {
        return Err(limit("BLTE encoded input", limits.max_encoded_bytes));
    }
    decode_chunk_inner(
        encoded,
        expected_size.map(|size| size as usize),
        expected_md5,
        0,
        limits,
        limits.max_decoded_bytes,
        &mut Inflater::default(),
    )
}

fn decode_chunk_inner(
    encoded: &[u8],
    expected_size: Option<usize>,
    expected_md5: Option<&[u8; 16]>,
    depth: u32,
    limits: ReadLimits,
    remaining_output: usize,
    inflater: &mut Inflater,
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
            if let Some(expected) = expected_size
                && payload.len() != expected
            {
                return Err(CascError::malformed(
                    "BLTE chunk",
                    format!(
                        "mode 'N' payload length {} does not match declared decompressed_size {expected}",
                        payload.len()
                    ),
                ));
            }
            check_chunk_output(payload.len(), limits, remaining_output)?;
            copy_bytes(payload, "BLTE raw chunk", limits.max_chunk_decoded_bytes)
        }
        b'Z' => {
            if let Some(expected) = expected_size {
                check_chunk_output(expected, limits, remaining_output)?;
            }
            let decoded = match expected_size {
                Some(expected) => {
                    let mut decoded = Vec::new();
                    decoded
                        .try_reserve_exact(expected)
                        .map_err(|_| limit("BLTE decoded chunk", limits.max_chunk_decoded_bytes))?;
                    decoded.resize(expected, 0);
                    inflate_exact(inflater, payload, &mut decoded)?;
                    decoded
                }
                None => inflate_to_vec(
                    inflater,
                    payload,
                    remaining_output.min(limits.max_chunk_decoded_bytes),
                )?,
            };
            check_chunk_output(decoded.len(), limits, remaining_output)?;
            Ok(decoded)
        }
        b'F' => {
            if depth >= limits.max_nesting {
                return Err(CascError::malformed(
                    "BLTE chunk",
                    format!(
                        "nested BLTE recursion exceeds max depth {}",
                        limits.max_nesting
                    ),
                ));
            }
            if let Some(expected) = expected_size {
                check_chunk_output(expected, limits, remaining_output)?;
            }
            let nested_limit =
                expected_size.unwrap_or(remaining_output.min(limits.max_chunk_decoded_bytes));
            let decoded = decode_inner(payload, depth + 1, limits, nested_limit, inflater)?;
            if let Some(expected) = expected_size
                && decoded.len() != expected
            {
                return Err(CascError::malformed(
                    "BLTE chunk",
                    format!(
                        "mode 'F' decoded length {} does not match declared decompressed_size {expected}",
                        decoded.len()
                    ),
                ));
            }
            check_chunk_output(decoded.len(), limits, remaining_output)?;
            Ok(decoded)
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
    decode_with_limits(data, ReadLimits::default())
}

/// Decodes a complete BLTE-encoded buffer under explicit resource limits.
pub fn decode_with_limits(data: &[u8], limits: ReadLimits) -> Result<Vec<u8>> {
    decode_inner(
        data,
        0,
        limits,
        limits.max_decoded_bytes,
        &mut Inflater::default(),
    )
}

fn decode_inner(
    data: &[u8],
    depth: u32,
    limits: ReadLimits,
    output_limit: usize,
    inflater: &mut Inflater,
) -> Result<Vec<u8>> {
    if data.len() > limits.max_encoded_bytes {
        return Err(limit("BLTE encoded input", limits.max_encoded_bytes));
    }
    let header = parse_with_limits(data, limits)?;

    if header.chunks.is_empty() {
        // header_size == 0: entire remainder is a single chunk of unknown size.
        let encoded = implicit_chunk(data, &header)?;
        return decode_chunk_inner(encoded, None, None, depth, limits, output_limit, inflater);
    }

    let declared_total = validate_chunk_table(data.len(), &header, limits)?;
    if declared_total > output_limit {
        return Err(limit("BLTE decoded output", output_limit));
    }
    verify_chunk_md5s(data, &header.chunks)?;

    let mut out = Vec::new();
    let initial = declared_total.min(limits.initial_reserve_bytes);
    out.try_reserve_exact(initial)
        .map_err(|_| limit("BLTE decoded output allocation", output_limit))?;
    for chunk in &header.chunks {
        // Each chunk decodes straight into the tail of `out`; its size was
        // checked against the limits by `validate_chunk_table` above.
        let start = out.len();
        let end = start + chunk.decompressed_size as usize;
        out.try_reserve(chunk.decompressed_size as usize)
            .map_err(|_| limit("BLTE decoded output allocation", output_limit))?;
        out.resize(end, 0);
        decode_chunk_into(
            chunk_data(data, chunk)?,
            &mut out[start..end],
            depth,
            limits,
            inflater,
        )?;
    }
    Ok(out)
}

/// Decodes a complete BLTE-encoded buffer into `out`, which must be exactly
/// the decoded size, without allocating any decoded output.
///
/// With a chunk table, the declared total must equal `out.len()` and each
/// chunk decodes straight into its own slice of `out`. Without one, the
/// single implicit chunk must decode to exactly `out.len()` bytes. Checks and
/// limits are the same as [`decode_with_limits`]; `out` may be partially
/// written when this fails.
pub fn decode_into(data: &[u8], out: &mut [u8], limits: ReadLimits) -> Result<()> {
    if out.len() > limits.max_decoded_bytes {
        return Err(limit("BLTE decoded output", limits.max_decoded_bytes));
    }
    decode_into_inner(data, out, 0, limits, &mut Inflater::default())
}

fn decode_into_inner(
    data: &[u8],
    out: &mut [u8],
    depth: u32,
    limits: ReadLimits,
    inflater: &mut Inflater,
) -> Result<()> {
    let header = parse_with_limits(data, limits)?;

    if header.chunks.is_empty() {
        // header_size == 0: the output length stands in for the missing
        // declared size.
        let encoded = implicit_chunk(data, &header)?;
        return decode_chunk_into(encoded, out, depth, limits, inflater);
    }

    let declared_total = validate_chunk_table(data.len(), &header, limits)?;
    if declared_total != out.len() {
        return Err(CascError::malformed(
            "BLTE chunk table",
            format!(
                "declared decoded size {declared_total} does not match expected size {}",
                out.len()
            ),
        ));
    }

    verify_chunk_md5s(data, &header.chunks)?;

    let mut rest = out;
    for chunk in &header.chunks {
        let (dst, tail) = rest
            .split_at_mut_checked(chunk.decompressed_size as usize)
            .ok_or_else(|| CascError::malformed("BLTE chunk table", "decoded size overflow"))?;
        rest = tail;
        decode_chunk_into(chunk_data(data, chunk)?, dst, depth, limits, inflater)?;
    }
    Ok(())
}

/// Decodes one chunk into `out`, whose length is the chunk's declared (or,
/// for header-less BLTE, expected) decoded size. The chunk's MD5, if it has
/// one, must already have been checked by [`verify_chunk_md5s`].
fn decode_chunk_into(
    encoded: &[u8],
    out: &mut [u8],
    depth: u32,
    limits: ReadLimits,
    inflater: &mut Inflater,
) -> Result<()> {
    let Some((&mode, payload)) = encoded.split_first() else {
        return Err(CascError::malformed(
            "BLTE chunk",
            "empty chunk (missing mode byte)",
        ));
    };
    let len = out.len();
    let check_len = || {
        if len > limits.max_chunk_decoded_bytes {
            return Err(limit("BLTE decoded chunk", limits.max_chunk_decoded_bytes));
        }
        Ok(())
    };

    match mode {
        b'N' => {
            check_len()?;
            if payload.len() != out.len() {
                return Err(CascError::malformed(
                    "BLTE chunk",
                    format!(
                        "mode 'N' payload length {} does not match declared decompressed_size {}",
                        payload.len(),
                        out.len()
                    ),
                ));
            }
            out.copy_from_slice(payload);
            Ok(())
        }
        b'Z' => {
            check_len()?;
            inflate_exact(inflater, payload, out)
        }
        b'F' => {
            check_len()?;
            if depth >= limits.max_nesting {
                return Err(CascError::malformed(
                    "BLTE chunk",
                    format!(
                        "nested BLTE recursion exceeds max depth {}",
                        limits.max_nesting
                    ),
                ));
            }
            decode_into_inner(payload, out, depth + 1, limits, inflater)
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

/// How many encoded bytes a caller should fetch up front for
/// [`ChunkStream::open`]: enough for the header of any realistic object, and
/// for small objects the whole thing.
pub(crate) const STREAM_PREFIX_BYTES: usize = 64 * 1024;
/// Upper bound on the encoded bytes fetched per positioned read while
/// streaming; adjacent chunks are batched up to this size. A single chunk
/// larger than this is read on its own.
const STREAM_BATCH_BYTES: usize = 1024 * 1024;

/// Positioned reader over a BLTE stream: `read(offset, buf)` fills `buf` with
/// the stream bytes starting at `offset`.
pub(crate) trait ChunkRead: FnMut(u64, &mut [u8]) -> Result<()> {}
impl<F: FnMut(u64, &mut [u8]) -> Result<()>> ChunkRead for F {}

/// Result of [`ChunkStream::open`].
pub(crate) enum StreamOpen<R> {
    /// The object has a chunk table and can be decoded chunk-by-chunk.
    Chunked(ChunkStream<R>),
    /// `header_size == 0`: a single chunk of unknown size that has to be
    /// decoded from a complete buffer.
    Headerless,
}

/// A BLTE object whose chunk table has been read and validated but whose
/// chunk data is still in the backing store. Chunks are fetched in batches
/// through `read_at`, verified and decoded straight into the output, so peak
/// memory is the output plus one batch rather than the whole encoded object.
///
/// `read_at(offset, buf)` must fill `buf` with the BLTE bytes starting at
/// `offset` (relative to the start of the BLTE stream).
pub(crate) struct ChunkStream<R> {
    header: BlteHeader,
    declared_total: usize,
    window: Vec<u8>,
    window_start: usize,
    read_at: R,
    limits: ReadLimits,
}

impl<R: ChunkRead> ChunkStream<R> {
    /// Parses and validates the BLTE header of a `blte_len`-byte stream whose
    /// first bytes are `prefix` (at least the 8-byte preamble unless the
    /// stream is shorter). Fetches the rest of the chunk table through
    /// `read_at` when it extends past `prefix`.
    pub(crate) fn open(
        prefix: &[u8],
        blte_len: usize,
        mut read_at: R,
        limits: ReadLimits,
    ) -> Result<StreamOpen<R>> {
        if blte_len > limits.max_encoded_bytes {
            return Err(limit("BLTE encoded input", limits.max_encoded_bytes));
        }
        let prefix = &prefix[..prefix.len().min(blte_len)];
        let mut window = Vec::new();
        window
            .try_reserve_exact(prefix.len())
            .map_err(|_| limit("BLTE read buffer allocation", limits.max_encoded_bytes))?;
        window.extend_from_slice(prefix);

        // The preamble must be in hand to size the header.
        if window.len() < 8 && blte_len > window.len() {
            let have = window.len();
            let want = blte_len.min(8);
            window.resize(want, 0);
            read_at(have as u64, &mut window[have..])?;
        }
        // A header longer than the prefix needs its tail fetched before it can
        // be parsed. The chunk count is checked first so the fetch is bounded
        // by `max_chunk_count`; anything else implausible is rejected by the
        // parser from the bytes already in hand.
        if window.len() >= 8 && window.starts_with(MAGIC) {
            let header_size = u32::from_be_bytes(window[4..8].try_into().unwrap()) as usize;
            if header_size > window.len() && header_size <= blte_len {
                if let Some(count) = window.get(9..12)
                    && u32::from_be_bytes([0, count[0], count[1], count[2]]) as usize
                        > limits.max_chunk_count
                {
                    return Err(limit("BLTE chunk count", limits.max_chunk_count));
                }
                if header_size
                    > CHUNK_ENTRY_SIZE
                        .saturating_mul(limits.max_chunk_count)
                        .saturating_add(12)
                {
                    return Err(CascError::malformed(
                        "BLTE header",
                        "header_size does not match chunk_count",
                    ));
                }
                let have = window.len();
                window.resize(header_size, 0);
                read_at(have as u64, &mut window[have..])?;
            }
        }

        let header = parse_with_limits(&window, limits)?;
        if header.chunks.is_empty() {
            return Ok(StreamOpen::Headerless);
        }
        let declared_total = validate_chunk_table(blte_len, &header, limits)?;
        Ok(StreamOpen::Chunked(ChunkStream {
            header,
            declared_total,
            window,
            window_start: 0,
            read_at,
            limits,
        }))
    }

    /// Total decoded size declared by the chunk table.
    pub(crate) fn decoded_size(&self) -> usize {
        self.declared_total
    }

    /// Fetches, verifies, and decodes every chunk into `out`, whose length
    /// must equal [`Self::decoded_size`]. Checks match [`decode_into`]; `out`
    /// may be partially written on failure.
    pub(crate) fn decode_into(mut self, out: &mut [u8]) -> Result<()> {
        if out.len() != self.declared_total {
            return Err(CascError::malformed(
                "BLTE chunk table",
                format!(
                    "declared decoded size {} does not match expected size {}",
                    self.declared_total,
                    out.len()
                ),
            ));
        }
        let chunks = &self.header.chunks;
        let mut inflater = Inflater::default();
        let mut rest = out;
        let mut i = 0;
        while i < chunks.len() {
            // Batch adjacent chunks into one read, always taking at least one.
            let start = chunks[i].offset;
            let mut end = start + chunks[i].compressed_size as usize;
            let mut j = i + 1;
            while let Some(next) = chunks.get(j) {
                let next_end = next.offset + next.compressed_size as usize;
                if next_end - start > STREAM_BATCH_BYTES {
                    break;
                }
                end = next_end;
                j += 1;
            }

            let window_end = self.window_start + self.window.len();
            if start < self.window_start || end > window_end {
                let need = end - start;
                if need > self.window.len() {
                    self.window
                        .try_reserve(need - self.window.len())
                        .map_err(|_| {
                            limit("BLTE read buffer allocation", self.limits.max_encoded_bytes)
                        })?;
                }
                self.window.resize(need, 0);
                (self.read_at)(start as u64, &mut self.window)?;
                self.window_start = start;
            }

            // Verify the whole batch before decoding any of it, hashing
            // several chunks at a time as `verify_chunk_md5s` does.
            let window = &self.window;
            let window_start = self.window_start;
            let encoded = |chunk: &ChunkInfo| {
                let from = chunk.offset - window_start;
                &window[from..from + chunk.compressed_size as usize]
            };
            if !md5_all_match(chunks[i..j].iter().map(|c| (encoded(c), &c.md5))) {
                return Err(CascError::ChecksumMismatch("BLTE chunk"));
            }
            for chunk in &chunks[i..j] {
                let (dst, tail) = rest
                    .split_at_mut_checked(chunk.decompressed_size as usize)
                    .ok_or_else(|| {
                        CascError::malformed("BLTE chunk table", "decoded size overflow")
                    })?;
                rest = tail;
                decode_chunk_into(encoded(chunk), dst, 0, self.limits, &mut inflater)?;
            }
            i = j;
        }
        Ok(())
    }
}

/// The single implicit chunk of a header-less (`header_size == 0`) buffer.
fn implicit_chunk<'a>(data: &'a [u8], header: &BlteHeader) -> Result<&'a [u8]> {
    data.get(header.data_start..)
        .ok_or_else(|| CascError::malformed("BLTE header", "missing implicit chunk"))
}

/// Checks a parsed chunk table against the input and limits before any chunk
/// is decoded, returning the declared total decoded size.
fn validate_chunk_table(data_len: usize, header: &BlteHeader, limits: ReadLimits) -> Result<usize> {
    let declared_total = header.chunks.iter().try_fold(0usize, |sum, chunk| {
        sum.checked_add(chunk.decompressed_size as usize)
            .ok_or_else(|| CascError::malformed("BLTE header", "decoded size overflow"))
    })?;
    let encoded_end = header
        .chunks
        .last()
        .and_then(|chunk| chunk.offset.checked_add(chunk.compressed_size as usize))
        .ok_or_else(|| CascError::malformed("BLTE header", "chunk size overflow"))?;
    if encoded_end != data_len {
        return Err(CascError::malformed(
            "BLTE chunk data",
            format!("declared chunks end at byte {encoded_end}, but input length is {data_len}"),
        ));
    }
    if header
        .chunks
        .iter()
        .any(|chunk| chunk.decompressed_size as usize > limits.max_chunk_decoded_bytes)
    {
        return Err(limit("BLTE decoded chunk", limits.max_chunk_decoded_bytes));
    }
    Ok(declared_total)
}

/// Checks every chunk's MD5 against its chunk table entry.
///
/// Chunks are hashed several at a time (see `md5lanes`, native only), which is
/// markedly faster than hashing them one after another. Doing this for the
/// whole table before decoding also means no chunk is inflated from a
/// buffer that failed verification.
fn verify_chunk_md5s(data: &[u8], chunks: &[ChunkInfo]) -> Result<()> {
    let mut bad_span = None;
    let jobs = chunks
        .iter()
        .map_while(|chunk| match chunk_data(data, chunk) {
            Ok(encoded) => Some((encoded, &chunk.md5)),
            Err(e) => {
                bad_span = Some(e);
                None
            }
        });
    let all_match = md5_all_match(jobs);
    if let Some(e) = bad_span {
        return Err(e);
    }
    if !all_match {
        return Err(CascError::ChecksumMismatch("BLTE chunk"));
    }
    Ok(())
}

/// Whether every `(data, expected)` pair's MD5 matches.
#[cfg(not(target_arch = "wasm32"))]
fn md5_all_match<'a>(jobs: impl Iterator<Item = (&'a [u8], &'a [u8; 16])>) -> bool {
    hash_many(jobs, |expected, actual| &actual == expected)
}

/// Whether every `(data, expected)` pair's MD5 matches.
///
/// On wasm32 the multi-lane hasher gains only a few percent (the engine
/// doesn't exploit the instruction-level parallelism) while adding ~10 KB of
/// code, so hash serially.
#[cfg(target_arch = "wasm32")]
fn md5_all_match<'a>(mut jobs: impl Iterator<Item = (&'a [u8], &'a [u8; 16])>) -> bool {
    jobs.all(|(data, expected)| &<[u8; 16]>::from(Md5::digest(data)) == expected)
}

/// One chunk's encoded bytes (mode byte included).
fn chunk_data<'a>(data: &'a [u8], chunk: &ChunkInfo) -> Result<&'a [u8]> {
    chunk
        .offset
        .checked_add(chunk.compressed_size as usize)
        .and_then(|end| data.get(chunk.offset..end))
        .ok_or_else(|| CascError::malformed("BLTE chunk", "chunk extends past end of input"))
}

fn check_chunk_output(size: usize, limits: ReadLimits, remaining_output: usize) -> Result<()> {
    if size > limits.max_chunk_decoded_bytes {
        return Err(limit("BLTE decoded chunk", limits.max_chunk_decoded_bytes));
    }
    if size > remaining_output {
        return Err(limit("BLTE decoded output", remaining_output));
    }
    Ok(())
}

fn copy_bytes(bytes: &[u8], what: &'static str, allocation_limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| limit(what, allocation_limit))?;
    out.extend_from_slice(bytes);
    Ok(out)
}

fn limit(what: &'static str, limit: usize) -> CascError {
    CascError::LimitExceeded { what, limit }
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
    fn md5_mismatch_in_any_chunk_of_a_large_table_is_detected() {
        let payloads: Vec<Vec<u8>> = (0..11u8)
            .map(|i| vec![i; 40 + usize::from(i) * 37])
            .collect();
        let chunks: Vec<(u8, &[u8], u32)> = payloads
            .iter()
            .map(|p| (b'N', p.as_slice(), p.len() as u32))
            .collect();
        let blte = build_blte(&chunks);
        let expected: Vec<u8> = payloads.concat();
        assert_eq!(decode(&blte).unwrap(), expected);

        let header = BlteHeader::parse(&blte).unwrap();
        for chunk in header.chunks() {
            let mut bad = blte.clone();
            // Flip the last byte of this chunk's payload.
            bad[chunk.offset + chunk.compressed_size as usize - 1] ^= 1;
            let err = decode(&bad).unwrap_err();
            assert!(matches!(err, CascError::ChecksumMismatch("BLTE chunk")));
            let err = decode_into_vec(&bad, expected.len(), ReadLimits::default()).unwrap_err();
            assert!(matches!(err, CascError::ChecksumMismatch("BLTE chunk")));
        }
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
        for _ in 0..(ReadLimits::default().max_nesting + 2) {
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
    fn short_nonzero_header_is_rejected_without_panicking() {
        let mut input = Vec::new();
        input.extend_from_slice(MAGIC);
        input.extend_from_slice(&8u32.to_be_bytes());
        assert!(BlteHeader::parse(&input).is_err());
    }

    #[test]
    fn bad_flags_byte_is_rejected() {
        let mut blte = build_blte(&[(b'N', b"hello", 5)]);
        blte[8] = 0x00;
        assert!(decode(&blte).is_err());
    }

    #[test]
    fn huge_declared_chunk_count_is_rejected_before_table_allocation() {
        let mut input = Vec::new();
        input.extend_from_slice(MAGIC);
        input.extend_from_slice(&12u32.to_be_bytes());
        input.push(0x0F);
        input.extend_from_slice(&16_385u32.to_be_bytes()[1..]);

        let err = BlteHeader::parse(&input).unwrap_err();
        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "BLTE chunk count",
                ..
            }
        ));
    }

    #[test]
    fn encoded_input_limit_is_checked_before_header_parsing() {
        let blte = build_single_chunk(b'N', b"hello");
        let limits = ReadLimits {
            max_encoded_bytes: blte.len() - 1,
            ..ReadLimits::default()
        };
        let err = decode_with_limits(&blte, limits).unwrap_err();
        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "BLTE encoded input",
                ..
            }
        ));
    }

    #[test]
    fn per_chunk_decoded_limit_is_enforced_before_copying() {
        let blte = build_blte(&[(b'N', b"12345", 5)]);
        let limits = ReadLimits {
            max_chunk_decoded_bytes: 4,
            ..ReadLimits::default()
        };
        let err = decode_with_limits(&blte, limits).unwrap_err();
        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "BLTE decoded chunk",
                ..
            }
        ));
    }

    #[test]
    fn aggregate_decoded_limit_is_enforced_before_decoding_chunks() {
        let blte = build_blte(&[(b'N', b"1234", 4), (b'N', b"5678", 4)]);
        let limits = ReadLimits {
            max_decoded_bytes: 7,
            max_chunk_decoded_bytes: 4,
            ..ReadLimits::default()
        };
        let err = decode_with_limits(&blte, limits).unwrap_err();
        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "BLTE decoded output",
                ..
            }
        ));
    }

    #[test]
    fn chunk_table_rejects_trailing_unchecked_bytes() {
        let mut blte = build_blte(&[(b'N', b"payload", 7)]);
        blte.extend_from_slice(b"trailing");

        let err = decode(&blte).unwrap_err();
        assert!(matches!(
            err,
            CascError::Malformed {
                what: "BLTE chunk data",
                ..
            }
        ));
    }

    #[test]
    fn nested_frame_must_match_its_parent_declared_size() {
        let inner = build_blte(&[(b'N', b"ok", 2)]);
        let outer = build_blte(&[(b'F', &inner, 3)]);
        let err = decode(&outer).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }), "{err:?}");
    }

    #[test]
    fn empty_zlib_chunk_decodes_to_nothing() {
        let compressed = zlib(b"");
        let blte = build_blte(&[(b'Z', &compressed, 0)]);
        assert_eq!(decode(&blte).unwrap(), b"");
        assert!(
            decode_into_vec(&blte, 0, ReadLimits::default())
                .unwrap()
                .is_empty()
        );
        assert_eq!(decode(&build_single_chunk(b'Z', &compressed)).unwrap(), b"");
    }

    #[test]
    fn headerless_zlib_grows_past_initial_buffer_and_honors_limit() {
        // Highly compressible, so the initial 4x-of-input guess is far too small.
        let raw = vec![7u8; 1 << 20];
        let blte = build_single_chunk(b'Z', &zlib(&raw));
        assert_eq!(decode(&blte).unwrap(), raw);

        let limits = ReadLimits {
            max_decoded_bytes: raw.len() - 1,
            ..ReadLimits::default()
        };
        assert!(decode_with_limits(&blte, limits).is_err());
        let limits = ReadLimits {
            max_decoded_bytes: raw.len(),
            ..ReadLimits::default()
        };
        assert_eq!(decode_with_limits(&blte, limits).unwrap(), raw);
    }

    #[test]
    fn truncated_and_corrupt_zlib_streams_are_rejected() {
        let raw: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 251) as u8).collect();
        let compressed = zlib(&raw);
        for bad in [
            compressed[..compressed.len() - 1].to_vec(), // missing adler byte
            compressed[..compressed.len() / 2].to_vec(),
            {
                let mut c = compressed.clone();
                let last = c.len() - 1;
                c[last] ^= 1; // adler32 mismatch
                c
            },
        ] {
            let table = build_blte(&[(b'Z', &bad, raw.len() as u32)]);
            let headerless = build_single_chunk(b'Z', &bad);
            assert!(decode(&table).is_err());
            assert!(decode(&headerless).is_err());
            assert!(decode_into_vec(&table, raw.len(), ReadLimits::default()).is_err());
            assert!(decode_into_vec(&headerless, raw.len(), ReadLimits::default()).is_err());
        }
    }

    fn decode_into_vec(blte: &[u8], len: usize, limits: ReadLimits) -> Result<Vec<u8>> {
        let mut out = vec![0; len];
        decode_into(blte, &mut out, limits)?;
        Ok(out)
    }

    #[test]
    fn decode_into_matches_decode_for_each_mode() {
        let raw = b"raw chunk data";
        let text = b"compressible compressible compressible compressible text";
        let compressed = zlib(text);
        let inner = build_blte(&[
            (b'N', raw, raw.len() as u32),
            (b'Z', &compressed, text.len() as u32),
        ]);
        let inner_len = (raw.len() + text.len()) as u32;
        let cases = [
            build_blte(&[(b'N', raw, raw.len() as u32)]),
            build_blte(&[(b'Z', &compressed, text.len() as u32)]),
            build_blte(&[(b'F', &inner, inner_len)]),
            build_blte(&[
                (b'N', raw, raw.len() as u32),
                (b'N', b"", 0),
                (b'Z', &compressed, text.len() as u32),
                (b'F', &inner, inner_len),
            ]),
            build_single_chunk(b'N', raw),
            build_single_chunk(b'Z', &compressed),
            build_single_chunk(b'F', &inner),
            build_single_chunk(b'F', &build_single_chunk(b'Z', &compressed)),
        ];
        for blte in &cases {
            let expected = decode(blte).unwrap();
            let decoded = decode_into_vec(blte, expected.len(), ReadLimits::default()).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn decode_into_rejects_wrong_length_before_decoding() {
        // The chunk is corrupt, so any decode attempt would report the MD5
        // mismatch; a length error proves nothing was decoded.
        let mut blte = build_blte(&[(b'N', b"hello", 5)]);
        let last = blte.len() - 1;
        blte[last] ^= 0xFF;
        for len in [4, 6] {
            let err = decode_into_vec(&blte, len, ReadLimits::default()).unwrap_err();
            assert!(
                matches!(
                    err,
                    CascError::Malformed {
                        what: "BLTE chunk table",
                        ..
                    }
                ),
                "len {len}: {err:?}"
            );
        }
        let err = decode_into_vec(&blte, 5, ReadLimits::default()).unwrap_err();
        assert!(matches!(err, CascError::ChecksumMismatch("BLTE chunk")));
    }

    #[test]
    fn decode_into_rejects_inflated_size_mismatch_in_both_directions() {
        let text = b"compressible compressible compressible compressible text";
        let compressed = zlib(text);
        for len in [text.len() - 1, text.len() + 1] {
            let table = build_blte(&[(b'Z', &compressed, len as u32)]);
            let headerless = build_single_chunk(b'Z', &compressed);
            for blte in [table, headerless] {
                let err = decode_into_vec(&blte, len, ReadLimits::default()).unwrap_err();
                assert!(
                    matches!(
                        err,
                        CascError::Malformed {
                            what: "BLTE chunk",
                            ..
                        }
                    ),
                    "len {len}: {err:?}"
                );
            }
        }
    }

    #[test]
    fn decode_into_rejects_raw_and_nested_size_mismatch() {
        let headerless = build_single_chunk(b'N', b"hello");
        for len in [4, 6] {
            assert!(decode_into_vec(&headerless, len, ReadLimits::default()).is_err());
        }
        let inner = build_blte(&[(b'N', b"ok", 2)]);
        let outer = build_blte(&[(b'F', &inner, 3)]);
        assert!(decode_into_vec(&outer, 3, ReadLimits::default()).is_err());
    }

    #[test]
    fn decode_into_unsupported_modes_fail_as_decode_does() {
        for mode in [b'E', 0x34] {
            let blte = build_single_chunk(mode, b"whatever");
            let err = decode_into_vec(&blte, 8, ReadLimits::default()).unwrap_err();
            assert!(matches!(
                err,
                CascError::Unsupported {
                    what: "BLTE chunk",
                    ..
                }
            ));
        }
    }

    #[test]
    fn decode_into_enforces_limits() {
        let blte = build_blte(&[(b'N', b"1234", 4), (b'N', b"5678", 4)]);
        let limits = ReadLimits {
            max_decoded_bytes: 7,
            ..ReadLimits::default()
        };
        let err = decode_into_vec(&blte, 8, limits).unwrap_err();
        assert!(matches!(
            err,
            CascError::LimitExceeded {
                what: "BLTE decoded output",
                ..
            }
        ));

        let limits = ReadLimits {
            max_chunk_decoded_bytes: 3,
            ..ReadLimits::default()
        };
        let headerless = build_single_chunk(b'N', b"12345");
        for (blte, len) in [(&blte, 8), (&headerless, 5)] {
            let err = decode_into_vec(blte, len, limits).unwrap_err();
            assert!(matches!(
                err,
                CascError::LimitExceeded {
                    what: "BLTE decoded chunk",
                    ..
                }
            ));
        }
    }

    /// Streams `blte` through [`ChunkStream`] with a counting in-memory
    /// reader, returning the decode result and the number of reads issued.
    fn stream_decode(
        blte: &[u8],
        prefix_len: usize,
        out_len: Option<usize>,
        limits: ReadLimits,
    ) -> (Result<Vec<u8>>, usize) {
        let reads = std::cell::Cell::new(0usize);
        let source = blte.to_vec();
        let prefix = &blte[..prefix_len.min(blte.len())];
        let opened = ChunkStream::open(
            prefix,
            blte.len(),
            |offset, buf: &mut [u8]| {
                reads.set(reads.get() + 1);
                let start = usize::try_from(offset).unwrap();
                let src = source.get(start..start + buf.len()).ok_or_else(|| {
                    CascError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                })?;
                buf.copy_from_slice(src);
                Ok(())
            },
            limits,
        );
        let result = match opened {
            Err(e) => Err(e),
            Ok(StreamOpen::Headerless) => decode_with_limits(blte, limits),
            Ok(StreamOpen::Chunked(stream)) => {
                let mut out = vec![0; out_len.unwrap_or(stream.decoded_size())];
                stream.decode_into(&mut out).map(|()| out)
            }
        };
        (result, reads.get())
    }

    #[test]
    fn stream_matches_decode_for_every_prefix_length() {
        let raws = vec![
            (true, b"compressible compressible compressible".to_vec()),
            (false, b"raw".to_vec()),
            (true, vec![7u8; 5000]),
            (false, b"tail".to_vec()),
        ];
        let blte = build_valid_blte(&raws);
        let expected = decode(&blte).unwrap();
        for prefix_len in 0..=blte.len() {
            let (decoded, _) = stream_decode(&blte, prefix_len, None, ReadLimits::default());
            assert_eq!(decoded.unwrap(), expected, "prefix {prefix_len}");
        }
    }

    #[test]
    fn stream_nested_chunks_decode() {
        let inner = build_valid_blte(&[(true, b"inner inner inner".to_vec())]);
        let blte = build_blte(&[(b'F', &inner, 17), (b'N', b"!", 1)]);
        let (decoded, _) = stream_decode(&blte, 8, None, ReadLimits::default());
        assert_eq!(decoded.unwrap(), b"inner inner inner!");
    }

    #[test]
    fn stream_whole_object_in_prefix_needs_no_reads() {
        let blte = build_valid_blte(&[(false, b"abc".to_vec()), (true, vec![1; 100])]);
        let (decoded, reads) = stream_decode(&blte, blte.len(), None, ReadLimits::default());
        assert_eq!(decoded.unwrap().len(), 103);
        assert_eq!(reads, 0);
    }

    #[test]
    fn stream_batches_adjacent_chunks_into_few_reads() {
        // 40 incompressible-ish 100 KiB raw chunks = ~4 MiB encoded.
        let raws: Vec<(bool, Vec<u8>)> = (0..40u8).map(|i| (false, vec![i; 100 * 1024])).collect();
        let blte = build_valid_blte(&raws);
        let (decoded, reads) = stream_decode(&blte, 4096, None, ReadLimits::default());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.len(), 40 * 100 * 1024);
        assert_eq!(decoded, decode(&blte).unwrap());
        // Header tail (1) plus ceil(4 MiB / 1 MiB batches of 10 chunks).
        assert!(reads <= 6, "{reads} reads");
        assert!(reads > 1);
    }

    #[test]
    fn stream_single_chunk_larger_than_a_batch_is_read_whole() {
        let raw = vec![9u8; 3 * STREAM_BATCH_BYTES];
        let blte = build_valid_blte(&[(false, raw.clone())]);
        let (decoded, reads) = stream_decode(&blte, 4096, None, ReadLimits::default());
        assert_eq!(decoded.unwrap(), raw);
        assert_eq!(reads, 1);
    }

    #[test]
    fn stream_detects_corrupt_late_chunk() {
        let raws: Vec<(bool, Vec<u8>)> = (0..8u8).map(|i| (false, vec![i; 300 * 1024])).collect();
        let mut blte = build_valid_blte(&raws);
        let last = blte.len() - 1;
        blte[last] ^= 1;
        let (decoded, _) = stream_decode(&blte, 4096, None, ReadLimits::default());
        assert!(matches!(
            decoded.unwrap_err(),
            CascError::ChecksumMismatch("BLTE chunk")
        ));
    }

    #[test]
    fn stream_reports_source_truncation_as_error() {
        let raws: Vec<(bool, Vec<u8>)> = (0..8u8).map(|i| (false, vec![i; 300 * 1024])).collect();
        let blte = build_valid_blte(&raws);
        // Declared length is honored, but the backing store ends early.
        let reads = std::cell::Cell::new(0);
        let short = &blte[..blte.len() / 2];
        let opened = ChunkStream::open(
            &blte[..4096],
            blte.len(),
            |offset, buf: &mut [u8]| {
                reads.set(reads.get() + 1);
                let start = usize::try_from(offset).unwrap();
                let src = short
                    .get(start..start + buf.len())
                    .ok_or_else(|| CascError::malformed("test", "eof"))?;
                buf.copy_from_slice(src);
                Ok(())
            },
            ReadLimits::default(),
        );
        let Ok(StreamOpen::Chunked(stream)) = opened else {
            panic!("expected chunked stream");
        };
        let mut out = vec![0; stream.decoded_size()];
        assert!(stream.decode_into(&mut out).is_err());
    }

    #[test]
    fn stream_headerless_is_reported_not_decoded() {
        let blte = build_single_chunk(b'N', b"hello");
        let opened = ChunkStream::open(
            &blte,
            blte.len(),
            |_: u64, _: &mut [u8]| panic!("no reads expected"),
            ReadLimits::default(),
        );
        assert!(matches!(opened, Ok(StreamOpen::Headerless)));
    }

    #[test]
    fn stream_rejects_wrong_output_length() {
        let blte = build_valid_blte(&[(false, b"abcd".to_vec())]);
        let (decoded, _) = stream_decode(&blte, blte.len(), Some(3), ReadLimits::default());
        assert!(matches!(
            decoded.unwrap_err(),
            CascError::Malformed {
                what: "BLTE chunk table",
                ..
            }
        ));
    }

    #[test]
    fn stream_enforces_limits_before_reading_chunk_data() {
        let raws: Vec<(bool, Vec<u8>)> = (0..4u8).map(|i| (false, vec![i; 1000])).collect();
        let blte = build_valid_blte(&raws);

        let limits = ReadLimits {
            max_encoded_bytes: blte.len() - 1,
            ..ReadLimits::default()
        };
        let (r, reads) = stream_decode(&blte, 64, None, limits);
        assert!(matches!(r.unwrap_err(), CascError::LimitExceeded { .. }));
        assert_eq!(reads, 0);

        let limits = ReadLimits {
            max_chunk_count: 3,
            ..ReadLimits::default()
        };
        let (r, reads) = stream_decode(&blte, 64, None, limits);
        assert!(matches!(r.unwrap_err(), CascError::LimitExceeded { .. }));
        assert_eq!(reads, 0);

        let limits = ReadLimits {
            max_chunk_decoded_bytes: 999,
            ..ReadLimits::default()
        };
        let (r, reads) = stream_decode(&blte, 4096, None, limits);
        assert!(matches!(r.unwrap_err(), CascError::LimitExceeded { .. }));
        assert_eq!(reads, 0);
    }

    #[test]
    fn stream_agrees_with_decode_on_corrupted_inputs() {
        let blte = build_valid_blte(&[
            (true, b"alpha alpha alpha alpha".to_vec()),
            (false, b"beta".to_vec()),
        ]);
        for i in 0..blte.len() {
            for flip in [0x01u8, 0x80, 0xFF] {
                let mut bad = blte.clone();
                bad[i] ^= flip;
                let expected = decode(&bad);
                for prefix in [0, 8, 20, 40, bad.len()] {
                    let (got, _) = stream_decode(&bad, prefix, None, ReadLimits::default());
                    assert_eq!(got.is_ok(), expected.is_ok(), "byte {i} flip {flip:#x}");
                    if let (Ok(got), Ok(expected)) = (got, &expected) {
                        assert_eq!(&got, expected);
                    }
                }
            }
        }
        for len in 0..blte.len() {
            let (got, _) = stream_decode(&blte[..len], 16, None, ReadLimits::default());
            assert!(got.is_err(), "truncated to {len}");
        }
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
            let decoded_into =
                decode_into_vec(&blte, expected.len(), ReadLimits::default()).unwrap();
            prop_assert_eq!(&decoded, &expected);
            prop_assert_eq!(decoded_into, expected);
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
            let decoded_into = decode_into_vec(&blte, raw.len(), ReadLimits::default()).unwrap();
            prop_assert_eq!(&decoded, &raw);
            prop_assert_eq!(decoded_into, raw);
        }

        /// Neither decoder nor `BlteHeader::parse` should ever panic, no
        /// matter what bytes they're fed.
        #[test]
        fn prop_no_panic_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..2048),
            out_len in 0usize..4096,
        ) {
            let _ = decode(&data);
            let _ = decode_into_vec(&data, out_len, ReadLimits::default());
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
            let len = raws.iter().map(|(_, raw)| raw.len()).sum();
            let _ = decode(&blte);
            let _ = decode_into_vec(&blte, len, ReadLimits::default());
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
            let decoded_len = raws.iter().map(|(_, raw)| raw.len()).sum();
            let _ = decode(&blte[..len]);
            let _ = decode_into_vec(&blte[..len], decoded_len, ReadLimits::default());
        }
    }
}
