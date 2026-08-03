//! Local index (`.idx`) parser.
//!
//! Each CASC storage keeps 16 local index files (one per "bucket",
//! `00`..`0f`), each a fixed-size, mostly-zero-padded file mapping truncated
//! (9-byte) encoding keys to where their data lives in the `data.###`
//! archives. `LocalIndex` merges all 16 into a single lookup table, since a
//! handful of entries are stored under the "wrong" bucket (see the
//! placeholder-span note below) and the merged map is what real storages
//! guarantee has no key collisions.
//!
//! Layout (version 7; all header integers little-endian unless noted):
//!
//! ```text
//! 0x00  guarded-block header for the file header (8 bytes)
//!         +0x00  BlockSize   u32 LE   (must be 0x10)
//!         +0x04  BlockHash   u32 LE   (Jenkins `hashlittle` of the file header)
//! 0x08  file header (16 bytes)
//!         +0x00  Revision         u16 LE   (must be 7)
//!         +0x02  BucketIndex      u8       (unused here)
//!         +0x03  Flags            u8       (must be 0)
//!         +0x04  SpanSizeBytes    u8       (must be 4)
//!         +0x05  SpanOffsetBytes  u8       (must be 5)
//!         +0x06  KeyBytes         u8       (must be 9)
//!         +0x07  SegmentBits      u8       (16..=39; typically 30)
//!         +0x08  MaxFileOffset    u64 LE   (unused here)
//! 0x18  8 bytes of zero padding
//! 0x20  guarded-block header for the entry array (8 bytes, same shape as above)
//!         +0x00  BlockSize   u32 LE   (total bytes of the entry array)
//!         +0x04  BlockHash   u32 LE   (chained Jenkins `hashlittle2`)
//! 0x28  entry array: BlockSize / 18 entries of 18 bytes each
//! ```
//!
//! Entry layout (18 bytes):
//!
//! ```text
//! +0x00  9   EKey[9]          first 9 bytes of the 16-byte encoding key
//! +0x09  5   StorageOffset    u40 BE = (archive << SegmentBits) | offset
//! +0x0E  4   EncodedSize      u32 LE  (includes the 30-byte span header)
//! ```
//!
//! Entries with `EncodedSize <= 30` are synthetic placeholder/free-space
//! stubs written at the head of each `data.###` archive; they carry no real
//! span and are skipped rather than inserted. See `docs/casc-format.md` §2
//! and §3.3 for the full (empirically verified) spec this module follows,
//! including known discrepancies with published CascLib header comments.

use std::collections::HashMap;

use crate::error::{CascError, Result};
use crate::jenkins::{hashlittle, hashlittle2};
use crate::keys::{EncodingKey, TruncatedKey};

const GUARD_HEADER_LEN: usize = 8;
const FILE_HEADER_OFFSET: usize = 0x08;
const FILE_HEADER_LEN: usize = 16;
const ENTRIES_GUARD_OFFSET: usize = 0x20;
const ENTRIES_OFFSET: usize = 0x28;
const ENTRY_LEN: usize = 18;
const HEADER_BLOCK_SIZE: u32 = 0x10;
const SEGMENT_BITS_RANGE: std::ops::RangeInclusive<u8> = 16..=39;
/// SC:R has only tens of thousands of local entries. A much larger table is
/// not a supported storage and would otherwise amplify a bounded `.idx`
/// buffer into an unbounded hash-table allocation.
const MAX_INDEX_ENTRIES: usize = 1_000_000;

fn entry_block_hash(entries: &[u8]) -> u32 {
    let mut hi = 0;
    let mut lo = 0;
    for entry in entries.chunks_exact(ENTRY_LEN) {
        (hi, lo) = hashlittle2(entry, hi, lo);
    }
    hi
}

/// Where an encoded file span lives in the data archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdxEntry {
    /// `data.###` archive number.
    pub archive: u16,
    /// Byte offset of the 30-byte span header within that archive.
    pub offset: u64,
    /// Total span size including the 30-byte span header.
    pub encoded_size: u32,
}

/// Merged lookup table over all bucket `.idx` files.
///
/// Built from raw file contents via [`LocalIndex::from_files`]; use
/// [`LocalIndex::select_files`] first to decide which files to read off disk.
#[derive(Debug, Clone, Default)]
pub struct LocalIndex {
    entries: HashMap<TruncatedKey, IdxEntry>,
}

impl LocalIndex {
    /// Selects which `.idx` files to load from a directory listing.
    ///
    /// Groups names by bucket (the first 2 hex characters of the stem) and
    /// keeps only the highest version (the following 8 hex characters) per
    /// bucket, discarding the rest. Names that aren't a `.idx` file (case
    /// insensitive extension) or whose stem isn't exactly 10 hex characters
    /// with a bucket in `00`..=`0f` are ignored. Returns the winning file
    /// names in bucket order (`00`..`0f`); missing buckets are simply absent
    /// from the result.
    pub fn select_files(names: &[String]) -> Vec<String> {
        let mut best: [Option<(u32, &str)>; 16] = [None; 16];

        for name in names {
            let Some((stem, ext)) = name.rsplit_once('.') else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("idx") {
                continue;
            }
            if stem.len() != 10 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let Ok(bucket) = u8::from_str_radix(&stem[0..2], 16) else {
                continue;
            };
            if bucket > 0x0f {
                continue;
            }
            let Ok(version) = u32::from_str_radix(&stem[2..10], 16) else {
                continue;
            };

            let slot = &mut best[bucket as usize];
            let is_better = match slot {
                Some((current_version, _)) => version > *current_version,
                None => true,
            };
            if is_better {
                *slot = Some((version, name.as_str()));
            }
        }

        best.into_iter()
            .filter_map(|slot| slot.map(|(_, name)| name.to_string()))
            .collect()
    }

    /// Builds the merged index from the raw contents of one or more `.idx`
    /// files (as read from disk, e.g. via [`LocalIndex::select_files`]).
    ///
    /// If the same truncated key appears in more than one file, the entry
    /// from the later file wins. Real storages never have duplicate keys
    /// across buckets, so this only matters for malformed input.
    pub fn from_files<'a>(files: impl IntoIterator<Item = &'a [u8]>) -> Result<LocalIndex> {
        let mut entries = HashMap::new();
        for data in files {
            parse_file(data, &mut entries)?;
        }
        Ok(LocalIndex { entries })
    }

    /// Parses one additional selected bucket file. Storage bootstrap uses
    /// this to release each raw `.idx` buffer before reading the next one.
    pub(crate) fn add_file(&mut self, data: &[u8]) -> Result<()> {
        parse_file(data, &mut self.entries)
    }

    /// Looks up a full encoding key, truncating it to 9 bytes internally (as
    /// local indices only ever store the truncated form).
    pub fn lookup(&self, key: &EncodingKey) -> Option<&IdxEntry> {
        self.lookup_truncated(&key.truncated())
    }

    /// Looks up an already-truncated (9-byte) key.
    pub fn lookup_truncated(&self, key: &TruncatedKey) -> Option<&IdxEntry> {
        self.entries.get(key)
    }

    /// Number of entries in the merged index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the merged index has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates over all entries in the merged index, in arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = (&TruncatedKey, &IdxEntry)> {
        self.entries.iter()
    }
}

/// Parses one `.idx` file's entries into `out`, skipping placeholder spans
/// (`EncodedSize <= 30`). On a key collision within or across calls, the
/// later entry wins.
fn parse_file(data: &[u8], out: &mut HashMap<TruncatedKey, IdxEntry>) -> Result<()> {
    if data.len() < ENTRIES_OFFSET {
        return Err(CascError::malformed(
            "local index file",
            format!(
                "file too short ({} bytes, need at least {ENTRIES_OFFSET:#x})",
                data.len()
            ),
        ));
    }

    let header_block_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if header_block_size != HEADER_BLOCK_SIZE {
        return Err(CascError::malformed(
            "local index file",
            format!(
                "file header guarded-block size {header_block_size:#x} != {HEADER_BLOCK_SIZE:#x}"
            ),
        ));
    }

    let header = &data[FILE_HEADER_OFFSET..FILE_HEADER_OFFSET + FILE_HEADER_LEN];
    let expected_header_hash = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if hashlittle(header, 0) != expected_header_hash {
        return Err(CascError::ChecksumMismatch("local index file header"));
    }
    let revision = u16::from_le_bytes(header[0..2].try_into().unwrap());
    if revision != 7 {
        return Err(CascError::Unsupported {
            what: "local index file",
            reason: format!("revision {revision} (only revision 7 is supported)"),
        });
    }
    let flags = header[3];
    if flags != 0 {
        return Err(CascError::Unsupported {
            what: "local index file",
            reason: format!("flags {flags:#x} (only 0 is supported)"),
        });
    }
    let span_size_bytes = header[4];
    let span_offset_bytes = header[5];
    let key_bytes = header[6];
    if (span_size_bytes, span_offset_bytes, key_bytes) != (4, 5, 9) {
        return Err(CascError::Unsupported {
            what: "local index file",
            reason: format!(
                "field widths span_size={span_size_bytes} span_offset={span_offset_bytes} \
                 key={key_bytes} (only 4/5/9 are supported)"
            ),
        });
    }
    let segment_bits = header[7];
    if !SEGMENT_BITS_RANGE.contains(&segment_bits) {
        return Err(CascError::malformed(
            "local index file",
            format!(
                "segment_bits {segment_bits} outside supported range {}..={}",
                SEGMENT_BITS_RANGE.start(),
                SEGMENT_BITS_RANGE.end()
            ),
        ));
    }
    let segment_bits = u32::from(segment_bits);
    let offset_mask: u64 = (1u64 << segment_bits) - 1;

    let entry_block_size = u32::from_le_bytes(
        data[ENTRIES_GUARD_OFFSET..ENTRIES_GUARD_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    debug_assert_eq!(ENTRIES_GUARD_OFFSET + GUARD_HEADER_LEN, ENTRIES_OFFSET);

    if !entry_block_size.is_multiple_of(ENTRY_LEN) {
        return Err(CascError::malformed(
            "local index file",
            format!("entry block size {entry_block_size} is not a multiple of {ENTRY_LEN}"),
        ));
    }

    let entries_end = ENTRIES_OFFSET
        .checked_add(entry_block_size)
        .ok_or_else(|| {
            CascError::malformed("local index file", "entry block size overflows file offset")
        })?;
    if data.len() < entries_end {
        return Err(CascError::malformed(
            "local index file",
            format!(
                "entry block ({entry_block_size} bytes at {ENTRIES_OFFSET:#x}) overruns file \
                 (length {})",
                data.len()
            ),
        ));
    }

    let entry_bytes = &data[ENTRIES_OFFSET..entries_end];
    let expected_entry_hash = u32::from_le_bytes(
        data[ENTRIES_GUARD_OFFSET + 4..ENTRIES_GUARD_OFFSET + GUARD_HEADER_LEN]
            .try_into()
            .unwrap(),
    );
    if entry_block_hash(entry_bytes) != expected_entry_hash {
        return Err(CascError::ChecksumMismatch("local index entry array"));
    }

    let entry_count = entry_block_size / ENTRY_LEN;
    if out.len().saturating_add(entry_count) > MAX_INDEX_ENTRIES {
        return Err(CascError::LimitExceeded {
            what: "local index entries",
            limit: MAX_INDEX_ENTRIES,
        });
    }
    out.try_reserve(entry_count)
        .map_err(|_| CascError::LimitExceeded {
            what: "local index entries",
            limit: MAX_INDEX_ENTRIES,
        })?;

    for entry in entry_bytes.chunks_exact(ENTRY_LEN) {
        let mut key9 = [0u8; 9];
        key9.copy_from_slice(&entry[0..9]);

        let mut offset_bytes = [0u8; 8];
        offset_bytes[3..8].copy_from_slice(&entry[9..14]);
        let storage_offset = u64::from_be_bytes(offset_bytes);

        let encoded_size = u32::from_le_bytes(entry[14..18].try_into().unwrap());

        // Placeholder/free-space stub: no real span. Skip (§3.3).
        if encoded_size <= 30 {
            continue;
        }

        let archive_index = storage_offset >> segment_bits;
        let archive = u16::try_from(archive_index).map_err(|_| {
            CascError::malformed(
                "local index entry",
                format!("archive index {archive_index} does not fit in u16"),
            )
        })?;
        let offset = storage_offset & offset_mask;

        out.insert(
            TruncatedKey(key9),
            IdxEntry {
                archive,
                offset,
                encoded_size,
            },
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Builds a valid `.idx` (v7) file from raw entry tuples: `(key9,
    /// storage_offset as 5 raw big-endian bytes, encoded_size)`. Mirrors the
    /// on-disk layout exactly, including both guarded-block hashes.
    fn build_idx_file(segment_bits: u8, entries: &[([u8; 9], [u8; 5], u32)]) -> Vec<u8> {
        let entry_block_size = (entries.len() * ENTRY_LEN) as u32;

        let mut out = Vec::new();
        // File header guarded block.
        out.extend_from_slice(&HEADER_BLOCK_SIZE.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // BlockHash, filled below

        // File header (16 bytes).
        out.extend_from_slice(&7u16.to_le_bytes()); // Revision
        out.push(0); // BucketIndex (unused)
        out.push(0); // Flags
        out.push(4); // SpanSizeBytes
        out.push(5); // SpanOffsetBytes
        out.push(9); // KeyBytes
        out.push(segment_bits); // SegmentBits
        out.extend_from_slice(&0x0000_00FF_C000_0000u64.to_le_bytes()); // MaxFileOffset
        update_header_hash(&mut out);

        // 8 bytes zero padding.
        out.extend_from_slice(&[0u8; 8]);

        // Entries guarded block header.
        out.extend_from_slice(&entry_block_size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // BlockHash, filled below

        // Entries.
        for (key9, storage_offset, encoded_size) in entries {
            out.extend_from_slice(key9);
            out.extend_from_slice(storage_offset);
            out.extend_from_slice(&encoded_size.to_le_bytes());
        }
        let hash = entry_block_hash(&out[ENTRIES_OFFSET..]);
        out[ENTRIES_GUARD_OFFSET + 4..ENTRIES_OFFSET].copy_from_slice(&hash.to_le_bytes());

        out
    }

    fn update_header_hash(data: &mut [u8]) {
        let hash = hashlittle(
            &data[FILE_HEADER_OFFSET..FILE_HEADER_OFFSET + FILE_HEADER_LEN],
            0,
        );
        data[4..8].copy_from_slice(&hash.to_le_bytes());
    }

    /// Packs `(archive, offset)` into 5 raw big-endian bytes given
    /// `segment_bits`, the inverse of the unpacking this module implements.
    fn pack_storage_offset(archive: u16, offset: u64, segment_bits: u8) -> [u8; 5] {
        let v = (u64::from(archive) << segment_bits) | offset;
        let be = v.to_be_bytes();
        be[3..8].try_into().unwrap()
    }

    fn key9(byte: u8) -> [u8; 9] {
        [byte; 9]
    }

    #[test]
    fn documented_real_header_hash_matches() {
        // docs/casc-format.md §2.2, bytes +0x08..+0x17 from
        // 000000001b.idx. The guarded header stores 0x1bc0046b.
        let header = [
            0x07, 0x00, 0x00, 0x00, 0x04, 0x05, 0x09, 0x1e, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(hashlittle(&header, 0), 0x1bc0_046b);

        let mut file = Vec::new();
        file.extend_from_slice(&HEADER_BLOCK_SIZE.to_le_bytes());
        file.extend_from_slice(&0x1bc0_046bu32.to_le_bytes());
        file.extend_from_slice(&header);
        file.extend_from_slice(&[0; 8]);
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        assert!(
            LocalIndex::from_files([file.as_slice()])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn corrupt_header_payload_or_hash_is_rejected() {
        let original = build_idx_file(30, &[]);

        let mut bad_payload = original.clone();
        bad_payload[FILE_HEADER_OFFSET + 8] ^= 1;
        assert!(matches!(
            LocalIndex::from_files([bad_payload.as_slice()]),
            Err(CascError::ChecksumMismatch("local index file header"))
        ));

        let mut bad_hash = original;
        bad_hash[4] ^= 1;
        assert!(matches!(
            LocalIndex::from_files([bad_hash.as_slice()]),
            Err(CascError::ChecksumMismatch("local index file header"))
        ));
    }

    #[test]
    fn corrupt_entry_payload_or_hash_is_rejected() {
        let original = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 10, 30), 100)]);

        let mut bad_payload = original.clone();
        bad_payload[ENTRIES_OFFSET + 3] ^= 1;
        assert!(matches!(
            LocalIndex::from_files([bad_payload.as_slice()]),
            Err(CascError::ChecksumMismatch("local index entry array"))
        ));

        let mut bad_hash = original;
        bad_hash[ENTRIES_GUARD_OFFSET + 4] ^= 1;
        assert!(matches!(
            LocalIndex::from_files([bad_hash.as_slice()]),
            Err(CascError::ChecksumMismatch("local index entry array"))
        ));
    }

    #[test]
    fn parse_and_lookup_roundtrip_verified_example() {
        // From docs/casc-format.md §2.3: StorageOffset raw bytes
        // [0x01, 0x8B, 0xEA, 0x86, 0x7F] (ground truth, transcribed directly
        // from a hex dump of the real file) with segment_bits=30. The doc's
        // prose gives the derived offset as 0x0BE7A87F / "199 689 855", but
        // that's internally inconsistent (0x0BE7A87F is actually 199,731,327)
        // and doesn't match applying the documented archive/offset formula to
        // the verified raw bytes: 0x018BEA867F >> 30 = 6,
        // 0x018BEA867F & 0x3FFFFFFF = 0x0BEA867F (199,919,231) -- a
        // transcription slip in the worked example, not a spec error.
        // Confirmed independently in Python.
        let key = key9(0xAB);
        let data = build_idx_file(30, &[(key, [0x01, 0x8B, 0xEA, 0x86, 0x7F], 1234)]);

        let index = LocalIndex::from_files([data.as_slice()]).unwrap();
        assert_eq!(index.len(), 1);

        let entry = index.lookup_truncated(&TruncatedKey(key)).unwrap();
        assert_eq!(entry.archive, 6);
        assert_eq!(entry.offset, 0x0BEA_867F);
        assert_eq!(entry.encoded_size, 1234);
    }

    #[test]
    fn placeholder_entries_are_skipped() {
        let real_key = key9(0x01);
        let placeholder_key = key9(0x02);
        let data = build_idx_file(
            30,
            &[
                (placeholder_key, pack_storage_offset(0, 0, 30), 30),
                (real_key, pack_storage_offset(1, 100, 30), 200),
            ],
        );

        let index = LocalIndex::from_files([data.as_slice()]).unwrap();
        assert_eq!(index.len(), 1);
        assert!(
            index
                .lookup_truncated(&TruncatedKey(placeholder_key))
                .is_none()
        );
        assert!(index.lookup_truncated(&TruncatedKey(real_key)).is_some());
    }

    #[test]
    fn placeholder_boundary_is_inclusive() {
        // encoded_size == 30 exactly must also be skipped, not just < 30.
        let key = key9(0x03);
        let data = build_idx_file(30, &[(key, pack_storage_offset(0, 0, 30), 30)]);
        let index = LocalIndex::from_files([data.as_slice()]).unwrap();
        assert!(index.is_empty());
    }

    #[test]
    fn wrong_revision_is_rejected() {
        let mut data = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 0, 30), 100)]);
        data[FILE_HEADER_OFFSET..FILE_HEADER_OFFSET + 2].copy_from_slice(&6u16.to_le_bytes());
        update_header_hash(&mut data);
        let err = LocalIndex::from_files([data.as_slice()]).unwrap_err();
        assert!(matches!(err, CascError::Unsupported { .. }));
    }

    #[test]
    fn wrong_key_bytes_rejected_as_unsupported() {
        let mut data = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 0, 30), 100)]);
        data[FILE_HEADER_OFFSET + 6] = 16; // KeyBytes
        update_header_hash(&mut data);
        let err = LocalIndex::from_files([data.as_slice()]).unwrap_err();
        assert!(matches!(err, CascError::Unsupported { .. }));
    }

    #[test]
    fn nonzero_flags_rejected_as_unsupported() {
        let mut data = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 0, 30), 100)]);
        data[FILE_HEADER_OFFSET + 3] = 1; // Flags
        update_header_hash(&mut data);
        let err = LocalIndex::from_files([data.as_slice()]).unwrap_err();
        assert!(matches!(err, CascError::Unsupported { .. }));
    }

    #[test]
    fn truncated_file_is_rejected() {
        let data = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 0, 30), 100)]);
        // Cut off partway through the fixed header.
        assert!(LocalIndex::from_files([&data[..0x10]]).is_err());
        assert!(LocalIndex::from_files([&data[..0]]).is_err());
    }

    #[test]
    fn entry_block_size_not_multiple_of_18_is_rejected() {
        let mut data = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 0, 30), 100)]);
        data[ENTRIES_GUARD_OFFSET..ENTRIES_GUARD_OFFSET + 4].copy_from_slice(&19u32.to_le_bytes());
        let err = LocalIndex::from_files([data.as_slice()]).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn entry_block_overrunning_file_is_rejected() {
        let mut data = build_idx_file(30, &[(key9(1), pack_storage_offset(0, 0, 30), 100)]);
        // Claim two entries' worth of bytes when only one is actually present.
        data[ENTRIES_GUARD_OFFSET..ENTRIES_GUARD_OFFSET + 4]
            .copy_from_slice(&((ENTRY_LEN * 2) as u32).to_le_bytes());
        let err = LocalIndex::from_files([data.as_slice()]).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn select_files_picks_highest_version_and_ignores_junk() {
        let names: Vec<String> = [
            "000000001b.idx",
            "0000000005.idx", // older version of bucket 00, should lose
            "0f0000001e.idx",
            "070000001a.IDX", // uppercase extension, still valid
            "shmem",          // no extension match
            "data.000",       // wrong extension
            "1000000001.idx", // bucket 0x10 is out of range (only 00..0f exist)
            "0g0000001a.idx", // 'g' isn't hex
            "00000000.idx",   // stem too short
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let mut selected = LocalIndex::select_files(&names);
        selected.sort();
        let mut expected = vec![
            "000000001b.idx".to_string(),
            "070000001a.IDX".to_string(),
            "0f0000001e.idx".to_string(),
        ];
        expected.sort();
        assert_eq!(selected, expected);
    }

    #[test]
    fn select_files_handles_missing_buckets() {
        let names = vec!["050000000a.idx".to_string()];
        assert_eq!(LocalIndex::select_files(&names), vec!["050000000a.idx"]);
    }

    #[test]
    fn merge_across_files_duplicate_key_last_wins() {
        let key = key9(0x42);
        let first = build_idx_file(30, &[(key, pack_storage_offset(1, 10, 30), 100)]);
        let second = build_idx_file(30, &[(key, pack_storage_offset(2, 20, 30), 200)]);

        let index = LocalIndex::from_files([first.as_slice(), second.as_slice()]).unwrap();
        assert_eq!(index.len(), 1);
        let entry = index.lookup_truncated(&TruncatedKey(key)).unwrap();
        assert_eq!(entry.archive, 2);
        assert_eq!(entry.offset, 20);
        assert_eq!(entry.encoded_size, 200);
    }

    #[test]
    fn lookup_by_full_encoding_key_truncates() {
        let key9_bytes = key9(0x77);
        let data = build_idx_file(30, &[(key9_bytes, pack_storage_offset(3, 42, 30), 500)]);
        let index = LocalIndex::from_files([data.as_slice()]).unwrap();

        let mut full = [0x77u8; 16];
        full[9..].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6]); // arbitrary trailing bytes
        let ekey = EncodingKey(full);

        let entry = index.lookup(&ekey).unwrap();
        assert_eq!(entry.archive, 3);
        assert_eq!(entry.offset, 42);
    }

    #[test]
    fn non_default_segment_bits_honored() {
        let key = key9(0x11);
        let segment_bits = 20u8;
        let archive = 900u16; // needs > 10 bits to prove segment_bits is actually used
        let offset = 0x0007_FFFFu64; // just under 2^20
        let data = build_idx_file(
            segment_bits,
            &[(key, pack_storage_offset(archive, offset, segment_bits), 999)],
        );

        let index = LocalIndex::from_files([data.as_slice()]).unwrap();
        let entry = index.lookup_truncated(&TruncatedKey(key)).unwrap();
        assert_eq!(entry.archive, archive);
        assert_eq!(entry.offset, offset);
    }

    #[test]
    fn empty_index_is_empty() {
        let data = build_idx_file(30, &[]);
        let index = LocalIndex::from_files([data.as_slice()]).unwrap();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert_eq!(index.entries().count(), 0);
    }

    /// One generated round-trip entry: `(key9, archive, offset, encoded_size)`.
    type IdxRoundTripEntry = ([u8; 9], u16, u64, u32);

    /// Generates `(segment_bits, entries)` where each entry has a unique
    /// 9-byte key, an archive number that fits both in a `u16` and in
    /// whatever bits `segment_bits` leaves for it, an offset `< 2^segment_bits`,
    /// and a size `> 30` (so it's never treated as a placeholder span).
    fn idx_round_trip_strategy() -> impl Strategy<Value = (u8, Vec<IdxRoundTripEntry>)> {
        (16u8..=39u8).prop_flat_map(|segment_bits| {
            let avail_archive_bits = 40 - segment_bits as u32;
            let max_archive: u64 = if avail_archive_bits >= 16 {
                u16::MAX as u64
            } else {
                (1u64 << avail_archive_bits) - 1
            };
            let max_offset: u64 = (1u64 << segment_bits) - 1;

            proptest::collection::hash_set(any::<[u8; 9]>(), 1..12).prop_flat_map(move |keys| {
                let keys: Vec<[u8; 9]> = keys.into_iter().collect();
                let n = keys.len();
                (
                    Just(keys),
                    proptest::collection::vec(0..=max_archive, n),
                    proptest::collection::vec(0..=max_offset, n),
                    proptest::collection::vec(31u32..1_000_000u32, n),
                )
                    .prop_map(move |(keys, archives, offsets, sizes)| {
                        let entries = keys
                            .into_iter()
                            .zip(archives)
                            .zip(offsets)
                            .zip(sizes)
                            .map(|(((k, a), o), s)| (k, a as u16, o, s))
                            .collect();
                        (segment_bits, entries)
                    })
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Building an `.idx` file from arbitrary valid entries and parsing
        /// it back must reproduce the exact (archive, offset, size) for
        /// every key.
        #[test]
        fn prop_roundtrip_idx((segment_bits, entries) in idx_round_trip_strategy()) {
            let raw_entries: Vec<([u8; 9], [u8; 5], u32)> = entries
                .iter()
                .map(|&(key, archive, offset, size)| {
                    (key, pack_storage_offset(archive, offset, segment_bits), size)
                })
                .collect();
            let data = build_idx_file(segment_bits, &raw_entries);
            let index = LocalIndex::from_files([data.as_slice()]).unwrap();
            prop_assert_eq!(index.len(), entries.len());
            for &(key, archive, offset, size) in &entries {
                let found = index.lookup_truncated(&TruncatedKey(key)).unwrap();
                prop_assert_eq!(found.archive, archive);
                prop_assert_eq!(found.offset, offset);
                prop_assert_eq!(found.encoded_size, size);
            }
        }

        /// `LocalIndex::from_files` with a single file should never panic,
        /// no matter what bytes it's fed.
        #[test]
        fn prop_no_panic_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = LocalIndex::from_files([data.as_slice()]);
        }

        /// Flipping a handful of bytes in an otherwise-valid `.idx` file
        /// should never panic.
        #[test]
        fn prop_no_panic_flipped_bytes(
            segment_bits in 16u8..=39u8,
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..4),
        ) {
            let entries = vec![
                (key9(1), pack_storage_offset(0, 0, segment_bits), 100u32),
                (key9(2), pack_storage_offset(0, 1, segment_bits), 200u32),
            ];
            let mut data = build_idx_file(segment_bits, &entries);
            for (pos, xor) in &flips {
                if !data.is_empty() {
                    let idx = pos % data.len();
                    data[idx] ^= xor | 1;
                }
            }
            let _ = LocalIndex::from_files([data.as_slice()]);
        }

        /// Truncating an otherwise-valid `.idx` file to an arbitrary length
        /// should never panic.
        #[test]
        fn prop_no_panic_truncated(
            segment_bits in 16u8..=39u8,
            trunc_len in any::<usize>(),
        ) {
            let entries = vec![(key9(1), pack_storage_offset(0, 0, segment_bits), 100u32)];
            let data = build_idx_file(segment_bits, &entries);
            let len = trunc_len % (data.len() + 1);
            let _ = LocalIndex::from_files([&data[..len]]);
        }
    }
}
