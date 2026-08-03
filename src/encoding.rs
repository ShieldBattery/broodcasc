//! Encoding-table parser.
//!
//! The "encoding" file maps content keys (CKey, MD5 of a file's decoded
//! contents) to encoding keys (EKey, MD5 of the file's BLTE-encoded
//! representation) plus the decoded file size. It is itself delivered as a
//! BLTE-encoded file; this module parses the already-decoded bytes.
//!
//! Layout (all multi-byte integers are big-endian):
//!
//! ```text
//! 0x00  magic            b"EN"
//! 0x02  version          u8   (expect 1)
//! 0x03  ckey_length      u8   (expect 16)
//! 0x04  ekey_length      u8   (expect 16)
//! 0x05  ckey_page_size   u16  (in KB, e.g. 4 => 4096-byte pages)
//! 0x07  ekey_page_size   u16  (in KB)
//! 0x09  ckey_page_count  u32
//! 0x0d  ekey_page_count  u32
//! 0x11  flags            u8   (expect 0)
//! 0x12  espec_block_size u32
//! 0x16
//! ```
//!
//! Followed by, in order:
//!
//! 1. An ESpec string block of `espec_block_size` bytes (null-terminated
//!    encoding-spec strings); this is skipped over, not parsed.
//! 2. A CKey page index: `ckey_page_count` entries of
//!    `{ first_ckey: [u8; 16], page_md5: [u8; 16] }`, where `first_ckey` is
//!    the first CKey in the corresponding page and `page_md5` is the MD5 of
//!    that page's full (padded) bytes.
//! 3. `ckey_page_count` CKey pages, each exactly `ckey_page_size` KB. Each
//!    page holds a sequence of entries:
//!
//!    ```text
//!    ekey_count  u8
//!    file_size   u40  (5 bytes, decoded size)
//!    ckey        [u8; 16]
//!    ekeys       ekey_count * [u8; 16]
//!    ```
//!
//!    The entry list ends when the next byte would be `ekey_count == 0`
//!    (the page's remainder is zero-padded). Entries within a page are
//!    sorted by CKey, and pages are sorted by their first CKey, so the whole
//!    table is CKey-sorted.
//! 4. An EKey→ESpec page index and pages, mapping EKey to encoding-spec
//!    index. This implementation has no need to read EKeys back to specs,
//!    so it is skipped entirely; trailing data after the CKey pages is
//!    ignored.

use md5::{Digest, Md5};

use crate::error::{CascError, Result};
use crate::keys::{ContentKey, EncodingKey};

const MAGIC: &[u8; 2] = b"EN";
const HEADER_SIZE: usize = 0x16;
/// The only key length this implementation understands; CascLib likewise
/// hard-codes 16 (`MD5_HASH_SIZE`) for the encoding file.
const KEY_SIZE: usize = 16;
/// Size of one CKey page-index entry: first_ckey(16) + page_md5(16).
const PAGE_INDEX_ENTRY_SIZE: usize = KEY_SIZE * 2;
/// Size of the fixed part of a CKey page entry: ekey_count(1) + file_size(5) + ckey(16).
const ENTRY_FIXED_SIZE: usize = 1 + 5 + KEY_SIZE;

/// One CKey's entry in the encoding table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingEntry {
    pub ckey: ContentKey,
    /// EKey of the (first/primary) encoded representation — the one local
    /// storage indexes. A CKey can map to multiple EKeys (alternate
    /// encodings of the same content, e.g. encrypted vs. unencrypted); only
    /// the first is kept, since any of them decode to the same content.
    pub ekey: EncodingKey,
    /// Decoded file size in bytes.
    pub size: u64,
}

/// A parsed encoding table: CKey → (EKey, decoded size), sorted by CKey for
/// binary-search lookup.
#[derive(Debug, Clone, Default)]
pub struct EncodingTable {
    entries: Vec<EncodingEntry>,
}

impl EncodingTable {
    /// Parses a decoded (post-BLTE) encoding file.
    pub fn parse(data: &[u8]) -> Result<EncodingTable> {
        let header = Header::parse(data)?;

        let espec_end = HEADER_SIZE
            .checked_add(header.espec_block_size)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| {
                CascError::malformed("encoding table", "ESpec block extends past end of input")
            })?;

        let page_index_size = header
            .ckey_page_count
            .checked_mul(PAGE_INDEX_ENTRY_SIZE)
            .ok_or_else(|| CascError::malformed("encoding table", "CKey page count overflow"))?;
        let page_index_end = espec_end
            .checked_add(page_index_size)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| {
                CascError::malformed(
                    "encoding table",
                    "CKey page index extends past end of input",
                )
            })?;
        let page_index = &data[espec_end..page_index_end];

        let mut entries = Vec::new();
        let mut page_start = page_index_end;
        for page_num in 0..header.ckey_page_count {
            let index_entry =
                &page_index[page_num * PAGE_INDEX_ENTRY_SIZE..][..PAGE_INDEX_ENTRY_SIZE];
            let expected_first_ckey = &index_entry[..KEY_SIZE];
            let expected_md5 = &index_entry[KEY_SIZE..];

            let page_end = page_start
                .checked_add(header.ckey_page_size)
                .ok_or_else(|| {
                    CascError::malformed("encoding table", "CKey page extends past end of input")
                })?;
            let page = data.get(page_start..page_end).ok_or_else(|| {
                CascError::malformed("encoding table", "CKey page extends past end of input")
            })?;

            let actual_md5: [u8; 16] = Md5::digest(page).into();
            if actual_md5 != expected_md5 {
                return Err(CascError::ChecksumMismatch("encoding page"));
            }

            parse_page(page, expected_first_ckey, &mut entries)?;

            page_start = page_end;
        }

        Ok(EncodingTable { entries })
    }

    /// Looks up an entry by CKey via binary search.
    pub fn lookup(&self, ckey: &ContentKey) -> Option<&EncodingEntry> {
        self.entries
            .binary_search_by(|entry| entry.ckey.cmp(ckey))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// All entries, sorted by CKey.
    pub fn entries(&self) -> &[EncodingEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parses one CKey page's entries, appending them to `entries` and
/// validating that CKeys keep increasing (both within the page and relative
/// to whatever was already pushed from earlier pages).
fn parse_page(
    page: &[u8],
    expected_first_ckey: &[u8],
    entries: &mut Vec<EncodingEntry>,
) -> Result<()> {
    let mut cursor = 0usize;
    let mut first = true;

    while cursor < page.len() {
        let ekey_count = page[cursor];
        if ekey_count == 0 {
            // Zero padding: rest of the page is filler.
            break;
        }

        let ekeys_size = ekey_count as usize * KEY_SIZE;
        let entry_len = ENTRY_FIXED_SIZE + ekeys_size;
        let entry = page.get(cursor..cursor + entry_len).ok_or_else(|| {
            CascError::malformed("encoding page entry", "entry extends past end of page")
        })?;

        let mut size_bytes = [0u8; 8];
        size_bytes[3..8].copy_from_slice(&entry[1..6]);
        let size = u64::from_be_bytes(size_bytes);

        let ckey = ContentKey::from_slice(&entry[6..22])?;

        if first {
            if &entry[6..22] != expected_first_ckey {
                return Err(CascError::malformed(
                    "encoding page",
                    "first entry's CKey does not match page index",
                ));
            }
            first = false;
        }

        if let Some(last) = entries.last()
            && last.ckey >= ckey
        {
            return Err(CascError::malformed(
                "encoding table",
                "CKeys are not strictly increasing",
            ));
        }

        // Only the first EKey is kept; the rest (alternate encodings of the
        // same content) are skipped over.
        let ekey = EncodingKey::from_slice(&entry[22..22 + KEY_SIZE])?;

        entries.push(EncodingEntry { ckey, ekey, size });

        cursor += entry_len;
    }

    Ok(())
}

/// Parsed and validated encoding-file header.
struct Header {
    ckey_page_size: usize,
    ckey_page_count: usize,
    espec_block_size: usize,
}

impl Header {
    fn parse(data: &[u8]) -> Result<Header> {
        if data.len() < HEADER_SIZE {
            return Err(CascError::malformed(
                "encoding header",
                "input shorter than 22 bytes",
            ));
        }
        if &data[0..2] != MAGIC {
            return Err(CascError::malformed("encoding header", "bad magic"));
        }

        let version = data[2];
        if version != 1 {
            return Err(CascError::malformed(
                "encoding header",
                format!("unsupported version {version}"),
            ));
        }

        let ckey_length = data[3];
        if ckey_length as usize != KEY_SIZE {
            return Err(CascError::malformed(
                "encoding header",
                format!("unexpected ckey_length {ckey_length}"),
            ));
        }
        let ekey_length = data[4];
        if ekey_length as usize != KEY_SIZE {
            return Err(CascError::malformed(
                "encoding header",
                format!("unexpected ekey_length {ekey_length}"),
            ));
        }

        let ckey_page_size_kb = u16::from_be_bytes([data[5], data[6]]);
        if ckey_page_size_kb == 0 {
            return Err(CascError::malformed(
                "encoding header",
                "ckey_page_size is zero",
            ));
        }
        // ekey_page_size (data[7..9]) is only relevant to the EKey→ESpec
        // table, which this implementation skips entirely.

        let ckey_page_count = u32::from_be_bytes(data[9..13].try_into().unwrap());
        // ekey_page_count (data[13..17]) is likewise only relevant to the
        // skipped EKey→ESpec table.

        let flags = data[17];
        if flags != 0 {
            return Err(CascError::malformed(
                "encoding header",
                format!("unexpected flags 0x{flags:02x}"),
            ));
        }

        let espec_block_size = u32::from_be_bytes(data[18..22].try_into().unwrap());

        Ok(Header {
            ckey_page_size: ckey_page_size_kb as usize * 1024,
            ckey_page_count: ckey_page_count as usize,
            espec_block_size: espec_block_size as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One entry to feed into [`build_encoding`]: a CKey, its (possibly
    /// multiple) EKeys, and the decoded size.
    #[derive(Debug)]
    struct RawEntry {
        ckey: ContentKey,
        ekeys: Vec<EncodingKey>,
        size: u64,
    }

    fn entry(seed: u8, size: u64) -> RawEntry {
        RawEntry {
            ckey: ContentKey([seed; 16]),
            ekeys: vec![EncodingKey([seed.wrapping_add(0x40); 16])],
            size,
        }
    }

    fn entry_multi_ekey(seed: u8, size: u64, ekey_seeds: &[u8]) -> RawEntry {
        RawEntry {
            ckey: ContentKey([seed; 16]),
            ekeys: ekey_seeds.iter().map(|&s| EncodingKey([s; 16])).collect(),
            size,
        }
    }

    fn serialize_entry(e: &RawEntry) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(e.ekeys.len() as u8);
        let size_bytes = e.size.to_be_bytes();
        out.extend_from_slice(&size_bytes[3..8]);
        out.extend_from_slice(e.ckey.as_bytes());
        for ekey in &e.ekeys {
            out.extend_from_slice(ekey.as_bytes());
        }
        out
    }

    /// Builds a full encoding-file buffer from a list of entries (assumed
    /// already CKey-sorted), greedily packing them into pages of
    /// `page_size_kb` KB, with a real page index (first CKey + MD5) and a
    /// standard header. No EKey→ESpec table is appended (trailing data is
    /// optional per the format).
    fn build_encoding(entries: &[RawEntry], page_size_kb: u16) -> Vec<u8> {
        let page_bytes = page_size_kb as usize * 1024;

        // Pack entries into pages.
        let mut pages: Vec<Vec<u8>> = Vec::new();
        let mut current = Vec::new();
        for e in entries {
            let serialized = serialize_entry(e);
            assert!(
                serialized.len() <= page_bytes,
                "entry too large for page size in test"
            );
            if current.len() + serialized.len() > page_bytes {
                current.resize(page_bytes, 0);
                pages.push(std::mem::take(&mut current));
            }
            current.extend_from_slice(&serialized);
        }
        if !current.is_empty() {
            current.resize(page_bytes, 0);
            pages.push(current);
        }

        // Page index: first CKey of each page + page MD5.
        let mut page_index = Vec::new();
        for page in &pages {
            let first_ckey = &page[6..22]; // skip ekey_count(1) + file_size(5)
            page_index.extend_from_slice(first_ckey);
            let md5: [u8; 16] = Md5::digest(page).into();
            page_index.extend_from_slice(&md5);
        }

        let espec_block: Vec<u8> = Vec::new();

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1); // version
        out.push(KEY_SIZE as u8); // ckey_length
        out.push(KEY_SIZE as u8); // ekey_length
        out.extend_from_slice(&page_size_kb.to_be_bytes()); // ckey_page_size
        out.extend_from_slice(&page_size_kb.to_be_bytes()); // ekey_page_size (unused)
        out.extend_from_slice(&(pages.len() as u32).to_be_bytes()); // ckey_page_count
        out.extend_from_slice(&0u32.to_be_bytes()); // ekey_page_count (unused)
        out.push(0); // flags
        out.extend_from_slice(&(espec_block.len() as u32).to_be_bytes());
        out.extend_from_slice(&espec_block);
        out.extend_from_slice(&page_index);
        for page in &pages {
            out.extend_from_slice(page);
        }
        out
    }

    #[test]
    fn empty_table_parses() {
        let data = build_encoding(&[], 1);
        let table = EncodingTable::parse(&data).unwrap();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert!(table.lookup(&ContentKey([0; 16])).is_none());
    }

    #[test]
    fn single_page_lookup() {
        let entries = vec![entry(0x01, 100), entry(0x02, 200), entry(0x03, 300)];
        let data = build_encoding(&entries, 1);
        let table = EncodingTable::parse(&data).unwrap();
        assert_eq!(table.len(), 3);

        let found = table.lookup(&ContentKey([0x02; 16])).unwrap();
        assert_eq!(found.size, 200);
        assert_eq!(found.ekey, EncodingKey([0x42; 16]));

        assert!(table.lookup(&ContentKey([0x02; 16])).is_some());
        // A key that would sort between existing entries but isn't present.
        let mut between = [0x02u8; 16];
        between[15] = 0x80;
        assert!(table.lookup(&ContentKey(between)).is_none());
    }

    #[test]
    fn multi_page_lookup_first_and_last() {
        // Small page size forces multiple pages.
        let entries: Vec<RawEntry> = (1..=40u8).map(|i| entry(i, i as u64 * 10)).collect();
        let data = build_encoding(&entries, 1);
        let table = EncodingTable::parse(&data).unwrap();
        assert!(table.entries().len() == 40);

        let first = table.lookup(&ContentKey([1; 16])).unwrap();
        assert_eq!(first.size, 10);
        let last = table.lookup(&ContentKey([40; 16])).unwrap();
        assert_eq!(last.size, 400);

        assert!(table.lookup(&ContentKey([0; 16])).is_none());
        assert!(table.lookup(&ContentKey([41; 16])).is_none());
    }

    #[test]
    fn page_md5_mismatch_is_detected() {
        let entries = vec![entry(0x01, 100), entry(0x02, 200)];
        let mut data = build_encoding(&entries, 1);
        // Corrupt a byte inside the (single) page, after the header + espec
        // block + page index.
        let page_data_start = HEADER_SIZE + PAGE_INDEX_ENTRY_SIZE;
        data[page_data_start] ^= 0xFF;
        let err = EncodingTable::parse(&data).unwrap_err();
        assert!(matches!(err, CascError::ChecksumMismatch("encoding page")));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut data = build_encoding(&[entry(1, 1)], 1);
        data[0] = b'X';
        assert!(EncodingTable::parse(&data).is_err());
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut data = build_encoding(&[entry(1, 1)], 1);
        data[2] = 2;
        assert!(EncodingTable::parse(&data).is_err());
    }

    #[test]
    fn bad_key_length_is_rejected() {
        let mut ckey_len_bad = build_encoding(&[entry(1, 1)], 1);
        ckey_len_bad[3] = 20;
        assert!(EncodingTable::parse(&ckey_len_bad).is_err());

        let mut ekey_len_bad = build_encoding(&[entry(1, 1)], 1);
        ekey_len_bad[4] = 9;
        assert!(EncodingTable::parse(&ekey_len_bad).is_err());
    }

    #[test]
    fn zero_page_size_is_rejected() {
        let mut data = build_encoding(&[], 1);
        data[5] = 0;
        data[6] = 0;
        assert!(EncodingTable::parse(&data).is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(EncodingTable::parse(b"EN").is_err());
        assert!(EncodingTable::parse(b"").is_err());

        let entries = vec![entry(1, 1), entry(2, 2)];
        let data = build_encoding(&entries, 1);

        // Truncate mid-header.
        assert!(EncodingTable::parse(&data[..10]).is_err());
        // Truncate mid-page-index.
        assert!(EncodingTable::parse(&data[..HEADER_SIZE + 5]).is_err());
        // Truncate mid-page.
        let page_data_start = HEADER_SIZE + PAGE_INDEX_ENTRY_SIZE;
        assert!(EncodingTable::parse(&data[..page_data_start + 10]).is_err());
    }

    #[test]
    fn multiple_ekeys_only_first_is_stored() {
        let entries = vec![
            entry(0x01, 10),
            entry_multi_ekey(0x02, 20, &[0xAA, 0xBB, 0xCC]),
            entry(0x03, 30),
        ];
        let data = build_encoding(&entries, 1);
        let table = EncodingTable::parse(&data).unwrap();
        assert_eq!(table.len(), 3);

        let multi = table.lookup(&ContentKey([0x02; 16])).unwrap();
        assert_eq!(multi.ekey, EncodingKey([0xAA; 16]));
        assert_eq!(multi.size, 20);

        // The entry after the multi-EKey one must still parse correctly,
        // proving the extra EKeys were skipped over rather than misread.
        let after = table.lookup(&ContentKey([0x03; 16])).unwrap();
        assert_eq!(after.size, 30);
    }

    #[test]
    fn out_of_order_entries_are_rejected() {
        // Manually build a single page with descending CKeys, bypassing the
        // builder's implicit sortedness.
        let e1 = entry(0x05, 1);
        let e2 = entry(0x01, 2);
        let mut page = Vec::new();
        page.extend_from_slice(&serialize_entry(&e1));
        page.extend_from_slice(&serialize_entry(&e2));
        page.resize(1024, 0);

        let mut page_index = Vec::new();
        page_index.extend_from_slice(&page[6..22]); // first_ckey = e1's ckey
        let md5: [u8; 16] = Md5::digest(&page).into();
        page_index.extend_from_slice(&md5);

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(KEY_SIZE as u8);
        out.push(KEY_SIZE as u8);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.push(0);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&page_index);
        out.extend_from_slice(&page);

        let err = EncodingTable::parse(&out).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn zero_padding_tail_of_page_is_handled() {
        // A page much larger than its entries, so most of it is zero padding.
        let entries = vec![entry(1, 1), entry(2, 2)];
        let data = build_encoding(&entries, 4); // 4KB page, entries total ~76 bytes
        let table = EncodingTable::parse(&data).unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn u40_size_above_u32_max_round_trips() {
        let big_size = (u32::MAX as u64) + 12345;
        let entries = vec![entry(1, big_size)];
        let data = build_encoding(&entries, 1);
        let table = EncodingTable::parse(&data).unwrap();
        let found = table.lookup(&ContentKey([1; 16])).unwrap();
        assert_eq!(found.size, big_size);
    }

    /// Generates a strictly-increasing, unique-CKey list of [`RawEntry`]s:
    /// sizes span the full u40 range, and each entry has 1-3 EKeys.
    fn raw_entries_strategy() -> impl Strategy<Value = Vec<RawEntry>> {
        proptest::collection::hash_set(any::<[u8; 16]>(), 1..20).prop_flat_map(|ckey_set| {
            let mut ckeys: Vec<[u8; 16]> = ckey_set.into_iter().collect();
            ckeys.sort();
            let n = ckeys.len();
            (
                Just(ckeys),
                proptest::collection::vec(0u64..(1u64 << 40), n),
                proptest::collection::vec(proptest::collection::vec(any::<[u8; 16]>(), 1..=3), n),
            )
                .prop_map(|(ckeys, sizes, ekey_lists)| {
                    ckeys
                        .into_iter()
                        .zip(sizes)
                        .zip(ekey_lists)
                        .map(|((ckey, size), ekeys)| RawEntry {
                            ckey: ContentKey(ckey),
                            ekeys: ekeys.into_iter().map(EncodingKey).collect(),
                            size,
                        })
                        .collect()
                })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Building an encoding table from arbitrary strictly-increasing
        /// unique-CKey entries and parsing it back must reproduce every
        /// entry's (first EKey, size), and the total entry count.
        #[test]
        fn prop_roundtrip_encoding(entries in raw_entries_strategy()) {
            let data = build_encoding(&entries, 1);
            let table = EncodingTable::parse(&data).unwrap();
            prop_assert_eq!(table.len(), entries.len());
            for e in &entries {
                let found = table.lookup(&e.ckey).unwrap();
                prop_assert_eq!(found.ekey, e.ekeys[0]);
                prop_assert_eq!(found.size, e.size);
            }
        }

        /// `EncodingTable::parse` should never panic, no matter what bytes
        /// it's fed.
        #[test]
        fn prop_no_panic_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = EncodingTable::parse(&data);
        }

        /// Flipping a handful of bytes in an otherwise-valid encoding table
        /// should never panic.
        #[test]
        fn prop_no_panic_flipped_bytes(
            n in 1u8..10u8,
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..4),
        ) {
            let entries: Vec<RawEntry> = (1..=n).map(|i| entry(i, i as u64 * 7)).collect();
            let mut data = build_encoding(&entries, 1);
            for (pos, xor) in &flips {
                if !data.is_empty() {
                    let idx = pos % data.len();
                    data[idx] ^= xor | 1;
                }
            }
            let _ = EncodingTable::parse(&data);
        }

        /// Truncating an otherwise-valid encoding table to an arbitrary
        /// length should never panic.
        #[test]
        fn prop_no_panic_truncated(
            n in 1u8..10u8,
            trunc_len in any::<usize>(),
        ) {
            let entries: Vec<RawEntry> = (1..=n).map(|i| entry(i, i as u64 * 7)).collect();
            let data = build_encoding(&entries, 1);
            let len = trunc_len % (data.len() + 1);
            let _ = EncodingTable::parse(&data[..len]);
        }
    }
}
