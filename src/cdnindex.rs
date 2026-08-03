//! CDN archive-index (`.index`) parser.
//!
//! Every CDN archive Blizzard serves is accompanied by a `.index` file that
//! maps the full 16-byte EKeys stored in that archive to their `(offset,
//! size)` within it. Locally, the same files live at `Data\indices\*.index`
//! (see `docs/casc-format.md` §8) — they aren't needed to read an existing
//! local install (that's what `.idx`, see [`crate::idx`], is for), but they
//! are what a CDN-backed reader needs to locate content in an archive.
//!
//! Layout of one `.index` file:
//!
//! ```text
//! entry pages   fixed-size (`page_size_kb` KiB) pages of packed 24-byte
//!               entries, sorted ascending by EKey across the whole file;
//!               a page's unused tail is zero-padded
//! TOC           last EKey of each page + per-page checksums -- skipped
//! footer        36 bytes, at the very end of the file (see below)
//! ```
//!
//! Entry layout (24 bytes):
//!
//! ```text
//! +0x00  16  EKey
//! +0x10  4   EncodedSize   u32 BE
//! +0x14  4   Offset        u32 BE
//! ```
//!
//! An entry whose EKey is all-zero marks the start of a page's padding; the
//! rest of that page carries no data and reading resumes at the next page
//! boundary.
//!
//! Footer layout (36 bytes, verified against a real install; fields are
//! single bytes unless noted):
//!
//! ```text
//! +0x00  16  TocHash          not verified by this reader
//! +0x10  1   Version          must be 1
//! +0x11  1   Reserved         (=0, not checked)
//! +0x12  1   Reserved         (=0, not checked)
//! +0x13  1   PageSizeKB       page size in KiB; must be nonzero
//! +0x14  1   OffsetBytes      must be 4
//! +0x15  1   SizeBytes        must be 4
//! +0x16  1   EKeyLength       must be 16
//! +0x17  1   FooterHashBytes  must be 8
//! +0x18  4   ElementCount     u32 LE -- note: little-endian, verified on
//!                             real data (docs for other products/versions
//!                             claim big-endian here)
//! +0x1C  8   FooterHash       not verified by this reader
//! ```
//!
//! `PageSizeKB`, `OffsetBytes`, `SizeBytes` and `EKeyLength` vary across
//! Blizzard products in general; SC:R's CDN indices always use 4/4/4/16, and
//! this reader only supports that combination (other widths are rejected as
//! [`CascError::Unsupported`] rather than misparsed).

use std::collections::HashMap;

use crate::error::{CascError, Result};
use crate::keys::EncodingKey;

/// What this reader calls the file kind in error messages.
const WHAT: &str = "CDN archive index";

const ENTRY_LEN: usize = 24;
const EKEY_LEN: usize = 16;
const FOOTER_LEN: usize = 36;

/// Location of one EKey's data within a single CDN archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveIndexEntry {
    /// The full 16-byte encoding key.
    pub ekey: EncodingKey,
    /// Byte offset of the entry's data within the archive.
    pub offset: u32,
    /// Size in bytes of the entry's data within the archive.
    pub encoded_size: u32,
}

/// One parsed `.index` file: all EKey entries for a single CDN archive,
/// sorted ascending by EKey.
#[derive(Debug, Clone, Default)]
pub struct ArchiveIndex {
    entries: Vec<ArchiveIndexEntry>,
}

impl ArchiveIndex {
    /// Parses one `.index` file's raw bytes.
    ///
    /// Reads the 36-byte footer first (see the module docs), validates it,
    /// then walks the entry pages from offset 0 collecting `ElementCount`
    /// real entries, skipping zero-EKey page padding by jumping to the next
    /// page boundary. Errors with [`CascError::Unsupported`] if the footer
    /// declares field widths other than the SC:R-verified 4/4/16/8, and with
    /// [`CascError::Malformed`] for anything else incoherent: a truncated
    /// file, an element count whose entries don't fit before the footer, or
    /// entries that aren't sorted ascending by EKey (lookups rely on that).
    pub fn parse(data: &[u8]) -> Result<ArchiveIndex> {
        if data.len() < FOOTER_LEN {
            return Err(CascError::malformed(
                WHAT,
                format!(
                    "file too short ({} bytes, need at least {FOOTER_LEN} for the footer)",
                    data.len()
                ),
            ));
        }

        let footer = &data[data.len() - FOOTER_LEN..];
        let version = footer[16];
        if version != 1 {
            return Err(CascError::Unsupported {
                what: WHAT,
                reason: format!("footer version {version} (only version 1 is supported)"),
            });
        }
        let page_size_kb = footer[19];
        let offset_bytes = footer[20];
        let size_bytes = footer[21];
        let ekey_length = footer[22];
        let footer_hash_bytes = footer[23];
        if (offset_bytes, size_bytes, ekey_length, footer_hash_bytes) != (4, 4, 16, 8) {
            return Err(CascError::Unsupported {
                what: WHAT,
                reason: format!(
                    "field widths offset={offset_bytes} size={size_bytes} \
                     ekey={ekey_length} footer_hash={footer_hash_bytes} \
                     (only 4/4/16/8 are supported)"
                ),
            });
        }
        if page_size_kb == 0 {
            return Err(CascError::malformed(WHAT, "page size is zero"));
        }
        let element_count = u32::from_le_bytes(footer[24..28].try_into().unwrap());

        let page_size = usize::from(page_size_kb) * 1024;
        // The footer is always present past this point, so entries may never
        // be read from here on.
        let limit = data.len() - FOOTER_LEN;

        let mut entries = Vec::with_capacity(element_count as usize);
        let mut cursor = 0usize;
        while entries.len() < element_count as usize {
            let record_end = cursor.checked_add(ENTRY_LEN).ok_or_else(|| {
                CascError::malformed(WHAT, "entry cursor overflowed while scanning pages")
            })?;
            if record_end > limit {
                return Err(CascError::malformed(
                    WHAT,
                    format!(
                        "element count {element_count} claims more entries than fit before \
                         the footer ({} collected)",
                        entries.len()
                    ),
                ));
            }
            let record = &data[cursor..record_end];

            let mut ekey_bytes = [0u8; EKEY_LEN];
            ekey_bytes.copy_from_slice(&record[0..EKEY_LEN]);

            if ekey_bytes == [0u8; EKEY_LEN] {
                // Page padding: skip straight to the next page boundary.
                let page_index = cursor / page_size;
                let next_page = page_index
                    .checked_add(1)
                    .and_then(|p| p.checked_mul(page_size))
                    .ok_or_else(|| {
                        CascError::malformed(WHAT, "page boundary computation overflowed")
                    })?;
                cursor = next_page;
                continue;
            }

            let encoded_size = u32::from_be_bytes(record[16..20].try_into().unwrap());
            let offset = u32::from_be_bytes(record[20..24].try_into().unwrap());
            entries.push(ArchiveIndexEntry {
                ekey: EncodingKey(ekey_bytes),
                offset,
                encoded_size,
            });
            cursor = record_end;
        }

        if !entries.is_sorted_by(|a, b| a.ekey < b.ekey) {
            return Err(CascError::malformed(
                WHAT,
                "entries are not sorted ascending by EKey",
            ));
        }

        Ok(ArchiveIndex { entries })
    }

    /// All entries, sorted ascending by EKey.
    pub fn entries(&self) -> &[ArchiveIndexEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this index has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Binary-searches for `ekey`.
    pub fn lookup(&self, ekey: &EncodingKey) -> Option<&ArchiveIndexEntry> {
        self.entries
            .binary_search_by(|entry| entry.ekey.cmp(ekey))
            .ok()
            .map(|i| &self.entries[i])
    }
}

/// Where one EKey's data lives among a CDN config's archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdnIndexEntry {
    /// Position of the archive in the CDN config's `archives` list. The
    /// caller maps this back to the archive's hash/URL.
    pub archive: u32,
    /// Byte offset of the entry's data within that archive.
    pub offset: u32,
    /// Size in bytes of the entry's data within that archive.
    pub encoded_size: u32,
}

/// Merged EKey lookup across all archives of a CDN config, built by calling
/// [`CdnIndex::add_archive`] once per parsed `.index` file.
///
/// If the same EKey is added under more than one archive (or more than once
/// under the same archive), the most recently added entry wins -- the same
/// "later wins" policy [`crate::idx::LocalIndex`] uses when merging local
/// index files.
#[derive(Debug, Clone, Default)]
pub struct CdnIndex {
    entries: HashMap<EncodingKey, CdnIndexEntry>,
}

impl CdnIndex {
    /// Creates an empty merged index.
    pub fn new() -> Self {
        CdnIndex::default()
    }

    /// Adds one parsed archive's entries under archive number `archive`.
    pub fn add_archive(&mut self, archive: u32, index: &ArchiveIndex) {
        for entry in index.entries() {
            self.entries.insert(
                entry.ekey,
                CdnIndexEntry {
                    archive,
                    offset: entry.offset,
                    encoded_size: entry.encoded_size,
                },
            );
        }
    }

    /// Looks up an EKey across all archives added so far.
    pub fn lookup(&self, ekey: &EncodingKey) -> Option<&CdnIndexEntry> {
        self.entries.get(ekey)
    }

    /// Number of distinct EKeys in the merged index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the merged index has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One test-builder entry tuple: `(ekey, encoded_size, offset)`.
    type RawEntry = ([u8; 16], u32, u32);

    /// Builds one page's worth of raw bytes (`page_size_kb` KiB) from entry
    /// tuples `(ekey, encoded_size, offset)`, zero-padding the remainder.
    /// Entries must fit within the page; this is a test-only builder
    /// invariant (real files never let an entry straddle a page boundary).
    fn build_page(page_size_kb: u8, entries: &[RawEntry]) -> Vec<u8> {
        let page_size = usize::from(page_size_kb) * 1024;
        let mut out = Vec::with_capacity(page_size);
        for (ekey, encoded_size, offset) in entries {
            out.extend_from_slice(ekey);
            out.extend_from_slice(&encoded_size.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
        }
        assert!(
            out.len() <= page_size,
            "test builder: page overflowed (entries don't fit in {page_size} bytes)"
        );
        out.resize(page_size, 0);
        out
    }

    /// Builds the 36-byte footer.
    #[allow(clippy::too_many_arguments)]
    fn build_footer(
        version: u8,
        page_size_kb: u8,
        offset_bytes: u8,
        size_bytes: u8,
        ekey_length: u8,
        footer_hash_bytes: u8,
        element_count: u32,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(FOOTER_LEN);
        out.extend_from_slice(&[0xCDu8; 16]); // TocHash, unverified
        out.push(version);
        out.push(0); // reserved
        out.push(0); // reserved
        out.push(page_size_kb);
        out.push(offset_bytes);
        out.push(size_bytes);
        out.push(ekey_length);
        out.push(footer_hash_bytes);
        out.extend_from_slice(&element_count.to_le_bytes());
        out.extend_from_slice(&[0xEFu8; 8]); // FooterHash, unverified
        assert_eq!(out.len(), FOOTER_LEN);
        out
    }

    /// Assembles a full `.index` file from pages of entries, an arbitrary
    /// TOC filler (the parser must never depend on its content or exact
    /// length -- only the footer's `ElementCount` and the page boundaries
    /// matter), and a valid footer whose `ElementCount` is the given value
    /// (defaults to the true number of real entries via [`valid_file`]).
    fn build_file(page_size_kb: u8, pages: &[Vec<RawEntry>], element_count: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for page in pages {
            out.extend(build_page(page_size_kb, page));
        }
        out.extend_from_slice(&[0xAAu8; 41]); // arbitrary TOC filler, skipped
        out.extend(build_footer(1, page_size_kb, 4, 4, 16, 8, element_count));
        out
    }

    fn valid_file(page_size_kb: u8, pages: &[Vec<RawEntry>]) -> Vec<u8> {
        let element_count = pages.iter().map(Vec::len).sum::<usize>() as u32;
        build_file(page_size_kb, pages, element_count)
    }

    fn ekey(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    /// Builds an ascending-by-EKey run of `n` distinct entries starting at
    /// `first`, each `[u8; 16]` filled with a single repeated byte.
    fn ascending_entries(first: u8, n: u8) -> Vec<RawEntry> {
        (0..n)
            .map(|i| (ekey(first + i), 100 + u32::from(i), 1000 + u32::from(i)))
            .collect()
    }

    #[test]
    fn parses_single_page_roundtrip() {
        let entries = ascending_entries(1, 3);
        let data = valid_file(4, std::slice::from_ref(&entries));

        let index = ArchiveIndex::parse(&data).unwrap();
        assert_eq!(index.len(), 3);
        assert_eq!(index.entries().len(), 3);
        for (ek, size, off) in &entries {
            let found = index.lookup(&EncodingKey(*ek)).unwrap();
            assert_eq!(found.encoded_size, *size);
            assert_eq!(found.offset, *off);
        }
    }

    #[test]
    fn parses_multi_page_with_padding_mid_file() {
        // First page: a handful of entries, well short of capacity so the
        // padding region is large. Second page: more entries.
        let page1 = ascending_entries(1, 5);
        let page2 = ascending_entries(10, 4);
        let data = valid_file(4, &[page1.clone(), page2.clone()]);

        let index = ArchiveIndex::parse(&data).unwrap();
        assert_eq!(index.len(), 9);
        for (ek, size, off) in page1.iter().chain(&page2) {
            let found = index.lookup(&EncodingKey(*ek)).unwrap();
            assert_eq!(found.encoded_size, *size);
            assert_eq!(found.offset, *off);
        }
    }

    #[test]
    fn lookup_miss_returns_none() {
        let data = valid_file(4, &[ascending_entries(1, 2)]);
        let index = ArchiveIndex::parse(&data).unwrap();
        assert!(index.lookup(&EncodingKey(ekey(200))).is_none());
    }

    #[test]
    fn zero_entry_file_is_valid_and_empty() {
        let data = valid_file(4, &[vec![]]);
        let index = ArchiveIndex::parse(&data).unwrap();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn zero_entry_file_with_no_pages_is_valid() {
        let data = build_file(4, &[], 0);
        let index = ArchiveIndex::parse(&data).unwrap();
        assert!(index.is_empty());
    }

    #[test]
    fn element_count_exceeding_available_entries_errors() {
        // Only one real entry exists but the footer claims two. Build
        // without the usual arbitrary TOC filler so there's provably no
        // room for a second entry before the footer -- with filler bytes
        // present the parser can't tell "real data ran out" from "more TOC
        // padding", so a mismatch is only guaranteed detectable when the
        // shortfall runs past the footer boundary itself.
        let mut data = build_page(4, &ascending_entries(1, 1));
        data.extend(build_footer(1, 4, 4, 4, 16, 8, 2));
        let err = ArchiveIndex::parse(&data).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn unsorted_entries_are_rejected() {
        let entries = vec![
            (ekey(5), 100, 1000),
            (ekey(1), 100, 1000), // out of order
        ];
        let data = valid_file(4, &[entries]);
        let err = ArchiveIndex::parse(&data).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn truncated_shorter_than_footer_is_rejected() {
        let data = valid_file(4, &[ascending_entries(1, 1)]);
        let err = ArchiveIndex::parse(&data[..FOOTER_LEN - 1]).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
        assert!(ArchiveIndex::parse(&[]).is_err());
    }

    #[test]
    fn wrong_version_is_unsupported() {
        let mut data = valid_file(4, &[ascending_entries(1, 1)]);
        let footer_start = data.len() - FOOTER_LEN;
        data[footer_start + 16] = 2; // Version
        let err = ArchiveIndex::parse(&data).unwrap_err();
        assert!(matches!(err, CascError::Unsupported { .. }));
    }

    #[test]
    fn wrong_widths_are_unsupported() {
        for offset_in_footer in [20usize, 21, 22, 23] {
            let mut data = valid_file(4, &[ascending_entries(1, 1)]);
            let footer_start = data.len() - FOOTER_LEN;
            data[footer_start + offset_in_footer] = 99;
            let err = ArchiveIndex::parse(&data).unwrap_err();
            assert!(
                matches!(err, CascError::Unsupported { .. }),
                "field at footer offset {offset_in_footer} should be rejected as unsupported"
            );
        }
    }

    #[test]
    fn zero_page_size_is_rejected() {
        let mut data = valid_file(4, &[ascending_entries(1, 1)]);
        let footer_start = data.len() - FOOTER_LEN;
        data[footer_start + 19] = 0; // PageSizeKB
        let err = ArchiveIndex::parse(&data).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn u32_max_offsets_and_sizes_round_trip() {
        let entries = vec![(ekey(1), u32::MAX, u32::MAX)];
        let data = valid_file(4, &[entries]);
        let index = ArchiveIndex::parse(&data).unwrap();
        let found = index.lookup(&EncodingKey(ekey(1))).unwrap();
        assert_eq!(found.encoded_size, u32::MAX);
        assert_eq!(found.offset, u32::MAX);
    }

    #[test]
    fn cdn_index_merges_single_archive() {
        let entries = ascending_entries(1, 3);
        let data = valid_file(4, std::slice::from_ref(&entries));
        let archive_index = ArchiveIndex::parse(&data).unwrap();

        let mut cdn_index = CdnIndex::new();
        assert!(cdn_index.is_empty());
        cdn_index.add_archive(7, &archive_index);
        assert_eq!(cdn_index.len(), 3);

        for (ek, size, off) in &entries {
            let found = cdn_index.lookup(&EncodingKey(*ek)).unwrap();
            assert_eq!(found.archive, 7);
            assert_eq!(found.encoded_size, *size);
            assert_eq!(found.offset, *off);
        }
    }

    #[test]
    fn cdn_index_merge_duplicate_ekey_last_add_wins() {
        // Documented policy: the most recently added archive wins on a
        // duplicate EKey, mirroring `LocalIndex`'s "later file wins".
        let key = ekey(0x42);
        let first_data = valid_file(4, &[vec![(key, 100, 1000)]]);
        let second_data = valid_file(4, &[vec![(key, 200, 2000)]]);
        let first = ArchiveIndex::parse(&first_data).unwrap();
        let second = ArchiveIndex::parse(&second_data).unwrap();

        let mut cdn_index = CdnIndex::new();
        cdn_index.add_archive(1, &first);
        cdn_index.add_archive(2, &second);
        assert_eq!(cdn_index.len(), 1);

        let found = cdn_index.lookup(&EncodingKey(key)).unwrap();
        assert_eq!(found.archive, 2);
        assert_eq!(found.encoded_size, 200);
        assert_eq!(found.offset, 2000);
    }

    /// Generates `(page_size_kb, pages)` where every page's entries are
    /// unique, page-fitting, and ascending both within and across pages
    /// (each page's keys start above the previous page's last key), so the
    /// whole file satisfies the global sort requirement.
    fn cdn_index_strategy() -> impl Strategy<Value = (u8, Vec<Vec<RawEntry>>)> {
        (1u8..=8u8).prop_flat_map(|page_size_kb| {
            let page_size = usize::from(page_size_kb) * 1024;
            let max_entries_per_page = (page_size / ENTRY_LEN).min(20);
            proptest::collection::vec(1..=max_entries_per_page, 1..5).prop_map(move |page_lens| {
                let mut next_key = 1u8;
                let pages = page_lens
                    .into_iter()
                    .map(|n| {
                        let entries = ascending_entries(next_key, n as u8);
                        next_key = next_key.saturating_add(n as u8).saturating_add(1);
                        entries
                    })
                    .collect();
                (page_size_kb, pages)
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Building a `.index` file from arbitrary valid pages and parsing
        /// it back must reproduce every entry exactly.
        #[test]
        fn prop_roundtrip((page_size_kb, pages) in cdn_index_strategy()) {
            let data = valid_file(page_size_kb, &pages);
            let index = ArchiveIndex::parse(&data).unwrap();
            let expected: Vec<_> = pages.into_iter().flatten().collect();
            prop_assert_eq!(index.len(), expected.len());
            for (ek, size, off) in expected {
                let found = index.lookup(&EncodingKey(ek)).unwrap();
                prop_assert_eq!(found.encoded_size, size);
                prop_assert_eq!(found.offset, off);
            }
        }

        /// `ArchiveIndex::parse` should never panic on arbitrary bytes.
        #[test]
        fn prop_no_panic_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            let _ = ArchiveIndex::parse(&data);
        }

        /// Flipping bytes in an otherwise-valid file should never panic.
        #[test]
        fn prop_no_panic_flipped_bytes(
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..6),
        ) {
            let mut data = valid_file(4, &[ascending_entries(1, 5), ascending_entries(20, 3)]);
            for (pos, xor) in &flips {
                if !data.is_empty() {
                    let idx = pos % data.len();
                    data[idx] ^= xor | 1;
                }
            }
            let _ = ArchiveIndex::parse(&data);
        }

        /// Truncating an otherwise-valid file to an arbitrary length should
        /// never panic.
        #[test]
        fn prop_no_panic_truncated(trunc_len in any::<usize>()) {
            let data = valid_file(4, &[ascending_entries(1, 5)]);
            let len = trunc_len % (data.len() + 1);
            let _ = ArchiveIndex::parse(&data[..len]);
        }
    }
}
