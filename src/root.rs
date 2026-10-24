//! The StarCraft: Remastered root file: the name → [`ContentKey`] catalog.
//!
//! SC:R uses the plain-text root format (CascLib's `TRootHandler_SC1`), not
//! any of the binary root formats used by other Blizzard products. After
//! BLTE-decoding, the root is ASCII text with one record per CRLF-terminated
//! line:
//!
//! ```text
//! locales/enUS/Assets/sound/misc/button.wav|316b0274bf2dabaa8db60c3ff1270c85
//! ```
//!
//! Paths use `/` separators and mixed case; records are unsorted and unique.
//! The hash is a CKey (MD5 of the decoded contents) that must be resolved
//! through the encoding table to actually read the file. See
//! `docs/casc-format.md` §6.

use crate::error::{CascError, Result};
use crate::keys::ContentKey;

/// One record from the root file, borrowing its path from the [`RootFile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootEntry<'a> {
    /// The file's path as stored: `/`-separated, original casing.
    pub path: &'a str,
    /// MD5 of the file's decoded contents.
    pub ckey: ContentKey,
}

/// A parsed SC:R root file: the path → CKey mapping for every game asset.
///
/// Lookups are case-insensitive and accept either `/` or `\` separators,
/// since SC:R paths are mixed-case with no case-insensitive collisions and
/// callers frequently hold Windows-style paths.
#[derive(Debug, Clone)]
pub struct RootFile {
    /// All paths, concatenated in file order.
    arena: String,
    /// `offsets[i]..offsets[i + 1]` is entry `i`'s span in `arena`.
    offsets: Vec<u32>,
    ckeys: Vec<ContentKey>,
    /// Open-addressing hash table over normalized paths; see [`Slots`].
    slots: Slots,
}

/// Open-addressing (linear probing) table mapping a normalized-path hash to
/// an entry id. The normalized path itself is never stored: candidates are
/// confirmed by comparing against the entry's original path with
/// case/separator folding on the fly, so hash collisions can't produce false
/// matches.
///
/// Each slot packs `hash_hi32 << 32 | (id + 1)`; `0` is an empty slot.
#[derive(Debug, Clone)]
struct Slots {
    table: Vec<u64>,
    mask: usize,
}

impl Slots {
    fn with_capacity(entries: usize) -> Slots {
        // Load factor <= 0.5.
        let size = entries.saturating_mul(2).max(8).next_power_of_two();
        Slots {
            table: vec![0; size],
            mask: size - 1,
        }
    }

    /// Finds the id whose path matches `path` (a raw, un-normalized path),
    /// or the empty slot where it would be inserted.
    fn probe<'a>(&self, path: &str, paths: impl Fn(u32) -> &'a str) -> (usize, Option<u32>) {
        let hash = hash_path(path);
        let tag = hash & !0xFFFF_FFFF;
        let mut pos = (hash as usize) & self.mask;
        loop {
            let slot = self.table[pos];
            if slot == 0 {
                return (pos, None);
            }
            if slot & !0xFFFF_FFFF == tag {
                let id = (slot as u32) - 1;
                if paths_eq(path, paths(id)) {
                    return (pos, Some(id));
                }
            }
            pos = (pos + 1) & self.mask;
        }
    }

    fn fill(&mut self, pos: usize, path: &str, id: u32) {
        self.table[pos] = (hash_path(path) & !0xFFFF_FFFF) | (u64::from(id) + 1);
    }
}

impl RootFile {
    /// Parses a decoded (post-BLTE) root file.
    ///
    /// Lines that don't look like records (no `|`, or a hash that isn't 32
    /// hex chars) are skipped, matching CascLib's tolerance; a file yielding
    /// zero records is rejected as malformed since it almost certainly means
    /// the input isn't a root file at all. Duplicate normalized paths are
    /// rejected rather than silently making earlier records unreachable.
    pub fn parse(data: &[u8]) -> Result<RootFile> {
        let text = str::from_utf8(data)
            .map_err(|_| CascError::malformed("root file", "not valid UTF-8"))?;

        // Upper bound on record count, so nothing regrows or rehashes.
        let max_records = data.iter().filter(|&&b| b == b'\n').count() + 1;
        // Every valid record spends >= 34 bytes (hash, `|`, newline) on
        // non-path text; this is only a capacity guess, the String still grows.
        let mut arena = String::with_capacity(
            data.len()
                .saturating_sub(max_records.saturating_sub(1).saturating_mul(34)),
        );
        let mut offsets: Vec<u32> = Vec::with_capacity(max_records + 1);
        offsets.push(0);
        let mut ckeys: Vec<ContentKey> = Vec::with_capacity(max_records);
        let mut slots = Slots::with_capacity(max_records);
        for line in text.lines() {
            let Some((path, rest)) = line.split_once('|') else {
                continue;
            };
            // CascLib would accept a third column; SC:R never emits one, but
            // tolerating it costs nothing.
            let hash = rest.split('|').next().unwrap_or(rest);
            let Ok(ckey) = ContentKey::from_hex(hash) else {
                continue;
            };

            let id = u32::try_from(ckeys.len())
                .ok()
                .filter(|&id| id != u32::MAX)
                .ok_or_else(|| CascError::malformed("root file", "too many entries"))?;
            let end = u32::try_from(arena.len() + path.len())
                .map_err(|_| CascError::malformed("root file", "paths too large"))?;
            let (pos, existing) = slots.probe(path, |i| span(&arena, &offsets, i));
            if existing.is_some() {
                return Err(CascError::malformed(
                    "root file",
                    format!("duplicate normalized path: {path:?}"),
                ));
            }
            slots.fill(pos, path, id);
            arena.push_str(path);
            offsets.push(end);
            ckeys.push(ckey);
        }

        if ckeys.is_empty() {
            return Err(CascError::malformed(
                "root file",
                "no valid records; input is probably not a root file",
            ));
        }
        arena.shrink_to_fit();
        offsets.shrink_to_fit();
        ckeys.shrink_to_fit();

        Ok(RootFile {
            arena,
            offsets,
            ckeys,
            slots,
        })
    }

    /// Looks up a file by path, case-insensitively; `\` and `/` separators
    /// are interchangeable.
    pub fn lookup(&self, path: &str) -> Option<RootEntry<'_>> {
        let (_, id) = self
            .slots
            .probe(path, |i| span(&self.arena, &self.offsets, i));
        let id = id?;
        Some(RootEntry {
            path: span(&self.arena, &self.offsets, id),
            ckey: *self.ckeys.get(id as usize)?,
        })
    }

    /// All records, in file order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = RootEntry<'_>> + Clone {
        self.ckeys.iter().enumerate().map(|(i, &ckey)| RootEntry {
            path: span(&self.arena, &self.offsets, i as u32),
            ckey,
        })
    }

    pub fn len(&self) -> usize {
        self.ckeys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ckeys.is_empty()
    }
}

/// Entry `id`'s path. Offsets are built from whole-`&str` pushes, so the span
/// is always a valid slice; the fallback only guards against logic errors.
#[inline]
fn span<'a>(arena: &'a str, offsets: &[u32], id: u32) -> &'a str {
    let i = id as usize;
    match (offsets.get(i), offsets.get(i + 1)) {
        (Some(&a), Some(&b)) => arena.get(a as usize..b as usize).unwrap_or(""),
        _ => "",
    }
}

const LO7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
const HI: u64 = 0x8080_8080_8080_8080;
const ONES: u64 = 0x0101_0101_0101_0101;

/// Folds eight path bytes at once: ASCII-lowercase and `\` -> `/`. Bytes
/// with the high bit set (UTF-8 multibyte sequences) pass through unchanged,
/// matching per-char `to_ascii_lowercase`.
#[inline]
fn fold_word(w: u64) -> u64 {
    // Bytes in b'A'..=b'Z' (ASCII only) get 0x20 set.
    let heptets = w & LO7;
    let ge_a = heptets + (0x80 - u64::from(b'A')) * ONES;
    let gt_z = heptets + (0x7f - u64::from(b'Z')) * ONES;
    let upper = !w & (ge_a ^ gt_z) & HI;
    let w = w | (upper >> 2);
    // Exact zero-byte detection on `w ^ '\\'`, then flip 0x5c to 0x2f.
    let x = w ^ (u64::from(b'\\') * ONES);
    let zero = !(((x & LO7) + LO7) | x | LO7);
    w ^ ((zero >> 7) * u64::from(b'\\' ^ b'/'))
}

/// Folded little-endian words of `path`; the final partial word is
/// zero-padded (folding preserves zero).
#[inline]
fn folded_words(path: &str) -> impl Iterator<Item = u64> + '_ {
    let (chunks, rem) = path.as_bytes().as_chunks::<8>();
    let tail = (!rem.is_empty()).then(|| {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        buf
    });
    chunks
        .iter()
        .copied()
        .chain(tail)
        .map(|buf| fold_word(u64::from_le_bytes(buf)))
}

/// Case/separator-insensitive hash of a path (FxHash-style word mixing with
/// a final avalanche so both the low index bits and high tag bits are good).
#[inline]
fn hash_path(path: &str) -> u64 {
    const K: u64 = 0x517c_c1b7_2722_0a95;
    let mut h = path.len() as u64;
    for w in folded_words(path) {
        h = (h.rotate_left(5) ^ w).wrapping_mul(K);
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    h ^ (h >> 29)
}

#[inline]
fn paths_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && folded_words(a).eq(folded_words(b))
}

#[cfg(test)]
fn normalize_path(path: &str) -> String {
    path.chars()
        .map(|c| {
            if c == '\\' {
                '/'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_ok::assert_ok;
    use proptest::prelude::*;

    const SAMPLE: &str = "locales/enUS/Assets/campaign/EXPZerg/Zerg08/staredit/wav/zovtra01.ogg|316b0274bf2dabaa8db60c3ff1270c85\r\n\
        locales/zhCN/Assets/sound/terran/ghost/tghdth01.wav|6637ed776bd22089e083b8b0b2c0374c\r\n\
        SD/campaign/Starcraft/SWAR/staredit/scenario.chk|d41d8cd98f00b204e9800998ecf8427e\r\n";

    #[test]
    fn parses_real_shaped_records() {
        let root = assert_ok!(RootFile::parse(SAMPLE.as_bytes()));
        assert_eq!(root.len(), 3);
        assert_eq!(
            root.entries().next().unwrap().path,
            "locales/enUS/Assets/campaign/EXPZerg/Zerg08/staredit/wav/zovtra01.ogg"
        );
        assert_eq!(
            root.entries().nth(2).unwrap().ckey.to_string(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn lookup_is_case_insensitive_and_separator_agnostic() {
        let root = assert_ok!(RootFile::parse(SAMPLE.as_bytes()));
        let entry = root
            .lookup(r"sd\Campaign\starcraft\swar\STAREDIT\scenario.chk")
            .expect("should find the entry");
        // Original casing is preserved in the returned entry.
        assert_eq!(
            entry.path,
            "SD/campaign/Starcraft/SWAR/staredit/scenario.chk"
        );
        assert!(root.lookup("sd/campaign/missing.chk").is_none());
    }

    #[test]
    fn skips_malformed_lines() {
        let text = "no separator line\n\
            short/hash.wav|abcd\n\
            bad/hash.wav|zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n\
            good/file.wav|316b0274bf2dabaa8db60c3ff1270c85\n";
        let root = assert_ok!(RootFile::parse(text.as_bytes()));
        assert_eq!(root.len(), 1);
        assert_eq!(root.entries().next().unwrap().path, "good/file.wav");
    }

    #[test]
    fn tolerates_third_column() {
        let text = "some/file.wav|316b0274bf2dabaa8db60c3ff1270c85|extra\n";
        let root = assert_ok!(RootFile::parse(text.as_bytes()));
        assert_eq!(root.len(), 1);
        assert!(root.lookup("some/file.wav").is_some());
    }

    #[test]
    fn rejects_duplicate_normalized_paths() {
        let text = "Some/Path/file.wav|316b0274bf2dabaa8db60c3ff1270c85\n\
                    some\\path\\FILE.wav|6637ed776bd22089e083b8b0b2c0374c\n";
        let err = RootFile::parse(text.as_bytes()).unwrap_err();
        assert!(matches!(err, CascError::Malformed { .. }));
    }

    #[test]
    fn bare_lf_is_accepted() {
        let text =
            "a/b.wav|316b0274bf2dabaa8db60c3ff1270c85\nc/d.wav|6637ed776bd22089e083b8b0b2c0374c\n";
        let root = assert_ok!(RootFile::parse(text.as_bytes()));
        assert_eq!(root.len(), 2);
    }

    #[test]
    fn rejects_inputs_with_no_records() {
        assert!(RootFile::parse(b"").is_err());
        assert!(RootFile::parse(b"BLTE\x00\x01\x02").is_err());
        assert!(RootFile::parse(&[0xFF, 0xFE, 0x00]).is_err());
    }

    /// Printable-ASCII path character, excluding `|` (the field separator)
    /// and the (already-excluded-by-range) `\r`/`\n` line terminators.
    fn path_char() -> impl Strategy<Value = char> {
        (0x20u8..=0x7eu8)
            .prop_filter("no pipe", |&b| b != b'|')
            .prop_map(|b| b as char)
    }

    fn path_string() -> impl Strategy<Value = String> {
        proptest::collection::vec(path_char(), 1..24).prop_map(|cs| cs.into_iter().collect())
    }

    /// Generates a nonempty list of `(path, ckey)` pairs, deduplicated by
    /// normalized path (as [`RootFile`] itself would key them) so every
    /// generated path is independently look-up-able.
    fn root_entries_strategy() -> impl Strategy<Value = Vec<(String, [u8; 16])>> {
        proptest::collection::vec((path_string(), any::<[u8; 16]>()), 1..15)
            .prop_map(|entries| {
                let mut seen = std::collections::HashSet::new();
                entries
                    .into_iter()
                    .filter(|(path, _)| seen.insert(normalize_path(path)))
                    .collect::<Vec<_>>()
            })
            .prop_filter("need at least one entry after dedup", |v| !v.is_empty())
    }

    fn fold_byte(b: u8) -> u8 {
        if b == b'\\' {
            b'/'
        } else {
            b.to_ascii_lowercase()
        }
    }

    #[test]
    fn non_ascii_paths_look_up_and_collide_correctly() {
        let text = "Ünï/Cödé.wav|316b0274bf2dabaa8db60c3ff1270c85\n\
                    ÜNÏ/cödé.wav|6637ed776bd22089e083b8b0b2c0374c\n";
        // Only ASCII is case-folded, so these are distinct paths.
        let root = assert_ok!(RootFile::parse(text.as_bytes()));
        assert_eq!(root.len(), 2);
        assert_eq!(root.lookup(r"Ünï\CÖDÉ.wav").map(|e| e.path), None);
        assert!(root.lookup(r"Ünï\Cödé.WAV").is_some());
        assert!(root.lookup(r"Ünï\cödé.wav").is_some());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// The word-at-a-time fold must agree with the scalar fold per byte.
        #[test]
        fn prop_fold_word_matches_scalar(w in any::<u64>()) {
            let got = fold_word(w).to_le_bytes();
            for (g, b) in got.iter().zip(w.to_le_bytes()) {
                prop_assert_eq!(*g, fold_byte(b));
            }
        }

        /// Hash and equality see through case/separator differences, and
        /// equality agrees with comparing normalized strings.
        #[test]
        fn prop_hash_and_eq_match_normalization(a in "[A-Za-z/\\\\.é]{0,40}", b in "[A-Za-z/\\\\.é]{0,40}") {
            let na = normalize_path(&a);
            prop_assert_eq!(hash_path(&a), hash_path(&na));
            prop_assert!(paths_eq(&a, &na));
            prop_assert_eq!(paths_eq(&a, &b), na == normalize_path(&b));
        }

        /// Serializing arbitrary (deduplicated) path/CKey pairs as
        /// `path|hex\r\n` lines and parsing them back must reproduce every
        /// entry's CKey via lookup, plus the total count.
        #[test]
        fn prop_roundtrip_root(entries in root_entries_strategy()) {
            let mut text = String::new();
            for (path, ckey) in &entries {
                text.push_str(path);
                text.push('|');
                for b in ckey {
                    text.push_str(&format!("{b:02x}"));
                }
                text.push_str("\r\n");
            }

            let root = RootFile::parse(text.as_bytes()).unwrap();
            prop_assert_eq!(root.len(), entries.len());
            for (path, ckey) in &entries {
                let found = root.lookup(path).unwrap();
                prop_assert_eq!(found.ckey, ContentKey(*ckey));
            }
        }

        /// `RootFile::parse` should never panic, no matter what string it's
        /// fed.
        #[test]
        fn prop_no_panic_arbitrary_string(s in any::<String>()) {
            let _ = RootFile::parse(s.as_bytes());
        }

        /// Flipping a handful of bytes in an otherwise-valid root file
        /// (which may break UTF-8 validity) should never panic.
        #[test]
        fn prop_no_panic_flipped_bytes(
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..4),
        ) {
            let mut data = SAMPLE.as_bytes().to_vec();
            for (pos, xor) in &flips {
                if !data.is_empty() {
                    let idx = pos % data.len();
                    data[idx] ^= xor | 1;
                }
            }
            let _ = RootFile::parse(&data);
        }

        /// Truncating an otherwise-valid root file to an arbitrary length
        /// should never panic.
        #[test]
        fn prop_no_panic_truncated(trunc_len in any::<usize>()) {
            let data = SAMPLE.as_bytes();
            let len = trunc_len % (data.len() + 1);
            let _ = RootFile::parse(&data[..len]);
        }
    }
}
