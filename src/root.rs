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

use std::collections::HashMap;

use crate::error::{CascError, Result};
use crate::keys::ContentKey;

/// One record from the root file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEntry {
    /// The file's path as stored: `/`-separated, original casing.
    pub path: String,
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
    entries: Vec<RootEntry>,
    /// Normalized (lowercased, `/`-separated) path → index into `entries`.
    index: HashMap<String, u32>,
}

impl RootFile {
    /// Parses a decoded (post-BLTE) root file.
    ///
    /// Lines that don't look like records (no `|`, or a hash that isn't 32
    /// hex chars) are skipped, matching CascLib's tolerance; a file yielding
    /// zero records is rejected as malformed since it almost certainly means
    /// the input isn't a root file at all.
    pub fn parse(data: &[u8]) -> Result<RootFile> {
        let text = str::from_utf8(data)
            .map_err(|_| CascError::malformed("root file", "not valid UTF-8"))?;

        let mut entries = Vec::new();
        let mut index = HashMap::new();
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

            let id = u32::try_from(entries.len())
                .map_err(|_| CascError::malformed("root file", "too many entries"))?;
            index.insert(normalize_path(path), id);
            entries.push(RootEntry {
                path: path.to_string(),
                ckey,
            });
        }

        if entries.is_empty() {
            return Err(CascError::malformed(
                "root file",
                "no valid records; input is probably not a root file",
            ));
        }

        Ok(RootFile { entries, index })
    }

    /// Looks up a file by path, case-insensitively; `\` and `/` separators
    /// are interchangeable.
    pub fn lookup(&self, path: &str) -> Option<&RootEntry> {
        let id = *self.index.get(&normalize_path(path))?;
        Some(&self.entries[id as usize])
    }

    /// All records, in file order.
    pub fn entries(&self) -> &[RootEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => out.push('/'),
            _ => out.push(c.to_ascii_lowercase()),
        }
    }
    out
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
            root.entries()[0].path,
            "locales/enUS/Assets/campaign/EXPZerg/Zerg08/staredit/wav/zovtra01.ogg"
        );
        assert_eq!(
            root.entries()[2].ckey.to_string(),
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
        assert_eq!(root.entries()[0].path, "good/file.wav");
    }

    #[test]
    fn tolerates_third_column() {
        let text = "some/file.wav|316b0274bf2dabaa8db60c3ff1270c85|extra\n";
        let root = assert_ok!(RootFile::parse(text.as_bytes()));
        assert_eq!(root.len(), 1);
        assert!(root.lookup("some/file.wav").is_some());
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

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
