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
        let text = std::str::from_utf8(data)
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
}
