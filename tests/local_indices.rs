//! Integration test against the real `Data\indices\*.index` files of a
//! StarCraft: Remastered install.
//!
//! These are CDN archive indices (see `docs/casc-format.md` §8 and
//! `src/cdnindex.rs`): not needed to read a local install, but the exact
//! same files a Blizzard CDN would serve alongside each archive, so a real
//! install is a convenient source of real-world data to parse against.
//!
//! Gated exactly like `tests/real_storage.rs`: skip silently when the
//! directory (or env override `BROODCASC_TEST_STORAGE`) is absent, so CI
//! without game data stays green.
//!
//! **Discrepancy found while writing this test, not previously documented:**
//! of the 53 real `.index` files, 45 use the footer widths this parser
//! supports (`offset_bytes`/`size_bytes`/`ekey_length` = 4/4/16), but 8 do
//! not -- 4 use `offset_bytes = 0` (no offset field; these carry huge
//! `size` values up to ~605 MB and are presumably some other manifest
//! reusing the generic index/footer container, not a per-archive span
//! index) and 4 use `offset_bytes = 5` with offsets up to ~172 * 10^9,
//! `~10 000` times larger than fits in a `u32` (consistent with these being
//! "group index" files whose offset packs an archive number into the high
//! bits the way local `.idx` does, per `docs/casc-format.md` §2.3 --
//! plausible given two pairs of near-duplicate huge element counts, ~54.3k
//! each, look like successive versions of the same group index). This
//! contradicts `docs/casc-format.md` §8's claim that SC:R doesn't vary
//! these widths -- that note was only checked against one file. This
//! parser intentionally stays scoped to the documented per-archive format
//! (rejecting other widths as [`CascError::Unsupported`] rather than
//! misinterpreting them), so this test tolerates -- but separately counts
//! and reports -- `Unsupported` results instead of treating them as
//! failures.

#![cfg(feature = "fs")]

use broodcasc::CascError;
use broodcasc::cdnindex::ArchiveIndex;

fn indices_dir() -> Option<std::path::PathBuf> {
    let root = std::env::var("BROODCASC_TEST_STORAGE")
        .unwrap_or_else(|_| r"C:\Program Files (x86)\StarCraft".to_string());
    let dir = std::path::Path::new(&root).join(r"Data\indices");
    if !dir.is_dir() {
        eprintln!("skipping: no CDN indices directory at {}", dir.display());
        return None;
    }
    Some(dir)
}

#[test]
fn parses_every_real_index_file() {
    let Some(dir) = indices_dir() else {
        return;
    };

    let mut files = 0usize;
    let mut unsupported_files = 0usize;
    let mut total_entries = 0usize;
    let mut files_with_entries = 0usize;

    for entry in std::fs::read_dir(&dir).expect("read_dir should succeed") {
        let entry = entry.expect("dir entry should be readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("index") {
            continue;
        }
        files += 1;

        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("reading {} failed: {e}", path.display()));
        let index = match ArchiveIndex::parse(&data) {
            Ok(index) => index,
            // See the module doc comment: a handful of real files use
            // footer widths outside the documented per-archive format and
            // are expected to be rejected rather than misparsed.
            Err(CascError::Unsupported { reason, .. }) => {
                eprintln!("skipping {} (unsupported: {reason})", path.display());
                unsupported_files += 1;
                continue;
            }
            Err(e) => panic!("parsing {} failed: {e}", path.display()),
        };

        for e in index.entries() {
            assert!(
                e.encoded_size > 0,
                "{}: entry {} has zero encoded_size",
                path.display(),
                e.ekey
            );
        }

        if !index.is_empty() {
            files_with_entries += 1;
        }
        total_entries += index.len();
    }

    assert!(files > 0, "no .index files found in {}", dir.display());
    assert!(
        unsupported_files < files,
        "every .index file used an unsupported footer width"
    );
    assert!(
        total_entries > 10_000,
        "suspiciously few total entries across {files} index files: {total_entries}"
    );
    assert!(
        files_with_entries > 0,
        "every supported .index file was empty, which is implausible for a real install"
    );

    eprintln!(
        "parsed {} of {files} .index files ({unsupported_files} unsupported width variants), \
         {total_entries} entries total ({files_with_entries} non-empty)",
        files - unsupported_files
    );
}
