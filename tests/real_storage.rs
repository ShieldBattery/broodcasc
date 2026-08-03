//! Integration tests against a real StarCraft: Remastered install.
//!
//! These run only when a storage is present (default:
//! `C:\Program Files (x86)\StarCraft`, overridable via the
//! `BROODCASC_TEST_STORAGE` env var) and skip silently otherwise, so CI
//! without game data stays green. Every successful `read_*` already implies
//! end-to-end correctness: BLTE chunk MD5s and the whole-file CKey MD5 are
//! verified internally.

#![cfg(feature = "fs")]

use broodcasc::{CascError, Storage};

fn open_storage() -> Option<Storage<broodcasc::io::FsProvider>> {
    let dir = std::env::var("BROODCASC_TEST_STORAGE")
        .unwrap_or_else(|_| r"C:\Program Files (x86)\StarCraft".to_string());
    if !std::path::Path::new(&dir).join(".build.info").is_file() {
        eprintln!("skipping: no CASC storage at {dir}");
        return None;
    }
    Some(Storage::open(dir).expect("storage should open"))
}

#[test]
fn opens_and_has_plausible_catalog() {
    let Some(storage) = open_storage() else {
        return;
    };

    // Build-specific counts drift across patches; just sanity-bound them.
    assert!(storage.root().len() > 10_000, "root suspiciously small");
    assert!(
        storage.encoding().len() > 10_000,
        "encoding suspiciously small"
    );
    assert!(storage.index().len() > 10_000, "index suspiciously small");
    assert_eq!(storage.build_config().build_uid(), Some("s1"));
}

#[test]
fn reads_installed_files() {
    let Some(storage) = open_storage() else {
        return;
    };

    let mut read = 0;
    for entry in storage.root().entries() {
        if !storage.is_installed(&entry.path) {
            continue;
        }
        let expected_size = storage.file_size(&entry.path).expect("size should resolve");
        let bytes = storage
            .read_file(&entry.path)
            .unwrap_or_else(|e| panic!("reading {} failed: {e}", entry.path));
        assert_eq!(
            bytes.len() as u64,
            expected_size,
            "size mismatch for {}",
            entry.path
        );
        read += 1;
        if read >= 20 {
            break;
        }
    }
    assert!(read > 0, "no installed files found to read");
}

#[test]
fn reads_a_large_multi_chunk_file() {
    let Some(storage) = open_storage() else {
        return;
    };

    // Find something over 1 MiB so the BLTE chunk table path is exercised
    // (single chunks max out at 256 KiB in this storage).
    let entry = storage
        .root()
        .entries()
        .iter()
        .find(|e| {
            storage.is_installed(&e.path) && storage.file_size(&e.path).is_ok_and(|s| s > 1_000_000)
        })
        .expect("some large installed file should exist");
    let bytes = storage
        .read_file(&entry.path)
        .expect("large read should work");
    assert_eq!(bytes.len() as u64, storage.file_size(&entry.path).unwrap());
}

#[test]
fn lookup_is_case_and_separator_insensitive() {
    let Some(storage) = open_storage() else {
        return;
    };

    let entry = storage
        .root()
        .entries()
        .iter()
        .find(|e| e.path.contains('/') && e.path.chars().any(|c| c.is_ascii_uppercase()))
        .expect("some mixed-case path should exist");
    let upper = entry.path.to_ascii_uppercase().replace('/', "\\");
    assert!(
        storage.contains(&upper),
        "case/separator-normalized lookup failed"
    );
}

#[test]
fn missing_and_uninstalled_paths_error_distinctly() {
    let Some(storage) = open_storage() else {
        return;
    };

    match storage.read_file("no/such/file/anywhere.xyz") {
        Err(CascError::NotFound(_)) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Partial installs leave unselected-locale content cataloged but absent.
    // Not guaranteed to exist on a full install, so only assert when found.
    if let Some(entry) = storage
        .root()
        .entries()
        .iter()
        .find(|e| !storage.is_installed(&e.path))
    {
        match storage.read_file(&entry.path) {
            Err(CascError::NotInstalled(_)) => {}
            other => panic!("expected NotInstalled for {}, got {other:?}", entry.path),
        }
    }
}
