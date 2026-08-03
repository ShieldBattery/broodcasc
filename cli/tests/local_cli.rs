//! Integration tests against a real StarCraft: Remastered install, driving
//! the actual `broodcasc` binary via `assert_cmd`.
//!
//! Gated exactly like the root crate's `tests/real_storage.rs`: these run
//! only when a storage is present (default:
//! `C:\Program Files (x86)\StarCraft`, overridable via
//! `BROODCASC_TEST_STORAGE`) and skip silently otherwise, so CI without game
//! data stays green.

use std::path::PathBuf;

use assert_cmd::Command;
use broodcasc::Storage;

fn storage_dir() -> Option<String> {
    let dir = std::env::var("BROODCASC_TEST_STORAGE")
        .unwrap_or_else(|_| r"C:\Program Files (x86)\StarCraft".to_string());
    if std::path::Path::new(&dir).join(".build.info").is_file() {
        Some(dir)
    } else {
        eprintln!("skipping: no CASC storage at {dir}");
        None
    }
}

/// Picks up to `n` small installed catalog paths, smallest first, so `cat`
/// and `extract` runs stay fast.
fn small_installed_paths(dir: &str, n: usize) -> Vec<String> {
    let storage = Storage::open(dir).expect("storage should open");
    let mut candidates: Vec<(u64, String)> = storage
        .root()
        .entries()
        .iter()
        .filter(|e| storage.is_installed(&e.path))
        .filter_map(|e| {
            let size = storage.file_size(&e.path).ok()?;
            (size > 0).then_some((size, e.path.clone()))
        })
        .collect();
    candidates.sort_by_key(|(size, _)| *size);
    candidates.into_iter().take(n).map(|(_, p)| p).collect()
}

fn bin() -> Command {
    Command::cargo_bin("broodcasc").expect("binary should build")
}

#[test]
fn info_reports_local_summary() {
    let Some(dir) = storage_dir() else {
        return;
    };

    let output = bin()
        .args(["--local", &dir, "info"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).expect("stdout should be UTF-8");
    assert!(text.contains("local install"), "got:\n{text}");
    assert!(text.contains("files:"), "got:\n{text}");
}

#[test]
fn list_with_pattern_filters_output() {
    let Some(dir) = storage_dir() else {
        return;
    };
    let paths = small_installed_paths(&dir, 1);
    let Some(path) = paths.into_iter().next() else {
        eprintln!("skipping: no installed files found");
        return;
    };
    // A distinctive substring from the picked file's own path is guaranteed
    // to match at least that file.
    let needle = path
        .rsplit('/')
        .next()
        .unwrap_or(&path)
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .to_string();
    let needle = if needle.len() >= 3 {
        needle
    } else {
        path.clone()
    };

    let output = bin()
        .args(["--local", &dir, "list", &needle])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).expect("stdout should be UTF-8");
    assert!(
        text.lines().any(|l| l.eq_ignore_ascii_case(&path)),
        "expected {path:?} in list output for pattern {needle:?}, got:\n{text}"
    );
}

#[test]
fn cat_prints_nonempty_bytes() {
    let Some(dir) = storage_dir() else {
        return;
    };
    let paths = small_installed_paths(&dir, 1);
    let Some(path) = paths.into_iter().next() else {
        eprintln!("skipping: no installed files found");
        return;
    };

    let output = bin()
        .args(["--local", &dir, "cat", &path])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(!output.is_empty(), "cat of {path:?} produced no bytes");
}

#[test]
fn extract_writes_files_with_correct_sizes() {
    let Some(dir) = storage_dir() else {
        return;
    };
    let paths = small_installed_paths(&dir, 2);
    if paths.len() < 2 {
        eprintln!("skipping: fewer than 2 installed files found");
        return;
    }

    let storage = Storage::open(&dir).expect("storage should open");
    let out_dir = tempfile::tempdir().expect("creating temp out dir");

    let mut cmd = bin();
    cmd.arg("--local").arg(&dir).arg("extract");
    for path in &paths {
        cmd.arg(path);
    }
    cmd.arg("-o").arg(out_dir.path());
    cmd.assert().success();

    for path in &paths {
        let expected_size = storage.file_size(path).expect("size should resolve");
        let rel: PathBuf = path.split('/').collect();
        let extracted = out_dir.path().join(&rel);
        let metadata = std::fs::metadata(&extracted)
            .unwrap_or_else(|e| panic!("expected {extracted:?} to exist: {e}"));
        assert_eq!(
            metadata.len(),
            expected_size,
            "size mismatch for extracted {path:?}"
        );
    }
}
