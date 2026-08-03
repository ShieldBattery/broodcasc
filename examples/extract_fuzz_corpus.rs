//! Enriches the local fuzz corpus with real data pulled from an SC:R
//! install. This is a local-only enrichment step, not run in CI: the seeds
//! committed under `fuzz/seeds/` are synthetic (see `fuzz/seed_gen/`), but a
//! much larger, format-accurate corpus makes local `cargo fuzz run` sessions
//! far more effective at finding real bugs. Output goes to `fuzz/corpus/`,
//! which is gitignored — nothing this writes is ever committed.
//!
//! Usage:
//!
//! ```text
//! cargo run --example extract_fuzz_corpus
//! ```
//!
//! Reads from `C:\Program Files (x86)\StarCraft` by default, or the
//! directory named by `BROODCASC_TEST_STORAGE`. Does nothing (with a notice)
//! if no storage is found there.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use broodcasc::Storage;
use broodcasc::blte::BlteHeader;
use broodcasc::idx::LocalIndex;
use broodcasc::io::{FsProvider, ReadAt, StorageProvider};

fn main() -> Result<(), Box<dyn Error>> {
    let root = std::env::var("BROODCASC_TEST_STORAGE")
        .unwrap_or_else(|_| r"C:\Program Files (x86)\StarCraft".to_string());
    let root = PathBuf::from(root);

    if !root.join(".build.info").is_file() {
        eprintln!(
            "no CASC storage found at {} (set BROODCASC_TEST_STORAGE to override); nothing to do",
            root.display()
        );
        return Ok(());
    }

    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");

    let provider = FsProvider::new(root.clone());
    let storage = Storage::open(root)?;

    extract_idx(&provider, &corpus_root)?;
    extract_encoding(&storage, &corpus_root)?;
    extract_root(&storage, &corpus_root)?;
    extract_configs(&provider, &storage, &corpus_root)?;
    extract_blte_spans(&provider, &storage, &corpus_root)?;

    println!("done");
    Ok(())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let path = dir.join(name);
    fs::write(&path, bytes)?;
    println!(
        "wrote {} ({} bytes)",
        path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&path)
            .display(),
        bytes.len()
    );
    Ok(())
}

/// Raw `.idx` files, straight off disk, for `idx_parse`.
fn extract_idx(provider: &FsProvider, corpus_root: &Path) -> Result<(), Box<dyn Error>> {
    let dir = corpus_root.join("idx_parse");
    let names = provider.list_dir("Data/data")?;
    let idx_names = LocalIndex::select_files(&names);
    for (i, name) in idx_names.iter().take(2).enumerate() {
        let bytes = provider.read(&format!("Data/data/{name}"))?;
        write(&dir, &format!("real_{i:02}_{name}"), &bytes)?;
    }
    Ok(())
}

/// The decoded (post-BLTE) encoding table, for `encoding_parse`.
fn extract_encoding<P: StorageProvider>(
    storage: &Storage<P>,
    corpus_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let (ckey, ekey) = storage.build_config().encoding()?;
    let bytes = storage.read_by_ekey(&ekey, Some(&ckey))?;
    write(
        &corpus_root.join("encoding_parse"),
        "real_encoding.bin",
        &bytes,
    )
}

/// The decoded (post-BLTE) root file, for `root_parse`.
fn extract_root<P: StorageProvider>(
    storage: &Storage<P>,
    corpus_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let root_ckey = storage.build_config().root()?;
    let root_enc = storage
        .encoding()
        .lookup(&root_ckey)
        .ok_or("root CKey not present in encoding table")?;
    let bytes = storage.read_by_ekey(&root_enc.ekey, Some(&root_ckey))?;
    write(&corpus_root.join("root_parse"), "real_root.txt", &bytes)
}

/// `.build.info` and the active build config, for `config_parse`.
fn extract_configs<P: StorageProvider>(
    provider: &FsProvider,
    storage: &Storage<P>,
    corpus_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let dir = corpus_root.join("config_parse");

    let build_info_bytes = provider.read(".build.info")?;
    write(&dir, "real_build_info.txt", &build_info_bytes)?;

    let record = storage
        .build_info()
        .active_record()
        .ok_or("no active build record")?;
    let build_key_hex = record.build_key()?.to_string();
    let config_path = format!(
        "Data/config/{}/{}/{}",
        &build_key_hex[0..2],
        &build_key_hex[2..4],
        build_key_hex
    );
    let build_config_bytes = provider.read(&config_path)?;
    write(&dir, "real_build_config.txt", &build_config_bytes)
}

/// ~10 raw BLTE spans (post 30-byte span header) of assorted sizes, for
/// `blte_decode`. Read directly through the provider using index entries
/// rather than the higher-level `Storage` API, since we want the still-BLTE
/// -encoded bytes, not decoded content.
fn extract_blte_spans<P: StorageProvider>(
    provider: &FsProvider,
    storage: &Storage<P>,
    corpus_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let dir = corpus_root.join("blte_decode");

    let mut entries: Vec<_> = storage.index().entries().collect();
    entries.sort_by_key(|(_, e)| e.encoded_size);
    if entries.is_empty() {
        return Ok(());
    }

    // Spread picks evenly across the size distribution (smallest to
    // largest) rather than just taking the first N.
    let count = entries.len().min(10);
    let picks: Vec<usize> = if entries.len() <= count {
        (0..entries.len()).collect()
    } else {
        (0..count)
            .map(|i| i * (entries.len() - 1) / (count - 1))
            .collect()
    };

    let mut written = 0;
    for &idx in &picks {
        let (_key, entry) = entries[idx];
        let archive = match provider.open(&format!("Data/data/data.{:03}", entry.archive)) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("skipping archive {}: {e}", entry.archive);
                continue;
            }
        };
        let span_len = (entry.encoded_size as u64).saturating_sub(30);
        let span = match archive.read_vec_at(entry.offset + 30, span_len as usize) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "skipping span at archive {} offset {}: {e}",
                    entry.archive, entry.offset
                );
                continue;
            }
        };
        // Skip the (known, per docs/casc-format.md §3.4) one non-BLTE raw
        // span in the storage; this example is specifically for BLTE seeds.
        if BlteHeader::parse(&span).is_err() {
            continue;
        }
        write(&dir, &format!("real_span_{written:02}.blte"), &span)?;
        written += 1;
    }
    Ok(())
}
