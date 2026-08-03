//! `broodcasc extract`: extract every catalog file matching any of the
//! given patterns into an output directory.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use broodcasc::CascError;

use crate::matcher::{PathMatcher, any_match};
use crate::sanitize::sanitize_relative_path;
use crate::source::Source;

pub fn run(source: &Source, patterns: &[String], out: &Path, flat: bool) -> Result<()> {
    let matchers: Vec<PathMatcher> = patterns
        .iter()
        .map(|p| PathMatcher::new(p))
        .collect::<Result<_>>()?;

    let matched: Vec<&str> = source
        .file_names()
        .filter(|path| any_match(&matchers, path))
        .collect();

    if matched.is_empty() {
        bail!(
            "no catalog files matched pattern(s): {}",
            patterns.join(", ")
        );
    }

    if flat {
        check_no_duplicate_basenames(&matched)?;
    }

    std::fs::create_dir_all(out)
        .with_context(|| format!("creating output directory {}", out.display()))?;

    let mut extracted = 0usize;
    let mut skipped = 0usize;

    for path in matched {
        let dest = if flat {
            let name = Path::new(path)
                .file_name()
                .expect("checked non-empty basename above");
            Some(out.join(name))
        } else {
            match sanitize_relative_path(path) {
                Some(rel) => Some(out.join(rel)),
                None => {
                    eprintln!("warning: skipping {path}: path would escape output directory");
                    skipped += 1;
                    None
                }
            }
        };

        let Some(dest) = dest else { continue };

        let bytes = match source.read_file(path) {
            Ok(bytes) => bytes,
            Err(CascError::NotInstalled(_)) => {
                eprintln!("warning: skipping {path}: not installed locally");
                skipped += 1;
                continue;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("reading {path}"));
            }
        };

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
        std::fs::write(&dest, &bytes).with_context(|| format!("writing {}", dest.display()))?;

        eprintln!("{path} -> {}", dest.display());
        extracted += 1;
    }

    eprintln!("extracted {extracted} file(s), skipped {skipped}");
    Ok(())
}

/// With `--flat`, two different catalog paths that share a basename would
/// silently overwrite each other; refuse up front instead.
fn check_no_duplicate_basenames(paths: &[&str]) -> Result<()> {
    let mut seen: HashMap<String, &str> = HashMap::new();
    for &path in paths {
        let name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .unwrap_or_default();
        // Compare case-insensitively: Windows filesystems (the only ones a
        // real SC:R install lives on) can't hold both anyway.
        let key = name.to_lowercase();
        if let Some(prev) = seen.insert(key, path) {
            bail!("--flat would collide: {prev:?} and {path:?} both have basename {name:?}");
        }
    }
    Ok(())
}
