//! `broodcasc list`: print catalog paths, optionally filtered.

use std::io::{ErrorKind, Write};

use anyhow::Result;

use crate::matcher::PathMatcher;
use crate::source::Source;

pub fn run(source: &Source, pattern: Option<&str>, sizes: bool) -> Result<()> {
    let matcher = pattern.map(PathMatcher::new).transpose()?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for path in source.file_names() {
        if let Some(matcher) = &matcher
            && !matcher.is_match(path)
        {
            continue;
        }

        let line_result = if sizes {
            match source.file_size(path) {
                Ok(size) => writeln!(out, "{path}\t{size}"),
                Err(e) => {
                    eprintln!("warning: could not resolve size for {path}: {e}");
                    writeln!(out, "{path}\t?")
                }
            }
        } else {
            writeln!(out, "{path}")
        };

        // A downstream reader closing early (e.g. piping into `head`) isn't
        // a real error — stop quietly so `list` stays pipeable instead of
        // failing (or, on Windows, panicking on the next `println!`).
        match line_result {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
