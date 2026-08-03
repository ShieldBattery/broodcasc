//! `broodcasc cat`: write one file's decoded bytes to stdout.

use std::io::{ErrorKind, Write};

use anyhow::{Context, Result};

use crate::source::Source;

pub fn run(source: &Source, path: &str) -> Result<()> {
    let bytes = source
        .read_file(path)
        .with_context(|| format!("reading {path}"))?;

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    // A downstream reader closing early (e.g. piping into `head`) isn't a
    // real error — exit quietly rather than failing.
    match lock.write_all(&bytes) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e).with_context(|| format!("writing {path} to stdout")),
    }
}
