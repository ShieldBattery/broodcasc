//! `broodcasc info`: print a summary of the opened storage.

use anyhow::Result;

use crate::source::Source;

pub fn run(source: &Source) -> Result<()> {
    println!("source:  {}", source.label());
    if let Some(version) = source.version_label() {
        println!("version: {version}");
    }
    println!("files:   {}", source.file_count());

    if let Source::Local { .. } = source {
        let mut installed = 0usize;
        let mut total = 0usize;
        for path in source.file_names() {
            total += 1;
            if source.is_installed(path) {
                installed += 1;
            }
        }
        println!("installed: {installed}/{total}");
    }

    Ok(())
}
