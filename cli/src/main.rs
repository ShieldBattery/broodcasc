//! `broodcasc`: a CLI for reading files out of StarCraft: Remastered CASC
//! storage, either a local install or Blizzard's CDN.

mod args;
mod commands;
mod matcher;
mod sanitize;
mod source;

use anyhow::Result;
use clap::Parser;

use args::{Cli, Command};
use source::open_source;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let source = open_source(&cli)?;

    match cli.command {
        Command::Info => commands::info::run(&source),
        Command::List { pattern, sizes } => commands::list::run(&source, pattern.as_deref(), sizes),
        Command::Cat { path } => commands::cat::run(&source, &path),
        Command::Extract {
            patterns,
            out,
            flat,
        } => commands::extract::run(&source, &patterns, &out, flat),
    }
}
