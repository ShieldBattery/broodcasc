//! Command-line argument definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Default local install directory used when `--local` is given without a
/// value, or when neither `--local` nor `--cdn` is given at all.
pub const DEFAULT_LOCAL_DIR: &str = r"C:\Program Files (x86)\StarCraft";

/// Default region used for `--cdn` when `--region` isn't given.
pub const DEFAULT_REGION: &str = "us";

/// Default product used for `--cdn` when `--product` isn't given.
pub const DEFAULT_PRODUCT: &str = "s1";

#[derive(Parser)]
#[command(
    name = "broodcasc",
    about = "Read files out of StarCraft: Remastered CASC storage",
    version
)]
pub struct Cli {
    #[command(flatten)]
    pub source: SourceArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Global storage source selection: at most one of `--local`/`--cdn`.
#[derive(Args)]
pub struct SourceArgs {
    /// Open a local install (default: `C:\Program Files (x86)\StarCraft` if
    /// no value is given).
    #[arg(
        long,
        group = "source",
        num_args = 0..=1,
        default_missing_value = DEFAULT_LOCAL_DIR,
        value_name = "DIR"
    )]
    pub local: Option<PathBuf>,

    /// Open Blizzard's CDN instead of a local install.
    #[arg(long, group = "source")]
    pub cdn: bool,

    /// CDN region (only meaningful with `--cdn`).
    #[arg(long, default_value = DEFAULT_REGION, requires = "cdn")]
    pub region: String,

    /// CDN product (only meaningful with `--cdn`).
    #[arg(long, default_value = DEFAULT_PRODUCT, requires = "cdn")]
    pub product: String,

    /// Directory for cached CDN downloads (default: a `broodcasc-cache`
    /// directory under the OS temp dir).
    #[arg(long, value_name = "DIR", requires = "cdn")]
    pub cache: Option<PathBuf>,

    /// Pin a specific build's build-config hash (requires `--cdn-config`).
    #[arg(long, value_name = "HEX", requires_all = ["cdn", "cdn_config"])]
    pub build_config: Option<String>,

    /// Pin a specific build's CDN-config hash (requires `--build-config`).
    #[arg(long, value_name = "HEX", requires_all = ["cdn", "build_config"])]
    pub cdn_config: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print a summary of the opened storage.
    Info,
    /// List catalog paths, optionally filtered by a glob or substring.
    List {
        /// Case-insensitive glob (if it contains glob metacharacters) or
        /// substring match over the full catalog path.
        pattern: Option<String>,
        /// Also print each file's decoded size (tab-separated).
        #[arg(long)]
        sizes: bool,
    },
    /// Write one file's decoded bytes to stdout.
    Cat {
        /// Catalog path of the file to print.
        path: String,
    },
    /// Extract catalog files matching any of the given patterns.
    Extract {
        /// Case-insensitive globs or substrings over the full catalog path;
        /// a file is extracted if it matches any of them.
        #[arg(required = true)]
        patterns: Vec<String>,
        /// Output directory (created if needed).
        #[arg(short = 'o', long = "out", default_value = ".", value_name = "DIR")]
        out: PathBuf,
        /// Write just file names into the output directory instead of
        /// preserving catalog subdirectories; errors on duplicate basenames.
        #[arg(long)]
        flat: bool,
    },
}
