# broodcasc

A pure-Rust reader for CASC archives, targeting the StarCraft: Remastered
featureset. Intended as the storage layer for
[broodmap](https://github.com/tec27/broodmap) and neobrood, but usable by
anything that wants to read files out of an SC:R install.

## Goals

- Read files from a local SC:R CASC storage by path, efficiently and on demand
- Pure Rust, no C dependencies
- WASM-compatible core: all storage access goes through small traits
  (`ReadAt`/`StorageProvider`), so the browser can supply bytes however it
  likes (OPFS sync access handles, in-memory buffers, ...). The `fs` feature
  (on by default) provides the `std::fs`-backed implementation for native use.

## Non-goals

- Writing/repairing archives
- Patching/updating installs
- Products other than StarCraft: Remastered (other CASC games may work by
  accident, but only SC:R's format variant is tested or supported)

## Usage

```rust,ignore
use broodcasc::Storage;

let storage = Storage::open(r"C:\Program Files (x86)\StarCraft")?;

// Lookups are case-insensitive and accept either separator.
let chk = storage.read_file("SD/campaign/Starcraft/SWAR/staredit/scenario.chk")?;

for name in storage.file_names() {
    println!("{name}");
}
```

CKey-addressed reads verify BLTE chunk MD5s, the expected decoded size, and
the whole-file CKey. A direct `read_by_ekey(..., None)` has no whole-object
identity to verify; it still validates the local span/index framing and BLTE
chunk checks. A partial install catalogs files it never downloaded (e.g. other
locales' audio) — those reads fail with `CascError::NotInstalled`, distinct
from `NotFound`.

On WASM (or anything without `std::fs`), build with
`--no-default-features` and hand `Storage::open_with_provider` your own
`StorageProvider` implementation — e.g. OPFS sync access handles in a
worker, or in-memory buffers.

## Resource limits

`ReadLimits` bounds encoded input, decoded output, chunks, nesting, and
initial reservations. `StorageOptions` additionally bounds local and CDN
bootstrap metadata, including decoded encoding/root objects (64 MiB per object
by default). Structural caps also limit archive lists, hosts, and index-table
growth. The defaults are conservative for SC:R; applications with a different
asset policy can opt in explicitly:

```rust,ignore
use broodcasc::{ReadLimits, Storage, StorageOptions};

let options = StorageOptions::default()
    .with_read_limits(ReadLimits { max_decoded_bytes: 1024 * 1024 * 1024, ..ReadLimits::default() })
    .with_max_metadata_bytes(16 * 1024 * 1024);
let storage = Storage::open_with_options(r"C:\Program Files (x86)\StarCraft", options)?;
```

## CDN ("online") storage

Files can also be read straight from Blizzard's CDN, no install required —
handy for e.g. rendering tileset images on a server or in a browser:

```rust,ignore
use broodcasc::cdn::{CachingTransport, CdnStorage, HttpTransport};

let transport = CachingTransport::new(HttpTransport::new(), "./cdn-cache");
let storage = CdnStorage::open("s1", "us", transport)?;
let bytes = storage.read_file("SD/campaign/Starcraft/SWAR/staredit/scenario.chk")?;
```

`CdnStorage::open` discovers the current live build over unauthenticated plain
HTTP. Use `open_pinned` with build/CDN config CKeys obtained through a trusted
out-of-band channel whenever the selected build must be a trust anchor. All
fetching goes through the `CdnTransport` trait: the `cdn-http` feature
provides the ureq-based `HttpTransport` for native use, while WASM builds
(`--no-default-features --features cdn`) supply their own transport over
`fetch`/XHR. `CachingTransport` (with the `fs` feature) persists
content-addressed downloads to disk, making reopening cheap.
The cache has per-entry safety bounds and repairs rejected entries, but it does
not impose a total disk quota; applications should manage the cache directory's
lifetime or quota according to their platform.

The checksums detect corruption and mismatched content but are not active
authentication: MD5 is not a substitute for a signed manifest or authenticated
transport. CKey-addressed CDN reads verify decoded content as above;
`read_by_ekey(..., None)` does not establish a whole-object identity.

## CLI

`cli/` is a small command-line front end over the library, installable with:

```
cargo install --path cli
```

```
# Extract every tileset-ish file from a local install into ./out
broodcasc --local extract "*tileset*" -o out

# Extract a file straight from Blizzard's CDN, no install required
broodcasc --cdn extract "SD/campaign/Starcraft/SWAR/staredit/scenario.chk" -o out

# Print one file's decoded bytes to stdout
broodcasc --local cat "SD/campaign/Starcraft/SWAR/staredit/scenario.chk"

# List catalog paths matching a substring or glob
broodcasc --local list scenario --sizes
```

`--local` defaults to `C:\Program Files (x86)\StarCraft` when given without a
directory; with neither `--local` nor `--cdn`, it behaves as `--local`. See
`broodcasc --help` for the full option list (region/product selection,
pinning a specific CDN build, `--flat` extraction, ...).

## Fuzzing

`fuzz/` holds `cargo-fuzz` targets for the five parsers that touch untrusted
input directly: `blte_decode`, `encoding_parse`, `idx_parse`, `root_parse`,
`config_parse`. They require a nightly toolchain:

```
cargo install cargo-fuzz
cargo +nightly fuzz run root_parse fuzz/seeds/root_parse -- -max_total_time=60
```

`fuzz/seeds/<target>/` is a small, synthetic (hand-constructed, not from any
real game install) seed corpus committed to the repo — enough to get each
parser past its header checks. For a much stronger local corpus, run
`cargo run --example extract_fuzz_corpus` against a real SC:R install (path
`C:\Program Files (x86)\StarCraft` by default, or `BROODCASC_TEST_STORAGE`);
it dumps real `.idx` files, the decoded encoding table, the decoded root, and
a spread of raw BLTE spans into `fuzz/corpus/`, which is gitignored and never
committed — that data is Blizzard's, not ours to redistribute. Then:

```
cargo +nightly fuzz run blte_decode fuzz/seeds/blte_decode fuzz/corpus/blte_decode
```

CI runs a short smoke pass per target on every push/PR and a longer pass
weekly; see `.github/workflows/fuzz.yml`. `cargo-fuzz` on Windows/MSVC can be
finicky to link/run locally — if it doesn't work for you, `cargo +nightly
fuzz check` (or `cargo +nightly check` from inside `fuzz/`) at least verifies
the targets compile, and WSL/Linux is the reliable place to actually run
fuzzing sessions.

## Format documentation

See [docs/casc-format.md](docs/casc-format.md) for the on-disk format
reference this implementation follows.
[CascLib](https://github.com/ladislav-zezula/CascLib) and
[zezula.net](http://www.zezula.net/en/casc/main.html) are the canonical
references; this library is an independent implementation.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
