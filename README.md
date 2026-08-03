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
- Online (CDN) fetching or patching
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

Every read is verified end to end (BLTE chunk MD5s plus the whole-file
content MD5). Note that a partial install catalogs files it never
downloaded (e.g. other locales' audio) — those reads fail with
`CascError::NotInstalled`, distinct from `NotFound`.

On WASM (or anything without `std::fs`), build with
`--no-default-features` and hand `Storage::open_with_provider` your own
`StorageProvider` implementation — e.g. OPFS sync access handles in a
worker, or in-memory buffers.

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
