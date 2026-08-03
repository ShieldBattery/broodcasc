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
let bytes = storage.read_file("music\\terran1.ogg")?;
for name in storage.file_names() {
    println!("{name}");
}
```

## Format documentation

See [docs/casc-format.md](docs/casc-format.md) for the on-disk format
reference this implementation follows.
[CascLib](https://github.com/ladislav-zezula/CascLib) and
[zezula.net](http://www.zezula.net/en/casc/main.html) are the canonical
references; this library is an independent implementation.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
