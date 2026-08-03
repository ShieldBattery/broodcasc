# broodcasc

Pure-Rust reader for StarCraft: Remastered CASC archives. Consumers: broodmap
(../broodmap) and neobrood (../neobrood). WASM compatibility is a hard
requirement for the core: no direct filesystem access outside the `fs`
feature; all storage I/O goes through the `ReadAt`/`StorageProvider` traits
in `src/io.rs`.

`docs/casc-format.md` is the authoritative on-disk format reference — it was
empirically verified against a real install and corrects several errors in
public documentation (wowdev.wiki, CascLib header comments). Trust it over
external docs; if reality disagrees with it, update it.

## Commands

- `cargo test` — unit tests + integration tests (the latter self-skip unless
  a real install exists at `C:\Program Files (x86)\StarCraft` or
  `BROODCASC_TEST_STORAGE`)
- `cargo clippy --all-targets --all-features -- -D warnings` and
  `cargo fmt --check` — both must stay clean
- `cargo build --target wasm32-unknown-unknown --no-default-features` — must
  keep building; CI checks it
- `cargo +nightly fuzz run <target> fuzz/seeds/<target>` (from repo root;
  targets: `blte_decode`, `encoding_parse`, `idx_parse`, `root_parse`,
  `config_parse`) — fuzzing for the untrusted-input parsers; see the README's
  "Fuzzing" section. Committed seeds under `fuzz/seeds/` are synthetic —
  never add real game-install bytes there.

## Conventions

- Parsers never panic on malformed input: bounds-check/`checked_*`
  everything and return `CascError::Malformed`
- Checksums (BLTE chunk MD5s, encoding page MD5s, whole-file CKey) are
  verified always-on
- Public types stay `Send + Sync` (`Arc` over `Rc`) for Bevy compatibility
