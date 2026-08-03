//! Generates the committed seed corpus under `fuzz/seeds/<target>/`.
//!
//! Every byte here is synthetic: constructed by hand from the format spec in
//! `docs/casc-format.md`, never copied or derived from a real game install.
//! That's a hard requirement — the seeds are committed to a public repo, and
//! the real archive data belongs to Blizzard.
//!
//! Run with `cargo run --bin seed_gen` from `fuzz/`.

use std::fs;
use std::path::{Path, PathBuf};

use md5::{Digest, Md5};

const MAGIC_BLTE: &[u8; 4] = b"BLTE";
const CHUNK_ENTRY_SIZE: usize = 24;
const KEY_SIZE: usize = 16;

fn main() {
    let seeds_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");

    let blte = blte_seeds();
    let encoding = encoding_seeds();
    let idx = idx_seeds();
    let root = root_seeds();
    let config = config_seeds();

    write_seeds(&seeds_root.join("blte_decode"), &blte);
    write_seeds(&seeds_root.join("encoding_parse"), &encoding);
    write_seeds(&seeds_root.join("idx_parse"), &idx);
    write_seeds(&seeds_root.join("root_parse"), &root);
    write_seeds(&seeds_root.join("config_parse"), &config);

    println!("verifying seeds parse with the real parsers...");
    for (name, bytes) in &blte {
        let result = broodcasc::blte::decode(bytes).map(|_| ());
        if *name == "nested_f_parent_size_mismatch.blte" {
            match result {
                Err(broodcasc::CascError::Malformed {
                    what: "BLTE chunk",
                    reason,
                }) if reason.contains("mode 'F'") => {}
                other => panic!("seed {name} produced unexpected result: {other:?}"),
            }
        } else {
            expect_ok(name, result);
        }
    }
    for (name, bytes) in &encoding {
        expect_ok(
            name,
            broodcasc::encoding::EncodingTable::parse(bytes).map(|_| ()),
        );
    }
    for (name, bytes) in &idx {
        expect_ok(
            name,
            broodcasc::idx::LocalIndex::from_files([bytes.as_slice()]).map(|_| ()),
        );
    }
    for (name, bytes) in &root {
        expect_ok(name, broodcasc::root::RootFile::parse(bytes).map(|_| ()));
    }
    // The two config seeds are format-specific: one is a `.build.info`-shaped
    // file, the other a build-config-shaped file. Verify each against its
    // own parser rather than both against both.
    for (name, bytes) in &config {
        let text = String::from_utf8_lossy(bytes);
        if name.contains("build_info") {
            expect_ok(name, broodcasc::config::BuildInfo::parse(&text).map(|_| ()));
        } else if name.contains("build_config") {
            expect_ok(
                name,
                broodcasc::config::BuildConfig::parse(&text).map(|_| ()),
            );
        }
    }

    println!("done");
}

fn expect_ok(name: &str, result: Result<(), broodcasc::CascError>) {
    if let Err(e) = result {
        panic!("seed {name} failed to parse with the real parser: {e}");
    }
}

fn write_seeds(dir: &Path, seeds: &[(&str, Vec<u8>)]) {
    fs::create_dir_all(dir).expect("create seed dir");
    for (name, bytes) in seeds {
        let path = dir.join(name);
        assert!(
            bytes.len() <= 4096,
            "{} is {} bytes, over the 4 KiB seed budget",
            path.display(),
            bytes.len()
        );
        fs::write(&path, bytes).expect("write seed");
        println!(
            "wrote {} ({} bytes)",
            relative(&path).display(),
            bytes.len()
        );
    }
}

fn relative(path: &Path) -> PathBuf {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .to_path_buf()
}

// ---------------------------------------------------------------------
// BLTE

fn zlib(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

/// Builds a single-chunk BLTE buffer (`header_size == 0`): magic + 0u32 +
/// mode byte + payload, with no chunk table.
fn build_single_chunk(mode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_BLTE);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(mode);
    out.extend_from_slice(payload);
    out
}

/// Builds a BLTE buffer with a chunk table from `(mode, payload,
/// decompressed_size)` triples, where `payload` is the pre-mode-byte data
/// (raw bytes for `N`, already zlib-compressed bytes for `Z`, or a complete
/// nested BLTE stream for `F`).
fn build_multi_chunk(chunks: &[(u8, &[u8], u32)]) -> Vec<u8> {
    let chunk_count = chunks.len() as u32;
    let header_size = 8 + 4 + CHUNK_ENTRY_SIZE * chunks.len();

    let chunk_datas: Vec<Vec<u8>> = chunks
        .iter()
        .map(|&(mode, payload, _)| {
            let mut d = Vec::with_capacity(1 + payload.len());
            d.push(mode);
            d.extend_from_slice(payload);
            d
        })
        .collect();

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC_BLTE);
    out.extend_from_slice(&(header_size as u32).to_be_bytes());
    out.push(0x0F);
    out.extend_from_slice(&chunk_count.to_be_bytes()[1..4]);
    for (&(_, _, decompressed_size), data) in chunks.iter().zip(&chunk_datas) {
        let md5: [u8; 16] = Md5::digest(data).into();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&decompressed_size.to_be_bytes());
        out.extend_from_slice(&md5);
    }
    for data in &chunk_datas {
        out.extend_from_slice(data);
    }
    out
}

fn blte_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = Vec::new();

    // Single chunk, mode 'N' (no chunk table).
    let raw = b"synthetic seed payload, mode N, no chunk table";
    seeds.push(("single_n.blte", build_single_chunk(b'N', raw)));

    // Single chunk, mode 'Z' (no chunk table).
    let text = b"synthetic seed payload, mode Z, compressible compressible compressible";
    seeds.push(("single_z.blte", build_single_chunk(b'Z', &zlib(text))));

    // Two-chunk buffer: one 'N' chunk, one 'Z' chunk, real chunk table.
    let n_payload = b"first chunk, stored raw (mode N)";
    let z_text = b"second chunk, zlib compressed (mode Z), compressible compressible";
    let z_payload = zlib(z_text);
    seeds.push((
        "two_chunk_n_z.blte",
        build_multi_chunk(&[
            (b'N', n_payload, n_payload.len() as u32),
            (b'Z', &z_payload, z_text.len() as u32),
        ]),
    ));

    // Three 'Z' chunks, exercising a longer chunk table.
    let a_text: &[u8] = b"chunk a chunk a chunk a chunk a chunk a";
    let b_text: &[u8] = b"chunk b chunk b chunk b chunk b chunk b";
    let c_text: &[u8] = b"chunk c chunk c chunk c chunk c chunk c";
    let a = zlib(a_text);
    let b = zlib(b_text);
    let c = zlib(c_text);
    seeds.push((
        "three_chunk_z.blte",
        build_multi_chunk(&[
            (b'Z', &a, a_text.len() as u32),
            (b'Z', &b, b_text.len() as u32),
            (b'Z', &c, c_text.len() as u32),
        ]),
    ));

    // Empty single-chunk payload (mirrors the real "empty file" case noted in
    // docs/casc-format.md §4.1: header_size==0, mode byte, zero bytes of data).
    seeds.push(("empty_n.blte", build_single_chunk(b'N', b"")));

    // Valid recursive frame: a table-form F chunk containing another complete
    // table-form BLTE stream.
    let nested_text = b"synthetic nested F-mode payload";
    let inner = build_multi_chunk(&[(b'N', nested_text, nested_text.len() as u32)]);
    seeds.push((
        "nested_f.blte",
        build_multi_chunk(&[(b'F', &inner, nested_text.len() as u32)]),
    ));

    // The outer F frame's declared decoded size disagrees with its valid
    // nested stream. This intentionally-valid-shaped seed must be rejected.
    seeds.push((
        "nested_f_parent_size_mismatch.blte",
        build_multi_chunk(&[(b'F', &inner, nested_text.len() as u32 + 1)]),
    ));

    seeds
}

// ---------------------------------------------------------------------
// Encoding table

fn synthetic_key(seed: u8) -> [u8; KEY_SIZE] {
    let mut out = [0u8; KEY_SIZE];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_mul(7).wrapping_add(i as u8);
    }
    out
}

struct RawEntry {
    ckey: [u8; KEY_SIZE],
    ekeys: Vec<[u8; KEY_SIZE]>,
    size: u64,
}

fn serialize_entry(e: &RawEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(e.ekeys.len() as u8);
    let size_bytes = e.size.to_be_bytes();
    out.extend_from_slice(&size_bytes[3..8]);
    out.extend_from_slice(&e.ckey);
    for ekey in &e.ekeys {
        out.extend_from_slice(ekey);
    }
    out
}

/// Packs `entries` (assumed CKey-sorted) into pages of `page_size_kb` KB and
/// emits a complete encoding-file buffer per `docs/casc-format.md` §5: header,
/// empty ESpec block, CKey page index, CKey pages. No EKey->ESpec table is
/// appended (that trailing region is optional and unread by this
/// implementation).
fn build_encoding(entries: &[RawEntry], page_size_kb: u16) -> Vec<u8> {
    let page_bytes = page_size_kb as usize * 1024;

    let mut pages: Vec<Vec<u8>> = Vec::new();
    let mut current = Vec::new();
    for e in entries {
        let serialized = serialize_entry(e);
        assert!(
            serialized.len() <= page_bytes,
            "seed_gen: entry too large for page"
        );
        if current.len() + serialized.len() > page_bytes {
            current.resize(page_bytes, 0);
            pages.push(std::mem::take(&mut current));
        }
        current.extend_from_slice(&serialized);
    }
    if !current.is_empty() {
        current.resize(page_bytes, 0);
        pages.push(current);
    }

    let mut page_index = Vec::new();
    for page in &pages {
        let first_ckey = &page[6..22]; // skip ekey_count(1) + file_size(5)
        page_index.extend_from_slice(first_ckey);
        let md5: [u8; 16] = Md5::digest(page).into();
        page_index.extend_from_slice(&md5);
    }

    let espec_block: Vec<u8> = Vec::new();

    let mut out = Vec::new();
    out.extend_from_slice(b"EN");
    out.push(1); // version
    out.push(KEY_SIZE as u8); // ckey_length
    out.push(KEY_SIZE as u8); // ekey_length
    out.extend_from_slice(&page_size_kb.to_be_bytes()); // ckey_page_size
    out.extend_from_slice(&page_size_kb.to_be_bytes()); // ekey_page_size (unused)
    out.extend_from_slice(&(pages.len() as u32).to_be_bytes()); // ckey_page_count
    out.extend_from_slice(&0u32.to_be_bytes()); // ekey_page_count (unused)
    out.push(0); // flags
    out.extend_from_slice(&(espec_block.len() as u32).to_be_bytes());
    out.extend_from_slice(&espec_block);
    out.extend_from_slice(&page_index);
    for page in &pages {
        out.extend_from_slice(page);
    }
    out
}

fn encoding_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = Vec::new();

    // Empty table: valid header, zero pages.
    seeds.push(("empty.enc", build_encoding(&[], 1)));

    // A handful of entries in a single small page, one with multiple EKeys.
    let small_entries = vec![
        RawEntry {
            ckey: synthetic_key(1),
            ekeys: vec![synthetic_key(101)],
            size: 111,
        },
        RawEntry {
            ckey: synthetic_key(2),
            ekeys: vec![synthetic_key(102), synthetic_key(103)],
            size: 222,
        },
        RawEntry {
            ckey: synthetic_key(3),
            ekeys: vec![synthetic_key(104)],
            size: 333,
        },
    ];
    seeds.push(("small_single_page.enc", build_encoding(&small_entries, 1)));

    // Enough entries (with a large-ish per-entry size straddling u32) to
    // force multiple 1 KB pages.
    let multi_entries: Vec<RawEntry> = (1..=30u8)
        .map(|i| RawEntry {
            ckey: synthetic_key(i),
            ekeys: vec![synthetic_key(i.wrapping_add(200))],
            size: (i as u64) * 1_000_000_000,
        })
        .collect();
    seeds.push(("multi_page.enc", build_encoding(&multi_entries, 1)));

    seeds
}

// ---------------------------------------------------------------------
// Local index (.idx v7)

const HEADER_BLOCK_SIZE: u32 = 0x10;
const IDX_HEADER_OFFSET: usize = 0x08;
const IDX_HEADER_LEN: usize = 16;
const IDX_ENTRIES_GUARD_OFFSET: usize = 0x20;
const IDX_ENTRIES_OFFSET: usize = 0x28;
const IDX_ENTRY_LEN: usize = 18;

fn hashlittle(data: &[u8], initval: u32) -> u32 {
    hashlittle2(data, initval, 0).0
}

fn hashlittle2(mut data: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    let seed = 0xDEAD_BEEFu32
        .wrapping_add(data.len() as u32)
        .wrapping_add(pc);
    let mut a = seed;
    let mut b = seed;
    let mut c = seed.wrapping_add(pb);

    while data.len() > 12 {
        a = a.wrapping_add(u32::from_le_bytes(data[0..4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(data[4..8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(data[8..12].try_into().unwrap()));
        jenkins_mix(&mut a, &mut b, &mut c);
        data = &data[12..];
    }

    if data.is_empty() {
        return (c, b);
    }
    for (index, &byte) in data.iter().enumerate() {
        let value = u32::from(byte) << ((index % 4) * 8);
        match index / 4 {
            0 => a = a.wrapping_add(value),
            1 => b = b.wrapping_add(value),
            2 => c = c.wrapping_add(value),
            _ => unreachable!("hashlittle tail is at most 12 bytes"),
        }
    }
    jenkins_final(&mut a, &mut b, &mut c);
    (c, b)
}

fn jenkins_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = (*a).wrapping_sub(*c);
    *a ^= (*c).rotate_left(4);
    *c = (*c).wrapping_add(*b);
    *b = (*b).wrapping_sub(*a);
    *b ^= (*a).rotate_left(6);
    *a = (*a).wrapping_add(*c);
    *c = (*c).wrapping_sub(*b);
    *c ^= (*b).rotate_left(8);
    *b = (*b).wrapping_add(*a);
    *a = (*a).wrapping_sub(*c);
    *a ^= (*c).rotate_left(16);
    *c = (*c).wrapping_add(*b);
    *b = (*b).wrapping_sub(*a);
    *b ^= (*a).rotate_left(19);
    *a = (*a).wrapping_add(*c);
    *c = (*c).wrapping_sub(*b);
    *c ^= (*b).rotate_left(4);
    *b = (*b).wrapping_add(*a);
}

fn jenkins_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(14));
    *a ^= *c;
    *a = (*a).wrapping_sub((*c).rotate_left(11));
    *b ^= *a;
    *b = (*b).wrapping_sub((*a).rotate_left(25));
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(16));
    *a ^= *c;
    *a = (*a).wrapping_sub((*c).rotate_left(4));
    *b ^= *a;
    *b = (*b).wrapping_sub((*a).rotate_left(14));
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(24));
}

fn idx_entry_block_hash(entries: &[u8]) -> u32 {
    let mut hi = 0;
    let mut lo = 0;
    for entry in entries.chunks_exact(IDX_ENTRY_LEN) {
        (hi, lo) = hashlittle2(entry, hi, lo);
    }
    hi
}

/// Builds a valid `.idx` v7 file from raw entry tuples: `(key9,
/// storage_offset as 5 raw big-endian bytes, encoded_size)`, including the
/// authoritative guarded-block hashes from docs/casc-format.md §2.2.
fn build_idx_file(segment_bits: u8, entries: &[([u8; 9], [u8; 5], u32)]) -> Vec<u8> {
    let entry_block_size = (entries.len() * IDX_ENTRY_LEN) as u32;

    let mut out = Vec::new();
    // File header guarded block.
    out.extend_from_slice(&HEADER_BLOCK_SIZE.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BlockHash, filled below

    // File header (16 bytes).
    out.extend_from_slice(&7u16.to_le_bytes()); // Revision
    out.push(0); // BucketIndex (unused)
    out.push(0); // Flags
    out.push(4); // SpanSizeBytes
    out.push(5); // SpanOffsetBytes
    out.push(9); // KeyBytes
    out.push(segment_bits); // SegmentBits
    out.extend_from_slice(&0x0000_00FF_C000_0000u64.to_le_bytes()); // MaxFileOffset
    let header_hash = hashlittle(
        &out[IDX_HEADER_OFFSET..IDX_HEADER_OFFSET + IDX_HEADER_LEN],
        0,
    );
    if segment_bits == 30 {
        assert_eq!(header_hash, 0x1bc0_046b, "documented idx header vector");
    }
    out[4..8].copy_from_slice(&header_hash.to_le_bytes());

    out.extend_from_slice(&[0u8; 8]); // padding to 0x10 alignment

    // Entries guarded block header.
    out.extend_from_slice(&entry_block_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BlockHash, filled below

    for (key9, storage_offset, encoded_size) in entries {
        out.extend_from_slice(key9);
        out.extend_from_slice(storage_offset);
        out.extend_from_slice(&encoded_size.to_le_bytes());
    }
    let entries_hash = idx_entry_block_hash(&out[IDX_ENTRIES_OFFSET..]);
    out[IDX_ENTRIES_GUARD_OFFSET + 4..IDX_ENTRIES_OFFSET]
        .copy_from_slice(&entries_hash.to_le_bytes());

    out
}

fn pack_storage_offset(archive: u16, offset: u64, segment_bits: u8) -> [u8; 5] {
    let v = (u64::from(archive) << segment_bits) | offset;
    let be = v.to_be_bytes();
    be[3..8].try_into().unwrap()
}

fn key9(byte: u8) -> [u8; 9] {
    [byte; 9]
}

fn idx_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = Vec::new();

    // A handful of ordinary entries across a few synthetic archives.
    let entries = [
        (key9(0x11), pack_storage_offset(0, 0x1000, 30), 1234u32),
        (key9(0x22), pack_storage_offset(1, 0x2000, 30), 5678u32),
        (key9(0x33), pack_storage_offset(2, 0x0FF0, 30), 42u32),
        (key9(0x44), pack_storage_offset(3, 0, 30), 4096u32),
    ];
    seeds.push(("few_entries.idx", build_idx_file(30, &entries)));

    // Includes a placeholder span (encoded_size <= 30), which the parser
    // should skip rather than error on.
    let with_placeholder = [
        (key9(0xAA), pack_storage_offset(0, 0, 30), 30u32), // placeholder, encoded_size == 30
        (key9(0xBB), pack_storage_offset(0, 4096, 30), 500u32),
    ];
    seeds.push((
        "with_placeholder.idx",
        build_idx_file(30, &with_placeholder),
    ));

    // Non-default segment_bits, exercising the offset-mask math.
    let non_default_segment = [(
        key9(0xCC),
        pack_storage_offset(900, 0x0007_FFFF, 20),
        999u32,
    )];
    seeds.push((
        "non_default_segment_bits.idx",
        build_idx_file(20, &non_default_segment),
    ));

    // Empty entry table (valid header, zero entries).
    seeds.push(("empty.idx", build_idx_file(30, &[])));

    seeds
}

// ---------------------------------------------------------------------
// Root file (plain text)

fn synthetic_ckey_hex(n: u32) -> String {
    format!("{n:032x}")
}

fn root_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = Vec::new();

    // A few CRLF-terminated records, `/`-separated synthetic paths.
    let mut text = String::new();
    for (i, path) in [
        "synthetic/seed/fileA.txt",
        "synthetic/seed/nested/dir/fileB.bin",
        "synthetic/seed/FileWithMixedCase.DAT",
    ]
    .iter()
    .enumerate()
    {
        text.push_str(path);
        text.push('|');
        text.push_str(&synthetic_ckey_hex(i as u32 + 1));
        text.push_str("\r\n");
    }
    // Include the well-known MD5-of-empty-string as a synthetic "empty file"
    // record (a universal constant, not derived from any game content).
    text.push_str("synthetic/seed/empty.chk|d41d8cd98f00b204e9800998ecf8427e\r\n");
    seeds.push(("few_records.root", text.into_bytes()));

    // Bare-LF variant (the parser tolerates it, per docs/casc-format.md §6.3).
    let mut lf_text = String::new();
    for i in 0..3u32 {
        lf_text.push_str(&format!(
            "synthetic/lf/file{i}.bin|{}\n",
            synthetic_ckey_hex(100 + i)
        ));
    }
    seeds.push(("bare_lf.root", lf_text.into_bytes()));

    seeds
}

// ---------------------------------------------------------------------
// .build.info / build config text

/// Builds a synthetic `.build.info` file: a typed header followed by rows,
/// built from parallel column/value lists (rather than hand-typed `|`
/// strings) so column counts can't silently drift apart.
fn build_info_text(columns: &[&str], rows: &[&[&str]]) -> String {
    for row in rows {
        assert_eq!(
            row.len(),
            columns.len(),
            "seed_gen: build_info row has {} fields, header has {}",
            row.len(),
            columns.len()
        );
    }
    let mut out = String::new();
    let header: Vec<String> = columns.iter().map(|c| format!("{c}!STRING:0")).collect();
    out.push_str(&header.join("|"));
    out.push_str("\r\n");
    for row in rows {
        out.push_str(&row.join("|"));
        out.push_str("\r\n");
    }
    out
}

fn config_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = Vec::new();

    // Synthetic .build.info: header + two rows, one active.
    let columns = [
        "Branch",
        "Active",
        "Build Key",
        "CDN Key",
        "Install Key",
        "IM Size",
        "CDN Path",
        "CDN Hosts",
        "CDN Servers",
        "Tags",
        "Armadillo",
        "Last Activated",
        "Version",
        "KeyRing",
        "Product",
    ];
    let inactive_row: [&str; 15] = [
        "xx",
        "0",
        "00000000000000000000000000000000",
        "11111111111111111111111111111111",
        "",
        "",
        "tpr/fake",
        "fake.example.invalid",
        "http://fake.example.invalid",
        "",
        "",
        "",
        "0.0.0.0",
        "",
        "",
    ];
    let active_row: [&str; 15] = [
        "yy",
        "1",
        "22222222222222222222222222222222",
        "33333333333333333333333333333333",
        "",
        "",
        "tpr/fake",
        "fake.example.invalid",
        "http://fake.example.invalid",
        "Windows synthetic",
        "",
        "",
        "1.0.0.1",
        "",
        "",
    ];
    let build_info = build_info_text(&columns, &[&inactive_row, &active_row]);
    seeds.push(("synthetic_build_info.txt", build_info.into_bytes()));

    // Synthetic build config: comments + key/value pairs mirroring the real
    // key names, but with entirely fabricated hashes.
    let build_config = "\
# Synthetic build configuration (fuzz seed, not from a real install)

root = 44444444444444444444444444444444
install = 55555555555555555555555555555555 66666666666666666666666666666666
install-size = 1000 900
download = 77777777777777777777777777777777 88888888888888888888888888888888
download-size = 2000 1900
size = 99999999999999999999999999999999 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
size-size = 3000 2900
encoding = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccc
encoding-size = 4000 3900
patch = dddddddddddddddddddddddddddddddd
patch-size = 500
build-name = 0.0.0-synthetic
build-uid = zz
build-product = SyntheticProduct
build-comments = seed for fuzzing, not real build data
";
    seeds.push((
        "synthetic_build_config.txt",
        build_config.as_bytes().to_vec(),
    ));

    seeds
}
