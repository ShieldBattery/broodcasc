# CASC (local storage) format — implementation spec for StarCraft: Remastered

Target: a pure-Rust **read-only** reader for a local CASC install of Blizzard product `s1`
(StarCraft: Remastered). Scope is local disk only; no CDN/online fetching.

**Verification basis.** Every "verified" note in this document was confirmed empirically against a
real install at `C:\Program Files (x86)\StarCraft`, build `1.23.10.13515-retail`,
build key `864772b9ff94f6d372aa4ee90ee2f8ab`. The full pipeline
(`.build.info` → build config → `.idx` → `data.###` → BLTE → ENCODING → ROOT → file bytes)
was implemented in a throwaway Python script and MD5-validated end to end.

Cross-reference source: [CascLib](https://github.com/ladislav-zezula/CascLib) —
`src/CascStructs.h`, `src/CascIndexFiles.cpp`, `src/CascOpenStorage.cpp`,
`src/CascReadFile.cpp`, `src/CascDecrypt.cpp`, `src/CascRootFile_Text.cpp`, `src/CascFiles.cpp`.

## 0. Conventions and terminology

| Term | Meaning |
|---|---|
| **CKey** | Content Key. MD5 of the *decoded* (final) file content. 16 bytes. |
| **EKey** | Encoded Key. An opaque 16-byte address for an encoded representation, emitted by the CASC encoding pipeline and often truncated to 9 bytes in local storage. It is **not** the MD5 of the stored bare BLTE bytes in SC:R. |
| **span / archive entry** | One blob inside a `data.###` file: 30-byte header + BLTE stream. |
| **BLTE** | The block-compression container every stored file is wrapped in. |
| **bucket** | One of 16 local index shards, `00`..`0f`. |

Endianness is *mixed and inconsistent*. Rule of thumb, but always check the table:

- `.idx` **headers** and the `EncodedSize` field → **little-endian**.
- `.idx` **storage offset** field → **big-endian**.
- Everything inside **BLTE**, **ENCODING**, **INSTALL**, **DOWNLOAD** → **big-endian**.
- The 30-byte span header's `EncodedSize` → **little-endian**.

All actual MD5 values (CKeys, BLTE chunk hashes, ENCODING page hashes) are stored as raw bytes in
the order produced by MD5. EKeys are opaque identifiers rather than bare-BLTE MD5s; an EKey in a
30-byte span header is stored byte-**reversed**.

---

## 1. Local storage discovery

### 1.1 Directory layout (verified)

```
C:\Program Files (x86)\StarCraft\
  .build.info                 <- pipe-delimited, names the active build
  .product.db  .patch.result  Launcher.db     (hidden, ignorable)
  Data\
    config\<h0h1>\<h2h3>\<hash>     build configs, cdn configs, patch configs
    data\
      000000001b.idx .. 0f0000001b.idx        16 local index files (bucket 00..0f)
      data.000 .. data.010                    archives, each <= 0x40000000 bytes
      shmem                                   free-space bookkeeping; IGNORE for reading
    indices\<md5>.index                        CDN archive indices; NOT needed locally
    ecache\                                    tiny secondary CASC cache; IGNORE
    s1\                                        legacy/secondary idx set (v8); IGNORE
    patch\                                     empty on this install
```

### 1.2 `.build.info`

UTF-8 text, CRLF-terminated lines, `|`-delimited. Line 1 is a typed header, lines 2..n are rows.

Header column syntax: `Name!TYPE:width`, where `TYPE` ∈ `{STRING, HEX, DEC}` and `width` is a byte
width (`0` = variable). The types matter only for validation; for reading, treat every cell as text.

Actual header from the verified install:

```
Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Install Key!HEX:16|IM Size!DEC:4|
CDN Path!STRING:0|CDN Hosts!STRING:0|CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|
Last Activated!STRING:0|Version!STRING:0|KeyRing!HEX:16|Product!STRING:0
```

Actual data row (truncated):

```
us|1|864772b9ff94f6d372aa4ee90ee2f8ab|bd4a0f876fdbf39666f0fae661e54974|||tpr/sc1live|...|1.23.10.13515||
```

**Picking the active build**: select the row whose `Active` column == `1`. If several products
share one install directory, additionally filter by `Product`; note that on this SC:R install the
`Product` column is *empty* — do not require it. If exactly one row exists, just use it.

Columns you need:

| Column | Use |
|---|---|
| `Build Key` | hex MD5 → path of the **build config**. **Required.** |
| `CDN Key` | hex MD5 → path of the CDN config (archive list). Not needed for local reads. |
| `Version`, `Branch`, `Tags` | informational |

**Empty cells are normal** (`Install Key` and `IM Size` are empty here). A trailing empty line
follows the last row.

CascLib reference: `CascFiles.cpp`, `LoadBuildInfo()` / `CASC_CSV`.

### 1.3 Config file path derivation

For any config hash `h` (32 lowercase hex chars):

```
<StorageRoot>\Data\config\<h[0..2]>\<h[2..4]>\<h>
```

Verified: `864772b9…` → `Data\config\86\47\864772b9ff94f6d372aa4ee90ee2f8ab`.
The same `xx\yy\hash` scheme is used by `indices\` (flat there, actually) and by CDN caches.

### 1.4 Build config

Plain text. `#` starts a comment line. Lines are `key = value`, value is one or more
space-separated tokens. Verified content of `864772b9…`:

```
# Build Configuration

root = b96213f265684e16db5a8552eba1be09
install = 507094afe0cfb221bcd106f26e288cfa 311e6a69ea379077313e68b06d9126ed
install-size = 105144 100737
download = 45886a5df9c96d8d5ab6b46a93f60680 f04fd2ace1b4b204eb0b9baf05678e80
download-size = 1093564 948966
size = 996dba1b304873d353413d015ec54272 958428bb9ce4416ccfafde3b961a830f
size-size = 705785 616121
encoding = 6f0a25d319069d1b09bc4034820e5ae0 b135dde729b026904eeb4b7e76332750
encoding-size = 2757673 2757842
patch-index = df4c0ae0d32fe2a538936d2956b8ac09 55b3cbccbdf39e72afb934250933f6d7
patch-index-size = 5598 4805
patch = 155d14754816b49d2a6914f37122a718
patch-size = 9261
patch-config = 44c6c6219e2d1e94b9e2b815eddd0579
build-name = 1.23.10.13515-retail
build-uid = s1
build-product = StarCraft1
build-comments = prod build for new 2025 wildcard cert
build-playbuild-installer = ngdptool_casc2
```

**Value pair semantics (critical):**

| Form | Token 1 | Token 2 |
|---|---|---|
| `<name> = <hash1> <hash2>` | **CKey** (MD5 of decoded content) | **EKey** (opaque address of the encoded representation) |
| `<name>-size = <n1> <n2>` | decoded (content) size | encoded size, **excluding** the 30-byte span header |
| `root = <hash>` | **CKey only** — must be resolved via ENCODING | — |
| `patch = <hash>` | **EKey only** (raw file, not BLTE) | — |

Verified: decoded ENCODING is exactly 2 757 673 bytes (== `encoding-size` token 1) and
its MD5 == `6f0a25d3…` (== token 1 of `encoding`). The `.idx` records the ENCODING span's
encoded size as 2 757 872 == `2757842 + 30`, confirming that `*-size` token 2 excludes the
30-byte span header while the `.idx` `EncodedSize` includes it. Same relation holds for
`install`: 100 737 + 30 == 100 767.

Keys that matter for reading: **`encoding`** (take token 2, the EKey) and **`root`**
(a CKey; must go through ENCODING). `install` is optional (see §8). `download`, `size`,
`patch*` are not needed.

CascLib reference: `CascFiles.cpp`, `ParseFile_BuildDb()` / `LoadBuildConfiguration()`.

---

## 2. Local index files (`.idx`), version 7

### 2.1 Filename convention

`%02x%08x.idx` — 10 hex chars: **2 hex digits of bucket index** (`00`..`0f`) followed by
**8 hex digits of a monotonically increasing version/sequence number**.

Verified filenames: `000000001b.idx` (bucket 0, ver 0x1b), `070000001a.idx` (bucket 7, ver 0x1a),
`080000001e.idx` (bucket 8, ver 0x1e). All 16 buckets present, each file exactly 131 072 bytes
(0x20000, pre-allocated; the tail past the entry block is zero padding).

**If more than one file exists for the same bucket, use the one with the highest version number**
and ignore the rest. Blizzard writes a new file and deletes the old one, but crashes can leave
stale files behind.

### 2.2 File layout (v7)

```
+0x00  guarded-block header for the file header
+0x08  FILE_INDEX_HEADER_V2 (16 bytes)
+0x18  8 bytes of zero padding   (align to 0x10)
+0x20  guarded-block header for the entry array
+0x28  entry array: N * 18 bytes
 ...   zero padding to end of file
```

**Guarded block header** (`FILE_INDEX_GUARDED_BLOCK`, `CascStructs.h`):

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0 | 4 | LE | `BlockSize` — length of the guarded payload in bytes |
| +4 | 4 | LE | `BlockHash` — Jenkins `hashlittle` / `hashlittle2` over the payload |

**File header block** (`FILE_INDEX_HEADER_V2`, at +0x08, 16 bytes):

| Offset | Size | Endian | Field | Verified value |
|---|---|---|---|---|
| +0x00 | 2 | LE | `Revision` — must be `0x0007` | `7` |
| +0x02 | 1 | — | `BucketIndex` — must equal the filename's first byte | `0`..`15` |
| +0x03 | 1 | — | `Flags` — must be `0` | `0` |
| +0x04 | 1 | — | `SpanSizeBytes` — width of `EncodedSize` | `4` |
| +0x05 | 1 | — | `SpanOffsetBytes` — width of `StorageOffset` | `5` |
| +0x06 | 1 | — | `KeyBytes` — width of the truncated EKey | `9` |
| +0x07 | 1 | — | `SegmentBits` — bits of *offset* inside `StorageOffset` | `30` |
| +0x08 | 8 | LE | `MaxFileOffset` — max addressable byte | `0x000000FFC0000000` (1023 GiB) |

Verified raw header bytes of `000000001b.idx`:

```
00000000  10 00 00 00  6b 04 c0 1b  07 00 00 00  04 05 09 1e
00000010  00 00 00 c0  ff 00 00 00  00 00 00 00  00 00 00 00
00000020  ac ad 00 00  bf b6 65 0a  00 06 40 20  0a d2 5e f8
00000030  7e 01 8b ea  86 7f c8 da  01 00 …
```

i.e. `HeaderHashSize = 0x10`, `HeaderHash = 0x1bc0046b`, then version 7 / bucket 0 / flags 0 /
4,5,9,30 / `MaxFileOffset = 0xFFC0000000`; 8 zero bytes; then `BlockSize = 0xADAC = 44460`
(= 2470 entries × 18) and `BlockHash = 0x0A65B6BF`; then the first entry.

`EntryLength = KeyBytes + SpanOffsetBytes + SpanSizeBytes = 9 + 5 + 4 = 18`.
`EntryCount = BlockSize / EntryLength`.

**Hash algorithms (verified byte-exact):**

- File header block: `hashlittle(headerBlock, 16, initval=0)` → must equal `HeaderHash` at +0x04.
  Verified `0x1bc0046b`.
- Entry array: Bob Jenkins `hashlittle2` applied **per entry, chained**, taking the returned
  *high* word (`pc`) as the result:
  ```
  hi = 0; lo = 0
  for each entry (18 bytes):  (hi, lo) = hashlittle2(entry, hi, lo)
  assert hi == BlockHash
  ```
  Verified `0x0A65B6BF`. (CascLib `CaptureGuardedBlock2()` also accepts an alternative
  `hashlittle`-chained variant produced by the `blizzget` tool; SC:R uses the Blizzard variant.)
  For a read-only reader these checks are optional.

### 2.3 Entry layout (18 bytes)

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x00 | 9 | — | `EKey[9]` — **first 9 bytes of the 16-byte EKey** |
| +0x09 | 5 | **BE** | `StorageOffset` — packed archive index + byte offset |
| +0x0E | 4 | **LE** | `EncodedSize` — total span size **including** the 30-byte header |

> **Discrepancy flagged.** `CascStructs.h`'s `FILE_EKEY_ENTRY` comments claim `EncodedSize` is
> big-endian. It is **little-endian** — CascLib's own code reads it with
> `ConvertBytesToInteger_4_LE()` (`CascIndexFiles.cpp: CopyEKeyEntry()`), and LE is what matches
> the real data. The comment is wrong; the code is right.

**Unpacking `StorageOffset`** (40-bit big-endian integer `V`, with `SegmentBits = 30`):

```
archiveIndex = V >> SegmentBits            // 10 bits  -> data.NNN , NNN in 0..1023
fileOffset   = V & ((1 << SegmentBits)-1)  // 30 bits  -> byte offset, < 0x40000000
```

Verified: first entry of bucket 0 has `StorageOffset = 0x018BEA867F` → archive 6, offset
0x0BEA867F (199 919 231) — inside `data.006` (759 759 118 bytes). Also verified that
`data.004` is 1 073 741 823 bytes == `2^30 - 1`, exactly the 30-bit offset ceiling.

### 2.4 Bucket selection

```rust
fn bucket_of(ekey: &[u8]) -> u8 {
    let i = ekey[..9].iter().fold(0u8, |a, b| a ^ b);
    (i & 0x0f) ^ (i >> 4)
}
```

Verified against all 40 718 entries: **40 542 match, 176 do not.** The 176 exceptions are *not*
random — they are the synthetic placeholder entries described in §3.3 (11 archives × 16 buckets),
whose stored bucket is consistently `computed + 1 (mod 16)`.

**Recommendation: do not use the bucket function for lookup.** Load all 16 `.idx` files and merge
their entries into one `HashMap<[u8;9], (archive, offset, size)>`. This is what CascLib does
(`CascIndexFiles.cpp: BuildMapOfArchiveIndices()` → `hs->IndexEKeyMap`) and it is immune to the
placeholder anomaly. Verified: 40 718 entries, **zero duplicate 9-byte keys** across all buckets.

Entries within a file are sorted by the 9-byte key, so a binary search per bucket is possible if
you prefer not to build a map — but you would then need the (broken for 176 entries) bucket
function, so the merged map is safer.

### 2.5 The 9-byte EKey caveat

The `.idx` stores only the **first 9 bytes** of the EKey. Always truncate the 16-byte EKey from
ENCODING/build-config to 9 bytes before lookup. 9 bytes = 72 bits; collisions are not a practical
concern (verified: none in this storage), but the reader must not attempt a 16-byte match here.

See also the *reverse* caveat in §3.2: the span header in `data.###` sometimes stores a truncated
EKey too, so only the 9-byte address prefix can be compared there; this is not a full-key integrity
check.

---

## 3. `data.###` archive framing

### 3.1 File naming and limits

`data.%03d` (decimal, 3 digits): `data.000` … `data.010` on the verified install. Maximum size is
`0x40000000` (1 GiB) because the offset field is 30 bits. Archive index comes from the top 10 bits
of `StorageOffset`.

### 3.2 The 30-byte span header (`BLTE_ENCODED_HEADER`)

`StorageOffset`'s `fileOffset` points at **this header**, not at the `BLTE` magic.
`BLTE_HEADER_DELTA = 0x1E = 30` (`CascStructs.h`).

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x00 | 16 | — | `EKey` of the following BLTE data, **stored byte-reversed** |
| +0x10 | 4 | **LE** | `EncodedSize` — 30 + length of the BLTE stream |
| +0x14 | 1 | — | `field_14` — `1` if the span carries no data (placeholder), else `0` |
| +0x15 | 1 | — | `field_15` — always `0` |
| +0x16 | 4 | LE | `JenkinsHash` — `hashlittle2` of bytes +0x00..+0x15 |
| +0x1A | 4 | LE | `Checksum` — see CascLib `VerifyHeaderSpan()` |
| +0x1E | … | | the BLTE stream begins here |

**Byte-reversal**: read 16 bytes, reverse them, and you get the EKey.
Verified at `data.000` offset 0:

```
58 43 a2 ff 71 e8 c2 a1 be ff 0e 82 9b 00 00 07   1e 00 00 00   01   00   bd b2 a5 bb   a6 bc 92 91
```

reversed → EKey `0700009b820effbea1c2e871ffa24358`, `EncodedSize = 0x1E = 30`, `field_14 = 1`.

> **Gotcha (verified, not documented by CascLib): the header EKey is sometimes truncated.**
> Of 40 542 real spans, **38 877 carry the full 16-byte EKey and 1 665 carry only the first 9 bytes
> followed by 7 zero bytes.** Example: `locales/esES/.../*.ogg` has ENCODING EKey
> `9abe09444e5f69c0c5b5385f56d81b6f` but its span header holds
> `9abe09444e5f69c0c500000000000000`.
> **Only ever compare the first 9 bytes of this field.** A 16-byte assertion will fail on ~4 % of
> the storage.

`EncodedSize` here always equals the `.idx` entry's `EncodedSize` (verified: 0 mismatches across
all 40 718 entries). Read `EncodedSize - 30` bytes starting at `fileOffset + 30` to get the
complete BLTE stream.

### 3.3 Placeholder spans

176 entries (11 archives × 16 buckets) have `EncodedSize == 30` and `field_14 == 1`: a header with
no BLTE payload at all. These are the free-space/bookkeeping stubs Blizzard writes at the head of
each `data.###`. They are the same 176 entries that violate the bucket hash rule (§2.4).
**Skip any entry whose `EncodedSize <= 30`.** They are never referenced from ENCODING.

### 3.4 Non-BLTE spans

Exactly one indexed span in the verified storage does **not** start with `BLTE`: EKey prefix
`155d14754816b49d2a` (= `patch = 155d1475…` from the build config), which begins with
`50 41 02 10` (`"PA"` + version) — a Blizzard patch manifest stored raw. It is not reachable from
ROOT. A reader should simply error/skip on non-`BLTE` magic rather than assume it can't happen.

---

## 4. BLTE

### 4.1 Container header

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x00 | 4 | — | Magic `"BLTE"` = `42 4C 54 45` |
| +0x04 | 4 | **BE** | `HeaderSize` — total size of this header incl. the chunk table; **`0` means "single chunk, no table"** |

If `HeaderSize != 0`, the following 4 bytes are present:

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x08 | 1 | — | `Flags` — always `0x0F` (verified: all 40 540 multi-chunk spans) |
| +0x09 | 3 | **BE** | `ChunkCount` — 24-bit big-endian |

Then `ChunkCount` entries of 24 bytes each (`BLTE_FRAME`):

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x00 | 4 | **BE** | `EncodedSize` — bytes of this chunk in the stream, **including the mode byte** |
| +0x04 | 4 | **BE** | `ContentSize` — decoded size of this chunk |
| +0x08 | 16 | — | `ChunkMD5` — MD5 of the encoded chunk **including the mode byte** |

Sanity check: `12 + ChunkCount * 24 == HeaderSize`. Chunk data starts at `HeaderSize` and the
chunks are stored back-to-back in table order.

**Single-chunk form (`HeaderSize == 0`)**: there is no flags byte, no chunk count, no table, and
no MD5. Chunk data starts at offset 8 and runs to the end of the span
(`spanEncodedSize - 30 - 8` bytes).
Verified: this occurs exactly once in the storage (EKey prefix `d811d2588acfe0aa92`, span size 39
→ 30 header + 4 magic + 4 hsize + 1 mode byte + 0 data = an empty file). Rare, but you must
support it.

Max observed `ChunkCount`: 1 863. Chunk `ContentSize` is typically 256 KiB or 64 KiB (see the
ESpec strings in §5.2).

### 4.2 Chunk modes

The **first byte of each chunk** selects the codec; the rest of the chunk is codec input.

| Byte | Name | Handling |
|---|---|---|
| `'N'` (0x4E) | none | Copy bytes `[1..]` verbatim. |
| `'Z'` (0x5A) | zlib | `inflate(bytes[1..])` — raw **zlib** stream with the 2-byte zlib header (`78 9C` etc.), *not* raw deflate. |
| `'F'` (0x46) | frame | `bytes[1..]` is itself a complete nested BLTE stream; decode recursively. **CascLib does not implement this** (`CascReadFile.cpp` case `'F'` returns not-supported). Not present in SC:R. |
| `'E'` (0x45) | encrypted | See §4.3. Not present in SC:R. |
| `'4'` (0x34) | LZ4 | Seen in some newer Blizzard products only; **not in CascLib master**, not in SC:R. |

**Verified for SC:R: the entire storage uses only `'Z'` and `'N'`.** Scanning the first 16 KiB of
every one of the 40 718 spans produced 45 210 `'Z'` chunks and 7 `'N'` chunks and **zero** `'E'`,
`'F'`, or `'4'`. A SC:R-only reader can implement just `N` + `Z`; still emit a clear error for the
others rather than misparsing.

### 4.3 `'E'` — encryption (reference only; unused by SC:R)

Layout after the `'E'` mode byte (`CascDecrypt.cpp: CascDecrypt()`):

| Size | Field |
|---|---|
| 1 | `KeyNameSize` — must be `0` or `8` |
| `KeyNameSize` | `KeyName`, **little-endian** u64 — index into the product's key ring |
| 1 | `IVSize` — must be `4` or `8` |
| `IVSize` | `IV`, zero-extended to 8 bytes |
| 1 | `EncryptionType` — `'S'` = Salsa20, `'A'` = ARC4 (**CascLib implements only `'S'`**) |
| rest | ciphertext |

Before decrypting, the IV is XORed with the chunk index:
`for i in 0..4 { IV[i] ^= (chunkIndex >> (8*i)) as u8 }`. Key size is 16 bytes. The plaintext is
itself a mode-prefixed block (normally `'N'` or `'Z'`), so re-dispatch on its first byte.

### 4.4 Validation

If a chunk table is present, `MD5(encodedChunkIncludingModeByte) == ChunkMD5`. Verified to hold
for every chunk of ENCODING, ROOT, INSTALL and a random sample of content files.

The decoded whole-file bytes must MD5 to the **CKey**. Verified: decoded ENCODING → `6f0a25d3…`
(matches build config), decoded ROOT → `b96213f2…` (matches build config), and 5 randomly sampled
content files each matched the CKey from ROOT and the `ContentSize` from ENCODING exactly.

Do **not** validate an object by checking `MD5(storedBareBLTE) == EKey`; that relation does not hold
for this SC:R storage (see the measured ENCODING vector in §5). The layers establish different
properties:

| Layer | What it establishes |
|---|---|
| EKey → `.idx` entry → span-header EKey prefix | Addressing consistency: the located span is the one indexed for that opaque encoded key. Local indices and many span headers carry only the first 9 bytes. |
| `.idx` guarded hashes and BLTE chunk MD5s | Detection of accidental corruption in the guarded index blocks and encoded chunks. These values travel with the data and are not an authenticity or trust anchor. |
| Whole-file CKey | End-to-end integrity of the fully decoded content. Recompute it before returning a whole decoded object. MD5 is part of the format and detects corruption, but does not authenticate data against an active attacker. |

---

## 5. The ENCODING manifest

Found via the build config's `encoding` line, **token 2 = EKey**. This is the one file you look up
by EKey directly in the `.idx`, bypassing ENCODING itself (chicken-and-egg resolution).

Verified: EKey `b135dde729b026904eeb4b7e76332750` → bucket lookup → `data.005` @ `0x3E89C843`,
span size 2 757 872 → BLTE-decode → 2 757 673 bytes, MD5 `6f0a25d319069d1b09bc4034820e5ae0`.

**EKey is not the MD5 of the stored bare BLTE (verified).** The 2 757 842 BLTE bytes beginning at
`data.005` offset `0x3E89C843 + 30` have MD5
`41a0bab262d0ca3d03ee21e40dd54974`, not the EKey
`b135dde729b026904eeb4b7e76332750`. Hashing after excluding the first 8 BLTE header bytes, or
hashing only the complete chunk table, also does not produce the EKey. Treat an EKey as an opaque
encoded-representation address supplied by the build config or ENCODING manifest. Its exact writer
derivation is not established here; it may incorporate an encoding header/specification or other
pipeline metadata that is absent from the stored bare BLTE, so readers must not attempt to
recompute or authenticate it from those bytes.

### 5.1 Header (22 bytes, at offset 0 of the decoded file)

| Offset | Size | Endian | Field | Verified |
|---|---|---|---|---|
| +0x00 | 2 | — | Magic `"EN"` = `45 4E` | ✓ |
| +0x02 | 1 | — | `Version` — must be 1 | `1` |
| +0x03 | 1 | — | `CKeyLength` — 0x10 | `16` |
| +0x04 | 1 | — | `EKeyLength` — 0x10 | `16` |
| +0x05 | 2 | **BE** | `CKeyPageSizeKB` — page size in KiB | `4` (→ 4096 B) |
| +0x07 | 2 | **BE** | `EKeyPageSizeKB` | `4` (→ 4096 B) |
| +0x09 | 4 | **BE** | `CKeyPageCount` | `403` |
| +0x0D | 4 | **BE** | `EKeyPageCount` | `265` |
| +0x11 | 1 | — | `unknown` — asserted 0 | `0` |
| +0x12 | 4 | **BE** | `ESpecBlockSize` | `95` |

Verified first 32 bytes of the decoded ENCODING file:

```
45 4e 01 10 10 00 04 00 04 00 00 01 93 00 00 01 09 00 00 00 00 5f 62 3a 32 35 36 4b 2a 3d 7a 00
 E  N  1 16 16 |--4--| |--4--| |---403---| |---265---|  0 |---95---| "b:256K*=z\0"…
```

### 5.2 Overall file layout

```
off = 0                                        header, 22 bytes
off = 22                                       ESpec string block, ESpecBlockSize bytes
off = 22 + ESpecBlockSize                      CKey page index, CKeyPageCount * 32 bytes
   + CKeyPageCount*32                          CKey pages,      CKeyPageCount * CKeyPageSize
   + CKeyPageCount*CKeyPageSize                EKey page index, EKeyPageCount * 32 bytes
   + EKeyPageCount*32                          EKey pages,      EKeyPageCount * EKeyPageSize
   + EKeyPageCount*EKeyPageSize                trailing ESpec string for ENCODING itself
```

Verified offsets for this build: ESpec at 22 (95 B), CKey page index at 117, CKey pages at 13 013,
EKey page index at 1 663 701, EKey pages at 1 672 181, trailer at 2 757 621 (52 B).

The 52-byte trailer is the ESpec of the ENCODING file itself and is a perfect self-description of
the layout above:

```
b:{22=n,95=z,12896=n,1650688=n,8480=n,1085440=n,*=z}
```

(22 header, 95 espec, 403×32 = 12896, 403×4096 = 1650688, 265×32 = 8480, 265×4096 = 1085440.)

The **ESpec block** is a sequence of NUL-terminated ASCII strings describing how files were
encoded. First bytes verified: `b:256K*=z\0 b:64K*=z:6\0 b:{11=n,947914=n,145639=z}\0 …`.
**A reader can ignore it entirely** — the chunk table in each BLTE stream is self-describing.

### 5.3 CKey page index (32 bytes per entry)

| Offset | Size | Field |
|---|---|---|
| +0x00 | 16 | `FirstCKey` — the first CKey stored in the corresponding page |
| +0x10 | 16 | `PageMD5` — MD5 of the whole 4096-byte page |

Verified page[0]: `FirstCKey = 0000dc8515b1f317913f97da0ef177f5`,
`PageMD5 = d9a3a5dafa533c26a2d3836a4e1dc595`, and the first entry of page 0 indeed carries that
CKey. Pages are sorted by CKey ascending, so the index supports binary search without loading
every page.

### 5.4 CKey page entry (variable length)

Entries are packed back-to-back inside a page; the remainder of the page is zero padding.
**Stop parsing a page when the key-count byte is 0** (or when you run past the page end).

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x00 | 1 | — | `EKeyCount` — number of EKeys that follow |
| +0x01 | 5 | **BE** | `ContentSize` — decoded file size, **40-bit big-endian** |
| +0x06 | 16 | — | `CKey` |
| +0x16 | 16×`EKeyCount` | — | `EKey[EKeyCount]` |

Total length = `22 + 16 * EKeyCount`.

Verified first entry of CKey page 0:

```
01  00 00 00 02 21  00 00 dc 85 15 b1 f3 17 91 3f 97 da 0e f1 77 f5  0c0cb9d32fb127949f43ad8d877c8bbe
^1  ^ size = 545    ^ CKey 0000dc85…                                 ^ EKey
```

> **Discrepancy flagged (CascLib vs. reality).** `CascStructs.h`'s `FILE_CKEY_ENTRY` declares
> `USHORT EKeyCount; BYTE ContentSize[4];` and `LoadEncodingCKeyPage()` advances by
> `2 + 4 + CKeyLength + EKeyCount*EKeyLength` — i.e. a 2-byte LE count and a 4-byte BE size at
> +0x02. Numerically this is **identical** to the layout above whenever the count is < 256 *and*
> the file is < 4 GiB, because the disputed byte at +0x01 is the high byte of the 40-bit size and
> is always 0 in practice. wowdev.wiki documents it as `uint16 keyCount; uint40 fileSize`, which is
> **wrong** — parsing the count as a 2-byte big-endian value yields 256 for the verified first
> entry and desynchronises immediately (empirically confirmed).
> **Implement `u8 count` + `u40 BE size`**: it is a strict superset of CascLib's reading and
> handles files ≥ 4 GiB correctly.

Verified totals for this build: **43 091 CKey→EKey entries**, and **every single one has exactly
one EKey** (`EKeyCount == 1`). Multi-EKey entries do occur in other products (CascLib cites
Overwatch build 24919); handle `EKeyCount > 1` by trying each EKey in turn against the `.idx` and
using the first that resolves locally.

### 5.5 EKey (ESpec) pages — skippable

Same 32-byte page-index structure (`FirstEKey` + `PageMD5`), then fixed 25-byte entries:

| Offset | Size | Endian | Field |
|---|---|---|---|
| +0x00 | 16 | — | `EKey` |
| +0x10 | 4 | **BE** | `ESpecIndex` — index into the ESpec block (counting NUL-terminated strings) |
| +0x14 | 5 | **BE** | `EncodedSize` — 40-bit |

Verified first entry: EKey `0000c52f89508383fadc92e1a110860c`, `ESpecIndex = 1`,
`EncodedSize = 0x2B83D = 178 237`. **Not needed for reading** — the `.idx` already gives you the
encoded size. Skip this whole region.

### 5.6 Lookup

Build `HashMap<[u8;16], (u64 contentSize, Vec<[u8;16]> ekeys)>` from all CKey pages. 43 091 entries
is trivially small (~2 MB). Alternatively binary-search the page index and parse one 4 KiB page.

---

## 6. The SC:R ROOT file

**SC:R uses the plain-text `TRootHandler_SC1` format** — `CascRootFile_Text.cpp`,
`RootHandler_CreateStarcraft1()`. It is *not* MNDX (that's Heroes of the Storm), not TVFS, not
the WoW binary root, not the Overwatch format.

CascLib dispatch order (`CascOpenStorage.cpp` ~line 940): MNDX → Diablo3 → TVFS → WoW → Overwatch
→ **Starcraft1** → WoW fallback. Detection for SC1 (`TRootHandler_SC1::IsRootFile`) reads the first
CSV line and requires **2 or 3 `|`-separated columns** with the second column being exactly
32 characters (an MD5 string).

### 6.1 Resolution

`root = b96213f265684e16db5a8552eba1be09` is a **CKey only**. Resolve it through ENCODING:

```
CKey b96213f265684e16db5a8552eba1be09
  -> ENCODING -> contentSize 4668442, EKey a1dafecb51bc2cb22d3e682f46750cd6
  -> .idx     -> data.004 @ 0x11219E95, encodedSize 1630659
  -> BLTE     -> 4 668 442 bytes, MD5 b96213f2… ✓
```
(all values verified)

### 6.2 Format (verified)

ASCII text. **CRLF (`\r\n`) line terminators.** One record per line:

```
<path>|<32-hex-char CKey>
```

**Verified first 400 bytes of the decoded root, byte for byte:**

```
locales/enUS/Assets/campaign/EXPZerg/Zerg08/staredit/wav/zovtra01.ogg|316b0274bf2dabaa8db60c3ff1270c85\r\n
locales/zhCN/Assets/sound/terran/ghost/tghdth01.wav|6637ed776bd22089e083b8b0b2c0374c\r\n
locales/esES/Assets/sound/terran/scv/tscerr00.wav|fa731f51403e6985b743dae818f9b3ad\r\n
locales/itIT/Assets/SD/campaign/Starcraft/SWAR/staredit/scenario.chk|d41d8cd98f00b204e9800998ecf8427e\r\n
anim/Carbot/main_899.an…
```

Facts confirmed on the real file:

| Property | Value |
|---|---|
| Decoded size | 4 668 442 bytes |
| Records | **52 498** (file ends with a final `\r\n`; the trailing split element is empty — skip it) |
| Columns | **always exactly 2** — no locale/variant third column on SC:R (unlike Overwatch) |
| Separator | `|` (U+007C), exactly one per line |
| Path separator | **`/` (forward slash)**. Zero backslashes in the entire file. |
| Case | **Mixed case, and it is meaningful-looking but not collision-generating**: 48 120 of 52 498 paths contain uppercase; there are **zero case-insensitive collisions**. Safe to key your file table on the lowercased path. |
| Duplicate paths | **none** (52 498 unique paths) |
| Ordering | **unsorted** — do not assume any order; build a hash map |
| Hash column | lowercase hex **CKey** (MD5 of the *decoded* content). Must be resolved via ENCODING → EKey → `.idx`. |
| Empty files | present; e.g. `…/scenario.chk` has CKey `d41d8cd98f00b204e9800998ecf8427e` = MD5 of the empty string |

Top-level directories observed: `locales/` (37 356), `SD/`, `HD2/`, `anim/`, `sound/`, `webui/`,
`Carbot/`, `unit/`, `portrait/`, `glue/`. Top extensions: `.wav` (19 179), `.ogg` (16 053),
`.anim`, `.webm`, `.json`, `.txt`, `.dds`, `.chk`, `.grp`, `.png`, `.htm`, `.pcx`.

### 6.3 Parsing rules

- Split on `\r\n`; tolerate a bare `\n` and ignore trailing empties.
- Split each line on the **first** `|`. (CascLib's `CASC_CSV` would accept a 3rd column; SC:R never
  emits one, but tolerating extra columns costs nothing.)
- The hash must be 32 hex chars; skip malformed lines.
- CascLib **silently drops** entries whose CKey is not present in ENCODING
  (`if((pCKeyEntry = FindCKeyEntry_CKey(...)) != NULL)`). On the verified install **all 52 498 root
  CKeys are present in ENCODING**, so no entries are dropped for that reason.

### 6.4 Not everything listed in ROOT is on disk

**Verified and important:** of the 52 498 root entries, **48 538 resolve to a local `.idx` entry
and 3 960 do not** (7.5 %). All 3 960 are present in ENCODING but the encoded data was never
downloaded — they are the unselected locale/tag assets (this install has `enUS` selected out of
14 locales). Your API must distinguish "unknown path", "known path, content not installed locally",
and "read error". Do not treat a missing `.idx` entry as corruption.

---

## 7. Reading pipeline

```
                    .build.info  (Active==1)  ──► Build Key
                                                     │
                    Data/config/xx/yy/<BuildKey>  ◄──┘
                       │                    │
        encoding = CKey EKey ───────┐       └─── root = CKey
                                    │                 │
                          [EKey, direct]              │
                                    ▼                 │
   ┌──────────────────────────────────────────────┐   │
   │  .idx lookup: EKey[0..9] -> (archive, off,   │   │
   │               encodedSize)                   │   │
   └──────────────────────────────────────────────┘   │
                                    ▼                 │
   data.<archive> @ off : 30-byte span header ─► BLTE ─► ENCODING (decoded)
                                                      │
                                    ┌─────────────────┘
                                    ▼
                        CKey ──ENCODING──► EKey ──.idx──► span ──BLTE──► ROOT text
                                                                             │
   path ──ROOT──► CKey ──ENCODING──► EKey ──.idx──► span ──BLTE──► file bytes ◄┘
```

Bootstrapping order for an implementation:

1. Parse `.build.info`; pick the active row; take `Build Key`.
2. Load `Data/config/<h0h1>/<h2h3>/<buildkey>`; parse `key = value`.
3. Load and merge all 16 `Data/data/*.idx` (highest version per bucket) into one
   `HashMap<[u8;9], IdxEntry>`. Skip entries with `encodedSize <= 30`.
4. `encoding` token 2 is an **EKey** → look it up in the idx map directly. This is the *only*
   place where an EKey is known without ENCODING; that's why ENCODING can be loaded at all.
5. BLTE-decode it → parse into `HashMap<CKey, (contentSize, Vec<EKey>)>`.
6. `root` is a **CKey** → ENCODING → EKey → idx → BLTE-decode → parse the text root into
   `HashMap<lowercased path, CKey>`.
7. Open a file: path → CKey → ENCODING → EKey → idx → seek `data.NNN` → skip/verify the 30-byte
   header → read `encodedSize - 30` bytes → BLTE-decode → verify `MD5(decodedBytes) == CKey`
   before returning the whole decoded object. Do not compare the bare BLTE MD5 to the EKey.

Streaming note: BLTE's chunk table gives you `(encodedOffset, encodedSize, contentOffset,
contentSize)` per chunk, so random access into a large file is a matter of locating the chunk that
covers the requested content offset, seeking to `spanOffset + 30 + HeaderSize + Σ prior
EncodedSize`, and decoding only that chunk. See `CascReadFile.cpp` for CascLib's frame cache.

---

## 8. SC:R-specific notes for an implementer

**No encryption anywhere.** Verified across all 40 718 spans: only `'Z'` (zlib) and `'N'` (none)
chunk modes. No key ring, no Salsa20, no `.keys` file needed. This is a large simplification versus
a general CASC reader.

**`install` manifest — present, optional.** `install = 507094af… 311e6a69…`; the EKey resolves
locally. First bytes verified: `49 4e 01 10 00 1b 00 00 05 33 …` → magic `"IN"`, version 1,
EKeyLength 0x10, **TagCount = 27 (BE u16)**, **EntryCount = 1 331 (BE u32)**, then tags
(NUL-terminated name, BE u16 type, `ceil(EntryCount/8)`-byte bitmask), then entries
(NUL-terminated name, 16-byte CKey, BE u32 size). It names install-time files (launcher, DLLs,
`.exe`) by name → CKey. **Not required for reading game assets** — ROOT covers those. See
`CascRootFile_Install.cpp`. Support it only if you want the loose install files.

**`download` and `size` manifests**: CDN-download bookkeeping. Irrelevant to a local reader.

**`patch`, `patch-index`, `patch-config`**: `patch` is stored as a *raw non-BLTE* span
(magic `50 41` = `"PA"`). Ignore. It is the only indexed span in the storage that isn't BLTE.

**`Data\indices\*.index`** — 53 files, CDN-style archive indices for the CDN archives listed in the
CDN config (`bd4a0f87…`, key `archives = …`). Footer layout (`FILE_INDEX_FOOTER` in
`CascStructs.h`), read from the end of the file: `TocHash[16]`, `Version`, `Reserved[2]`,
`PageSizeKB`, `OffsetBytes`, `SizeBytes`, `EKeyLength`, `FooterHashBytes`, `ElementCount[4]`,
`FooterHash[FooterHashBytes]`. Verified tail of `bde0a585…index`:
`… 01 00 00 04 04 04 10 08 | a9 00 00 00 | 05 52 ff 37 cd 36 45 3b` → version 1, 4 KiB pages,
4-byte offsets, 4-byte sizes, 16-byte EKeys, 8-byte footer hash, **169 elements (little-endian in
this version)**. **Not needed for local reading** — they map EKey → (CDN archive, offset), which is
only useful when streaming from Blizzard's CDN. Skip the whole directory.

> **Width variation (verified across all 53 files):** only 45 of the `.index` files use the
> 4/4/16 widths above — the ones named by the CDN config's `archives` list (per-archive indices).
> 4 files use `OffsetBytes = 0` (a *file index*: loose-file EKeys + sizes, no offsets) and 4 use
> `OffsetBytes = 5` (an *archive group* index: merged across archives, with the archive number
> packed into the offset's high bits, like local `.idx` StorageOffsets). A reader of per-archive
> indices must validate the footer widths rather than assume them.

**`Data\data\shmem`** — 11 280 bytes; begins `04 00 00 00 | 50 01 00 00 | "Global\C:/Program Files
(x86)/StarCraft/Data/data\0…"`. It is the writer's free-space/allocation bookkeeping and the
"current .idx version per bucket" record. **Ignorable for read-only.** (If you wanted to be
maximally correct about which `.idx` is authoritative you could read it, but "highest version
number per bucket" is what CascLib does and it works.)

**`Data\ecache\`** — a second, tiny CASC storage (16 × 64 KiB v7 `.idx` totalling 15 entries, one
48 600-byte `data.000`, its own `shmem`). Online-download cache. **Ignore.**

**`Data\s1\`** — 16 × 131 072-byte `.idx` files plus `shmem` and `.residency`, but **no `data.###`
files**. Verified header: `Revision = 8`, `KeyBytes = 16`, `SpanOffsetBytes = 8`,
`SpanSizeBytes = 8`, `EntryLength = 32`, `MaxFileOffset = 0xFFFFFFFFFFFFFFFF`, 62 entries.
This is an **idx version 8** set belonging to a different (residency/streaming) storage. It is
**not** the storage you read; do not glob `Data\**\*.idx`. Point your reader at `Data\data`
specifically.

**`Data\patch\`** — empty on this install.

**Practical sizes** (for capacity planning): 40 718 idx entries, 43 091 ENCODING entries,
52 498 ROOT records, 11 archives totalling ~10.3 GB. All three maps fit comfortably in memory
(< 10 MB); no need for lazy paging.

---

## 9. Discrepancy summary (reality vs. published docs)

| Item | Published | Reality (verified) |
|---|---|---|
| `.idx` entry `EncodedSize` endianness | `CascStructs.h` comment says big-endian | **Little-endian** (CascLib's *code* agrees; the comment is wrong) |
| ENCODING CKey entry header | wowdev.wiki: `uint16 keyCount; uint40 fileSize` | **`u8 keyCount; u40 BE fileSize`**. wowdev's u16 count desyncs on real data. CascLib's `u16 LE count + u32 BE size` happens to be numerically equivalent for count<256 and size<4 GiB. |
| EKey derivation | Commonly described as MD5 of the stored encoded/BLTE bytes | **Not the MD5 of the stored bare BLTE in SC:R.** Treat it as an opaque encoded-representation address; exact derivation is not established here. |
| Span header EKey | implied to always be the full 16-byte EKey | **1 665 of 40 542 spans store only 9 bytes + 7 zero bytes.** Compare 9 bytes only. |
| Bucket hash function | `(xor of 9 key bytes) → (i & 0xF) ^ (i >> 4)`, universally | Holds for 40 542 / 40 718; the 176 placeholder stubs are stored in `computed + 1 (mod 16)`. Merge all buckets instead of relying on it. |
| BLTE `'F'` mode | documented as recursive frames | Declared in `CascStructs.h` but **unimplemented in CascLib** and absent from SC:R. |
| BLTE `'4'` (LZ4) | mentioned by some docs | Not in CascLib master; not in SC:R. |
