#![no_main]

use broodcasc::blte::{self, BlteHeader};
use libfuzzer_sys::fuzz_target;

/// Skip decoding inputs whose chunk table already declares an enormous total
/// decompressed size, so a malicious/degenerate chunk table can't turn a tiny
/// input into a multi-minute inflate (a "decompression bomb"). Inputs with no
/// chunk table (`header_size == 0`, unknown decompressed size) are still
/// decoded — `decode` internally caps that case at 1 GiB, and libFuzzer's
/// `-max_len` bounds the input size from the runner side.
const MAX_DECOMPRESSED: u64 = 64 * 1024 * 1024; // 64 MiB

fuzz_target!(|data: &[u8]| {
    let too_big = BlteHeader::parse(data)
        .ok()
        .and_then(|header| header.total_decompressed_size())
        .is_some_and(|total| total > MAX_DECOMPRESSED);
    if too_big {
        return;
    }
    let _ = blte::decode(data);
});
