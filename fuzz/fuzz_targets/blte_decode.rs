#![no_main]

use broodcasc::blte::{self, ReadLimits};
use libfuzzer_sys::fuzz_target;

/// Small, explicit bounds keep fuzz iterations cheap while still sending
/// oversized declarations through the production limit-rejection paths.
const FUZZ_LIMITS: ReadLimits = ReadLimits {
    max_encoded_bytes: 1024 * 1024,
    max_decoded_bytes: 256 * 1024,
    max_chunk_decoded_bytes: 64 * 1024,
    max_chunk_count: 128,
    max_nesting: 4,
    initial_reserve_bytes: 16 * 1024,
};

fuzz_target!(|data: &[u8]| {
    let _ = blte::decode_with_limits(data, FUZZ_LIMITS);
});
