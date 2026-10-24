#![no_main]

use broodcasc::blte::{self, BlteHeader, ReadLimits};
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
    // Both decoders must agree: whatever the growing decoder accepts, the
    // in-place decoder accepts at that exact length with identical output.
    if let Ok(decoded) = blte::decode_with_limits(data, FUZZ_LIMITS) {
        let mut out = vec![0; decoded.len()];
        blte::decode_into(data, &mut out, FUZZ_LIMITS)
            .expect("decode_into rejected input that decode_with_limits accepted");
        assert_eq!(out, decoded);
    }

    // Also drive decode_into at the header's declared size (or an arbitrary
    // one for header-less input), including just past the decoded limit.
    let len = BlteHeader::parse(data)
        .ok()
        .and_then(|header| header.total_decompressed_size())
        .map_or(data.len(), |size| size as usize)
        .min(FUZZ_LIMITS.max_decoded_bytes + 1);
    let mut out = vec![0; len];
    let _ = blte::decode_into(data, &mut out, FUZZ_LIMITS);
});
