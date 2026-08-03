#![no_main]

use broodcasc::idx::LocalIndex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = LocalIndex::from_files([data]);
});
