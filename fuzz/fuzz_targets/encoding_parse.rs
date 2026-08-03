#![no_main]

use broodcasc::encoding::EncodingTable;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EncodingTable::parse(data);
});
