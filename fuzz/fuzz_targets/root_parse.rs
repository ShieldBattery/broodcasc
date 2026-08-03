#![no_main]

use broodcasc::root::RootFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = RootFile::parse(data);
});
