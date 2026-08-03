#![no_main]

use broodcasc::config::{BuildConfig, BuildInfo};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = BuildInfo::parse(&text);
    let _ = BuildConfig::parse(&text);
});
