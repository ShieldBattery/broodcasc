//! Live integration tests against Blizzard's actual CDN.
//!
//! These hit the network and download tens of MB on a cold cache, so they
//! only run when explicitly requested: set `BROODCASC_TEST_CDN=1`. Downloads
//! are cached under the target dir, so reruns are cheap.

#![cfg(all(feature = "cdn", feature = "cdn-http", feature = "fs"))]

use broodcasc::cdn::{CachingTransport, CdnStorage, HttpTransport};
use broodcasc::error::CascError;

fn open_storage() -> Option<CdnStorage<CachingTransport<HttpTransport>>> {
    if std::env::var("BROODCASC_TEST_CDN").as_deref() != Ok("1") {
        eprintln!("skipping: set BROODCASC_TEST_CDN=1 to run live CDN tests");
        return None;
    }
    let cache = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cdn-cache");
    let transport = CachingTransport::new(HttpTransport::new(), cache);
    Some(CdnStorage::open("s1", "us", transport).expect("CDN storage should open"))
}

#[test]
fn opens_and_reads_from_live_cdn() {
    let Some(storage) = open_storage() else {
        return;
    };

    assert!(storage.root().len() > 10_000, "root suspiciously small");
    assert!(
        storage.encoding().len() > 10_000,
        "encoding suspiciously small"
    );
    assert_eq!(storage.build_config().build_uid(), Some("s1"));
    assert!(storage.version_name().is_some());

    // Download a couple of small files; read_by_ckey verifies MD5s
    // internally, so success == end-to-end correctness.
    let mut read = 0;
    for entry in storage.root().entries() {
        let Ok(size) = storage.file_size(&entry.path) else {
            continue;
        };
        if size == 0 || size > 200_000 {
            continue;
        }
        let bytes = storage
            .read_file(&entry.path)
            .unwrap_or_else(|e| panic!("reading {} failed: {e}", entry.path));
        assert_eq!(bytes.len() as u64, size, "size mismatch for {}", entry.path);
        read += 1;
        if read >= 3 {
            break;
        }
    }
    assert!(read > 0, "no small files found to read");

    match storage.read_file("no/such/file/anywhere.xyz") {
        Err(CascError::NotFound(_)) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}
