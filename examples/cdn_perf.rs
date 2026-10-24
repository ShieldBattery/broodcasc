//! Measures CdnStorage open/read cost: heap (counting allocator), request
//! counts/bytes at the logical layer (above the cache) and the network layer
//! (below it), and read throughput.
//!
//!   cargo run --release --example cdn_perf -- --cache DIR [--sample N]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

use broodcasc::cdn::{CachingTransport, CdnRequest, CdnStorage, CdnTransport, HttpTransport};
use broodcasc::error::Result;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(n: usize) {
    let live = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            grow(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            grow(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, n) };
        if !q.is_null() {
            if n > l.size() {
                grow(n - l.size());
            } else {
                LIVE.fetch_sub(l.size() - n, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[derive(Default)]
struct Stats {
    gets: AtomicUsize,
    ranges: AtomicUsize,
    rounds: AtomicUsize,
    bytes: AtomicUsize,
}

impl Stats {
    fn snap(&self) -> (usize, usize, usize) {
        (
            self.gets.load(Relaxed),
            self.ranges.load(Relaxed),
            self.bytes.load(Relaxed),
        )
    }
}

struct Count<T> {
    inner: T,
    stats: Arc<Stats>,
}

impl<T: CdnTransport> CdnTransport for Count<T> {
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>> {
        self.stats.rounds.fetch_add(1, Relaxed);
        let r = self.inner.get(url, max)?;
        if std::env::var_os("CDN_VERBOSE").is_some() {
            eprintln!("GET {url} -> {}", r.len());
        }
        self.stats.gets.fetch_add(1, Relaxed);
        self.stats.bytes.fetch_add(r.len(), Relaxed);
        Ok(r)
    }
    fn get_range(&self, url: &str, o: u64, l: u64) -> Result<Vec<u8>> {
        self.stats.rounds.fetch_add(1, Relaxed);
        let r = self.inner.get_range(url, o, l)?;
        if std::env::var_os("CDN_VERBOSE").is_some() {
            eprintln!("RANGE {url} {o}+{l}");
        }
        self.stats.ranges.fetch_add(1, Relaxed);
        self.stats.bytes.fetch_add(r.len(), Relaxed);
        Ok(r)
    }
    fn get_many(&self, reqs: &[CdnRequest]) -> Vec<Result<Vec<u8>>> {
        self.stats.rounds.fetch_add(1, Relaxed);
        let out = self.inner.get_many(reqs);
        for (rq, r) in reqs.iter().zip(&out) {
            if let Ok(b) = r {
                match rq {
                    CdnRequest::Whole { .. } => self.stats.gets.fetch_add(1, Relaxed),
                    CdnRequest::Range { .. } => self.stats.ranges.fetch_add(1, Relaxed),
                };
                self.stats.bytes.fetch_add(b.len(), Relaxed);
            }
        }
        out
    }
    fn invalidate(&self, url: &str, r: Option<(u64, u64)>) {
        self.inner.invalidate(url, r)
    }
}

fn show(name: &str, s: &Stats) {
    let (g, r, b) = s.snap();
    println!(
        "{name}.gets={g} {name}.ranges={r} {name}.bytes={b} {name}.rounds={}",
        s.rounds.load(Relaxed)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .map(|i| args[i + 1].clone())
    };
    let cache = arg("--cache").expect("--cache DIR");
    let sample: usize = arg("--sample").map_or(20, |s| s.parse().unwrap());

    let net = Arc::new(Stats::default());
    let logical = Arc::new(Stats::default());
    let transport = Count {
        inner: CachingTransport::new(
            Count {
                inner: HttpTransport::new(),
                stats: net.clone(),
            },
            cache,
        ),
        stats: logical.clone(),
    };

    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let t = Instant::now();
    let storage = CdnStorage::open("s1", "us", transport).expect("open");
    let open = t.elapsed();
    println!("open.ms={:.1}", open.as_secs_f64() * 1e3);
    println!("open.peak_heap_bytes={}", PEAK.load(Relaxed) - base);
    println!("open.retained_heap_bytes={}", LIVE.load(Relaxed) - base);
    show("open.logical", &logical);
    show("open.network", &net);
    println!(
        "root.len={} encoding.len={}",
        storage.root().len(),
        storage.encoding().len()
    );

    let l0 = logical.snap();
    let mut names: Vec<_> = storage
        .root()
        .entries()
        .filter_map(|e| {
            let sz = storage.file_size(e.path).ok()?;
            (sz > 0 && sz < 2_000_000).then_some(e.path.to_string())
        })
        .collect();
    names.sort();
    let step = (names.len() / sample.max(1)).max(1);
    let t = Instant::now();
    let (mut n, mut decoded) = (0, 0u64);
    for p in names.iter().step_by(step).take(sample) {
        decoded += storage.read_file(p).expect("read").len() as u64;
        n += 1;
    }
    let el = t.elapsed();
    let l1 = logical.snap();
    println!(
        "read.files={n} read.decoded_bytes={decoded} read.ms={:.1}",
        el.as_secs_f64() * 1e3
    );
    println!(
        "read.logical.gets={} read.logical.ranges={} read.logical.bytes={}",
        l1.0 - l0.0,
        l1.1 - l0.1,
        l1.2 - l0.2
    );
    show("total.network", &net);
}
