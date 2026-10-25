//! Measures local `Storage` open, lookup, and read cost against a real
//! install (`BROODCASC_TEST_STORAGE` or the default SC:R path):
//!
//!   cargo run --release --example perf -- [--install DIR] [--open-iters N]
//!       [--sample N] [--lookup-iters N] [--phase open|lookup|read|all]
//!
//! Prints `key=value` lines so before/after runs can be diffed. Heap numbers
//! come from a counting global allocator and are deterministic; wall-clock
//! numbers are noisy when other builds are running, so compare A/B runs
//! back-to-back and look at the min.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use broodcasc::Storage;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

fn grow(n: usize) {
    let live = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Relaxed);
            grow(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Relaxed);
            grow(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            ALLOCS.fetch_add(1, Relaxed);
            if new_size > layout.size() {
                ALLOC_BYTES.fetch_add(new_size - layout.size(), Relaxed);
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Heap activity over a region, relative to the live bytes at its start.
struct Region {
    base_live: usize,
    base_allocs: usize,
    base_bytes: usize,
}

impl Region {
    fn start() -> Self {
        let base_live = LIVE.load(Relaxed);
        PEAK.store(base_live, Relaxed);
        Self {
            base_live,
            base_allocs: ALLOCS.load(Relaxed),
            base_bytes: ALLOC_BYTES.load(Relaxed),
        }
    }
    fn report(&self, prefix: &str) {
        let live = LIVE.load(Relaxed);
        println!(
            "{prefix}.peak_heap_bytes={}",
            PEAK.load(Relaxed) - self.base_live
        );
        println!(
            "{prefix}.retained_heap_bytes={}",
            live as isize - self.base_live as isize
        );
        println!(
            "{prefix}.alloc_count={}",
            ALLOCS.load(Relaxed) - self.base_allocs
        );
        println!(
            "{prefix}.alloc_bytes_total={}",
            ALLOC_BYTES.load(Relaxed) - self.base_bytes
        );
    }
}

fn ms(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64() * 1000.0)
}

fn summarize(prefix: &str, mut times: Vec<Duration>) {
    times.sort();
    println!("{prefix}.min_ms={}", ms(times[0]));
    println!("{prefix}.median_ms={}", ms(times[times.len() / 2]));
}

fn main() {
    let mut install = std::env::var("BROODCASC_TEST_STORAGE")
        .unwrap_or_else(|_| r"C:\Program Files (x86)\StarCraft".to_string());
    let mut open_iters = 5usize;
    let mut sample = 2000usize;
    let mut lookup_iters = 3usize;
    let mut phase = "all".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().expect("missing value");
        match a.as_str() {
            "--install" => install = val(),
            "--open-iters" => open_iters = val().parse().unwrap(),
            "--sample" => sample = val().parse().unwrap(),
            "--lookup-iters" => lookup_iters = val().parse().unwrap(),
            "--phase" => phase = val(),
            other => panic!("unknown arg {other}"),
        }
    }
    let want = |p: &str| phase == "all" || phase == p;

    // --- open ---
    let mut open_times = Vec::new();
    let mut storage = None;
    for i in 0..open_iters.max(1) {
        drop(storage.take());
        let region = Region::start();
        let t = Instant::now();
        let s = Storage::open(&install).expect("open failed");
        open_times.push(t.elapsed());
        if i == 0 {
            region.report("open");
        }
        storage = Some(s);
    }
    let storage = storage.unwrap();
    if want("open") {
        summarize("open", open_times);
        println!("counts.root_entries={}", storage.root().len());
        println!("counts.encoding_entries={}", storage.encoding().len());
        println!("counts.index_entries={}", storage.index().len());
    }

    // --- lookups ---
    if want("lookup") {
        let paths: Vec<String> = storage.file_names().map(str::to_string).collect();
        // Mixed-case/backslash variants exercise the normalizing path.
        let alt_paths: Vec<String> = paths
            .iter()
            .map(|p| p.to_ascii_uppercase().replace('/', "\\"))
            .collect();
        let ckeys: Vec<_> = storage.root().entries().map(|e| e.ckey).collect();
        let ekeys: Vec<_> = storage
            .encoding()
            .entries()
            .iter()
            .map(|e| e.ekey)
            .collect();

        let mut root_t = Vec::new();
        let mut root_alt_t = Vec::new();
        let mut enc_t = Vec::new();
        let mut idx_t = Vec::new();
        let mut contains_t = Vec::new();
        let region = Region::start();
        for _ in 0..lookup_iters.max(1) {
            let t = Instant::now();
            for p in &paths {
                black_box(storage.root().lookup(black_box(p)));
            }
            root_t.push(t.elapsed() / paths.len() as u32);
            let t = Instant::now();
            for p in &alt_paths {
                black_box(storage.root().lookup(black_box(p)));
            }
            root_alt_t.push(t.elapsed() / alt_paths.len() as u32);
            let t = Instant::now();
            for k in &ckeys {
                black_box(storage.encoding().lookup(black_box(k)));
            }
            enc_t.push(t.elapsed() / ckeys.len() as u32);
            let t = Instant::now();
            for k in &ekeys {
                black_box(storage.index().lookup(black_box(k)));
            }
            idx_t.push(t.elapsed() / ekeys.len() as u32);
            let t = Instant::now();
            for p in &paths {
                black_box(storage.is_installed(black_box(p)));
            }
            contains_t.push(t.elapsed() / paths.len() as u32);
        }
        region.report("lookup");
        let ns = |v: Vec<Duration>| v.iter().min().unwrap().as_nanos();
        println!("lookup.root_ns={}", ns(root_t));
        println!("lookup.root_alt_case_ns={}", ns(root_alt_t));
        println!("lookup.encoding_ns={}", ns(enc_t));
        println!("lookup.index_ns={}", ns(idx_t));
        println!("lookup.is_installed_ns={}", ns(contains_t));
    }

    // --- reads ---
    if want("read") {
        let mut installed: Vec<String> = storage
            .file_names()
            .filter(|p| storage.is_installed(p))
            .map(str::to_string)
            .collect();
        installed.sort();
        let step = (installed.len() / sample.max(1)).max(1);
        let picked: Vec<&String> = installed.iter().step_by(step).take(sample).collect();
        println!("read.files={}", picked.len());

        // read_file: fresh Vec per file.
        let region = Region::start();
        let t = Instant::now();
        let mut total = 0u64;
        let mut largest = 0usize;
        for p in &picked {
            let bytes = storage.read_file(p).expect("read_file failed");
            total += bytes.len() as u64;
            largest = largest.max(bytes.len());
            black_box(&bytes);
        }
        let elapsed = t.elapsed();
        region.report("read_file");
        println!("read_file.decoded_bytes={total}");
        println!("read_file.largest_file_bytes={largest}");
        println!("read_file.ms={}", ms(elapsed));
        println!(
            "read_file.mb_per_s={:.1}",
            total as f64 / 1e6 / elapsed.as_secs_f64()
        );

        // read_file_into: one reused buffer.
        let mut buf = Vec::new();
        let region = Region::start();
        let t = Instant::now();
        for p in &picked {
            let size = storage.file_size(p).expect("file_size failed") as usize;
            buf.resize(size, 0);
            storage
                .read_file_into(p, &mut buf[..size])
                .expect("read_file_into failed");
            black_box(&buf);
        }
        let elapsed = t.elapsed();
        region.report("read_file_into");
        println!("read_file_into.ms={}", ms(elapsed));
        println!(
            "read_file_into.mb_per_s={:.1}",
            total as f64 / 1e6 / elapsed.as_secs_f64()
        );
    }
}
