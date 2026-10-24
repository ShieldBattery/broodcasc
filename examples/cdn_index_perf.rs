//! Offline microbenchmark of the merged CDN archive index: parses every
//! `*.index` file under a cache dir, merges them, and measures retained
//! heap, build time and lookup time.
//!
//!   cargo run --release --example cdn_index_perf -- DIR

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

use broodcasc::cdnindex::{ArchiveIndex, CdnIndex};

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

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|e| e == "index") {
            out.push(p);
        }
    }
}

fn main() {
    let dir = std::env::args().nth(1).expect("DIR");
    let mut files = Vec::new();
    collect(Path::new(&dir), &mut files);
    files.sort();
    let datas: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();

    let mut best = f64::MAX;
    let (mut peak, mut retained) = (0, 0);
    let mut keys = Vec::new();
    for round in 0..5 {
        let base = LIVE.load(Relaxed);
        PEAK.store(base, Relaxed);
        let t = Instant::now();
        let mut idx = CdnIndex::new();
        for (i, d) in datas.iter().enumerate() {
            let a = ArchiveIndex::parse(d).unwrap();
            if round == 0 {
                keys.extend(a.entries().iter().map(|e| e.ekey));
            }
            idx.add_archive(i as u32, &a);
        }
        best = best.min(t.elapsed().as_secs_f64() * 1e3);
        peak = PEAK.load(Relaxed) - base;
        retained = LIVE.load(Relaxed) - base;
        if round == 4 {
            let t = Instant::now();
            let mut hits = 0;
            for _ in 0..20 {
                for k in &keys {
                    hits += idx.lookup(black_box(k)).is_some() as usize;
                }
            }
            println!(
                "lookup.ns_each={:.1} hits={hits}",
                t.elapsed().as_secs_f64() * 1e9 / (20 * keys.len()) as f64
            );
            println!("entries={} len={}", keys.len(), idx.len());
        }
    }
    println!("archives={}", datas.len());
    println!("build.ms_min={best:.3}");
    println!("peak_heap_bytes={peak}");
    println!("retained_heap_bytes={retained}");
}
