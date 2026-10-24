//! Multi-lane MD5 compression.
//!
//! MD5 is a serial dependency chain within one message, so a single stream is
//! latency-bound on a modern core. Running several independent messages in
//! lockstep gives the CPU independent work to overlap (and lets LLVM
//! vectorize where SIMD is available), which raises aggregate throughput
//! without any `unsafe`, platform intrinsics, or threads. Everything here is
//! portable Rust and builds for `wasm32-unknown-unknown`.

const RC: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const INIT: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

#[inline(always)]
fn f1(b: u32, c: u32, d: u32) -> u32 {
    d ^ (b & (c ^ d))
}
#[inline(always)]
fn f2(b: u32, c: u32, d: u32) -> u32 {
    c ^ (d & (b ^ c))
}
#[inline(always)]
fn f3(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
#[inline(always)]
fn f4(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b | !d)
}

/// Compresses one 64-byte block into each of `N` independent states.
#[inline(always)]
fn compress_lanes<const N: usize>(states: &mut [[u32; 4]; N], blocks: [&[u8; 64]; N]) {
    let mut m = [[0u32; N]; 16];
    for (l, block) in blocks.iter().enumerate() {
        for (w, bytes) in block.as_chunks::<4>().0.iter().enumerate() {
            m[w][l] = u32::from_le_bytes(*bytes);
        }
    }
    let mut v = [[0u32; N]; 4];
    for l in 0..N {
        for j in 0..4 {
            v[j][l] = states[l][j];
        }
    }
    // One MD5 step across all lanes: `$a = $b + rotl($a + f($b,$c,$d) + m + k, $s)`.
    macro_rules! step {
        ($f:ident, $a:expr, $b:expr, $c:expr, $d:expr, $g:expr, $k:expr, $s:expr) => {
            for l in 0..N {
                let (b, c, d) = (v[$b][l], v[$c][l], v[$d][l]);
                v[$a][l] = v[$a][l]
                    .wrapping_add($f(b, c, d))
                    .wrapping_add(m[$g][l])
                    .wrapping_add($k)
                    .rotate_left($s)
                    .wrapping_add(b);
            }
        };
    }
    macro_rules! quad {
        ($f:ident, $i:expr, $g0:expr, $g1:expr, $g2:expr, $g3:expr, $s0:expr, $s1:expr, $s2:expr, $s3:expr) => {
            step!($f, 0, 1, 2, 3, $g0, RC[$i], $s0);
            step!($f, 3, 0, 1, 2, $g1, RC[$i + 1], $s1);
            step!($f, 2, 3, 0, 1, $g2, RC[$i + 2], $s2);
            step!($f, 1, 2, 3, 0, $g3, RC[$i + 3], $s3);
        };
    }
    quad!(f1, 0, 0, 1, 2, 3, 7, 12, 17, 22);
    quad!(f1, 4, 4, 5, 6, 7, 7, 12, 17, 22);
    quad!(f1, 8, 8, 9, 10, 11, 7, 12, 17, 22);
    quad!(f1, 12, 12, 13, 14, 15, 7, 12, 17, 22);
    quad!(f2, 16, 1, 6, 11, 0, 5, 9, 14, 20);
    quad!(f2, 20, 5, 10, 15, 4, 5, 9, 14, 20);
    quad!(f2, 24, 9, 14, 3, 8, 5, 9, 14, 20);
    quad!(f2, 28, 13, 2, 7, 12, 5, 9, 14, 20);
    quad!(f3, 32, 5, 8, 11, 14, 4, 11, 16, 23);
    quad!(f3, 36, 1, 4, 7, 10, 4, 11, 16, 23);
    quad!(f3, 40, 13, 0, 3, 6, 4, 11, 16, 23);
    quad!(f3, 44, 9, 12, 15, 2, 4, 11, 16, 23);
    quad!(f4, 48, 0, 7, 14, 5, 6, 10, 15, 21);
    quad!(f4, 52, 12, 3, 10, 1, 6, 10, 15, 21);
    quad!(f4, 56, 8, 15, 6, 13, 6, 10, 15, 21);
    quad!(f4, 60, 4, 11, 2, 9, 6, 10, 15, 21);
    for l in 0..N {
        for j in 0..4 {
            states[l][j] = states[l][j].wrapping_add(v[j][l]);
        }
    }
}

/// Number of messages hashed concurrently.
const LANES: usize = 4;

/// One in-flight message: a cursor over its full blocks, then over its
/// padded tail (one or two blocks).
struct Lane<'a, T> {
    data: &'a [u8],
    /// Offset of the next full block; reaches `full_len` once the data blocks
    /// are exhausted.
    pos: usize,
    full_len: usize,
    tail: [u8; 128],
    tail_blocks: usize,
    tail_idx: usize,
    state: [u32; 4],
    tag: T,
}

impl<'a, T> Lane<'a, T> {
    fn new(data: &'a [u8], tag: T) -> Self {
        let full_len = data.len() / 64 * 64;
        let rest = &data[full_len..];
        let mut tail = [0u8; 128];
        tail[..rest.len()].copy_from_slice(rest);
        tail[rest.len()] = 0x80;
        let tail_blocks = if rest.len() < 56 { 1 } else { 2 };
        let bit_len = (data.len() as u64).wrapping_mul(8);
        tail[tail_blocks * 64 - 8..tail_blocks * 64].copy_from_slice(&bit_len.to_le_bytes());
        Self {
            data,
            pos: 0,
            full_len,
            tail,
            tail_blocks,
            tail_idx: 0,
            state: INIT,
            tag,
        }
    }

    /// The blocks still to hash in the current segment (the message's full
    /// blocks, then its padded tail): a whole number of 64-byte blocks.
    fn segment(&self) -> &[u8] {
        if self.pos < self.full_len {
            &self.data[self.pos..self.full_len]
        } else {
            &self.tail[self.tail_idx * 64..self.tail_blocks * 64]
        }
    }

    /// Marks `blocks` blocks of the current segment as hashed.
    fn advance(&mut self, blocks: usize) {
        if self.pos < self.full_len {
            self.pos += blocks * 64;
        } else {
            self.tail_idx += blocks;
        }
    }

    fn is_done(&self) -> bool {
        self.pos >= self.full_len && self.tail_idx == self.tail_blocks
    }

    fn digest(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (dst, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *dst = word.to_le_bytes();
        }
        out
    }
}

/// Hashes blocks in the `K` lanes at `idx` in lockstep until one of them
/// reaches the end of its current segment. Keeping the loop (and so the
/// states) inside this function matters: re-entering per block costs more
/// than the hashing itself.
fn run<const K: usize, T>(lanes: &mut [Option<Lane<'_, T>>; LANES], idx: [usize; K]) {
    let mut states = idx.map(|i| lanes[i].as_ref().expect("active lane").state);
    let segments = idx.map(|i| lanes[i].as_ref().expect("active lane").segment());
    let blocks = segments.iter().map(|s| s.len() / 64).min().unwrap_or(0);
    for t in 0..blocks {
        compress_lanes(
            &mut states,
            segments.map(|s| <&[u8; 64]>::try_from(&s[t * 64..t * 64 + 64]).expect("64 bytes")),
        );
    }
    for (state, &i) in states.into_iter().zip(&idx) {
        let lane = lanes[i].as_mut().expect("active lane");
        lane.state = state;
        lane.advance(blocks);
    }
}

/// Computes the MD5 of every message from `jobs`, several at a time, and
/// calls `done(tag, digest)` as each completes (in completion order, not job
/// order). Stops early and returns `false` as soon as `done` returns `false`;
/// returns `true` if every message was reported and accepted.
///
/// Lanes are refilled from `jobs` as they finish, so messages of unequal
/// length keep the lanes busy; once fewer than [`LANES`] messages remain the
/// rest are hashed one at a time.
pub(crate) fn hash_many<'a, T>(
    jobs: impl IntoIterator<Item = (&'a [u8], T)>,
    mut done: impl FnMut(T, [u8; 16]) -> bool,
) -> bool {
    let mut jobs = jobs.into_iter();
    let mut lanes: [Option<Lane<'a, T>>; LANES] = [const { None }; LANES];
    for lane in &mut lanes {
        *lane = jobs.next().map(|(data, tag)| Lane::new(data, tag));
    }
    loop {
        let mut idx = [0usize; LANES];
        let mut n = 0;
        for (i, lane) in lanes.iter().enumerate() {
            if lane.is_some() {
                idx[n] = i;
                n += 1;
            }
        }
        match n {
            0 => return true,
            LANES => run(&mut lanes, idx),
            // Only the last few messages: not worth a kernel instantiation
            // per width (each is a large unrolled function).
            _ => {
                for &i in &idx[..n] {
                    run(&mut lanes, [i]);
                }
            }
        }
        for slot in &mut lanes {
            if slot.as_ref().is_some_and(Lane::is_done) {
                let lane = slot.take().expect("checked above");
                let digest = lane.digest();
                if !done(lane.tag, digest) {
                    return false;
                }
                *slot = jobs.next().map(|(data, tag)| Lane::new(data, tag));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};
    use proptest::prelude::*;

    #[test]
    fn known_vectors() {
        let long = [b'a'; 1000];
        let msgs: [&[u8]; 3] = [b"", b"abc", &long];
        let mut got = vec![[0u8; 16]; msgs.len()];
        assert!(hash_many(
            msgs.iter().enumerate().map(|(i, m)| (*m, i)),
            |i, d| {
                got[i] = d;
                true
            }
        ));
        for (m, g) in msgs.iter().zip(&got) {
            assert_eq!(*g, <[u8; 16]>::from(Md5::digest(m)));
        }
    }

    #[test]
    fn stops_when_callback_rejects() {
        let msgs = [&b"a"[..], b"b", b"c"];
        let mut calls = 0;
        let ok = hash_many(msgs.iter().map(|m| (*m, ())), |(), _| {
            calls += 1;
            false
        });
        assert!(!ok);
        assert_eq!(calls, 1);
    }

    #[test]
    fn no_jobs_is_ok() {
        assert!(hash_many(core::iter::empty::<(&[u8], ())>(), |(), _| false));
    }

    proptest! {
        /// Every batch size and message length (including the 55/56/63/64
        /// padding boundaries) must match the reference implementation.
        #[test]
        fn matches_md5_crate(
            lens in proptest::collection::vec(
                prop_oneof![0usize..200, 54usize..58, 62usize..66, 120usize..130, 0usize..1500],
                0..12,
            ),
            seed in any::<u8>(),
        ) {
            let msgs: Vec<Vec<u8>> = lens
                .iter()
                .enumerate()
                .map(|(i, &len)| {
                    (0..len)
                        .map(|j| (j as u8).wrapping_mul(31).wrapping_add(seed ^ i as u8))
                        .collect()
                })
                .collect();
            let mut got = vec![None; msgs.len()];
            let ok = hash_many(
                msgs.iter().enumerate().map(|(i, m)| (m.as_slice(), i)),
                |i, d| {
                    got[i] = Some(d);
                    true
                },
            );
            prop_assert!(ok);
            for (m, g) in msgs.iter().zip(&got) {
                prop_assert_eq!(g.unwrap(), <[u8; 16]>::from(Md5::digest(m)));
            }
        }
    }
}
