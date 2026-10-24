//! Bob Jenkins' little-endian lookup hash used by CASC guarded blocks.
//!
//! This is crate-private because CASC consumers should not need to depend on
//! the implementation detail; local index and span framing are its only
//! callers.

/// Bob Jenkins' `hashlittle`, with an explicit initial value.
pub(crate) fn hashlittle(data: &[u8], initval: u32) -> u32 {
    hashlittle2(data, initval, 0).0
}

/// Bob Jenkins' `hashlittle2`. The tuple is `(pc, pb)`, matching the high and
/// low words chained by Blizzard's v7 index writer.
pub(crate) fn hashlittle2(mut data: &[u8], pc: u32, pb: u32) -> (u32, u32) {
    let seed = 0xDEAD_BEEFu32
        .wrapping_add(data.len() as u32)
        .wrapping_add(pc);
    let mut a = seed;
    let mut b = seed;
    let mut c = seed.wrapping_add(pb);

    while data.len() > 12 {
        a = a.wrapping_add(u32::from_le_bytes(data[0..4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(data[4..8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(data[8..12].try_into().unwrap()));
        mix(&mut a, &mut b, &mut c);
        data = &data[12..];
    }

    if data.is_empty() {
        return (c, b);
    }

    // Zero-padding the tail to 12 bytes adds the same words as the
    // byte-at-a-time reference (absent bytes contribute nothing).
    let mut tail = [0u8; 12];
    tail[..data.len()].copy_from_slice(data);
    a = a.wrapping_add(u32::from_le_bytes(tail[0..4].try_into().unwrap()));
    b = b.wrapping_add(u32::from_le_bytes(tail[4..8].try_into().unwrap()));
    c = c.wrapping_add(u32::from_le_bytes(tail[8..12].try_into().unwrap()));
    final_mix(&mut a, &mut b, &mut c);
    (c, b)
}

fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = (*a).wrapping_sub(*c);
    *a ^= (*c).rotate_left(4);
    *c = (*c).wrapping_add(*b);
    *b = (*b).wrapping_sub(*a);
    *b ^= (*a).rotate_left(6);
    *a = (*a).wrapping_add(*c);
    *c = (*c).wrapping_sub(*b);
    *c ^= (*b).rotate_left(8);
    *b = (*b).wrapping_add(*a);
    *a = (*a).wrapping_sub(*c);
    *a ^= (*c).rotate_left(16);
    *c = (*c).wrapping_add(*b);
    *b = (*b).wrapping_sub(*a);
    *b ^= (*a).rotate_left(19);
    *a = (*a).wrapping_add(*c);
    *c = (*c).wrapping_sub(*b);
    *c ^= (*b).rotate_left(4);
    *b = (*b).wrapping_add(*a);
}

fn final_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(14));
    *a ^= *c;
    *a = (*a).wrapping_sub((*c).rotate_left(11));
    *b ^= *a;
    *b = (*b).wrapping_sub((*a).rotate_left(25));
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(16));
    *a ^= *c;
    *a = (*a).wrapping_sub((*c).rotate_left(4));
    *b ^= *a;
    *b = (*b).wrapping_sub((*a).rotate_left(14));
    *c ^= *b;
    *c = (*c).wrapping_sub((*b).rotate_left(24));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_span_header_hash_uses_casclib_seed_and_first_word() {
        let header_prefix = [
            0x58, 0x43, 0xa2, 0xff, 0x71, 0xe8, 0xc2, 0xa1, 0xbe, 0xff, 0x0e, 0x82, 0x9b, 0x00,
            0x00, 0x07, 0x1e, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];
        assert_eq!(hashlittle2(&header_prefix, 0x3d6b_e971, 0).0, 0xbba5_b2bd);
    }
}
