//! The kernel symbol-table blob format, shared by the host-side builder
//! (`xtask`) and the kernel-side resolver (panic backtraces).
//!
//! Keeping both in one `no_std` crate means they can never disagree on layout,
//! and the round-trip (build → resolve) is host-tested. The blob is:
//!
//! ```text
//! magic "KSY2" | count:u32 | count × { addr:u64, size:u32, name_off:u32 } | names
//! ```
//!
//! Entries are sorted ascending by address; `name_off` indexes the NUL-separated
//! name region. [`resolve`] respects each symbol's `size`, so an address past a
//! function's end is reported as unknown rather than mis-attributed.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

const MAGIC: &[u8; 4] = b"KSY2";
const HEADER: usize = 8;
const ENTRY: usize = 16;

/// Builds a blob from `(address, size, name)` triples (any order; sorted here).
#[must_use]
pub fn build(symbols: &[(u64, u32, &str)]) -> Vec<u8> {
    let mut syms: Vec<(u64, u32, &str)> = symbols.to_vec();
    syms.sort_by_key(|&(addr, _, _)| addr);
    syms.dedup_by_key(|&mut (addr, _, _)| addr);

    let mut names: Vec<u8> = Vec::new();
    let mut entries: Vec<(u64, u32, u32)> = Vec::with_capacity(syms.len());
    for &(addr, size, name) in &syms {
        let off = names.len() as u32;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        entries.push((addr, size, off));
    }

    let mut blob = Vec::with_capacity(HEADER + entries.len() * ENTRY + names.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&(syms.len() as u32).to_le_bytes());
    for (addr, size, off) in &entries {
        blob.extend_from_slice(&addr.to_le_bytes());
        blob.extend_from_slice(&size.to_le_bytes());
        blob.extend_from_slice(&off.to_le_bytes());
    }
    blob.extend_from_slice(&names);
    blob
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Resolves `addr` to the containing function's `(name, offset)` in `blob`.
///
/// Returns `None` when the blob is empty/invalid, `addr` precedes the first
/// symbol, or `addr` lies past the nearest preceding symbol's `size` (so stray
/// addresses are not mis-attributed to a distant function).
pub fn resolve(blob: &[u8], addr: u64) -> Option<(&str, u64)> {
    if blob.len() < HEADER || &blob[0..4] != MAGIC {
        return None;
    }
    let count = read_u32(blob, 4)? as usize;
    if count == 0 {
        return None;
    }
    let names_start = HEADER + count * ENTRY;
    if blob.len() < names_start {
        return None;
    }

    let entry_addr = |i: usize| read_u64(blob, HEADER + i * ENTRY);

    // Greatest symbol address <= `addr`.
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if entry_addr(mid)? <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let idx = lo - 1;
    let sym_addr = entry_addr(idx)?;
    let size = u64::from(read_u32(blob, HEADER + idx * ENTRY + 8)?);
    // Respect the symbol's size: a zero size means "unknown extent" (accept).
    if size != 0 && addr >= sym_addr + size {
        return None;
    }
    let name_off = read_u32(blob, HEADER + idx * ENTRY + 12)? as usize;
    let name = read_cstr(blob, names_start + name_off)?;
    Some((name, addr - sym_addr))
}

fn read_cstr(blob: &[u8], off: usize) -> Option<&str> {
    let rest = blob.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        build(&[
            (0x1000, 0x40, "alpha"),
            (0x1100, 0x20, "beta"),
            (0x1200, 0, "gamma_unknown_size"),
        ])
    }

    #[test]
    fn resolves_within_function() {
        let b = sample();
        assert_eq!(resolve(&b, 0x1000), Some(("alpha", 0)));
        assert_eq!(resolve(&b, 0x1004), Some(("alpha", 4)));
        assert_eq!(resolve(&b, 0x1100), Some(("beta", 0)));
        assert_eq!(resolve(&b, 0x1110), Some(("beta", 0x10)));
    }

    #[test]
    fn respects_symbol_size() {
        let b = sample();
        // 0x1040 is past alpha's end (0x1000 + 0x40) and before beta → unknown.
        assert_eq!(resolve(&b, 0x1040), None);
        // beta ends at 0x1120; 0x1120 is past it → unknown.
        assert_eq!(resolve(&b, 0x1120), None);
    }

    #[test]
    fn zero_size_accepts_any_following_address() {
        let b = sample();
        // gamma has unknown size: any address at/after it resolves to it.
        assert_eq!(resolve(&b, 0x9999), Some(("gamma_unknown_size", 0x8799)));
    }

    #[test]
    fn before_first_symbol_is_none() {
        let b = sample();
        assert_eq!(resolve(&b, 0x0500), None);
    }

    #[test]
    fn empty_and_invalid_blobs() {
        assert_eq!(resolve(&[], 0x1000), None);
        assert_eq!(resolve(b"KSY2\0\0\0\0", 0x1000), None);
        assert_eq!(resolve(b"junk", 0x1000), None);
        assert_eq!(resolve(&build(&[]), 0x1000), None);
    }

    #[test]
    fn entries_are_sorted_and_deduped() {
        let b = build(&[(0x200, 1, "b"), (0x100, 1, "a"), (0x200, 1, "dup")]);
        // Sorted: a@0x100, then the first 0x200 kept.
        assert_eq!(resolve(&b, 0x100), Some(("a", 0)));
        assert!(matches!(resolve(&b, 0x200), Some((_, 0))));
    }
}
