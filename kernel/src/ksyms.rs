//! Embedded kernel symbol table for symbolized panic backtraces.
//!
//! `xtask` builds the kernel twice: the first pass produces an ELF whose
//! function symbols it extracts (and demangles) into a compact blob; the second
//! pass embeds that blob here via `include_bytes!`. Because the blob lands in
//! `.rodata` — which follows `.text` — adding it never shifts a function's
//! address, so the addresses recorded in the blob stay valid for the final
//! image. When no blob is provided the table is empty and backtraces fall back
//! to raw addresses.
//!
//! Blob format (little-endian): magic `"KSY1"`, `count: u32`, then `count`
//! entries of `{ addr: u64, name_off: u32 }` sorted ascending by address,
//! followed by NUL-terminated names (`name_off` indexes this string region).

/// The embedded blob. `FLUOS_KSYMS_FILE` is set by `build.rs` to either the
/// generated symbol file or an empty placeholder.
static KSYMS: &[u8] = include_bytes!(env!("FLUOS_KSYMS_FILE"));

const HEADER: usize = 8;
const ENTRY: usize = 12;

/// Reads a little-endian `u32` at `off`, or `None` if out of bounds.
fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a little-endian `u64` at `off`, or `None` if out of bounds.
fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Resolves `addr` to the nearest preceding function symbol, returning its
/// name and the offset of `addr` within it. `None` if the table is empty or
/// `addr` precedes every symbol.
pub fn resolve(addr: u64) -> Option<(&'static str, u64)> {
    let buf = KSYMS;
    if buf.len() < HEADER || &buf[0..4] != b"KSY1" {
        return None;
    }
    let count = read_u32(buf, 4)? as usize;
    if count == 0 {
        return None;
    }
    let strings_start = HEADER + count * ENTRY;
    if buf.len() < strings_start {
        return None;
    }

    let entry_addr = |i: usize| read_u64(buf, HEADER + i * ENTRY);

    // Binary search for the greatest symbol address <= `addr`.
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
        return None; // before the first symbol
    }
    let idx = lo - 1;
    let sym_addr = entry_addr(idx)?;
    let name_off = read_u32(buf, HEADER + idx * ENTRY + 8)? as usize;

    let name = read_cstr(buf, strings_start + name_off)?;
    Some((name, addr - sym_addr))
}

/// Reads a NUL-terminated UTF-8 string starting at `off`.
fn read_cstr(buf: &'static [u8], off: usize) -> Option<&'static str> {
    let rest = buf.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    // SAFETY note: `buf` is `'static` (embedded), so the slice is `'static`.
    core::str::from_utf8(&rest[..end]).ok()
}
