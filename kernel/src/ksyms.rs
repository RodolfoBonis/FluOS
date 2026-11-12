//! Embedded kernel symbol table for symbolized panic backtraces.
//!
//! `xtask` builds the kernel twice: pass 1 yields an ELF whose function symbols
//! (address, size, demangled name) it extracts into a blob; pass 2 embeds that
//! blob via `include_bytes!`. Because the blob lands in `.rodata` — which
//! follows `.text` — adding it never shifts a function's address, so the
//! recorded addresses stay valid; `xtask` additionally regenerates the blob
//! from the final ELF and byte-compares (a fixed-point check) to prove it.
//!
//! The blob format and resolver live in the host-tested [`ksyms`] crate.

/// The embedded blob. `FLUOS_KSYMS_FILE` is set by `build.rs` to either the
/// generated symbol file or an empty placeholder.
static KSYMS: &[u8] = include_bytes!(env!("FLUOS_KSYMS_FILE"));

/// Resolves `addr` to the nearest preceding function symbol (respecting sizes).
pub fn resolve(addr: u64) -> Option<(&'static str, u64)> {
    ksyms::resolve(KSYMS, addr)
}

/// Boot self-test: confirms the embedded table resolves a known function (this
/// resolver) to its own name — catching a stale or mis-aligned blob early.
pub fn selftest() {
    let addr = resolve as *const () as u64;
    match resolve(addr) {
        Some((name, _)) if name.contains("resolve") => {
            crate::log::info!("ksyms: symbol table OK ({} entries resolved self as {name})", "backtrace");
        }
        Some((name, off)) => {
            crate::log::warning!("ksyms: self-resolve mismatch: {name}+{off:#x} (expected *resolve*)");
        }
        None => crate::log::warning!("ksyms: symbol table empty or unresolved (raw-address backtraces)"),
    }
}
