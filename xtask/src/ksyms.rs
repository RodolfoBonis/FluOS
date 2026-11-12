//! Kernel symbol-table extraction for symbolized panic backtraces.
//!
//! Reads the function symbols from a first-pass kernel ELF, demangles them, and
//! writes a compact blob the kernel embeds on its second build pass. See
//! `kernel/src/ksyms.rs` for the matching reader and the blob format.

use anyhow::{Context, Result};
use object::{Object, ObjectSymbol, SymbolKind};
use std::fs;
use std::path::Path;

/// Extracts function symbols from `elf` and writes the symbol blob to `out`.
/// Returns the number of symbols written.
pub fn generate(elf: &Path, out: &Path) -> Result<usize> {
    let data = fs::read(elf).with_context(|| format!("reading {}", elf.display()))?;
    let obj = object::File::parse(&*data).context("parsing kernel ELF")?;

    // Collect function symbols with a real address.
    let mut syms: Vec<(u64, String)> = obj
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0)
        .filter_map(|s| {
            let name = s.name().ok()?;
            Some((s.address(), format!("{:#}", rustc_demangle::demangle(name))))
        })
        .collect();

    syms.sort_by_key(|(addr, _)| *addr);
    syms.dedup_by_key(|(addr, _)| *addr);

    // Build the blob: magic, count, entries {addr:u64, name_off:u32}, strings.
    let mut strings: Vec<u8> = Vec::new();
    let mut entries: Vec<(u64, u32)> = Vec::with_capacity(syms.len());
    for (addr, name) in &syms {
        let off = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        entries.push((*addr, off));
    }

    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(b"KSY1");
    blob.extend_from_slice(&(syms.len() as u32).to_le_bytes());
    for (addr, off) in &entries {
        blob.extend_from_slice(&addr.to_le_bytes());
        blob.extend_from_slice(&off.to_le_bytes());
    }
    blob.extend_from_slice(&strings);

    fs::write(out, &blob).with_context(|| format!("writing {}", out.display()))?;
    Ok(syms.len())
}
