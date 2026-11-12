//! Kernel symbol-table extraction for symbolized panic backtraces.
//!
//! Reads function symbols (address, size, name) from a kernel ELF, demangles
//! them, and produces the blob the kernel embeds. The blob format and the
//! matching resolver live in the host-tested `ksyms` crate, so the two can
//! never disagree.

use anyhow::{Context, Result};
use object::{Object, ObjectSymbol, SymbolKind};
use std::fs;
use std::path::Path;

/// Builds the symbol blob for `elf`, returning its bytes.
pub fn extract(elf: &Path) -> Result<Vec<u8>> {
    let data = fs::read(elf).with_context(|| format!("reading {}", elf.display()))?;
    let obj = object::File::parse(&*data).context("parsing kernel ELF")?;

    let demangled: Vec<(u64, u32, String)> = obj
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0)
        .filter_map(|s| {
            let name = s.name().ok()?;
            Some((s.address(), s.size() as u32, format!("{:#}", rustc_demangle::demangle(name))))
        })
        .collect();

    let triples: Vec<(u64, u32, &str)> =
        demangled.iter().map(|(a, sz, n)| (*a, *sz, n.as_str())).collect();
    Ok(ksyms::build(&triples))
}

/// Extracts the blob and writes it to `out`, returning the symbol count.
pub fn generate(elf: &Path, out: &Path) -> Result<usize> {
    let blob = extract(elf)?;
    fs::write(out, &blob).with_context(|| format!("writing {}", out.display()))?;
    // Count = (len - header) / entry_size is implementation detail; recompute
    // from the ELF for the log.
    let data = fs::read(elf)?;
    let obj = object::File::parse(&*data)?;
    let count = obj
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0)
        .count();
    Ok(count)
}
