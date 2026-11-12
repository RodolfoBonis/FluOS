//! A minimal ELF64 loader for static and static-PIE user programs.
//!
//! It maps each `PT_LOAD` segment into the target [`AddressSpace`] with W^X
//! permissions, copying the file bytes and zero-filling the BSS, then reports
//! the entry point and program-header location so the stack builder can hand
//! musl the auxv it expects. PIE (`ET_DYN`) images are loaded at a fixed base
//! and self-relocate in their crt startup.

use crate::process::AddressSpace;
use abi::Errno;

/// Base address for position-independent (`ET_DYN`) executables.
const PIE_BASE: u64 = 0x4000_0000;

const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

/// Result of loading an ELF: everything the auxv and entry need.
#[derive(Clone, Copy, Debug)]
pub struct Loaded {
    pub entry: u64,
    pub phdr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub base: u64,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

/// Loads the ELF image `data` into `space`.
pub fn load(space: &mut AddressSpace, data: &[u8]) -> Result<Loaded, Errno> {
    // ELF identity: 0x7F 'E' 'L' 'F', class 2 (64-bit), data 1 (little-endian).
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return Err(Errno(abi::errno::ENOEXEC));
    }
    let e_type = u16_at(data, 16).ok_or(Errno(abi::errno::ENOEXEC))?;
    let e_machine = u16_at(data, 18).ok_or(Errno(abi::errno::ENOEXEC))?;
    if e_machine != EM_X86_64 || (e_type != ET_EXEC && e_type != ET_DYN) {
        return Err(Errno(abi::errno::ENOEXEC));
    }
    let base = if e_type == ET_DYN { PIE_BASE } else { 0 };

    let e_entry = u64_at(data, 24).ok_or(Errno(abi::errno::ENOEXEC))?;
    let e_phoff = u64_at(data, 32).ok_or(Errno(abi::errno::ENOEXEC))?;
    let e_phentsize = u16_at(data, 54).ok_or(Errno(abi::errno::ENOEXEC))? as usize;
    let e_phnum = u16_at(data, 56).ok_or(Errno(abi::errno::ENOEXEC))? as usize;

    let mut phdr_vaddr = base + e_phoff; // fallback AT_PHDR

    for i in 0..e_phnum {
        let ph = e_phoff as usize + i * e_phentsize;
        let p_type = u32_at(data, ph).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_flags = u32_at(data, ph + 4).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_offset = u64_at(data, ph + 8).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_vaddr = u64_at(data, ph + 16).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_filesz = u64_at(data, ph + 32).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_memsz = u64_at(data, ph + 40).ok_or(Errno(abi::errno::ENOEXEC))?;

        match p_type {
            PT_PHDR => phdr_vaddr = base + p_vaddr,
            PT_LOAD => {
                let vaddr = base + p_vaddr;
                let writable = p_flags & 2 != 0;
                let exec = p_flags & 1 != 0;
                // Real permissions (W^X): the kernel writes segment contents
                // through the HHDM below, bypassing the user mapping, so a
                // read-only text segment stays non-writable from user mode.
                space.map_region(vaddr, p_memsz, writable, exec);
                let fsz = p_filesz as usize;
                let start = p_offset as usize;
                if let Some(bytes) = data.get(start..start + fsz) {
                    space.write(vaddr, bytes);
                }
            }
            _ => {}
        }
    }

    Ok(Loaded {
        entry: base + e_entry,
        phdr: phdr_vaddr,
        phent: e_phentsize as u64,
        phnum: e_phnum as u64,
        base,
    })
}
