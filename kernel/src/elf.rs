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

    // Every user virtual address the loader produces must land in the user half.
    // All address math is checked: a hostile or corrupt ELF must never wrap or
    // alias into the kernel range.
    let user_max = crate::usercopy::USER_MAX;
    let check_vaddr = |v: u64| -> Result<u64, Errno> {
        if v >= user_max { Err(Errno(abi::errno::ENOEXEC)) } else { Ok(v) }
    };

    // AT_PHDR must be the *virtual* address where the program headers are
    // loaded. Default to the PT_LOAD that covers `e_phoff` (set below); fall
    // back to base+e_phoff only if nothing covers it.
    let mut phdr_vaddr = base.checked_add(e_phoff).ok_or(Errno(abi::errno::ENOEXEC))?;

    for i in 0..e_phnum {
        // ph = e_phoff + i * e_phentsize, all checked against overflow.
        let ph = e_phoff
            .checked_add((i as u64).checked_mul(e_phentsize as u64).ok_or(Errno(abi::errno::ENOEXEC))?)
            .ok_or(Errno(abi::errno::ENOEXEC))? as usize;
        let p_type = u32_at(data, ph).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_flags = u32_at(data, ph + 4).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_offset = u64_at(data, ph + 8).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_vaddr = u64_at(data, ph + 16).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_filesz = u64_at(data, ph + 32).ok_or(Errno(abi::errno::ENOEXEC))?;
        let p_memsz = u64_at(data, ph + 40).ok_or(Errno(abi::errno::ENOEXEC))?;

        match p_type {
            PT_PHDR => {
                phdr_vaddr = check_vaddr(base.checked_add(p_vaddr).ok_or(Errno(abi::errno::ENOEXEC))?)?;
            }
            PT_LOAD => {
                let vaddr = check_vaddr(base.checked_add(p_vaddr).ok_or(Errno(abi::errno::ENOEXEC))?)?;
                // The mapped span [vaddr, vaddr + p_memsz) must stay in-range.
                let vend = vaddr.checked_add(p_memsz).ok_or(Errno(abi::errno::ENOEXEC))?;
                if vend > user_max {
                    return Err(Errno(abi::errno::ENOEXEC));
                }
                // File-backed span [p_offset, p_offset + p_filesz) must fit the
                // image, with no overflow and filesz <= memsz.
                let fend = p_offset.checked_add(p_filesz).ok_or(Errno(abi::errno::ENOEXEC))?;
                if p_filesz > p_memsz || fend as usize > data.len() {
                    return Err(Errno(abi::errno::ENOEXEC));
                }
                // If this segment contains the program headers, derive AT_PHDR
                // from where they land in memory.
                if p_offset <= e_phoff && e_phoff < fend {
                    phdr_vaddr = check_vaddr(vaddr + (e_phoff - p_offset))?;
                }
                let writable = p_flags & 2 != 0;
                let exec = p_flags & 1 != 0;
                // Real permissions (W^X): the kernel writes segment contents
                // through the HHDM below, bypassing the user mapping, so a
                // read-only text segment stays non-writable from user mode.
                space.map_region(vaddr, p_memsz, writable, exec);
                if let Some(bytes) = data.get(p_offset as usize..fend as usize) {
                    space.write(vaddr, bytes);
                }
            }
            _ => {}
        }
    }

    Ok(Loaded {
        entry: check_vaddr(base.checked_add(e_entry).ok_or(Errno(abi::errno::ENOEXEC))?)?,
        phdr: phdr_vaddr,
        phent: e_phentsize as u64,
        phnum: e_phnum as u64,
        base,
    })
}
