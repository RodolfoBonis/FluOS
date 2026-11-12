//! Fault-safe copies between kernel and user memory.
//!
//! Copies go through [`copy_user`], a tiny assembly routine that accesses the
//! user virtual addresses *directly* (bracketed by `stac`/`clac` so SMAP lets
//! the kernel touch user pages). Two things make this safe:
//!
//! * A fault on a bad user address does not crash the kernel: the faulting
//!   instruction is registered in an exception-fixup table ([`extable_fixup`]),
//!   and the page-fault handler redirects it to a fixup that returns the number
//!   of bytes left uncopied, which the wrappers turn into `EFAULT`.
//! * Because the CPU performs the access itself, a demand-paged or copy-on-write
//!   page faults normally and is resolved by the page-fault handler mid-copy —
//!   no translate-then-copy window. That also makes it correct once a
//!   `clone(CLONE_VM)` peer can mutate the address space concurrently (the old
//!   validate-via-HHDM scheme was a TOCTOU there).

use abi::Errno;
use alloc::vec::Vec;
use core::arch::global_asm;

/// Exclusive upper bound of the user address range (canonical lower half).
pub const USER_MAX: u64 = 0x0000_8000_0000_0000;

/// Set once `clone(CLONE_VM)` threads share an address space. The direct-VA
/// copies below are TOCTOU-safe either way, so this is now informational.
#[allow(dead_code)] // set by clone(CLONE_VM); copies are TOCTOU-safe regardless
pub static ADDRESS_SPACE_SHARED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// `copy_user(dst, src, len) -> usize`: copies `len` bytes and returns the number
// NOT copied (0 on success, the remaining count if a fault aborted it). The
// `rep movsb` is the only faulting instruction; a fault there is redirected to
// the `clac; mov rax,rcx; ret` tail via the exception-fixup table.
global_asm!(
    r#"
.global fluos_copy_user
.global fluos_copy_user_fault
.global fluos_copy_user_fixup
fluos_copy_user:
    mov rcx, rdx
    stac
fluos_copy_user_fault:
    rep movsb
fluos_copy_user_fixup:
    clac
    mov rax, rcx
    ret
"#
);

unsafe extern "C" {
    fn fluos_copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    fn fluos_copy_user_fault();
    fn fluos_copy_user_fixup();
}

/// If `rip` is the faulting instruction of a user copy, returns the fixup
/// address the page-fault handler should resume at. Called for kernel-mode
/// faults only.
#[must_use]
pub fn extable_fixup(rip: u64) -> Option<u64> {
    if rip == fluos_copy_user_fault as *const () as u64 {
        Some(fluos_copy_user_fixup as *const () as u64)
    } else {
        None
    }
}

/// Rejects a user range that is empty-safe but out of the user half or wrapping.
fn check_range(uaddr: u64, len: usize) -> Result<(), Errno> {
    let end = uaddr.checked_add(len as u64).ok_or(Errno::EFAULT)?;
    if uaddr >= USER_MAX || end > USER_MAX {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// Copies `out.len()` bytes from user address `uaddr` into `out`.
pub fn copy_from_user(uaddr: u64, out: &mut [u8]) -> Result<(), Errno> {
    if out.is_empty() {
        return Ok(());
    }
    check_range(uaddr, out.len())?;
    // SAFETY: `copy_user` reads user memory with SMAP open and a registered
    // fixup; a fault returns the uncopied count instead of crashing.
    let left = unsafe { fluos_copy_user(out.as_mut_ptr(), uaddr as *const u8, out.len()) };
    if left == 0 { Ok(()) } else { Err(Errno::EFAULT) }
}

/// Copies `data` into user memory at `uaddr`.
pub fn copy_to_user(uaddr: u64, data: &[u8]) -> Result<(), Errno> {
    if data.is_empty() {
        return Ok(());
    }
    check_range(uaddr, data.len())?;
    // SAFETY: as above; writing user memory (demand/CoW faults resolve mid-copy).
    let left = unsafe { fluos_copy_user(uaddr as *mut u8, data.as_ptr(), data.len()) };
    if left == 0 { Ok(()) } else { Err(Errno::EFAULT) }
}

/// Writes a `T` to user memory at `uaddr`.
pub fn put_user<T: Copy>(uaddr: u64, value: T) -> Result<(), Errno> {
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(&value).cast::<u8>(), size_of::<T>())
    };
    copy_to_user(uaddr, bytes)
}

/// Reads a NUL-terminated string (up to `max` bytes) from user memory.
pub fn read_cstr(uaddr: u64, max: usize) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    for i in 0..max as u64 {
        let mut b = [0u8; 1];
        copy_from_user(uaddr + i, &mut b)?;
        if b[0] == 0 {
            return Ok(out);
        }
        out.push(b[0]);
    }
    Err(Errno(abi::errno::ENAMETOOLONG))
}

/// Reads a NUL-terminated array of user pointers (argv/envp) into a `Vec`.
#[allow(dead_code)] // used by execve
pub fn read_ptr_array(uaddr: u64, max: usize) -> Result<Vec<u64>, Errno> {
    let mut out = Vec::new();
    for i in 0..max as u64 {
        let mut b = [0u8; 8];
        copy_from_user(uaddr + i * 8, &mut b)?;
        let p = u64::from_le_bytes(b);
        if p == 0 {
            return Ok(out);
        }
        out.push(p);
    }
    Err(Errno::EINVAL)
}

use core::mem::size_of;
