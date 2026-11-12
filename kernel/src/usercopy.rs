//! Fault-safe copies between kernel and user memory.
//!
//! User pointers are validated (must lie in the lower, user half) and then
//! reached through the HHDM alias of their backing frames. Because the HHDM is a
//! supervisor mapping, these copies never touch a user (U=1) page directly, so
//! SMAP is not engaged and no page fault can occur on a mapped address — the
//! routines simply return `EFAULT` for any unmapped page. (Direct user-VA access
//! with `stac`/`clac` and an exception-fixup table is a future optimization.)

use crate::mm::paging;
use abi::Errno;
use alloc::vec::Vec;

const PAGE: u64 = 4096;
/// Exclusive upper bound of the user address range (canonical lower half).
pub const USER_MAX: u64 = 0x0000_8000_0000_0000;

/// Set true once `clone(CLONE_VM)` can create threads sharing an address space.
/// While false (M4 so far) the validate-then-copy-via-HHDM scheme below is safe;
/// once true it becomes a TOCTOU (a peer thread could `munmap` between the
/// mapping check and the copy, after which the freed frame may be recycled), so
/// the copy routines MUST switch to direct user-VA access with stac/clac and an
/// exception-fixup table before that lands.
pub static ADDRESS_SPACE_SHARED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn user_phys(vaddr: u64) -> Result<u64, Errno> {
    debug_assert!(
        !ADDRESS_SPACE_SHARED.load(core::sync::atomic::Ordering::Relaxed),
        "usercopy via HHDM is a TOCTOU with shared address spaces; needs          stac/clac + exception fixup before CLONE_VM"
    );
    if vaddr >= USER_MAX {
        return Err(Errno::EFAULT);
    }
    paging::translate_active(vaddr).ok_or(Errno::EFAULT)
}

/// Copies `out.len()` bytes from user address `uaddr` into `out`.
pub fn copy_from_user(uaddr: u64, out: &mut [u8]) -> Result<(), Errno> {
    let hhdm = crate::mm::phys::hhdm_offset();
    let mut done = 0usize;
    while done < out.len() {
        let va = uaddr + done as u64;
        let page_off = va & (PAGE - 1);
        let chunk = ((PAGE - page_off) as usize).min(out.len() - done);
        let phys = user_phys(va)?;
        let src = (hhdm + phys) as *const u8;
        // SAFETY: `phys` is a mapped frame; `chunk` stays within the page.
        unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr().add(done), chunk) };
        done += chunk;
    }
    Ok(())
}

/// Copies `data` into user memory at `uaddr`.
pub fn copy_to_user(uaddr: u64, data: &[u8]) -> Result<(), Errno> {
    let hhdm = crate::mm::phys::hhdm_offset();
    let mut done = 0usize;
    while done < data.len() {
        let va = uaddr + done as u64;
        let page_off = va & (PAGE - 1);
        let chunk = ((PAGE - page_off) as usize).min(data.len() - done);
        let phys = user_phys(va)?;
        let dst = (hhdm + phys) as *mut u8;
        // SAFETY: `phys` is a mapped frame; `chunk` stays within the page.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(done), dst, chunk) };
        done += chunk;
    }
    Ok(())
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
