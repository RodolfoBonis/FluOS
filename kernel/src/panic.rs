//! Panic handling and a frame-pointer backtrace.
//!
//! Frame pointers are forced on for every target (see `.cargo/config.toml`), so
//! each stack frame stores the caller's RBP at `[rbp]` and the return address
//! at `[rbp + 8]`. Walking that chain gives a backtrace without any unwinding
//! tables. Addresses are printed raw and as offsets from the kernel's virtual
//! base, which `addr2line` against the kernel ELF can resolve to source lines.

use crate::arch::x86_64::{QemuExitCode, halt_forever, qemu_exit};
use core::panic::PanicInfo;

/// Kernel virtual base (see `kernel/linker.ld`). Backtrace frames are reported
/// relative to this so symbols can be looked up in the ELF.
const KERNEL_VIRT_BASE: u64 = 0xffff_ffff_8000_0000;

/// Lowest canonical higher-half address; anything below is not a kernel stack
/// pointer and signals the end (or corruption) of the chain.
const HIGHER_HALF_MIN: u64 = 0xffff_8000_0000_0000;

/// Walks the saved-RBP chain from the current frame and logs each return
/// address. Safe to call from any kernel context, including fault handlers.
pub fn backtrace() {
    let mut rbp: u64;
    // SAFETY: reading RBP has no side effects; the value is validated below
    // before any dereference.
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags)) };

    crate::log::error!("backtrace (kernel base {KERNEL_VIRT_BASE:#018x}):");
    for frame in 0..64u32 {
        // A valid frame pointer is non-null, 8-byte aligned, and higher-half.
        if rbp < HIGHER_HALF_MIN || rbp & 0x7 != 0 {
            break;
        }
        // SAFETY: `rbp` is a canonical, aligned higher-half address, which in
        // our address space is backed by the HHDM-mapped kernel stack.
        let return_addr = unsafe { ((rbp + 8) as *const u64).read_volatile() };
        let saved_rbp = unsafe { (rbp as *const u64).read_volatile() };

        if return_addr == 0 {
            break;
        }
        let rel = return_addr.wrapping_sub(KERNEL_VIRT_BASE);
        crate::log::error!("  #{frame:<2} {return_addr:#018x}  (kernel+{rel:#x})");

        // Frame pointers grow toward higher addresses up the stack; a
        // non-increasing value means we have left the chain.
        if saved_rbp <= rbp {
            break;
        }
        rbp = saved_rbp;
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crate::log::write_unlocked(format_args!("{info}"));
    backtrace();
    qemu_exit(QemuExitCode::Failure);
    halt_forever()
}
