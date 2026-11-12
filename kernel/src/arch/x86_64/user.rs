//! User-mode entry, the `syscall` fast path, and the saved-register frame.
//!
//! We keep the GS base pointed at per-CPU state in both ring 0 and ring 3 (user
//! TLS uses FS via `arch_prctl`, as musl does), so no `swapgs` is needed: every
//! interrupt and syscall sees the correct GS. The `syscall` entry parks the user
//! stack pointer, switches to the current thread's kernel stack (reached through
//! `gs:[0]`), builds a [`Regs`] frame, dispatches, then restores and `sysretq`s.

use super::gdt::{self, KERNEL_CODE, KERNEL_DATA, USER_CODE, USER_DATA};
use core::arch::naked_asm;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{DS, ES, Segment};
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::SegmentSelector;

/// The user register frame built by [`syscall_entry`] (ascending address order
/// matches the push sequence). The dispatcher reads syscall args from it and
/// writes the result into `rax`.
#[repr(C)]
#[derive(Debug)]
pub struct Regs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    /// Syscall number on entry; return value on exit.
    pub rax: u64,
    /// User instruction pointer (from `rcx`, for `sysretq`).
    pub rip: u64,
    /// User RFLAGS (from `r11`, for `sysretq`).
    pub rflags: u64,
    pub user_rsp: u64,
}

impl Regs {
    /// The six syscall arguments, in Linux order (rdi, rsi, rdx, r10, r8, r9).
    #[must_use]
    pub fn args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }
}

fn sel(raw: u16) -> SegmentSelector {
    SegmentSelector(raw)
}

/// Programs the `syscall`/`sysret` MSRs on this CPU. Idempotent per CPU.
pub fn init_syscall() {
    // SAFETY: enabling SCE only turns on `syscall`/`sysret`.
    unsafe { Efer::update(|f| f.insert(EferFlags::SYSTEM_CALL_EXTENSIONS)) };

    // STAR: on syscall CS=kernel code / SS=kernel data; on sysret CS=user code /
    // SS=user data. `Star::write` validates the selector adjacency.
    Star::write(sel(USER_CODE), sel(USER_DATA), sel(KERNEL_CODE), sel(KERNEL_DATA))
        .expect("STAR selector layout");

    LStar::write(VirtAddr::new(syscall_entry as *const () as u64));
    // Clear IF/DF/TF/AC on entry so the handler runs with a sane flags state and
    // interrupts masked (short syscalls are non-preemptible).
    SFMask::write(
        RFlags::INTERRUPT_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::TRAP_FLAG
            | RFlags::ALIGNMENT_CHECK,
    );
}

/// The `syscall` instruction entry point. Naked: it manages the stack switch and
/// register frame by hand before calling the Rust dispatcher.
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        "swapgs",                // GS_BASE <- per-CPU (KERNEL_GS_BASE holds user GS)
        "mov gs:[8], rsp",       // park user rsp
        "mov rsp, gs:[0]",       // switch to this thread's kernel stack
        "push qword ptr gs:[8]", // Regs.user_rsp
        "push r11",              // Regs.rflags
        "push rcx",              // Regs.rip
        "push rax",              // Regs.rax (syscall number)
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbx",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",          // &mut Regs
        "call {dispatch}",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rbx",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rax",               // return value
        "pop rcx",               // user rip
        "pop r11",               // user rflags
        "pop rsp",               // restore user rsp
        "swapgs",                // GS_BASE <- user GS before returning to ring 3
        "sysretq",
        dispatch = sym crate::syscall::dispatch,
    );
}

/// Enters user mode at `entry` with stack `user_sp`, never returning. GS stays
/// pointed at per-CPU state; the user sets its own FS for TLS.
///
/// # Safety
/// `entry` and `user_sp` must be valid user virtual addresses in the active
/// address space, and the TSS `RSP0` / `gs:[0]` kernel stack must already be set
/// for this thread.
pub unsafe fn enter_user(entry: u64, user_sp: u64) -> ! {
    // SAFETY: loading the ring-3 data selector into DS/ES is valid from ring 0.
    unsafe {
        DS::set_reg(sel(USER_DATA));
        ES::set_reg(sel(USER_DATA));
    }
    // SAFETY: disable interrupts across the swapgs→iretq window (an IRQ here
    // would run with the user GS already swapped in), flip to the user GS, and
    // iretq to ring 3 (the pushed RFLAGS re-enables interrupts there).
    unsafe {
        core::arch::asm!(
            "cli",
            "swapgs",
            "push {ss}",
            "push {sp}",
            "push {flags}",
            "push {cs}",
            "push {ip}",
            "iretq",
            ss = in(reg) u64::from(USER_DATA),
            sp = in(reg) user_sp,
            flags = in(reg) 0x202u64, // IF set + reserved bit 1
            cs = in(reg) u64::from(USER_CODE),
            ip = in(reg) entry,
            options(noreturn),
        )
    }
}

/// Updates this CPU's kernel-stack pointers (TSS `RSP0` and `gs:[0]`) so a
/// syscall or interrupt from user mode lands on `kstack_top`.
pub fn set_kernel_stack(kstack_top: u64) {
    let cpu = crate::percpu::this();
    cpu.kernel_rsp.store(kstack_top, core::sync::atomic::Ordering::Relaxed);
    let tss = cpu.tss.load(core::sync::atomic::Ordering::Relaxed);
    if tss != 0 {
        // SAFETY: `tss` is this CPU's live TSS pointer recorded at init.
        unsafe { gdt::set_rsp0(tss as *mut _, kstack_top) };
    }
}
