//! User-mode entry, the `syscall` fast path, and the saved-register frame.
//!
//! Ring 3 runs with the user's GS base; the kernel's per-CPU GS lives in
//! `KERNEL_GS_BASE`, so every user-reachable entry (`syscall` and the interrupt
//! stubs) `swapgs`es on the way in and out. User TLS uses FS via `arch_prctl`,
//! as musl does. The `syscall` entry swaps to the per-CPU GS, parks the user
//! stack pointer, switches to the current thread's kernel stack (reached through
//! `gs:[0]`), builds a [`Regs`] frame, dispatches, then restores and `sysretq`s
//! — unless the user RIP to resume is non-canonical, in which case it kills the
//! process rather than executing a `sysretq` that would #GP in ring 0.

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
#[derive(Debug, Clone, Copy)]
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
        // L1/CVE-2012-0217: the value we are about to load into RCX for
        // `sysretq` is the user RIP. A non-canonical RCX makes `sysretq` #GP
        // *in ring 0* with a user-controlled stack. Validate canonicality
        // (bits [63:47] all equal) first; if it fails, kill the process on the
        // kernel stack instead of ever executing the vulnerable `sysretq`.
        // RAX/RCX are scratch here — the pops below reload them from the frame.
        "mov rax, [rsp + {o_rip}]",
        "mov rcx, rax",
        "shl rcx, 16",
        "sar rcx, 16",
        "cmp rcx, rax",
        "jne 2f",
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
        "2:",                    // non-canonical user rip: never sysretq
        "mov rdi, rsp",          // &Regs (frame base is 16-aligned here)
        "call {bad_sysret}",
        dispatch = sym crate::syscall::dispatch,
        bad_sysret = sym bad_sysret,
        o_rip = const core::mem::offset_of!(Regs, rip),
    );
}

/// Called from the `syscall` return path when the user RIP to load into RCX is
/// non-canonical. Executing `sysretq` with such an RCX would #GP in ring 0 with
/// a user-controlled stack (CVE-2012-0217), so we never run it: the offending
/// process is killed with SIGSEGV. GS is still the kernel's per-CPU GS here, so
/// per-CPU and process state are reachable. Never returns.
extern "C" fn bad_sysret(regs: &Regs) -> ! {
    crate::log::error!(
        "syscall return with non-canonical rip {:#018x} -> killing process (SIGSEGV)",
        regs.rip,
    );
    if let Some(p) = crate::process::current() {
        let ppid = {
            let mut g = p.lock();
            g.exit_code = Some(128 + abi::types::SIGSEGV);
            g.ppid
        };
        crate::signal::notify_parent(ppid);
    }
    crate::scheduler::thread_exit();
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

/// Enters user mode with a full saved register set (used by a `fork` child,
/// which resumes exactly where the parent was with `rax = 0`). Never returns.
///
/// # Safety
/// `regs` must describe a valid user context in the active address space, and
/// the per-CPU kernel stack / GS must be set up for this thread.
pub unsafe fn enter_user_regs(regs: &Regs) -> ! {
    use core::mem::offset_of;
    // SAFETY: builds an iretq frame from `regs`, restores the GPRs (loading the
    // pointer register r15 last), flips to the user GS, and returns to ring 3.
    unsafe {
        core::arch::asm!(
            "cli",
            "swapgs",
            "push {ss}",
            "push qword ptr [r15 + {o_rsp}]",
            "push qword ptr [r15 + {o_rflags}]",
            "push {cs}",
            "push qword ptr [r15 + {o_rip}]",
            "mov rax, [r15 + {o_rax}]",
            "mov rbx, [r15 + {o_rbx}]",
            "xor rcx, rcx",
            "mov rdx, [r15 + {o_rdx}]",
            "mov rsi, [r15 + {o_rsi}]",
            "mov rdi, [r15 + {o_rdi}]",
            "mov rbp, [r15 + {o_rbp}]",
            "mov r8,  [r15 + {o_r8}]",
            "mov r9,  [r15 + {o_r9}]",
            "mov r10, [r15 + {o_r10}]",
            "xor r11, r11",
            "mov r12, [r15 + {o_r12}]",
            "mov r13, [r15 + {o_r13}]",
            "mov r14, [r15 + {o_r14}]",
            "mov r15, [r15 + {o_r15}]",
            "iretq",
            in("r15") regs,
            ss = const USER_DATA as u64,
            cs = const USER_CODE as u64,
            o_rsp = const offset_of!(Regs, user_rsp),
            o_rflags = const offset_of!(Regs, rflags),
            o_rip = const offset_of!(Regs, rip),
            o_rax = const offset_of!(Regs, rax),
            o_rbx = const offset_of!(Regs, rbx),
            o_rdx = const offset_of!(Regs, rdx),
            o_rsi = const offset_of!(Regs, rsi),
            o_rdi = const offset_of!(Regs, rdi),
            o_rbp = const offset_of!(Regs, rbp),
            o_r8 = const offset_of!(Regs, r8),
            o_r9 = const offset_of!(Regs, r9),
            o_r10 = const offset_of!(Regs, r10),
            o_r12 = const offset_of!(Regs, r12),
            o_r13 = const offset_of!(Regs, r13),
            o_r14 = const offset_of!(Regs, r14),
            o_r15 = const offset_of!(Regs, r15),
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
