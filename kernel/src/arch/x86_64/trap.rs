//! CPU-exception entry: naked stubs with conditional `swapgs`, a uniform
//! register frame, and the Rust fault handlers.
//!
//! Exceptions can fire in ring 3 (a user page fault, a bad instruction), where
//! GS_BASE holds the user's GS. Each exception is reached through a naked stub
//! that `swapgs`es based on the saved CS privilege level (so the handler sees
//! the per-CPU GS), builds a [`TrapFrame`], and dispatches. The page-fault
//! handler can then safely reach per-CPU and process state for demand paging.
//!
//! IST faults (#DF/#NMI/#MC) keep their dedicated stacks and use a *paranoid*
//! entry: they can fire in the user<->kernel transition windows where CS and
//! GS_BASE disagree, so the stub reads IA32_GS_BASE and swapgs only when a
//! user-half base is loaded, rather than trusting the saved CS.

use crate::arch::x86_64::gdt;
use x86_64::VirtAddr;
use x86_64::structures::idt::InterruptDescriptorTable;

/// Saved register + hardware frame built by the exception stubs.
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    fn from_user(&self) -> bool {
        self.cs & 3 != 0
    }
}

/// Generates a naked exception stub. `$err` is `has_err` for error-code
/// exceptions (CPU pushes the code) or `no_err` (we push a dummy 0).
macro_rules! trap_stub {
    ($stub:ident, $handler:path, has_err) => {
        trap_stub!(@inner $stub, $handler, "test qword ptr [rsp + 16], 3", "");
    };
    ($stub:ident, $handler:path, no_err) => {
        trap_stub!(@inner $stub, $handler, "test qword ptr [rsp + 8], 3", "push 0");
    };
    (@inner $stub:ident, $handler:path, $cstest:literal, $pusherr:literal) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $stub() {
            core::arch::naked_asm!(
                $cstest,          // from user? (RPL of saved CS)
                "jz 1f",
                "swapgs",
                "1:",
                $pusherr,         // normalize: dummy error code for no-err traps
                "push rax", "push rbx", "push rcx", "push rdx", "push rsi",
                "push rdi", "push rbp", "push r8", "push r9", "push r10",
                "push r11", "push r12", "push r13", "push r14", "push r15",
                "mov rdi, rsp",   // &TrapFrame
                "mov rbp, rsp",
                "and rsp, -16",   // align for the SysV call
                "cld",
                "call {h}",
                "mov rsp, rbp",
                "pop r15", "pop r14", "pop r13", "pop r12", "pop r11",
                "pop r10", "pop r9", "pop r8", "pop rbp", "pop rdi",
                "pop rsi", "pop rdx", "pop rcx", "pop rbx", "pop rax",
                "add rsp, 8",     // drop error code
                "test qword ptr [rsp + 8], 3",
                "jz 2f",
                "swapgs",
                "2:",
                "iretq",
                h = sym $handler,
            );
        }
    };
}

/// Logs the faulting context shared by every handler.
fn dump(name: &str, f: &TrapFrame) {
    crate::log::error!("CPU EXCEPTION: {name} (from {})", if f.from_user() { "user" } else { "kernel" });
    crate::log::error!("  error code: {:#018x}", f.error_code);
    crate::log::error!("  rip={:#018x}  cs={:#06x}  rflags={:#018x}", f.rip, f.cs, f.rflags);
    crate::log::error!("  rsp={:#018x}  ss={:#06x}", f.rsp, f.ss);
    crate::log::error!("  rax={:#018x} rbx={:#018x} rcx={:#018x}", f.rax, f.rbx, f.rcx);
    crate::log::error!("  rdi={:#018x} rsi={:#018x} rbp={:#018x}", f.rdi, f.rsi, f.rbp);
    crate::panic::backtrace();
}

/// Terminates the current user process as if killed by `signal`, after logging
/// the faulting context. Never returns: the dead thread is scheduled away and
/// never requeued, so the fault is contained to the offending process and the
/// kernel keeps running. GS is already the kernel's (the stub swapped it), so
/// per-CPU and process state are reachable here.
fn kill_current(signal: i32, name: &str, f: &TrapFrame) -> ! {
    let pid = crate::process::current().map(|p| {
        let (pid, ppid) = {
            let mut g = p.lock();
            // Shell convention for "killed by signal N": 128 + N. Enough for the
            // parent (and our selftests) to see the process died by that signal.
            g.exit_code = Some(128 + signal);
            (g.pid, g.ppid)
        };
        crate::signal::notify_parent(ppid);
        pid
    });
    crate::log::error!(
        "user fault: {name} at rip={:#018x} (pid={pid:?}) -> killed by signal {signal}",
        f.rip,
    );
    crate::scheduler::thread_exit();
}

/// Builds a handler that kills the faulting *user* process with `$signal`, but
/// panics on a kernel-mode fault (which is always a kernel bug).
macro_rules! user_or_fatal {
    ($handler:ident, $name:literal, $signal:expr) => {
        extern "C" fn $handler(frame: &mut TrapFrame) {
            if frame.from_user() {
                kill_current($signal, $name, frame);
            }
            dump($name, frame);
            panic!("unhandled CPU exception in kernel: {}", $name);
        }
    };
}

/// Builds a handler that is fatal regardless of origin (IST hardware faults).
macro_rules! fatal {
    ($handler:ident, $name:literal) => {
        extern "C" fn $handler(frame: &mut TrapFrame) {
            dump($name, frame);
            panic!("unhandled CPU exception: {}", $name);
        }
    };
}

user_or_fatal!(divide_error, "divide error (#DE)", abi::types::SIGFPE);
user_or_fatal!(debug_exc, "debug (#DB)", abi::types::SIGTRAP);
user_or_fatal!(breakpoint, "breakpoint (#BP)", abi::types::SIGTRAP);
user_or_fatal!(overflow, "overflow (#OF)", abi::types::SIGSEGV);
user_or_fatal!(bound_range, "bound range (#BR)", abi::types::SIGSEGV);
user_or_fatal!(invalid_opcode, "invalid opcode (#UD)", abi::types::SIGILL);
user_or_fatal!(device_na, "device not available (#NM)", abi::types::SIGILL);
user_or_fatal!(invalid_tss, "invalid TSS (#TS)", abi::types::SIGSEGV);
user_or_fatal!(segment_not_present, "segment not present (#NP)", abi::types::SIGBUS);
user_or_fatal!(stack_segment, "stack-segment fault (#SS)", abi::types::SIGBUS);
user_or_fatal!(general_protection, "general protection fault (#GP)", abi::types::SIGSEGV);
user_or_fatal!(x87_fp, "x87 floating-point (#MF)", abi::types::SIGFPE);
user_or_fatal!(alignment_check, "alignment check (#AC)", abi::types::SIGBUS);
user_or_fatal!(simd_fp, "SIMD floating-point (#XM)", abi::types::SIGFPE);
user_or_fatal!(virtualization, "virtualization (#VE)", abi::types::SIGSEGV);
user_or_fatal!(cp_protection, "control-protection (#CP)", abi::types::SIGSEGV);

// IST hardware faults: fatal regardless of origin, entered through a paranoid
// GS stub (below) rather than the CS-RPL test.
fatal!(double_fault, "double fault (#DF)");
fatal!(machine_check, "machine check (#MC)");

/// NMI: during a panic it is the halt signal broadcast by the panicking CPU;
/// otherwise it is a fatal hardware NMI.
extern "C" fn nmi(frame: &mut TrapFrame) {
    if crate::panic::PANICKING.load(core::sync::atomic::Ordering::SeqCst) {
        crate::arch::x86_64::halt_forever();
    }
    dump("non-maskable interrupt (NMI)", frame);
    panic!("unhandled NMI");
}

/// Page fault: try demand paging first (CoW, lazy mappings); otherwise kill the
/// faulting user process (SIGSEGV) or panic on a kernel fault.
///
/// Nest-safe: a per-CPU `in_fault` guard turns a fault *while handling a fault*
/// (only ever a kernel bug) into an immediate panic instead of unbounded
/// recursion that would overflow the stack and escalate to #DF.
extern "C" fn page_fault(frame: &mut TrapFrame) {
    use core::sync::atomic::Ordering;
    let cr2 = x86_64::registers::control::Cr2::read_raw();
    let cpu = crate::percpu::this();

    if cpu.in_fault.fetch_add(1, Ordering::AcqRel) > 0 {
        cpu.in_fault.store(0, Ordering::Release);
        crate::log::error!("CPU EXCEPTION: nested page fault at {cr2:#018x}");
        dump("page fault (#PF, nested)", frame);
        panic!("nested page fault at {cr2:#018x}");
    }

    let resolved = crate::mm::fault::handle(cr2, frame.error_code, frame.from_user());
    cpu.in_fault.fetch_sub(1, Ordering::AcqRel);
    if resolved {
        return; // resolved — retry the faulting instruction
    }

    crate::log::error!("CPU EXCEPTION: page fault (#PF) at {cr2:#018x}");
    let code = frame.error_code;
    crate::log::error!(
        "  {}, {} access{}{}",
        if code & 1 != 0 { "protection violation" } else { "non-present page" },
        if code & 2 != 0 { "write" } else { "read" },
        if code & 16 != 0 { ", instruction fetch" } else { "" },
        if code & 4 != 0 { ", user mode" } else { "" },
    );
    if frame.from_user() {
        kill_current(abi::types::SIGSEGV, "page fault (#PF)", frame);
    }
    dump("page fault (#PF)", frame);
    panic!("unhandled page fault at {cr2:#018x}");
}

trap_stub!(divide_error_stub, divide_error, no_err);
trap_stub!(debug_stub, debug_exc, no_err);
trap_stub!(breakpoint_stub, breakpoint, no_err);
trap_stub!(overflow_stub, overflow, no_err);
trap_stub!(bound_range_stub, bound_range, no_err);
trap_stub!(invalid_opcode_stub, invalid_opcode, no_err);
trap_stub!(device_na_stub, device_na, no_err);
trap_stub!(invalid_tss_stub, invalid_tss, has_err);
trap_stub!(segment_not_present_stub, segment_not_present, has_err);
trap_stub!(stack_segment_stub, stack_segment, has_err);
trap_stub!(general_protection_stub, general_protection, has_err);
trap_stub!(page_fault_stub, page_fault, has_err);
trap_stub!(x87_fp_stub, x87_fp, no_err);
trap_stub!(alignment_check_stub, alignment_check, has_err);
trap_stub!(simd_fp_stub, simd_fp, no_err);
trap_stub!(virtualization_stub, virtualization, no_err);
trap_stub!(cp_protection_stub, cp_protection, has_err);

// Paranoid IST stubs for NMI/#DF/#MC. These vectors can fire in the narrow
// user->kernel entry/exit windows where CS is already the kernel's but GS_BASE
// still holds the user's value (or vice versa), so the CS-RPL test used by the
// ordinary stubs would run the handler on an attacker-controlled GS. Instead we
// read IA32_GS_BASE and `swapgs` only when it currently holds a user-half
// (non-negative) address. These handlers never return, so we need not track the
// swap for an `iretq` tail.
macro_rules! paranoid_stub {
    ($stub:ident, $handler:path, has_err) => { paranoid_stub!(@inner $stub, $handler, ""); };
    ($stub:ident, $handler:path, no_err) => { paranoid_stub!(@inner $stub, $handler, "push 0"); };
    (@inner $stub:ident, $handler:path, $pusherr:literal) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $stub() {
            core::arch::naked_asm!(
                // Decide swapgs from the live GS base, not from CS.
                "push rax", "push rcx", "push rdx",
                "mov ecx, 0xC0000101",   // IA32_GS_BASE
                "rdmsr",                  // edx:eax = base; edx bit31 = base bit63
                "test edx, edx",
                "js 1f",                  // kernel-half (sign set): GS already ours
                "swapgs",
                "1:",
                "pop rdx", "pop rcx", "pop rax",
                $pusherr,                 // normalize: dummy error code for no-err
                "push rax", "push rbx", "push rcx", "push rdx", "push rsi",
                "push rdi", "push rbp", "push r8", "push r9", "push r10",
                "push r11", "push r12", "push r13", "push r14", "push r15",
                "mov rdi, rsp",
                "mov rbp, rsp",
                "and rsp, -16",
                "cld",
                "call {h}",
                // Fatal handlers do not return; contain any stray return.
                "2:",
                "hlt",
                "jmp 2b",
                h = sym $handler,
            );
        }
    };
}

paranoid_stub!(nmi_stub, nmi, no_err);
paranoid_stub!(double_fault_stub, double_fault, has_err);
paranoid_stub!(machine_check_stub, machine_check, no_err);

/// Installs every CPU-exception entry on `idt` via its swapgs stub.
pub fn install(idt: &mut InterruptDescriptorTable) {
    let addr = |f: unsafe extern "C" fn()| VirtAddr::new(f as *const () as u64);
    // SAFETY: each address is a valid naked exception entry with a well-formed
    // frame and `iretq`.
    unsafe {
        idt.divide_error.set_handler_addr(addr(divide_error_stub));
        idt.debug.set_handler_addr(addr(debug_stub));
        idt.breakpoint.set_handler_addr(addr(breakpoint_stub));
        idt.overflow.set_handler_addr(addr(overflow_stub));
        idt.bound_range_exceeded.set_handler_addr(addr(bound_range_stub));
        idt.invalid_opcode.set_handler_addr(addr(invalid_opcode_stub));
        idt.device_not_available.set_handler_addr(addr(device_na_stub));
        idt.invalid_tss.set_handler_addr(addr(invalid_tss_stub));
        idt.segment_not_present.set_handler_addr(addr(segment_not_present_stub));
        idt.stack_segment_fault.set_handler_addr(addr(stack_segment_stub));
        idt.general_protection_fault.set_handler_addr(addr(general_protection_stub));
        idt.page_fault.set_handler_addr(addr(page_fault_stub));
        idt.x87_floating_point.set_handler_addr(addr(x87_fp_stub));
        idt.alignment_check.set_handler_addr(addr(alignment_check_stub));
        idt.simd_floating_point.set_handler_addr(addr(simd_fp_stub));
        idt.virtualization.set_handler_addr(addr(virtualization_stub));
        idt.cp_protection_exception.set_handler_addr(addr(cp_protection_stub));

        // IST faults keep their dedicated stacks and use paranoid GS entry.
        idt.non_maskable_interrupt
            .set_handler_addr(addr(nmi_stub))
            .set_stack_index(gdt::NMI_IST_INDEX);
        idt.double_fault
            .set_handler_addr(addr(double_fault_stub))
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        idt.machine_check
            .set_handler_addr(addr(machine_check_stub))
            .set_stack_index(gdt::MACHINE_CHECK_IST_INDEX);
    }
}
