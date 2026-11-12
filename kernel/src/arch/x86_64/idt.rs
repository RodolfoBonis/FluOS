//! Interrupt Descriptor Table and CPU exception handlers.
//!
//! Every architectural exception is wired to a handler that dumps the faulting
//! context — the interrupt stack frame, the control registers, and (for page
//! faults) CR2 and the access flags — then panics. A fault in M1 always means a
//! kernel bug, so turning it into a logged panic gives us the most information
//! and fails the boot test loudly instead of triple-faulting silently.
//!
//! Double-fault, NMI, and machine-check run on private IST stacks (see
//! [`super::gdt`]) because they can fire when the current stack is unusable.

use super::{apic, gdt, input, ps2};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::registers::control::{Cr0, Cr2, Cr3, Cr4};
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

/// Logs the faulting context shared by every handler.
fn dump(name: &str, frame: &InterruptStackFrame, error_code: Option<u64>) {
    crate::log::error!("CPU EXCEPTION: {name}");
    if let Some(code) = error_code {
        crate::log::error!("  error code: {code:#018x}");
    }
    crate::log::error!(
        "  rip={:#018x}  cs={:#06x}  rflags={:#018x}",
        frame.instruction_pointer.as_u64(),
        frame.code_segment.0,
        frame.cpu_flags.bits(),
    );
    crate::log::error!(
        "  rsp={:#018x}  ss={:#06x}",
        frame.stack_pointer.as_u64(),
        frame.stack_segment.0,
    );
    crate::log::error!(
        "  cr0={:#018x}  cr2={:#018x}",
        Cr0::read_raw(),
        Cr2::read_raw(),
    );
    crate::log::error!(
        "  cr3={:#018x}  cr4={:#018x}",
        Cr3::read().0.start_address().as_u64(),
        Cr4::read_raw(),
    );
    crate::panic::backtrace();
}

/// Generates a handler that logs and panics, with or without an error code.
macro_rules! exception {
    ($handler:ident, $name:literal) => {
        extern "x86-interrupt" fn $handler(frame: InterruptStackFrame) {
            dump($name, &frame, None);
            panic!("unhandled CPU exception: {}", $name);
        }
    };
    ($handler:ident, $name:literal, code) => {
        extern "x86-interrupt" fn $handler(frame: InterruptStackFrame, error_code: u64) {
            dump($name, &frame, Some(error_code));
            panic!("unhandled CPU exception: {}", $name);
        }
    };
}

exception!(divide_error, "divide error (#DE)");
exception!(debug, "debug (#DB)");
exception!(breakpoint, "breakpoint (#BP)");
exception!(overflow, "overflow (#OF)");
exception!(bound_range, "bound range exceeded (#BR)");
exception!(invalid_opcode, "invalid opcode (#UD)");
exception!(device_not_available, "device not available (#NM)");
exception!(invalid_tss, "invalid TSS (#TS)", code);
exception!(segment_not_present, "segment not present (#NP)", code);
exception!(stack_segment_fault, "stack-segment fault (#SS)", code);
exception!(general_protection_fault, "general protection fault (#GP)", code);
exception!(x87_floating_point, "x87 floating-point (#MF)");
exception!(alignment_check, "alignment check (#AC)", code);
exception!(simd_floating_point, "SIMD floating-point (#XM)");
exception!(virtualization, "virtualization (#VE)");
exception!(cp_protection, "control-protection (#CP)", code);

/// NMI runs on its own IST stack; it can interrupt at any point.
extern "x86-interrupt" fn non_maskable_interrupt(frame: InterruptStackFrame) {
    // During a panic, NMIs are the halt signal broadcast by the panicking CPU.
    if crate::panic::PANICKING.load(core::sync::atomic::Ordering::SeqCst) {
        super::halt_forever();
    }
    dump("non-maskable interrupt (NMI)", &frame, None);
    panic!("unhandled NMI");
}

/// Page fault decodes CR2 (the faulting address) and the access flags.
extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    crate::log::error!("CPU EXCEPTION: page fault (#PF)");
    let addr = Cr2::read_raw();
    crate::log::error!("  faulting address (cr2): {addr:#018x}");
    crate::log::error!(
        "  caused by {}, {} access{}{}",
        if code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
            "protection violation"
        } else {
            "non-present page"
        },
        if code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) { "write" } else { "read" },
        if code.contains(PageFaultErrorCode::INSTRUCTION_FETCH) { ", instruction fetch" } else { "" },
        if code.contains(PageFaultErrorCode::USER_MODE) { ", from user mode" } else { "" },
    );
    dump("page fault (#PF)", &frame, Some(code.bits()));
    panic!("unhandled page fault at {addr:#018x}");
}

/// Double fault is unrecoverable by definition; it must diverge.
extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, error_code: u64) -> ! {
    dump("double fault (#DF)", &frame, Some(error_code));
    panic!("double fault");
}

/// Machine check reports unrecoverable hardware errors; it must diverge.
extern "x86-interrupt" fn machine_check(frame: InterruptStackFrame) -> ! {
    dump("machine check (#MC)", &frame, None);
    panic!("machine check");
}

/// Decoder state shared between successive keyboard IRQs.
static KEYBOARD: Mutex<ps2::Keyboard> = Mutex::new(ps2::Keyboard::new());

// --- device-interrupt entry (ring3-reachable → needs swapgs) ---------------
//
// These vectors can fire while a user process runs, where GS_BASE holds the
// user's GS. Each is reached through a naked stub that conditionally `swapgs`es
// (based on the saved CS privilege level) so the Rust handler always sees the
// per-CPU GS, then swaps back before `iretq`. Caller-saved registers are
// preserved by the stub; the Rust handler preserves callee-saved per the ABI.

/// Generates a naked interrupt stub (no error code) that swapgs-wraps `$handler`.
macro_rules! irq_stub {
    ($stub:ident, $handler:path) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $stub() {
            core::arch::naked_asm!(
                "test qword ptr [rsp + 8], 3", // saved CS RPL: nonzero => from user
                "jz 2f",
                "swapgs",
                "2:",
                // Save caller-saved registers plus rbp (used to re-align the
                // stack: a same-privilege interrupt does NOT align rsp, so we
                // must 16-align it ourselves before calling into Rust/SSE code).
                "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
                "push r8", "push r9", "push r10", "push r11", "push rbp",
                "mov rbp, rsp",
                "and rsp, -16",
                "cld",
                "call {h}",
                "mov rsp, rbp",
                "pop rbp", "pop r11", "pop r10", "pop r9", "pop r8",
                "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
                "test qword ptr [rsp + 8], 3",
                "jz 3f",
                "swapgs",
                "3:",
                "iretq",
                h = sym $handler,
            );
        }
    };
}

extern "C" fn keyboard_handler() {
    // SAFETY: reading the i8042 data port fetches the scancode and clears the
    // output-buffer-full condition that raised this IRQ.
    let code = unsafe { super::port::inb(0x60) };
    KEYBOARD.lock().feed(code, input::push);
    apic::eoi();
}

extern "C" fn spurious_handler() {}

extern "C" fn timer_handler() {
    apic::eoi();
    apic::rearm_timer();
    crate::scheduler::tick();
}

extern "C" fn reschedule_handler() {
    use core::sync::atomic::Ordering;
    apic::eoi();
    let cpu = crate::percpu::this();
    cpu.need_resched.store(true, Ordering::Relaxed);
    if cpu.preempt_count.load(Ordering::Acquire) == 0 {
        crate::scheduler::schedule();
    }
}

extern "C" fn tlb_handler() {
    apic::eoi();
    x86_64::instructions::tlb::flush_all();
}

irq_stub!(keyboard_stub, keyboard_handler);
irq_stub!(spurious_stub, spurious_handler);
irq_stub!(timer_stub, timer_handler);
irq_stub!(reschedule_stub, reschedule_handler);
irq_stub!(tlb_stub, tlb_handler);

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(divide_error);
    idt.debug.set_handler_fn(debug);
    idt.breakpoint.set_handler_fn(breakpoint);
    idt.overflow.set_handler_fn(overflow);
    idt.bound_range_exceeded.set_handler_fn(bound_range);
    idt.invalid_opcode.set_handler_fn(invalid_opcode);
    idt.device_not_available.set_handler_fn(device_not_available);
    idt.invalid_tss.set_handler_fn(invalid_tss);
    idt.segment_not_present.set_handler_fn(segment_not_present);
    idt.stack_segment_fault.set_handler_fn(stack_segment_fault);
    idt.general_protection_fault.set_handler_fn(general_protection_fault);
    idt.page_fault.set_handler_fn(page_fault);
    idt.x87_floating_point.set_handler_fn(x87_floating_point);
    idt.alignment_check.set_handler_fn(alignment_check);
    idt.simd_floating_point.set_handler_fn(simd_floating_point);
    idt.virtualization.set_handler_fn(virtualization);
    idt.cp_protection_exception.set_handler_fn(cp_protection);

    // SAFETY: each IST index refers to a stack installed in the TSS by
    // `gdt::init`, so the CPU has a valid stack to switch to for these faults.
    unsafe {
        idt.non_maskable_interrupt
            .set_handler_fn(non_maskable_interrupt)
            .set_stack_index(gdt::NMI_IST_INDEX);
        idt.double_fault
            .set_handler_fn(double_fault)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        idt.machine_check
            .set_handler_fn(machine_check)
            .set_stack_index(gdt::MACHINE_CHECK_IST_INDEX);
    }
    // Device IRQs use naked swapgs stubs (set by raw address).
    // SAFETY: each address is a valid naked interrupt entry with a well-formed
    // frame and `iretq`.
    unsafe {
        idt[apic::KEYBOARD_VECTOR].set_handler_addr(VirtAddr::new(keyboard_stub as *const () as u64));
        idt[apic::SPURIOUS_VECTOR].set_handler_addr(VirtAddr::new(spurious_stub as *const () as u64));
        idt[apic::TIMER_VECTOR].set_handler_addr(VirtAddr::new(timer_stub as *const () as u64));
        idt[apic::RESCHED_VECTOR].set_handler_addr(VirtAddr::new(reschedule_stub as *const () as u64));
        idt[apic::TLB_VECTOR].set_handler_addr(VirtAddr::new(tlb_stub as *const () as u64));
    }
    idt
});

/// Loads the IDT on the current CPU.
pub fn init() {
    IDT.load();
}
