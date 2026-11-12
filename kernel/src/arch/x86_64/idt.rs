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

/// PS/2 keyboard IRQ: read the scancode, decode it, queue the bytes, ack.
extern "x86-interrupt" fn keyboard_interrupt(_frame: InterruptStackFrame) {
    // SAFETY: reading the i8042 data port fetches the scancode and clears the
    // controller's output-buffer-full condition that raised this IRQ.
    let code = unsafe { super::port::inb(0x60) };
    KEYBOARD.lock().feed(code, input::push);
    apic::eoi();
}

/// LAPIC spurious interrupt: by design it needs no end-of-interrupt.
extern "x86-interrupt" fn spurious_interrupt(_frame: InterruptStackFrame) {}

/// LAPIC timer: drives scheduler preemption. EOI and rearm first, because the
/// following reschedule may not return to this handler for a long time.
extern "x86-interrupt" fn timer_interrupt(_frame: InterruptStackFrame) {
    apic::eoi();
    apic::rearm_timer();
    crate::scheduler::tick();
}

/// Reschedule IPI: another CPU asked us to re-run the scheduler.
extern "x86-interrupt" fn reschedule_ipi(_frame: InterruptStackFrame) {
    apic::eoi();
    if crate::percpu::this().preempt_count.load(core::sync::atomic::Ordering::Acquire) == 0 {
        crate::scheduler::schedule();
    }
}

/// TLB-shootdown IPI: flush this CPU's TLB. A full flush is a correct (if
/// coarse) stand-in until per-page shootdown ranges are plumbed through.
extern "x86-interrupt" fn tlb_shootdown_ipi(_frame: InterruptStackFrame) {
    apic::eoi();
    x86_64::instructions::tlb::flush_all();
}

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
    idt[apic::KEYBOARD_VECTOR].set_handler_fn(keyboard_interrupt);
    idt[apic::SPURIOUS_VECTOR].set_handler_fn(spurious_interrupt);
    idt[apic::TIMER_VECTOR].set_handler_fn(timer_interrupt);
    idt[apic::RESCHED_VECTOR].set_handler_fn(reschedule_ipi);
    idt[apic::TLB_VECTOR].set_handler_fn(tlb_shootdown_ipi);
    idt
});

/// Loads the IDT on the current CPU.
pub fn init() {
    IDT.load();
}
