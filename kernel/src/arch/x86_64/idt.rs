//! Interrupt Descriptor Table: device IRQ entries and CPU-exception wiring.
//!
//! CPU exceptions are installed by [`super::trap`], which provides naked
//! `swapgs` stubs so a fault from ring 3 is handled with the correct GS. The
//! device IRQs (keyboard, LAPIC timer, IPIs) likewise use naked `swapgs` stubs
//! defined here, since they too can interrupt a user process.

use super::{apic, input, ps2};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::structures::idt::InterruptDescriptorTable;

/// Decoder state shared between successive keyboard IRQs.
static KEYBOARD: Mutex<ps2::Keyboard> = Mutex::new(ps2::Keyboard::new());

// --- device-interrupt entry (ring3-reachable → needs swapgs) ---------------
//
// Each vector can fire while a user process runs, where GS_BASE holds the user's
// GS. The naked stub conditionally `swapgs`es (based on the saved CS privilege
// level), 16-aligns the stack, calls the Rust handler, and swaps back before
// `iretq`. Caller-saved registers are preserved by the stub; the Rust handler
// preserves callee-saved per the ABI.

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
    crate::mm::paging::tlb_ack();
}

irq_stub!(keyboard_stub, keyboard_handler);
irq_stub!(spurious_stub, spurious_handler);
irq_stub!(timer_stub, timer_handler);
irq_stub!(reschedule_stub, reschedule_handler);
irq_stub!(tlb_stub, tlb_handler);

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    super::trap::install(&mut idt);

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
