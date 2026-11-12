//! x86_64 architecture support.

pub mod acpi;
pub mod apic;
pub mod context;
pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod input;
pub mod port;
pub mod ps2;
pub mod serial;
pub mod user;

/// Installs the GDT/TSS and IDT on the bootstrap processor and returns the TSS
/// pointer so per-CPU state can update its RSP0 for user processes. After this
/// call the CPU can take exceptions without triple-faulting.
pub fn init_cpu() -> *mut x86_64::structures::tss::TaskStateSegment {
    let tss = gdt::init();
    idt::init();
    tss
}

/// Idles the CPU until the next interrupt (timer or IPI). Interrupts are
/// enabled before halting so the wakeup is delivered. `_monitor_addr` is the
/// address the scheduler would MONITOR; a plain `hlt` wake is used for now.
pub fn idle_wait(monitor_addr: usize) {
    if cpu::has_monitor() {
        // SAFETY: arm MONITOR on `monitor_addr` (this CPU's `need_resched`),
        // then MWAIT with interrupts enabled. A store to that line (a wakeup) or
        // any interrupt (timer/IPI) resumes us; the periodic timer guarantees we
        // never sleep forever.
        unsafe {
            core::arch::asm!(
                "monitor",
                in("rax") monitor_addr, in("rcx") 0, in("rdx") 0,
                options(nostack, preserves_flags),
            );
            core::arch::asm!(
                "sti",
                "mwait",
                in("rax") 0u32, in("rcx") 0u32,
                options(nomem, nostack, preserves_flags),
            );
        }
    } else {
        // SAFETY: `sti; hlt` enables interrupts then halts until one arrives.
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)) };
    }
}

/// Disables interrupts and halts this CPU forever.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `cli; hlt` only stops this CPU; no memory is touched.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// QEMU `isa-debug-exit` device port (see `xtask` QEMU args).
const QEMU_EXIT_PORT: u16 = 0xf4;

/// Exit status written to the QEMU debug-exit device.
/// QEMU reports `(code << 1) | 1` as its process exit status.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failure = 0x11,
}

/// Terminates QEMU when running under the test harness; a no-op on real hardware
/// where nothing is listening on the port.
pub fn qemu_exit(code: QemuExitCode) {
    // SAFETY: writing to an unused I/O port has no effect on real hardware.
    unsafe { port::outl(QEMU_EXIT_PORT, code as u32) };
}

/// Exits QEMU with success if the kernel was booted with `qemu-exit` on its command line.
/// Used by `cargo xtask test` to turn a successful boot into a passing process.
pub fn qemu_exit_if_requested(cmdline: &str) {
    if cmdline.split_whitespace().any(|arg| arg == "qemu-exit") {
        qemu_exit(QemuExitCode::Success);
    }
}
