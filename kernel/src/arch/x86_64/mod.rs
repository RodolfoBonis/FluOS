//! x86_64 architecture support.

pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod port;
pub mod serial;

/// Installs the GDT/TSS and IDT on the bootstrap processor. After this call the
/// CPU can take exceptions without triple-faulting.
pub fn init_cpu() {
    gdt::init();
    idt::init();
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
