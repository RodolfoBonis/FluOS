//! FluOS kernel entry point.

#![no_std]
#![no_main]

mod arch;
mod boot;
mod console;
mod demo;
mod elf;
mod font;
mod fs;
mod ksyms;
mod log;
mod mm;
mod panic;
mod percpu;
mod process;
mod rng;
mod scheduler;
mod signal;
mod smp;
mod sync;
mod syscall;
mod thread;
mod usercopy;
mod userspace;

extern crate alloc;

/// Entry point jumped to by Limine on the bootstrap processor.
#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
    arch::x86_64::serial::init();
    log::info!("FluOS {} booting", env!("CARGO_PKG_VERSION"));

    let info = boot::info();
    log::info!(
        "bootloader: {} {} (base revision {})",
        info.bootloader_name,
        info.bootloader_version,
        info.base_revision
    );
    log::info!("hhdm offset: {:#x}", info.hhdm_offset);
    log::info!(
        "memory: {} MiB usable across {} regions",
        info.usable_bytes / (1024 * 1024),
        info.usable_regions
    );

    let tss = arch::x86_64::init_cpu() as u64;
    let features = arch::x86_64::cpu::enable_protections();
    arch::x86_64::cpu::enable_sse();
    log::info!(
        "cpu: gdt+idt installed; nx={} smep={} smap={} pcid={}",
        features.nx,
        features.smep,
        features.smap,
        features.pcid
    );

    mm::init(info.hhdm_offset);
    ksyms::selftest();

    if let Some(fb) = boot::framebuffer() {
        console::init(&fb);
        log::info!(
            "console: {}x{} framebuffer, {}x{} px cells",
            fb.width,
            fb.height,
            font::CELL_W,
            font::CELL_H
        );
    } else {
        log::warning!("no framebuffer provided by bootloader");
    }

    // SMP + scheduler bring-up and self-test.
    if let Some(apic_info) = arch::x86_64::acpi::parse() {
        arch::x86_64::apic::init(apic_info);
        smp::init_bsp(tss);
        arch::x86_64::user::init_syscall();
        smp::bringup();
        arch::x86_64::apic::start_timer();
        x86_64::instructions::interrupts::enable();
        smp::run_selftest();

        // Userspace: root filesystem, RNG, and the ring-3 self-test.
        fs::init(boot::initramfs());
        // SAFETY: `_rdtsc` reads the timestamp counter for an RNG seed.
        rng::seed(unsafe { core::arch::x86_64::_rdtsc() });
        userspace::run_selftest();
        userspace::run_syscall_bench();
        userspace::run_security_selftests();
        userspace::run_signal_selftest();
        userspace::run_vm_selftests();
    } else {
        log::warning!("no ACPI MADT; SMP and scheduler timer disabled");
    }

    demo::starship_prompt();

    log::info!("boot complete");
    arch::x86_64::qemu_exit_if_requested(boot::cmdline());

    // Interactive: run the busybox shell if an initramfs is present, else echo
    // typed keys. (Under the test harness we already exited above.)
    arch::x86_64::apic::drain_ps2();
    x86_64::instructions::interrupts::enable();
    if boot::initramfs().is_some() {
        userspace::run_init();
    } else if console::is_ready() {
        demo::input_echo_loop();
    }
    arch::x86_64::halt_forever()
}
