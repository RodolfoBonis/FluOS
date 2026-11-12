//! FluOS kernel entry point.

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod arch;
mod boot;
mod log;
mod mm;
mod panic;
mod video;

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

    arch::x86_64::init_cpu();
    log::info!("gdt + idt installed");

    let features = arch::x86_64::cpu::enable_protections();
    log::info!(
        "cpu protections: nx={} smep={} smap={} pcid={}",
        features.nx,
        features.smep,
        features.smap,
        features.pcid
    );

    mm::init(info.hhdm_offset);

    if let Some(fb) = boot::framebuffer() {
        video::splash(&fb);
        log::info!("framebuffer: {}x{} {}bpp", fb.width, fb.height, fb.bpp);
    } else {
        log::warning!("no framebuffer provided by bootloader");
    }

    log::info!("boot complete");
    arch::x86_64::qemu_exit_if_requested(boot::cmdline());
    arch::x86_64::halt_forever()
}
