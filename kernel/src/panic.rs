use crate::arch::x86_64::{QemuExitCode, halt_forever, qemu_exit};
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    crate::log::write_unlocked(format_args!("{info}"));
    qemu_exit(QemuExitCode::Failure);
    halt_forever()
}
