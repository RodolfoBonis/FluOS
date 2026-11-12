//! Leveled kernel logging to the serial console.

use core::fmt::{self, Write};

#[derive(Clone, Copy)]
pub enum Level {
    #[allow(dead_code)] // first user arrives with fault handlers in M1
    Error,
    Warn,
    Info,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Error => "\x1b[31mERROR\x1b[0m",
            Level::Warn => "\x1b[33mWARN \x1b[0m",
            Level::Info => "\x1b[32mINFO \x1b[0m",
        }
    }
}

pub fn write(level: Level, args: fmt::Arguments) {
    let mut serial = crate::arch::x86_64::serial::COM1_PORT.lock();
    // Serial writes are infallible; ignore the fmt::Result.
    let _ = writeln!(serial, "[{}] {}", level.tag(), args);
}

/// Logs even if the serial lock is held; only for the panic path, where the
/// code that panicked may own the lock.
pub fn write_unlocked(args: fmt::Arguments) {
    let port = &crate::arch::x86_64::serial::COM1_PORT;
    // SAFETY: we are about to halt; a torn line is preferable to a deadlock.
    unsafe { port.force_unlock() };
    let _ = writeln!(port.lock(), "[\x1b[31mPANIC\x1b[0m] {args}");
}

macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, format_args!($($arg)*)) };
}
macro_rules! warning {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, format_args!($($arg)*)) };
}
#[allow(unused_macros)]
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, format_args!($($arg)*)) };
}

#[allow(unused_imports)]
pub(crate) use {error, info, warning};
