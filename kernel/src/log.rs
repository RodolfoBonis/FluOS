//! Leveled kernel logging.
//!
//! Every record is fanned out to three sinks: the COM1 serial port (always
//! available, captured by the test harness), an in-memory ring buffer that will
//! back `dmesg`, and — once the framebuffer console is up — an optional console
//! sink registered by M2. A single `writeln!` feeds all of them through a tee
//! writer so the formatting happens exactly once.

use core::fmt::{self, Write};
use spin::Mutex;

#[derive(Clone, Copy)]
pub enum Level {
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

/// Fixed-size byte ring that retains the most recent log output for `dmesg`.
pub struct Ring {
    buf: [u8; Ring::CAP],
    /// Index of the next byte to write.
    head: usize,
    /// Number of valid bytes currently stored (<= `CAP`).
    len: usize,
}

impl Ring {
    const CAP: usize = 64 * 1024;

    const fn new() -> Self {
        Self { buf: [0; Ring::CAP], head: 0, len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.head] = b;
            self.head = (self.head + 1) % Ring::CAP;
            if self.len < Ring::CAP {
                self.len += 1;
            }
        }
    }

    /// Copies the retained log into `out` in chronological order, returning the
    /// number of bytes written (capped at `out.len()`).
    #[allow(dead_code)] // consumed by `dmesg`, wired up in M2
    pub fn snapshot(&self, out: &mut [u8]) -> usize {
        let start = (self.head + Ring::CAP - self.len) % Ring::CAP;
        let n = self.len.min(out.len());
        for (i, slot) in out.iter_mut().take(n).enumerate() {
            *slot = self.buf[(start + i) % Ring::CAP];
        }
        n
    }
}

static RING: Mutex<Ring> = Mutex::new(Ring::new());

/// Optional console sink, installed by the framebuffer console in M2. A plain
/// function pointer keeps `log` free of any console dependency.
static CONSOLE: Mutex<Option<fn(&str)>> = Mutex::new(None);

/// Registers (or clears) the console sink that mirrors log output to the screen.
#[allow(dead_code)] // installed by the framebuffer console in M2
pub fn set_console_sink(sink: Option<fn(&str)>) {
    *CONSOLE.lock() = sink;
}

/// Copies the retained log history into `out`, returning the byte count.
#[allow(dead_code)] // exposed via the `syslog` syscall in a later milestone
pub fn dmesg(out: &mut [u8]) -> usize {
    RING.lock().snapshot(out)
}

/// Writer that fans a single formatting pass out to every sink.
struct Tee<'a> {
    serial: &'a mut crate::arch::x86_64::serial::Serial,
    ring: &'a mut Ring,
    console: Option<fn(&str)>,
}

impl Write for Tee<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Serial writes are infallible; the ring never fails; the console sink,
        // if any, swallows its own errors.
        let _ = self.serial.write_str(s);
        self.ring.push(s.as_bytes());
        if let Some(sink) = self.console {
            sink(s);
        }
        Ok(())
    }
}

pub fn write(level: Level, args: fmt::Arguments) {
    let mut serial = crate::arch::x86_64::serial::COM1_PORT.lock();
    let mut ring = RING.lock();
    let console = *CONSOLE.lock();
    let mut tee = Tee { serial: &mut serial, ring: &mut ring, console };
    let _ = writeln!(tee, "[{}] {}", level.tag(), args);
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
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, format_args!($($arg)*)) };
}

#[allow(unused_imports)]
pub(crate) use {error, info, warning};
