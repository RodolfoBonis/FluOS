//! Leveled kernel logging.
//!
//! Each record is formatted once into a fixed stack buffer, then emitted to
//! three sinks — the COM1 serial port, an in-memory ring buffer (for `dmesg`),
//! and an optional framebuffer console — each under its OWN lock with no
//! nesting. That matters for two reasons: the locks are IRQ-safe (so logging is
//! never preempted mid-write, which would let a syscall that spins on the same
//! lock deadlock the CPU), and the no-nesting discipline means the log and a
//! user program writing `/dev/console` can never invert lock order under SMP.

use crate::sync::SpinLock;
use core::fmt::{self, Write};

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
    head: usize,
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

    /// Copies the retained log into `out` in chronological order.
    #[allow(dead_code)] // consumed by `dmesg`
    pub fn snapshot(&self, out: &mut [u8]) -> usize {
        let start = (self.head + Ring::CAP - self.len) % Ring::CAP;
        let n = self.len.min(out.len());
        for (i, slot) in out.iter_mut().take(n).enumerate() {
            *slot = self.buf[(start + i) % Ring::CAP];
        }
        n
    }
}

static RING: SpinLock<Ring> = SpinLock::new(Ring::new());

/// Optional console sink, installed by the framebuffer console in M2.
static CONSOLE: SpinLock<Option<fn(&str)>> = SpinLock::new(None);

/// Registers (or clears) the console sink that mirrors log output to the screen.
#[allow(dead_code)]
pub fn set_console_sink(sink: Option<fn(&str)>) {
    *CONSOLE.lock() = sink;
}

/// Copies the retained log history into `out`, returning the byte count.
#[allow(dead_code)] // exposed via the `syslog` syscall later
pub fn dmesg(out: &mut [u8]) -> usize {
    RING.lock().snapshot(out)
}

/// A bounded formatting buffer, so a record is composed before any sink is
/// locked (short, nesting-free lock holds).
struct FixedBuf {
    buf: [u8; 512],
    len: usize,
}

impl FixedBuf {
    fn new() -> Self {
        Self { buf: [0; 512], len: 0 }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Write for FixedBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let n = s.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

pub fn write(level: Level, args: fmt::Arguments) {
    // Format once. Timestamp (TSC) + CPU id correlate SMP logs; CPU id is `?`
    // before per-CPU state exists.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let mut fb = FixedBuf::new();
    match crate::percpu::try_cpu_id() {
        Some(cpu) => {
            let _ = writeln!(fb, "[{tsc:>16} c{cpu} {}] {args}", level.tag());
        }
        None => {
            let _ = writeln!(fb, "[{tsc:>16} c? {}] {args}", level.tag());
        }
    }
    let bytes = fb.as_bytes();

    // Emit to each sink under its own lock — no nesting, consistent order.
    crate::arch::x86_64::serial::write_bytes(bytes);
    RING.lock().push(bytes);
    let sink = *CONSOLE.lock();
    if let Some(sink) = sink
        && let Ok(text) = core::str::from_utf8(bytes)
    {
        sink(text);
    }
}

/// Logs even if a sink lock is held; only for the panic path.
pub fn write_unlocked(args: fmt::Arguments) {
    let mut fb = FixedBuf::new();
    let _ = writeln!(fb, "[\x1b[31mPANIC\x1b[0m] {args}");
    crate::arch::x86_64::serial::write_bytes_unlocked(fb.as_bytes());
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
