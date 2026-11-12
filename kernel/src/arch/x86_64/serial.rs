//! 16550 UART on COM1, used as the always-available kernel console.

use super::port::{inb, outb};
use core::fmt;
use crate::sync::SpinLock;

const COM1: u16 = 0x3f8;

pub struct Serial {
    base: u16,
}

impl Serial {
    const fn new(base: u16) -> Self {
        Self { base }
    }

    fn init(&mut self) {
        // SAFETY: standard 16550 programming sequence on the COM1 ports.
        unsafe {
            outb(self.base + 1, 0x00); // disable interrupts
            outb(self.base + 3, 0x80); // DLAB on
            outb(self.base, 0x01); // divisor 1 => 115200 baud
            outb(self.base + 1, 0x00);
            outb(self.base + 3, 0x03); // 8N1, DLAB off
            outb(self.base + 2, 0xc7); // FIFO on, clear, 14-byte threshold
            outb(self.base + 4, 0x0b); // DTR | RTS | OUT2
        }
    }

    /// Writes raw bytes, translating LF to CR+LF for terminals.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    fn write_byte(&mut self, byte: u8) {
        // SAFETY: polling the line status register, then writing THR.
        unsafe {
            while inb(self.base + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            outb(self.base, byte);
        }
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// IRQ-safe so logging is never preempted mid-write (a syscall spinning on
/// this lock would otherwise deadlock the CPU).
pub static COM1_PORT: SpinLock<Serial> = SpinLock::new(Serial::new(COM1));

pub fn init() {
    COM1_PORT.lock().init();
}

/// Writes raw bytes to COM1 (used for logging and user console output).
pub fn write_bytes(bytes: &[u8]) {
    COM1_PORT.lock().put_bytes(bytes);
}

/// Writes to COM1 even if the lock is held; only for the panic path.
pub fn write_bytes_unlocked(bytes: &[u8]) {
    // SAFETY: on the panic path the lock owner may never run again; a torn line
    // is preferable to a deadlock.
    unsafe { COM1_PORT.force_unlock() };
    COM1_PORT.lock().put_bytes(bytes);
}
