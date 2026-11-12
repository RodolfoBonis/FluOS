//! A small lock-protected byte ring carrying decoded keyboard input from the
//! IRQ handler to the consumer loop.
//!
//! The keyboard handler [`push`]es the UTF-8 / escape bytes a keypress produces;
//! the main loop [`pop`]s them to echo. Callers on the consumer side must access
//! this with interrupts disabled (the handler already runs with them off), so
//! the spin lock is never contended across the IRQ boundary.

use crate::sync::SpinLock;

const CAP: usize = 256;

struct Ring {
    buf: [u8; CAP],
    head: usize,
    tail: usize,
}

static INPUT: SpinLock<Ring> = SpinLock::new(Ring { buf: [0; CAP], head: 0, tail: 0 });

/// Enqueues a byte, dropping it if the ring is full (a stalled consumer should
/// not wedge the interrupt handler).
pub fn push(byte: u8) {
    // Line-discipline first: a signal-generating control char (Ctrl-C/Z/\) is
    // consumed here and never enqueued.
    if crate::fs::tty_input_filter(byte) {
        return;
    }
    let mut ring = INPUT.lock();
    let next = (ring.head + 1) % CAP;
    if next != ring.tail {
        let head = ring.head;
        ring.buf[head] = byte;
        ring.head = next;
    }
}

/// Dequeues the next byte, if any.
pub fn pop() -> Option<u8> {
    let mut ring = INPUT.lock();
    if ring.head == ring.tail {
        return None;
    }
    let tail = ring.tail;
    let byte = ring.buf[tail];
    ring.tail = (tail + 1) % CAP;
    Some(byte)
}
