//! A small kernel PRNG backing `getrandom` and `/dev/urandom`.
//!
//! This is an xorshift64 seeded from the TSC at boot — enough entropy for musl's
//! stack canary and `AT_RANDOM` during bring-up, not a cryptographic RNG. A real
//! CSPRNG (seeded from hardware RNG / interrupt timing) is future work.

use core::sync::atomic::{AtomicU64, Ordering};

static STATE: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);

/// Seeds the generator (call once at boot with a TSC sample).
pub fn seed(value: u64) {
    STATE.store(value | 1, Ordering::Relaxed);
}

fn next(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Fills `buf` with pseudo-random bytes.
pub fn fill(buf: &mut [u8]) {
    let mut x = STATE.load(Ordering::Relaxed);
    for chunk in buf.chunks_mut(8) {
        let bytes = next(&mut x).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    STATE.store(x, Ordering::Relaxed);
}
