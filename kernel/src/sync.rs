//! Interrupt-safe spin locks.
//!
//! A kernel lock taken in both thread and interrupt context must disable
//! interrupts while held: otherwise an IRQ that fires mid-critical-section and
//! tries to take the same lock deadlocks the CPU. [`SpinLock`] saves the
//! interrupt flag on acquire, disables interrupts, and restores the prior state
//! when the guard drops. Debug builds additionally trip a panic if a lock spins
//! implausibly long, surfacing deadlocks instead of hanging.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::interrupts;

/// Spin count after which a debug build declares a deadlock.
#[cfg(debug_assertions)]
const DEADLOCK_SPINS: u64 = 200_000_000;

/// A mutual-exclusion lock that disables interrupts for the critical section.
pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialized by the atomic flag, and the contained
// value need only be `Send` to be safely transferred into the critical section.
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Creates an unlocked lock. `const` so it can back a `static`.
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), data: UnsafeCell::new(value) }
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Acquires the lock, disabling interrupts until the guard drops.
    pub fn lock(&self) -> SpinGuard<'_, T> {
        let interrupts_were_enabled = interrupts::are_enabled();
        interrupts::disable();

        #[cfg(debug_assertions)]
        let mut spins: u64 = 0;

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Test-and-test-and-set: spin on a cheap read until it looks free.
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
                #[cfg(debug_assertions)]
                {
                    spins += 1;
                    assert!(
                        spins < DEADLOCK_SPINS,
                        "spinlock deadlock: held too long (same-CPU reentry?)"
                    );
                }
            }
        }

        SpinGuard { lock: self, interrupts_were_enabled, _not_send: PhantomData }
    }

    /// Forcibly releases the lock without a guard. Only for the panic path,
    /// where the owner may never run again.
    ///
    /// # Safety
    /// The caller must ensure no live guard references the protected data.
    #[allow(dead_code)] // panic-path use, wired up with the serial console later
    pub unsafe fn force_unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

/// RAII guard: releases the lock and restores interrupts on drop.
pub struct SpinGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
    interrupts_were_enabled: bool,
    /// A raw pointer makes the guard `!Send` and `!Sync`: a lock guard must not
    /// cross threads/CPUs (it would unlock on the wrong CPU and mis-manage the
    /// interrupt flag) — M12.
    _not_send: PhantomData<*const ()>,
}

impl<T: ?Sized> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard guarantees exclusive access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard guarantees exclusive access.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        if self.interrupts_were_enabled {
            interrupts::enable();
        }
    }
}
