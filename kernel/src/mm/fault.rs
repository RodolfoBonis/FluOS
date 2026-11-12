//! Page-fault handling: demand paging and copy-on-write for user memory.
//!
//! The exception entry calls [`handle`] for every page fault. It consults the
//! current process's regions: a fault on a valid lazily-mapped or CoW page is
//! resolved (and the instruction retried); anything else is reported unhandled
//! and becomes a fatal fault / SIGSEGV (ring 3) or an exception-fixup (a kernel
//! `copy_user` touching a bad user address).

use crate::process::Cow;

/// Page-fault error-code bits.
const PF_WRITE: u64 = 1 << 1;
const PF_PRESENT: u64 = 1 << 0;

/// Attempts to resolve a page fault at `cr2`. Returns `true` if handled (retry
/// the instruction), `false` if it is a genuine fault.
///
/// Faults on a *user* address are resolved against the current process's
/// address space regardless of the access's privilege level: ring 3 faults come
/// here directly, and the kernel's direct-VA `copy_user` also faults here (as a
/// supervisor access, so `PF_USER == 0`) when it touches a demand-paged or
/// copy-on-write user page. A kernel fault on a kernel address is always a bug
/// and is left unresolved.
///
/// A copy-on-write *copy* in a shared (CLONE_VM) address space is followed by a
/// TLB shootdown — done AFTER releasing the process lock, so a peer spinning on
/// that lock can still service the IPI — so peer CPUs' stale read-only entries
/// (which a *read* would otherwise satisfy from the pre-copy frame, never
/// faulting) are invalidated. Faulting writers self-heal locally in `handle_cow`.
pub fn handle(cr2: u64, error_code: u64, _from_user: bool) -> bool {
    if cr2 >= crate::usercopy::USER_MAX {
        return false; // kernel-address fault: never demand/CoW
    }
    let Some(proc) = crate::process::current() else {
        return false;
    };
    let write = error_code & PF_WRITE != 0;
    let present = error_code & PF_PRESENT != 0;

    let mut copied = false;
    let (resolved, shared) = {
        let mut p = proc.lock();
        // "Shared" means this address space has more than one thread (CLONE_VM),
        // so it may be active on other CPUs. A single-threaded process (incl. a
        // fork child) never needs a cross-CPU shootdown — a global flag would
        // wrongly shoot down on every unrelated process's CoW faults.
        let shared = p.thread_count > 1;
        let resolved = if present && write {
            // Serialised per address space by the process lock: two threads
            // faulting on the same CoW page cannot both copy — the second sees
            // it already writable.
            match p.space.handle_cow(cr2) {
                Cow::Copied => {
                    copied = true;
                    true
                }
                Cow::NoChange => true,
                Cow::Fault => false,
            }
        } else if !present {
            p.space.handle_demand(cr2, write)
        } else {
            false
        };
        (resolved, shared)
    };

    if copied && shared {
        // Lock is dropped; safe to broadcast and wait for peer acknowledgement.
        crate::mm::paging::shootdown_all();
    }
    resolved
}
