//! Page-fault handling: demand paging and copy-on-write for user memory.
//!
//! The exception entry calls [`handle`] for every page fault. It consults the
//! current process's regions: a fault on a valid lazily-mapped or CoW page is
//! resolved (and the instruction retried); anything else is reported unhandled
//! and becomes a fatal fault / SIGSEGV (ring 3) or an exception-fixup (a kernel
//! `copy_user` touching a bad user address).

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
pub fn handle(cr2: u64, error_code: u64, _from_user: bool) -> bool {
    if cr2 >= crate::usercopy::USER_MAX {
        return false; // kernel-address fault: never demand/CoW
    }
    let Some(proc) = crate::process::current() else {
        return false;
    };
    let write = error_code & PF_WRITE != 0;
    let present = error_code & PF_PRESENT != 0;

    let mut p = proc.lock();
    if present && write {
        // A write to a present page → copy-on-write.
        p.space.handle_cow(cr2)
    } else if !present {
        // Not present → demand-map if the address lies in a known region.
        p.space.handle_demand(cr2, write)
    } else {
        false
    }
}
