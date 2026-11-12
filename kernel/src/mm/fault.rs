//! Page-fault handling: demand paging and copy-on-write for user memory.
//!
//! The exception entry calls [`handle`] for every page fault. It consults the
//! current process's regions: a fault on a valid lazily-mapped or CoW page is
//! resolved (and the instruction retried); anything else is reported unhandled
//! and becomes a fatal fault / SIGSEGV.

/// Page-fault error-code bits.
const PF_PRESENT: u64 = 1 << 0;
const PF_WRITE: u64 = 1 << 1;
const PF_USER: u64 = 1 << 2;

/// Attempts to resolve a page fault at `cr2`. Returns `true` if handled (retry
/// the instruction), `false` if it is a genuine fault.
pub fn handle(cr2: u64, error_code: u64, from_user: bool) -> bool {
    if !from_user || error_code & PF_USER == 0 {
        return false; // kernel faults are always bugs here
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
