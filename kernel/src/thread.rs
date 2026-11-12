//! Kernel threads: their stacks, saved context, and lifecycle state.
//!
//! A thread owns a kernel stack and a 512-byte FXSAVE area. Its identity (the
//! [`Tid`] the scheduler keys on) is simply its stable heap address, so the
//! scheduler never needs a separate lookup table to go from a scheduling
//! decision to the thread it switches to. Threads are leaked for the kernel's
//! lifetime in this milestone (no reaping yet).

use crate::arch::x86_64::context;
use alloc::alloc::{Layout, alloc, alloc_zeroed};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Scheduler thread identity: a thread's own address, as the `sched` crate's
/// `Tid` (a `u64`).
pub type Tid = u64;

/// Per-thread kernel stack size.
pub const KSTACK_SIZE: usize = 32 * 1024;

/// FXSAVE image size.
const FPU_AREA: usize = 512;

/// Lifecycle state of a thread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum State {
    Ready = 0,
    Running = 1,
    Blocked = 2,
    Finished = 3,
}

/// A kernel thread.
pub struct Thread {
    /// Sequential id for logging (distinct from the scheduler [`Tid`]).
    #[allow(dead_code)] // diagnostic id
    pub seq: u32,
    /// Saved kernel stack pointer; 0 until the thread is first switched out.
    pub rsp: u64,
    /// Entry point and argument (unused for the already-running idle context).
    pub entry: Option<extern "C" fn(usize)>,
    pub arg: usize,
    /// Scheduling weight (nice-derived).
    pub weight: u64,
    /// Accumulated virtual runtime (EEVDF units), carried across run periods.
    pub vruntime: AtomicU64,
    pub state: State,
    /// FXSAVE area; a raw pointer so it is reachable from the switch path.
    pub fpu: *mut u8,
    /// Base of the owned stack allocation, or null for the idle context.
    #[allow(dead_code)] // owns the allocation; freed when reaping lands
    stack: *mut u8,
    /// Times this thread was scheduled (self-test accounting).
    pub run_count: AtomicU64,
    /// Bitmask of CPUs this thread has executed on (self-test accounting).
    pub ran_on: AtomicU32,
}

// SAFETY: a Thread is only mutated by its owning CPU while running or under the
// scheduler lock during a switch; the raw pointers are plain kernel addresses.
unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

/// Monotonic sequence-number source for thread logging.
static NEXT_SEQ: AtomicU32 = AtomicU32::new(0);

impl Thread {
    /// This thread's scheduler [`Tid`] (its own address).
    pub fn tid(&self) -> Tid {
        core::ptr::from_ref(self) as Tid
    }

    /// Allocates a fresh FXSAVE area initialised to a sane default FPU state.
    fn new_fpu() -> *mut u8 {
        let layout = Layout::from_size_align(FPU_AREA, 16).expect("valid FPU layout");
        // SAFETY: non-zero layout; zeroed is a valid starting image once we set
        // the control words below.
        let area = unsafe { alloc_zeroed(layout) };
        assert!(!area.is_null(), "FPU area allocation failed");
        // SAFETY: `area` owns 512 bytes; FCW at +0, MXCSR at +24 are in bounds.
        unsafe {
            (area as *mut u16).write(0x037F); // default x87 control word
            (area.add(24) as *mut u32).write(0x0000_1F80); // default MXCSR
        }
        area
    }

    /// Creates a runnable worker thread that will enter `entry(arg)`.
    pub fn new_worker(entry: extern "C" fn(usize), arg: usize, weight: u64) -> Box<Thread> {
        let stack_layout = Layout::from_size_align(KSTACK_SIZE, 16).expect("valid stack layout");
        // SAFETY: non-zero layout; the stack is written below before use.
        let stack = unsafe { alloc(stack_layout) };
        assert!(!stack.is_null(), "kernel stack allocation failed");

        let mut thread = Box::new(Thread {
            seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
            rsp: 0,
            entry: Some(entry),
            arg,
            weight,
            vruntime: AtomicU64::new(0),
            state: State::Ready,
            fpu: Self::new_fpu(),
            stack,
            run_count: AtomicU64::new(0),
            ran_on: AtomicU32::new(0),
        });
        thread.rsp = Self::init_stack(stack);
        thread
    }

    /// Wraps the CPU's *current* execution (idle/bootstrap context) as a thread.
    /// It has no owned stack or entry; its `rsp` is filled on first switch-out.
    pub fn new_current(weight: u64) -> Box<Thread> {
        Box::new(Thread {
            seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
            rsp: 0,
            entry: None,
            arg: 0,
            weight,
            vruntime: AtomicU64::new(0),
            state: State::Running,
            fpu: Self::new_fpu(),
            stack: core::ptr::null_mut(),
            run_count: AtomicU64::new(1),
            ran_on: AtomicU32::new(0),
        })
    }

    /// Builds the initial stack frame so that the first switch into this thread
    /// returns into [`crate::scheduler::thread_trampoline`].
    ///
    /// Layout (low→high) matches what [`context_switch`] pops:
    /// `[r15][r14][r13][r12][rbx][rbp][ret=trampoline][pad]`, with the saved
    /// stack pointer 16-byte aligned so the trampoline sees the ABI-required
    /// `rsp % 16 == 8` on entry.
    fn init_stack(stack: *mut u8) -> u64 {
        // SAFETY: `stack` owns `KSTACK_SIZE` bytes; we only write within them.
        let top = (stack as u64 + KSTACK_SIZE as u64) & !0xF;
        let sp = top - 64; // 6 saved regs (48) + ret (8) + 8 bytes padding
        let frame = sp as *mut u64;
        unsafe {
            for i in 0..6 {
                frame.add(i).write(0); // r15..rbp
            }
            frame.add(6).write(crate::scheduler::thread_trampoline as *const () as u64); // return address
            frame.add(7).write(0); // padding
        }
        sp
    }
}

/// Saves `old`'s FPU state, restores `new`'s, then switches stacks. On return,
/// control resumes in whichever thread was switched *to* previously.
///
/// # Safety
/// Both pointers must reference live threads; `old` must be the currently
/// running thread on this CPU.
pub unsafe fn switch(old: *mut Thread, new: *mut Thread) {
    // SAFETY: caller guarantees both are live; the FPU areas are owned and
    // correctly sized, and `rsp` fields are valid stacks.
    unsafe {
        context::fxsave((*old).fpu);
        context::fxrstor((*new).fpu);
        context::context_switch(&mut (*old).rsp, (*new).rsp);
    }
}
