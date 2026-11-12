//! User address spaces and the process object.
//!
//! A [`AddressSpace`] owns a fresh PML4 whose higher half is shared with the
//! kernel (so kernel mappings stay valid in any CR3) and whose lower half holds
//! the process's user mappings. The kernel reaches user frames through the HHDM
//! to load ELF segments and build the initial stack. A [`Process`] bundles the
//! address space with the per-process state the syscall layer needs (brk, the
//! file-descriptor table, pid).

use crate::fs::FdTable;
use crate::signal::SignalState;
use crate::scheduler::WaitQueue;
use crate::mm::{paging, phys};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicI32, Ordering};
use x86_64::structures::paging::mapper::Translate;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags as Flags, PhysFrame,
    Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

const PAGE: u64 = 4096;


/// Frame source for user mappings; hands out zeroed frames.
struct UserFrames;

// SAFETY: `alloc_frame_zeroed` returns a unique, zeroed frame each call.
unsafe impl FrameAllocator<Size4KiB> for UserFrames {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        phys::alloc_frame_zeroed().map(|p| PhysFrame::containing_address(PhysAddr::new(p)))
    }
}

/// Software PTE bit (available bit 9) marking a copy-on-write page.
const PTE_COW: Flags = Flags::BIT_9;

/// Flags for *intermediate* user page-table entries (PML4E/PDPTE/PDE). These
/// must always be present/writable/user: x86 ANDs the R/W and U/S permissions
/// across all levels, so a read-only parent would make every leaf beneath it
/// effectively read-only. Actual permissions are enforced at the leaf only.
/// (Plain `map_to` derives parent flags from the leaf, which breaks when the
/// first leaf mapped under a table is read-only — e.g. code, or a CoW page.)
const USER_PARENT_FLAGS: Flags =
    Flags::PRESENT.union(Flags::WRITABLE).union(Flags::USER_ACCESSIBLE);

/// A reserved-but-not-yet-populated user region (anonymous, zero-fill on first
/// touch). Demand paging backs these lazily; the `kind` is kept minimal now but
/// is the seam where file-backed MAP_PRIVATE mappings slot in later.
#[derive(Clone, Copy)]
struct Region {
    start: u64,
    end: u64,
    writable: bool,
    exec: bool,
}

/// A user virtual address space.
pub struct AddressSpace {
    pml4_phys: u64,
    hhdm: u64,
    /// Lazily-backed regions (brk, anonymous mmap), consulted on a page fault.
    regions: Vec<Region>,
    /// Pending CoW copies `(page, frame, exec)`: a write fault unmaps the shared
    /// page and stashes the private writable copy; the retry faults non-present
    /// and maps it.
    pending_cow: Vec<(u64, u64, bool)>,
}

impl AddressSpace {
    /// Builds a new address space sharing the kernel's higher half.
    pub fn new() -> Option<Self> {
        let hhdm = phys::hhdm_offset();
        let pml4_phys = phys::alloc_frame_zeroed()?;
        let kernel = paging::kernel_pml4_phys();

        // SAFETY: both PML4 frames are mapped through the HHDM; copying the top
        // 256 entries shares every kernel mapping with the new space.
        unsafe {
            let dst = &mut *((hhdm + pml4_phys) as *mut PageTable);
            let src = &*((hhdm + kernel) as *const PageTable);
            for i in 256..512 {
                dst[i] = src[i].clone();
            }
        }
        Some(Self { pml4_phys, hhdm, regions: Vec::new(), pending_cow: Vec::new() })
    }

    /// Physical address of this space's PML4 (a CR3 value, PCID 0).
    pub fn cr3(&self) -> u64 {
        self.pml4_phys
    }

    /// Switches the CPU to this address space.
    ///
    /// # Safety
    /// The caller must ensure the current kernel stack and code remain mapped
    /// (guaranteed: the higher half is shared).
    #[allow(dead_code)] // used by execve/fork paths
    pub unsafe fn activate(&self) {
        use x86_64::registers::control::{Cr3, Cr3Flags};
        let frame = PhysFrame::containing_address(PhysAddr::new(self.pml4_phys));
        // SAFETY: a valid PML4 with the kernel higher half mapped.
        unsafe { Cr3::write(frame, Cr3Flags::empty()) };
    }

    fn mapper(&mut self) -> OffsetPageTable<'static> {
        // SAFETY: the PML4 is HHDM-mapped and owned by this address space.
        unsafe {
            let pml4 = &mut *((self.hhdm + self.pml4_phys) as *mut PageTable);
            OffsetPageTable::new(pml4, VirtAddr::new(self.hhdm))
        }
    }

    /// Maps `[vaddr, vaddr+size)` as user pages (zeroed), rounding to pages.
    /// Idempotent for already-mapped pages.
    pub fn map_region(&mut self, vaddr: u64, size: u64, writable: bool, exec: bool) {
        let mut flags = Flags::PRESENT | Flags::USER_ACCESSIBLE;
        if writable {
            flags |= Flags::WRITABLE;
        }
        if !exec {
            flags |= Flags::NO_EXECUTE;
        }
        let start = vaddr & !(PAGE - 1);
        let end = (vaddr + size + PAGE - 1) & !(PAGE - 1);
        let mut frames = UserFrames;
        let mut mapper = self.mapper();
        let mut a = start;
        while a < end {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(a));
            if let Some(frame) = frames.allocate_frame() {
                // SAFETY: fresh user mapping into this space's inactive tables.
                // Intermediate entries are always writable/user (see
                // USER_PARENT_FLAGS); permission is enforced at the leaf.
                match unsafe {
                    mapper.map_to_with_table_flags(page, frame, flags, USER_PARENT_FLAGS, &mut frames)
                } {
                    Ok(flush) => flush.ignore(),
                    Err(_) => {} // already mapped — leave as is
                }
            }
            a += PAGE;
        }
    }

    /// Copies `data` into already-mapped user memory at `vaddr` (via the HHDM).
    pub fn write(&mut self, vaddr: u64, data: &[u8]) {
        let mapper = self.mapper();
        let mut written = 0usize;
        while written < data.len() {
            let va = vaddr + written as u64;
            let page_off = (va & (PAGE - 1)) as usize;
            let chunk = (PAGE as usize - page_off).min(data.len() - written);
            if let Some(phys) = mapper.translate_addr(VirtAddr::new(va)) {
                let dst = (self.hhdm + phys.as_u64()) as *mut u8;
                // SAFETY: `phys` is a mapped, owned user frame; `chunk` stays
                // within the page.
                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr().add(written), dst, chunk);
                }
            }
            written += chunk;
        }
    }

    /// Maps a specific physical frame at `vaddr` with the given permissions.
    pub fn map_page_to(&mut self, vaddr: u64, phys: u64, writable: bool, exec: bool) {
        let mut flags = Flags::PRESENT | Flags::USER_ACCESSIBLE;
        if writable {
            flags |= Flags::WRITABLE;
        }
        if !exec {
            flags |= Flags::NO_EXECUTE;
        }
        let mut frames = UserFrames;
        let mut mapper = self.mapper();
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(vaddr));
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        // SAFETY: mapping an owned frame; intermediates stay writable/user.
        if let Ok(flush) =
            unsafe { mapper.map_to_with_table_flags(page, frame, flags, USER_PARENT_FLAGS, &mut frames) }
        {
            flush.ignore();
        }
    }

    /// Reserves `[vaddr, vaddr+size)` as a lazily-backed anonymous region: no
    /// frames are mapped now; the first access faults in a zeroed page (demand
    /// paging). Used by `brk`/anonymous `mmap`.
    pub fn reserve_region(&mut self, vaddr: u64, size: u64, writable: bool, exec: bool) {
        let start = vaddr & !(PAGE - 1);
        let end = (vaddr + size + PAGE - 1) & !(PAGE - 1);
        if end > start {
            self.regions.push(Region { start, end, writable, exec });
        }
    }

    /// Walks this space's tables to the leaf PTE for `vaddr`, returning a mutable
    /// pointer if every level up to it is present (no huge pages). The space need
    /// not be active (we go through the HHDM).
    ///
    /// # Safety
    /// The returned pointer aliases this space's page tables; the caller must not
    /// hold another reference to the same entry and must keep the space alive.
    unsafe fn walk_pte(&self, vaddr: u64) -> Option<*mut PageTableEntry> {
        let hhdm = self.hhdm;
        let idx = |lvl: u32| ((vaddr >> (12 + 9 * lvl)) & 0x1ff) as usize;
        // SAFETY: each present, non-huge entry points at an HHDM-mapped table.
        unsafe {
            let pml4 = &mut *((hhdm + self.pml4_phys) as *mut PageTable);
            let e4 = &mut pml4[idx(3)];
            if !e4.flags().contains(Flags::PRESENT) {
                return None;
            }
            let pdpt = &mut *((hhdm + e4.addr().as_u64()) as *mut PageTable);
            let e3 = &mut pdpt[idx(2)];
            if !e3.flags().contains(Flags::PRESENT) || e3.flags().contains(Flags::HUGE_PAGE) {
                return None;
            }
            let pd = &mut *((hhdm + e3.addr().as_u64()) as *mut PageTable);
            let e2 = &mut pd[idx(1)];
            if !e2.flags().contains(Flags::PRESENT) || e2.flags().contains(Flags::HUGE_PAGE) {
                return None;
            }
            let pt = &mut *((hhdm + e2.addr().as_u64()) as *mut PageTable);
            Some(core::ptr::from_mut(&mut pt[idx(0)]))
        }
    }

    /// Maps `phys` at `vaddr` with the exact `flags` (used to share a frame into
    /// a child with copy-on-write flags during `fork`).
    fn map_page_raw(&mut self, vaddr: u64, phys: u64, flags: Flags) {
        let mut frames = UserFrames;
        let mut mapper = self.mapper();
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(vaddr));
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        // SAFETY: fresh mapping into this (inactive) child space; intermediate
        // entries are forced writable/user so an RO leaf (code/CoW) does not
        // make later writable leaves in the same subtree effectively RO.
        if let Ok(flush) =
            unsafe { mapper.map_to_with_table_flags(page, frame, flags, USER_PARENT_FLAGS, &mut frames) }
        {
            flush.ignore();
        }
    }

    /// Creates a child via copy-on-write: every present user page is shared
    /// read-only, writable pages are additionally marked CoW in BOTH spaces, and
    /// the lazily-reserved regions are inherited. The actual copy happens on the
    /// first write fault ([`handle_cow`]). The parent is the active space, so its
    /// now-read-only pages are flushed from the local TLB before returning.
    ///
    /// NOTE: frames are shared without a per-frame refcount (address-space
    /// teardown currently leaks user frames, so there is no double-free). A
    /// refcount is required before frames are reclaimed on exit/munmap.
    pub fn fork(&mut self) -> Option<AddressSpace> {
        let mut child = AddressSpace::new()?;
        child.regions = self.regions.clone();
        let hhdm = self.hhdm;
        // SAFETY: the PML4 is HHDM-mapped; we only touch present entries.
        let pml4 = unsafe { &mut *((hhdm + self.pml4_phys) as *mut PageTable) };
        for i in 0..256 {
            if !pml4[i].flags().contains(Flags::PRESENT) {
                continue;
            }
            let pdpt = unsafe { &mut *((hhdm + pml4[i].addr().as_u64()) as *mut PageTable) };
            for j in 0..512 {
                let e3 = &pdpt[j];
                if !e3.flags().contains(Flags::PRESENT) || e3.flags().contains(Flags::HUGE_PAGE) {
                    continue;
                }
                let pd = unsafe { &mut *((hhdm + e3.addr().as_u64()) as *mut PageTable) };
                for k in 0..512 {
                    let e2 = &pd[k];
                    if !e2.flags().contains(Flags::PRESENT) || e2.flags().contains(Flags::HUGE_PAGE) {
                        continue;
                    }
                    let pt = unsafe { &mut *((hhdm + e2.addr().as_u64()) as *mut PageTable) };
                    for (l, pte) in pt.iter_mut().enumerate() {
                        let f = pte.flags();
                        if !f.contains(Flags::PRESENT) {
                            continue;
                        }
                        let vaddr = ((i as u64) << 39) | ((j as u64) << 30) | ((k as u64) << 21) | ((l as u64) << 12);
                        let frame = pte.addr().as_u64();
                        let shared = if f.contains(Flags::WRITABLE) {
                            let ro_cow = (f & !Flags::WRITABLE) | PTE_COW;
                            pte.set_flags(ro_cow);
                            ro_cow
                        } else {
                            f
                        };
                        child.map_page_raw(vaddr, frame, shared);
                    }
                }
            }
        }
        // The parent is active: flush its now-read-only entries locally.
        x86_64::instructions::tlb::flush_all();
        Some(child)
    }

    /// Resolves a demand-paging fault (not-present) at `vaddr`: if it lies in a
    /// reserved region (and the access is permitted), maps a fresh zeroed page.
    pub fn handle_demand(&mut self, vaddr: u64, write: bool) -> bool {
        let page = vaddr & !(PAGE - 1);
        if let Some(i) = self.pending_cow.iter().position(|&(p, _, _)| p == page) {
            let (_, frame, exec) = self.pending_cow.swap_remove(i);
            self.map_page_to(page, frame, true, exec);
            x86_64::instructions::tlb::flush(VirtAddr::new(page));
            return true;
        }
        let Some(r) = self.regions.iter().find(|r| page >= r.start && page < r.end).copied() else {
            return false;
        };
        if write && !r.writable {
            return false; // write to a read-only region: genuine fault
        }
        // Lost the race to another fault that already mapped it? Then it's done.
        // SAFETY: walk only reads the tables.
        if let Some(pte) = unsafe { self.walk_pte(page) } {
            if unsafe { (*pte).flags() }.contains(Flags::PRESENT) {
                return true;
            }
        }
        let Some(frame) = phys::alloc_frame_zeroed() else {
            return false;
        };
        self.map_page_to(page, frame, r.writable, r.exec);
        x86_64::instructions::tlb::flush(VirtAddr::new(page));
        true
    }

    /// Resolves a write fault at `vaddr`. Returns `true` if the page is (now)
    /// writable: a copy-on-write page is copied and made writable; a page that is
    /// already writable needs nothing; a read-only non-CoW page is a real fault.
    pub fn handle_cow(&mut self, vaddr: u64) -> bool {
        let page = vaddr & !(PAGE - 1);
        // SAFETY: walk returns a pointer into this space's tables; we hold `&mut`.
        let Some(pte) = (unsafe { self.walk_pte(page) }) else {
            return false;
        };
        let f = unsafe { (*pte).flags() };
        if !f.contains(Flags::PRESENT) {
            return false;
        }
        if f.contains(Flags::WRITABLE) {
            return true;
        }
        if !f.contains(PTE_COW) {
            return false;
        }
        let old = unsafe { (*pte).addr().as_u64() };
        let exec = !f.contains(Flags::NO_EXECUTE);
        let Some(new) = phys::alloc_frame() else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.hhdm + old) as *const u8,
                (self.hhdm + new) as *mut u8,
                PAGE as usize,
            );
        }
        // Two-phase remap: unmap the shared page (making it non-present) and
        // stash the private writable copy. The faulting instruction then retries
        // and faults *non-present*, which `handle_demand` maps in. Going through
        // the non-present state is deliberate: a protection-fault retry on a page
        // left present (merely upgraded RO->RW) is not reliably re-checked by the
        // TCG MMU, whereas a non-present fill always is.
        let page_obj = Page::<Size4KiB>::containing_address(VirtAddr::new(page));
        let mut mapper = self.mapper();
        if let Ok((_f, flush)) = mapper.unmap(page_obj) {
            flush.flush();
        }
        self.pending_cow.push((page, new, exec));
        true
    }

    /// Translates a user virtual address to a physical address, if mapped.
    #[allow(dead_code)] // used by fork copy
    pub fn translate(&mut self, vaddr: u64) -> Option<u64> {
        self.mapper().translate_addr(VirtAddr::new(vaddr)).map(|p| p.as_u64())
    }
}

/// Monotonic PID / TID source (Linux draws both from one id space).
static NEXT_PID: AtomicI32 = AtomicI32::new(1);

/// Allocates a fresh thread id (for `clone(CLONE_VM)` threads).
pub fn alloc_tid() -> i32 {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}

/// A process: an address space plus the state syscalls mutate.
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub space: AddressSpace,
    pub fds: FdTable,
    /// Program break (end of the heap), for `brk`.
    pub brk: u64,
    /// Start of the heap region, so `brk(0)` reports it.
    pub brk_start: u64,
    /// Next free address for anonymous `mmap` allocations (grows up).
    pub mmap_next: u64,
    /// Process group and session ids (job control).
    pub pgid: i32,
    pub sid: i32,
    /// Exit status once the process has exited.
    pub exit_code: Option<i32>,
    /// Signal dispositions, pending set, and blocked mask.
    pub sig: SignalState,
    /// Scheduler tid of this process's (single) thread, for targeted wakeups
    /// (signals interrupting a blocked syscall). 0 until the thread is spawned.
    pub main_thread: u64,
    /// Number of live threads in this thread group (1 until `clone(CLONE_VM)`
    /// adds more). The last thread to exit reports the group's exit status.
    pub thread_count: u32,
}

impl Process {
    /// Allocates a process with a fresh address space and an empty fd table.
    pub fn new() -> Option<Arc<SpinLock<Process>>> {
        let space = AddressSpace::new()?;
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        Some(Arc::new(SpinLock::new(Process {
            pid,
            ppid: 1,
            space,
            fds: FdTable::new(),
            brk: 0,
            brk_start: 0,
            mmap_next: 0x6000_0000,
            pgid: pid,
            sid: pid,
            exit_code: None,
            sig: SignalState::new(),
            main_thread: 0,
            thread_count: 1,
        })))
    }
}

/// Live processes, keyed by nothing fancy — just kept alive here.
static PROCS: SpinLock<Vec<Arc<SpinLock<Process>>>> = SpinLock::new(Vec::new());

/// Registers a process so it stays alive for the kernel's lifetime.
pub fn register(proc: Arc<SpinLock<Process>>) {
    PROCS.lock().push(proc);
}

/// Sets the current process pointer for this CPU.
#[allow(dead_code)] // switch_mm stores the pointer directly
pub fn set_current(proc: &Arc<SpinLock<Process>>) {
    crate::percpu::this()
        .current_proc
        .store(Arc::as_ptr(proc) as u64, Ordering::Relaxed);
}

/// The process currently running on this CPU, if any.
pub fn current() -> Option<&'static SpinLock<Process>> {
    let ptr = crate::percpu::this().current_proc.load(Ordering::Relaxed);
    if ptr == 0 {
        None
    } else {
        // SAFETY: a non-zero pointer references a live process kept alive in
        // PROCS for the kernel's lifetime.
        Some(unsafe { &*(ptr as *const SpinLock<Process>) })
    }
}

/// Switches this CPU to `next`'s address space and user-context pointers, as
/// the scheduler hands the CPU to `next`. For kernel-only threads it loads the
/// kernel page tables. Redundant CR3 reloads are skipped.
///
/// # Safety
/// `next` must be a live thread owned by this CPU during the switch.
pub unsafe fn switch_mm(next: *mut crate::thread::Thread) {
    use x86_64::registers::control::{Cr3, Cr3Flags};
    use x86_64::structures::paging::PhysFrame;
    use x86_64::PhysAddr;

    let cpu = crate::percpu::this();
    // SAFETY: caller guarantees `next` is live.
    let (cr3, proc_ptr, kstack_top) =
        unsafe { ((*next).cr3, (*next).proc_ptr, (*next).kstack_top) };

    if cr3 != 0 {
        cpu.current_proc.store(proc_ptr, Ordering::Relaxed);
        crate::arch::x86_64::user::set_kernel_stack(kstack_top);
    } else {
        cpu.current_proc.store(0, Ordering::Relaxed);
    }

    let target = if cr3 == 0 { paging::kernel_pml4_phys() } else { cr3 };
    if cpu.active_cr3.load(Ordering::Relaxed) != target {
        let frame = PhysFrame::containing_address(PhysAddr::new(target));
        // SAFETY: `target` is a valid PML4 whose higher half maps the kernel.
        unsafe { Cr3::write(frame, Cr3Flags::empty()) };
        cpu.active_cr3.store(target, Ordering::Relaxed);
    }
}

impl Process {
    /// Creates a child of `parent` (eager-copied address space, cloned fds).
    pub fn fork_from(parent: &mut Process) -> Option<Arc<SpinLock<Process>>> {
        let space = parent.space.fork()?;
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        Some(Arc::new(SpinLock::new(Process {
            pid,
            ppid: parent.pid,
            space,
            fds: parent.fds.fork_clone(),
            brk: parent.brk,
            brk_start: parent.brk_start,
            mmap_next: parent.mmap_next,
            pgid: parent.pgid,
            sid: parent.sid,
            exit_code: None,
            // A child inherits handlers and the blocked mask; the pending set
            // does not cross `fork`.
            sig: parent.sig.forked(),
            main_thread: 0,
            thread_count: 1,
        })))
    }
}

/// Reaps an exited child of `parent_pid`: returns `(pid, exit_code)` and removes
/// it from the table, or `None` if no child has exited.
pub fn reap_child(parent_pid: i32) -> Option<(i32, i32)> {
    let mut procs = PROCS.lock();
    let idx = procs.iter().position(|p| {
        let g = p.lock();
        g.ppid == parent_pid && g.exit_code.is_some()
    })?;
    let child = procs.remove(idx);
    let g = child.lock();
    Some((g.pid, g.exit_code.unwrap_or(0)))
}

/// Whether `parent_pid` has any live (unreaped) children.
pub fn has_children(parent_pid: i32) -> bool {
    PROCS.lock().iter().any(|p| p.lock().ppid == parent_pid)
}

/// Wait queue a parent blocks on in `wait4`; woken whenever any process exits.
static CHILD_EXIT: WaitQueue = WaitQueue::new();

/// The child-exit wait queue (for `wait4` to block on).
pub fn child_exit_wq() -> &'static WaitQueue {
    &CHILD_EXIT
}

/// Wakes every parent blocked in `wait4` (a child changed state).
pub fn notify_child_exit() {
    crate::scheduler::wake_all(&CHILD_EXIT);
}

/// Runs `f` against the process with pid `pid` (under its lock), returning the
/// result, or `None` if no such live process exists.
pub fn with_pid<R>(pid: i32, f: impl FnOnce(&mut Process) -> R) -> Option<R> {
    let procs = PROCS.lock();
    let proc = procs.iter().find(|p| p.lock().pid == pid)?.clone();
    drop(procs);
    let mut g = proc.lock();
    Some(f(&mut g))
}

/// Runs `f` against every live process in group `pgid` (each under its lock),
/// returning how many matched.
pub fn for_each_in_pgrp(pgid: i32, mut f: impl FnMut(&mut Process)) -> usize {
    let snapshot: Vec<Arc<SpinLock<Process>>> = PROCS.lock().iter().cloned().collect();
    let mut n = 0;
    for proc in snapshot {
        let mut g = proc.lock();
        if g.pgid == pgid {
            f(&mut g);
            n += 1;
        }
    }
    n
}
