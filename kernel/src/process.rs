//! User address spaces and the process object.
//!
//! A [`AddressSpace`] owns a fresh PML4 whose higher half is shared with the
//! kernel (so kernel mappings stay valid in any CR3) and whose lower half holds
//! the process's user mappings. The kernel reaches user frames through the HHDM
//! to load ELF segments and build the initial stack. A [`Process`] bundles the
//! address space with the per-process state the syscall layer needs (brk, the
//! file-descriptor table, pid).

use crate::fs::FdTable;
use vfs::Ino;
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

/// Outcome of a copy-on-write write fault.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Cow {
    /// A shared page was copied into a private writable one.
    Copied,
    /// The page was already writable; nothing copied (this CPU's TLB flushed).
    NoChange,
    /// A genuine read-only violation (not a CoW page).
    Fault,
}

/// A user virtual address space.
pub struct AddressSpace {
    pml4_phys: u64,
    hhdm: u64,
    /// Lazily-backed regions (brk, anonymous mmap), consulted on a page fault.
    regions: Vec<Region>,
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
        Some(Self { pml4_phys, hhdm, regions: Vec::new() })
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
                        // The child now shares this frame: bump its refcount so
                        // it is freed only when the last owner drops it.
                        phys::frame_incref(frame);
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

    /// Resolves a write fault at `vaddr`. Returns [`Cow::Copied`] if it copied a
    /// shared page into a private writable one (callers must then shoot down
    /// peer CPUs for a shared address space), [`Cow::NoChange`] if the page was
    /// already writable (this CPU's stale read-only entry is flushed locally so
    /// the retry succeeds — the self-heal for a concurrent writer), or
    /// [`Cow::Fault`] for a genuine read-only violation.
    pub fn handle_cow(&mut self, vaddr: u64) -> Cow {
        let page = vaddr & !(PAGE - 1);
        // SAFETY: walk returns a pointer into this space's tables; we hold `&mut`.
        let Some(pte) = (unsafe { self.walk_pte(page) }) else {
            return Cow::Fault;
        };
        let f = unsafe { (*pte).flags() };
        if !f.contains(Flags::PRESENT) {
            return Cow::Fault;
        }
        if f.contains(Flags::WRITABLE) {
            // Already writable (another thread CoW'd it first): flush this CPU's
            // stale read-only entry so the faulting write retries successfully.
            x86_64::instructions::tlb::flush(VirtAddr::new(page));
            return Cow::NoChange;
        }
        if !f.contains(PTE_COW) {
            return Cow::Fault;
        }
        let old = unsafe { (*pte).addr().as_u64() };
        // Sole owner (refcount 1): no copy needed — just take it writable in
        // place and clear the CoW marker. This is the common post-exec case.
        if phys::frame_refcount(old) <= 1 {
            let new_flags = (f & !PTE_COW) | Flags::WRITABLE;
            // SAFETY: upgrade this leaf's permissions in place.
            unsafe { (*pte).set_flags(new_flags) };
            x86_64::instructions::tlb::flush(VirtAddr::new(page));
            return Cow::Copied;
        }
        // Shared: copy into a private frame, repoint the leaf, and drop this
        // space's reference to the old (shared) frame.
        let Some(new) = phys::alloc_frame() else {
            return Cow::Fault;
        };
        // SAFETY: both frames are HHDM-mapped and page-sized.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.hhdm + old) as *const u8,
                (self.hhdm + new) as *mut u8,
                PAGE as usize,
            );
        }
        let new_flags = (f & !PTE_COW) | Flags::WRITABLE;
        // SAFETY: re-point this leaf at the private copy, now writable.
        unsafe { (*pte).set_addr(PhysAddr::new(new), new_flags) };
        x86_64::instructions::tlb::flush(VirtAddr::new(page));
        // This space no longer references the shared frame.
        phys::free_user_frame(old);
        Cow::Copied
    }

    /// Reclaims every user data (leaf) frame in this address space, dropping one
    /// reference each (freeing the frame when it was the last owner). Called when
    /// the owning process has exited: no thread runs this space, so there is no
    /// live TLB to shoot down — an idle CPU still parked on this CR3 (lazy TLB)
    /// executes only kernel code and never touches these user addresses.
    ///
    /// The page-table frames themselves (PML4/PDPT/PD/PT) are intentionally NOT
    /// freed yet: reclaiming them safely needs the CR3-eviction/shootdown step
    /// (a CPU must never run on freed tables), which lands with QEMU validation.
    /// Leaf frames are the bulk of memory; the table frames are a few per space.
    pub fn free_leaves(&mut self) {
        let hhdm = self.hhdm;
        // SAFETY: the PML4 is HHDM-mapped; we only read present, non-huge entries
        // in the user half (0..256) and free the leaf frames they point at.
        unsafe {
            let pml4 = &*((hhdm + self.pml4_phys) as *const PageTable);
            for i in 0..256 {
                if !pml4[i].flags().contains(Flags::PRESENT) {
                    continue;
                }
                let pdpt = &*((hhdm + pml4[i].addr().as_u64()) as *const PageTable);
                for e3 in pdpt.iter() {
                    if !e3.flags().contains(Flags::PRESENT) || e3.flags().contains(Flags::HUGE_PAGE) {
                        continue;
                    }
                    let pd = &*((hhdm + e3.addr().as_u64()) as *const PageTable);
                    for e2 in pd.iter() {
                        if !e2.flags().contains(Flags::PRESENT) || e2.flags().contains(Flags::HUGE_PAGE) {
                            continue;
                        }
                        let pt = &*((hhdm + e2.addr().as_u64()) as *const PageTable);
                        for e1 in pt.iter() {
                            if e1.flags().contains(Flags::PRESENT) {
                                phys::free_user_frame(e1.addr().as_u64());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Unmaps `[vaddr, vaddr+size)`, clearing the leaf PTEs and RETURNING the
    /// physical frames that were mapped (without freeing them). The caller frees
    /// them with [`phys::free_user_frame`] only AFTER any required TLB shootdown,
    /// so a peer CPU cannot write a freed-then-recycled frame through a stale
    /// entry (use-after-free). Used by `munmap`.
    pub fn unmap_region(&mut self, vaddr: u64, size: u64) -> Vec<u64> {
        let start = vaddr & !(PAGE - 1);
        let end = (vaddr.saturating_add(size) + PAGE - 1) & !(PAGE - 1);
        self.regions.retain(|r| r.end <= start || r.start >= end);
        let mut freed = Vec::new();
        let mut a = start;
        while a < end {
            // SAFETY: walk reads this space's tables; we hold &mut self.
            if let Some(pte) = unsafe { self.walk_pte(a) } {
                let f = unsafe { (*pte).flags() };
                if f.contains(Flags::PRESENT) {
                    let frame = unsafe { (*pte).addr().as_u64() };
                    // SAFETY: clear the leaf now; the frame is freed later.
                    unsafe { (*pte).set_unused() };
                    freed.push(frame);
                }
            }
            a += PAGE;
        }
        freed
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
    /// Real/effective user and group ids (login shell runs as a real user).
    pub uid: u32,
    pub gid: u32,
    /// Current working directory, stored as an inode so `getcwd` is always
    /// consistent with the live tree (see `vfs::path_of`). Inherited across
    /// `fork`.
    pub cwd: Ino,
    /// File-creation mask applied to `mode` on `open(O_CREAT)`/`mkdir`.
    pub umask: u32,
    /// Alternate signal stack set via `sigaltstack`: `(ss_sp, ss_size, ss_flags)`.
    /// Stored so a future `SA_ONSTACK` delivery can honour it; `ss_flags`
    /// defaults to `SS_DISABLE` (2).
    pub altstack: (u64, u64, i32),
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
            uid: 0,
            gid: 0,
            cwd: vfs::ROOT,
            umask: 0o022,
            altstack: (0, 0, 2),
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
        // User thread: switch to its address space only if different from the
        // one currently loaded.
        if cpu.active_cr3.load(Ordering::Relaxed) != cr3 {
            let frame = PhysFrame::containing_address(PhysAddr::new(cr3));
            // SAFETY: `cr3` is a valid PML4 whose higher half maps the kernel.
            unsafe { Cr3::write(frame, Cr3Flags::empty()) };
            cpu.active_cr3.store(cr3, Ordering::Relaxed);
        }
    } else {
        // Kernel-only thread (idle / kernel worker): LAZY TLB. Keep whatever user
        // CR3 is already loaded rather than switching to the kernel PML4 — the
        // kernel higher half is mapped in every address space, so kernel code,
        // stack, and data are reachable. This avoids two CR3 reloads (and two
        // full TLB flushes) on every user<->idle bounce, which is a large win
        // under TCG softmmu. active_cr3 is left unchanged so the next user thread
        // with that same CR3 skips the reload entirely.
        //
        // SAFETY NOTE: this holds a possibly-foreign user CR3 while in the
        // kernel. It is sound only because user address spaces are never freed
        // yet; frame reclamation must flush/step off a dying space's CR3 from any
        // CPU parked on it before freeing its page tables.
        cpu.current_proc.store(0, Ordering::Relaxed);
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
            uid: parent.uid,
            gid: parent.gid,
            cwd: parent.cwd,
            umask: parent.umask,
            altstack: parent.altstack,
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
    drop(procs); // release PROCS before the (potentially long) frame reclaim
    let mut g = child.lock();
    let result = (g.pid, g.exit_code.unwrap_or(0));
    // Reclaim the child's user memory now that it is reaped. Shared (CoW) frames
    // are only freed when the child held the last reference.
    g.space.free_leaves();
    drop(g);
    Some(result)
}

/// Whether `parent_pid` has any live (unreaped) children.
pub fn has_children(parent_pid: i32) -> bool {
    PROCS.lock().iter().any(|p| p.lock().ppid == parent_pid)
}

/// Reaps exited processes that no live parent will `wait4` (orphans whose parent
/// is init/pid 1, which is the role the kernel plays for its own spawned
/// processes). Frees each one's user frames and removes it. Returns the count
/// reaped. Call periodically from the init/idle path so kernel-spawned and
/// orphaned processes don't leak.
pub fn reap_orphan_zombies() -> usize {
    // Collect orphan zombies under the PROCS lock, then free their memory with
    // the lock released (free_leaves can be long).
    let orphans: Vec<Arc<SpinLock<Process>>> = {
        let mut procs = PROCS.lock();
        let mut taken = Vec::new();
        procs.retain(|p| {
            let g = p.lock();
            let orphan_zombie = g.exit_code.is_some() && g.ppid <= 1;
            drop(g);
            if orphan_zombie {
                taken.push(p.clone());
                false // remove from PROCS
            } else {
                true
            }
        });
        taken
    };
    let n = orphans.len();
    for proc in orphans {
        proc.lock().space.free_leaves();
    }
    n
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
