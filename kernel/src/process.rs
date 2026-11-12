//! User address spaces and the process object.
//!
//! A [`AddressSpace`] owns a fresh PML4 whose higher half is shared with the
//! kernel (so kernel mappings stay valid in any CR3) and whose lower half holds
//! the process's user mappings. The kernel reaches user frames through the HHDM
//! to load ELF segments and build the initial stack. A [`Process`] bundles the
//! address space with the per-process state the syscall layer needs (brk, the
//! file-descriptor table, pid).

use crate::fs::FdTable;
use crate::mm::{paging, phys};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicI32, Ordering};
use x86_64::structures::paging::mapper::Translate;
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

/// A user virtual address space.
pub struct AddressSpace {
    pml4_phys: u64,
    hhdm: u64,
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
        Some(Self { pml4_phys, hhdm })
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
                match unsafe { mapper.map_to(page, frame, flags, &mut frames) } {
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

    /// Translates a user virtual address to a physical address, if mapped.
    #[allow(dead_code)] // used by fork copy
    pub fn translate(&mut self, vaddr: u64) -> Option<u64> {
        self.mapper().translate_addr(VirtAddr::new(vaddr)).map(|p| p.as_u64())
    }
}

/// Monotonic PID source.
static NEXT_PID: AtomicI32 = AtomicI32::new(1);

/// A process: an address space plus the state syscalls mutate.
pub struct Process {
    pub pid: i32,
    pub space: AddressSpace,
    pub fds: FdTable,
    /// Program break (end of the heap), for `brk`.
    pub brk: u64,
    /// Start of the heap region, so `brk(0)` reports it.
    pub brk_start: u64,
    /// `set_tid_address` clear-child-tid pointer (stored, cleared on exit).
    pub clear_child_tid: u64,
    /// Next free address for anonymous `mmap` allocations (grows up).
    pub mmap_next: u64,
    /// Exit status once the process has exited.
    pub exit_code: Option<i32>,
}

impl Process {
    /// Allocates a process with a fresh address space and an empty fd table.
    pub fn new() -> Option<Arc<SpinLock<Process>>> {
        let space = AddressSpace::new()?;
        let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        Some(Arc::new(SpinLock::new(Process {
            pid,
            space,
            fds: FdTable::new(),
            brk: 0,
            brk_start: 0,
            clear_child_tid: 0,
            mmap_next: 0x6000_0000,
            exit_code: None,
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
