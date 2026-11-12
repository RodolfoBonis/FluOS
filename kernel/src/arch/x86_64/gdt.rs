//! Global Descriptor Table with a TSS (IST stacks + settable RSP0) and the
//! user-mode segments.
//!
//! The segment order is dictated by `syscall`/`sysret`: kernel code then kernel
//! data (data = code + 8), then the TSS, then **user data before user code**
//! (user code = user data + 8), which is what `sysret` requires. The TSS's
//! privilege-stack `RSP0` is updated per process so an interrupt taken in user
//! mode lands on that process's kernel stack.

use spin::Lazy;
use x86_64::PrivilegeLevel;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

/// IST slot for the double-fault handler.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
/// IST slot for the NMI handler.
pub const NMI_IST_INDEX: u16 = 1;
/// IST slot for the machine-check handler.
pub const MACHINE_CHECK_IST_INDEX: u16 = 2;

/// Kernel code selector (ring 0).
pub const KERNEL_CODE: u16 = 0x08;
/// Kernel data selector (ring 0).
pub const KERNEL_DATA: u16 = 0x10;
/// User data selector (ring 3): 0x28 | RPL 3.
pub const USER_DATA: u16 = 0x28 | 3;
/// User code selector (ring 3): 0x30 | RPL 3.
pub const USER_CODE: u16 = 0x30 | 3;

const IST_STACK_SIZE: usize = 4096 * 5;

#[repr(align(16))]
#[allow(dead_code)] // accessed only through a raw pointer to its top
struct FaultStack([u8; IST_STACK_SIZE]);

impl FaultStack {
    const fn new() -> Self {
        Self([0; IST_STACK_SIZE])
    }
}

static mut DOUBLE_FAULT_STACK: FaultStack = FaultStack::new();
static mut NMI_STACK: FaultStack = FaultStack::new();
static mut MACHINE_CHECK_STACK: FaultStack = FaultStack::new();

/// Top (highest address) of a fault stack; stacks grow downward.
fn stack_top(stack: *const FaultStack) -> VirtAddr {
    VirtAddr::from_ptr(stack) + IST_STACK_SIZE as u64
}

/// The BSP's TSS. `static mut` so `RSP0` can be updated per process; it is only
/// written by the owning CPU.
static mut BSP_TSS: TaskStateSegment = TaskStateSegment::new();

fn bsp_tss_ref() -> &'static TaskStateSegment {
    // SAFETY: the TSS lives for the kernel's lifetime; a shared ref is fine for
    // building the descriptor.
    unsafe { &*core::ptr::addr_of!(BSP_TSS) }
}

static GDT: Lazy<GlobalDescriptorTable> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    gdt.append(Descriptor::kernel_code_segment()); // 0x08
    gdt.append(Descriptor::kernel_data_segment()); // 0x10
    gdt.append(Descriptor::tss_segment(bsp_tss_ref())); // 0x18 (16-byte system desc)
    gdt.append(Descriptor::user_data_segment()); // 0x28
    gdt.append(Descriptor::user_code_segment()); // 0x30
    gdt
});

/// Loads the BSP GDT/TSS, reloads segment registers, and returns the TSS pointer
/// so the caller can register it with per-CPU state (for `RSP0` updates).
pub fn init() -> *mut TaskStateSegment {
    // SAFETY: single-threaded early boot; set the fault stacks into the TSS.
    unsafe {
        let tss = &mut *core::ptr::addr_of_mut!(BSP_TSS);
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            stack_top(&raw const DOUBLE_FAULT_STACK);
        tss.interrupt_stack_table[NMI_IST_INDEX as usize] = stack_top(&raw const NMI_STACK);
        tss.interrupt_stack_table[MACHINE_CHECK_IST_INDEX as usize] =
            stack_top(&raw const MACHINE_CHECK_STACK);
    }
    GDT.load();
    // SAFETY: standard long-mode selector reload with our freshly loaded GDT.
    unsafe {
        CS::set_reg(sel(KERNEL_CODE));
        SS::set_reg(sel(KERNEL_DATA));
        DS::set_reg(sel(KERNEL_DATA));
        ES::set_reg(sel(KERNEL_DATA));
        load_tss(sel(0x18));
    }
    core::ptr::addr_of_mut!(BSP_TSS)
}

/// Builds a [`SegmentSelector`] from a raw selector value.
fn sel(raw: u16) -> SegmentSelector {
    let rpl = match raw & 3 {
        0 => PrivilegeLevel::Ring0,
        3 => PrivilegeLevel::Ring3,
        _ => PrivilegeLevel::Ring0,
    };
    SegmentSelector::new(raw >> 3, rpl)
}

/// Per-CPU GDT/TSS setup for application processors; returns the TSS pointer.
/// Each AP needs its own TSS (the busy bit forbids sharing) and IST stacks.
pub fn init_ap() -> *mut TaskStateSegment {
    use alloc::boxed::Box;

    let tss: *mut TaskStateSegment = Box::leak(Box::new(TaskStateSegment::new()));
    // SAFETY: freshly leaked, uniquely owned TSS.
    unsafe {
        (*tss).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = ap_stack_top();
        (*tss).interrupt_stack_table[NMI_IST_INDEX as usize] = ap_stack_top();
        (*tss).interrupt_stack_table[MACHINE_CHECK_IST_INDEX as usize] = ap_stack_top();
    }

    let gdt = Box::leak(Box::new(GlobalDescriptorTable::new()));
    gdt.append(Descriptor::kernel_code_segment());
    gdt.append(Descriptor::kernel_data_segment());
    // SAFETY: the TSS is 'static (leaked); the descriptor only records its base.
    gdt.append(Descriptor::tss_segment(unsafe { &*tss }));
    gdt.append(Descriptor::user_data_segment());
    gdt.append(Descriptor::user_code_segment());
    gdt.load();
    // SAFETY: selector reload against this AP's freshly loaded GDT.
    unsafe {
        CS::set_reg(sel(KERNEL_CODE));
        SS::set_reg(sel(KERNEL_DATA));
        DS::set_reg(sel(KERNEL_DATA));
        ES::set_reg(sel(KERNEL_DATA));
        load_tss(sel(0x18));
    }
    tss
}

/// Allocates one heap-backed IST stack and returns its top.
fn ap_stack_top() -> VirtAddr {
    let buf = alloc::vec![0u8; IST_STACK_SIZE].into_boxed_slice();
    let leaked = alloc::boxed::Box::leak(buf);
    VirtAddr::from_ptr(leaked.as_ptr()) + IST_STACK_SIZE as u64
}

/// Sets `RSP0` (the kernel stack an interrupt/syscall from user mode switches
/// to) in `tss`.
///
/// # Safety
/// `tss` must be this CPU's live TSS and `rsp` a valid kernel stack top.
pub unsafe fn set_rsp0(tss: *mut TaskStateSegment, rsp: u64) {
    // SAFETY: caller guarantees `tss` is this CPU's TSS.
    unsafe { (*tss).privilege_stack_table[0] = VirtAddr::new(rsp) };
}
