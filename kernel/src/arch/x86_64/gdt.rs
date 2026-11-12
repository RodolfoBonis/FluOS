//! Global Descriptor Table with a TSS carrying dedicated IST stacks.
//!
//! Limine hands us a usable GDT, but we install our own so we control the
//! kernel code/data selectors and, crucially, a TSS whose Interrupt Stack
//! Table (IST) gives the double-fault, NMI, and machine-check handlers private,
//! always-valid stacks. Those faults can fire precisely because the current
//! stack is unusable (overflow, corruption), so they must not reuse it.

use spin::Lazy;
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

/// Size of each fault stack: generous enough to log a full register dump and
/// run the panic path without itself overflowing.
const IST_STACK_SIZE: usize = 4096 * 5;

/// A naturally-aligned fault stack. Lives in `.bss`, which the kernel page
/// tables map read-write, so it stays valid after the CR3 switch.
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

/// Returns the top (highest address) of a fault stack; stacks grow downward.
fn stack_top(stack: *const FaultStack) -> VirtAddr {
    VirtAddr::from_ptr(stack) + IST_STACK_SIZE as u64
}

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    // `&raw const` avoids forming a reference to a `static mut`; each stack is
    // used only as a fault stack top, never read through this pointer here.
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        stack_top(&raw const DOUBLE_FAULT_STACK);
    tss.interrupt_stack_table[NMI_IST_INDEX as usize] = stack_top(&raw const NMI_STACK);
    tss.interrupt_stack_table[MACHINE_CHECK_IST_INDEX as usize] =
        stack_top(&raw const MACHINE_CHECK_STACK);
    tss
});

/// Segment selectors for the descriptors we install, needed to reload the
/// segment registers after loading the GDT.
struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));
    (gdt, Selectors { code, data, tss })
});

/// Loads the GDT, reloads the segment registers, and installs the TSS.
pub fn init() {
    GDT.0.load();
    // SAFETY: the selectors index descriptors we just loaded; CS gets the code
    // segment, the data/stack registers the data segment, and the task register
    // our TSS. All are well-formed, so this is the standard long-mode reload.
    unsafe {
        CS::set_reg(GDT.1.code);
        SS::set_reg(GDT.1.data);
        DS::set_reg(GDT.1.data);
        ES::set_reg(GDT.1.data);
        load_tss(GDT.1.tss);
    }
}
