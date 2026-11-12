//! Limine boot protocol requests and typed accessors over their responses.

use limine::request::{
    BootloaderInfoRequest, ExecutableCmdlineRequest, FramebufferRequest, HhdmRequest,
    MemmapRequest,
};
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker, memmap};

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static BOOTLOADER_INFO: BootloaderInfoRequest = BootloaderInfoRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMMAP: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static FRAMEBUFFER: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static CMDLINE: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Summary of what the bootloader handed us.
pub struct BootInfo {
    pub bootloader_name: &'static str,
    pub bootloader_version: &'static str,
    pub base_revision: u64,
    pub hhdm_offset: u64,
    pub usable_bytes: u64,
    pub usable_regions: usize,
}

/// Validates the protocol handshake and collects the mandatory responses.
///
/// Panics if a response the kernel cannot live without is missing.
pub fn info() -> BootInfo {
    assert!(
        BASE_REVISION.is_supported(),
        "Limine does not support base revision {} (actual: {:?})",
        BaseRevision::MAX_SUPPORTED,
        BASE_REVISION.actual_revision()
    );

    let loader = BOOTLOADER_INFO.response().expect("bootloader info response");
    let hhdm = HHDM.response().expect("HHDM response");
    let memmap = MEMMAP.response().expect("memory map response");

    let usable = memmap
        .entries()
        .iter()
        .filter(|e| e.type_ == memmap::MEMMAP_USABLE);

    BootInfo {
        bootloader_name: loader.name(),
        bootloader_version: loader.version(),
        base_revision: BASE_REVISION.actual_revision().unwrap_or(BaseRevision::MAX_SUPPORTED),
        hhdm_offset: hhdm.offset,
        usable_bytes: usable.clone().map(|e| e.length).sum(),
        usable_regions: usable.count(),
    }
}

/// Kernel command line, empty when the bootloader passed none.
pub fn cmdline() -> &'static str {
    CMDLINE.response().map_or("", |r| r.cmdline())
}

/// Linear 32-bit RGB framebuffer.
pub struct Framebuffer {
    pub addr: *mut u32,
    pub width: usize,
    pub height: usize,
    /// Bytes per scanline.
    pub pitch: usize,
    pub bpp: u16,
}

/// First framebuffer, if it is in a 32bpp RGB format we know how to drive.
pub fn framebuffer() -> Option<Framebuffer> {
    let fb = *FRAMEBUFFER.response()?.framebuffers().first()?;
    if fb.bpp != 32 || fb.memory_model != limine::framebuffer::FRAMEBUFFER_RGB {
        return None;
    }
    Some(Framebuffer {
        addr: fb.address().cast(),
        width: fb.width as usize,
        height: fb.height as usize,
        pitch: fb.pitch as usize,
        bpp: fb.bpp,
    })
}
