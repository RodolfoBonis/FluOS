//! Early framebuffer output (text console arrives in M2).

use crate::boot::Framebuffer;

/// Starship prompt palette from the user's `starship.toml`.
const PALETTE: [u32; 6] = [0x5D3499, 0xDA627D, 0xFCA17D, 0x86BBD8, 0x06969A, 0x33658A];
const BACKGROUND: u32 = 0x1a1b26;

/// Clears the screen and draws the palette as a band at the top, proving the
/// framebuffer is mapped and writable.
pub fn splash(fb: &Framebuffer) {
    let band_height = (fb.height / 24).max(4);
    let stripe_width = fb.width.div_ceil(PALETTE.len());
    let stride = fb.pitch / 4;

    for y in 0..fb.height {
        for x in 0..fb.width {
            let color = if y < band_height { PALETTE[x / stripe_width] } else { BACKGROUND };
            // SAFETY: (x, y) is within the bounds reported by the bootloader.
            unsafe { fb.addr.add(y * stride + x).write_volatile(color) };
        }
    }
}
