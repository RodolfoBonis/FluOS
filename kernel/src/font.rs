//! Access to the build-time Nerd Font glyph atlas.
//!
//! `build.rs` rasterized each covered glyph into a fixed `CELL_W × CELL_H`
//! 8-bit alpha cell and emitted a codepoint-sorted index. Here we binary-search
//! that index to fetch a glyph's alpha coverage; missing glyphs return `None`
//! and the console draws a replacement box.

mod atlas {
    include!(concat!(env!("OUT_DIR"), "/font_atlas.rs"));
}

pub use atlas::{CELL_H, CELL_W, GLYPH_BYTES};

/// Reads the little-endian codepoint stored at index `i`.
fn codepoint_at(i: usize) -> u32 {
    let o = i * 4;
    u32::from_le_bytes([
        atlas::INDEX[o],
        atlas::INDEX[o + 1],
        atlas::INDEX[o + 2],
        atlas::INDEX[o + 3],
    ])
}

/// Returns the alpha coverage (`CELL_W * CELL_H` bytes, row-major) for `ch`,
/// or `None` if the font has no glyph for it.
pub fn glyph(ch: char) -> Option<&'static [u8]> {
    let cp = ch as u32;
    let (mut lo, mut hi) = (0usize, atlas::GLYPH_COUNT);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let v = codepoint_at(mid);
        if v == cp {
            let start = mid * GLYPH_BYTES;
            return Some(&atlas::ALPHA[start..start + GLYPH_BYTES]);
        } else if v < cp {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    None
}
