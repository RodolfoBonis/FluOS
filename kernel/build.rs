//! Build script: points the linker at our script and rasterizes the Nerd Font
//! into a compact glyph atlas embedded in the kernel.
//!
//! The atlas is produced on the host (where the TTF and `fontdue` live) so the
//! kernel ships only an 8-bit alpha bitmap per glyph plus a sorted codepoint
//! index — no font parsing in `no_std`. The TTF itself is never committed; its
//! path defaults to the user's installed FiraCode Nerd Font and can be
//! overridden with `FLUOS_FONT`.

use std::env;
use std::fs;
use std::path::PathBuf;

/// Default location of the user's terminal font.
const DEFAULT_FONT: &str = "/Users/rodolfodebonis/Library/Fonts/FiraCodeNerdFontMono-Regular.ttf";

/// Unicode ranges we rasterize (glyphs absent from the font are skipped).
/// Covers ASCII, Latin-1, common punctuation, box/block drawing, Powerline,
/// and the Nerd Font icon planes starship and colorls rely on.
const RANGES: &[(u32, u32)] = &[
    (0x0020, 0x007E), // ASCII printable
    (0x00A0, 0x00FF), // Latin-1 (Portuguese accents)
    (0x2010, 0x2027), // dashes, quotes, ellipsis
    (0x2190, 0x21FF), // arrows
    (0x2500, 0x257F), // box drawing
    (0x2580, 0x259F), // block elements
    (0x25A0, 0x25FF), // geometric shapes (cheap extras)
    (0x2700, 0x27BF), // dingbats (cheap extras)
    (0xE0A0, 0xE0D7), // Powerline
    (0xE5FA, 0xE6B7), // Seti / custom
    (0xE700, 0xE8EF), // Devicons
    (0xEA60, 0xEC1E), // Codicons
    (0xF000, 0xF2FF), // Font Awesome
    (0xF400, 0xF533), // Octicons
    (0xF0001, 0xF1AF0), // Material Design icons
];

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    println!("cargo:rustc-link-arg-bin=kernel=-T{dir}/linker.ld");
    println!("cargo:rerun-if-changed={dir}/linker.ld");

    generate_font_atlas();
    embed_symbol_env();
}

/// Points `FLUOS_KSYMS_FILE` at the symbol blob xtask generated (via the
/// `FLUOS_KSYMS` env), or at an empty placeholder when building standalone.
fn embed_symbol_env() {
    println!("cargo:rerun-if-env-changed=FLUOS_KSYMS");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let file = match env::var("FLUOS_KSYMS") {
        Ok(path) if std::path::Path::new(&path).exists() => path,
        _ => {
            let placeholder = out.join("ksyms_empty.bin");
            // Magic "KSY1" + count 0.
            fs::write(&placeholder, b"KSY1\x00\x00\x00\x00").expect("write ksyms placeholder");
            placeholder.display().to_string()
        }
    };
    println!("cargo:rustc-env=FLUOS_KSYMS_FILE={file}");
}

/// Whether a generated atlas already exists and is newer than the font file.
fn atlas_is_current(out: &std::path::Path, font_path: &str) -> bool {
    let rs = out.join("font_atlas.rs");
    let alpha = out.join("font_alpha.bin");
    let index = out.join("font_index.bin");
    if !(rs.exists() && alpha.exists() && index.exists()) {
        return false;
    }
    let mtime = |p: &std::path::Path| fs::metadata(p).and_then(|m| m.modified()).ok();
    match (mtime(&rs), mtime(std::path::Path::new(font_path))) {
        (Some(atlas_t), Some(font_t)) => atlas_t >= font_t,
        _ => false,
    }
}

fn generate_font_atlas() {
    let font_path = env::var("FLUOS_FONT").unwrap_or_else(|_| DEFAULT_FONT.to_string());
    println!("cargo:rerun-if-env-changed=FLUOS_FONT");
    println!("cargo:rerun-if-env-changed=FLUOS_FONT_PX");
    println!("cargo:rerun-if-changed={font_path}");

    // Skip rasterization if a current atlas already exists in OUT_DIR. The two
    // kernel build passes (for the symbol table) share OUT_DIR, so this avoids
    // rasterizing ~9600 glyphs a second time.
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    if atlas_is_current(&out, &font_path) {
        return;
    }

    let ttf = fs::read(&font_path).unwrap_or_else(|e| {
        panic!(
            "\n\nFluOS console font not found at `{font_path}` ({e}).\n\
             Install FiraCode Nerd Font Mono there, or set FLUOS_FONT to a .ttf path:\n\
             \n    FLUOS_FONT=/path/to/font.ttf cargo xtask build\n"
        )
    });

    let font = fontdue::Font::from_bytes(ttf.as_slice(), fontdue::FontSettings::default())
        .expect("fontdue could not parse the font");

    let px: f32 = env::var("FLUOS_FONT_PX").ok().and_then(|v| v.parse().ok()).unwrap_or(16.0);
    let line = font
        .horizontal_line_metrics(px)
        .expect("font lacks horizontal line metrics");

    // Cell geometry: width from a representative advance, height from the font's
    // ascent-to-descent span. Both are exported so the console agrees with us.
    let cell_w = font.metrics('M', px).advance_width.ceil().max(1.0) as usize;
    let cell_h = (line.ascent - line.descent).ceil().max(1.0) as usize;
    let baseline = line.ascent.round() as i32;
    let glyph_bytes = cell_w * cell_h;

    let mut codepoints: Vec<u32> = Vec::new();
    let mut alpha: Vec<u8> = Vec::new();

    for &(start, end) in RANGES {
        for cp in start..=end {
            let Some(ch) = char::from_u32(cp) else { continue };
            if font.lookup_glyph_index(ch) == 0 {
                continue; // .notdef — not in this font
            }
            let (metrics, bitmap) = font.rasterize(ch, px);
            let mut cell = vec![0u8; glyph_bytes];
            // Top-left of the glyph bitmap within the cell.
            let x0 = metrics.xmin;
            let y0 = baseline - metrics.height as i32 - metrics.ymin;
            for gy in 0..metrics.height {
                for gx in 0..metrics.width {
                    let cx = x0 + gx as i32;
                    let cy = y0 + gy as i32;
                    if cx >= 0 && (cx as usize) < cell_w && cy >= 0 && (cy as usize) < cell_h {
                        cell[cy as usize * cell_w + cx as usize] = bitmap[gy * metrics.width + gx];
                    }
                }
            }
            codepoints.push(cp);
            alpha.extend_from_slice(&cell);
        }
    }

    // Codepoints are already ascending (ranges are sorted and disjoint); store
    // them little-endian for a direct binary search at runtime.
    let mut index = Vec::with_capacity(codepoints.len() * 4);
    for cp in &codepoints {
        index.extend_from_slice(&cp.to_le_bytes());
    }
    fs::write(out.join("font_alpha.bin"), &alpha).expect("write font_alpha.bin");
    fs::write(out.join("font_index.bin"), &index).expect("write font_index.bin");

    let atlas_rs = format!(
        "// Generated by build.rs — do not edit.\n\
         pub const CELL_W: usize = {cell_w};\n\
         pub const CELL_H: usize = {cell_h};\n\
         pub const GLYPH_BYTES: usize = {glyph_bytes};\n\
         pub const GLYPH_COUNT: usize = {count};\n\
         pub static ALPHA: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/font_alpha.bin\"));\n\
         pub static INDEX: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/font_index.bin\"));\n",
        count = codepoints.len(),
    );
    fs::write(out.join("font_atlas.rs"), atlas_rs).expect("write font_atlas.rs");

    println!(
        "cargo:warning=font atlas: {} glyphs, {}x{} px cell, {} KiB",
        codepoints.len(),
        cell_w,
        cell_h,
        alpha.len() / 1024,
    );
}
