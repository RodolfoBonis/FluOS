//! Terminal colors: the 16 ANSI names, the 256-color cube, and 24-bit truecolor.

/// A 24-bit RGB triple.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Packs into `0x00RRGGBB`, the format the framebuffer console blits.
    pub const fn pack(self) -> u32 {
        (self.r as u32) << 16 | (self.g as u32) << 8 | self.b as u32
    }
}

/// A character cell's foreground or background color.
///
/// `Default` defers to the console's configured default, which lets a themed
/// console pick its own base colors without the grid hard-coding them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Color {
    #[default]
    Default,
    /// Index into the 256-color palette (0–15 named, 16–231 cube, 232–255 gray).
    Indexed(u8),
    /// 24-bit truecolor.
    Rgb(Rgb),
}

/// The classic 16 ANSI colors (the VGA-ish xterm defaults). Indices 0–7 are the
/// normal set, 8–15 the bright set.
pub const ANSI_16: [Rgb; 16] = [
    Rgb::new(0x00, 0x00, 0x00), // 0 black
    Rgb::new(0xcd, 0x00, 0x00), // 1 red
    Rgb::new(0x00, 0xcd, 0x00), // 2 green
    Rgb::new(0xcd, 0xcd, 0x00), // 3 yellow
    Rgb::new(0x00, 0x00, 0xee), // 4 blue
    Rgb::new(0xcd, 0x00, 0xcd), // 5 magenta
    Rgb::new(0x00, 0xcd, 0xcd), // 6 cyan
    Rgb::new(0xe5, 0xe5, 0xe5), // 7 white
    Rgb::new(0x7f, 0x7f, 0x7f), // 8 bright black
    Rgb::new(0xff, 0x00, 0x00), // 9 bright red
    Rgb::new(0x00, 0xff, 0x00), // 10 bright green
    Rgb::new(0xff, 0xff, 0x00), // 11 bright yellow
    Rgb::new(0x5c, 0x5c, 0xff), // 12 bright blue
    Rgb::new(0xff, 0x00, 0xff), // 13 bright magenta
    Rgb::new(0x00, 0xff, 0xff), // 14 bright cyan
    Rgb::new(0xff, 0xff, 0xff), // 15 bright white
];

/// Resolves any [`Color`] to concrete RGB, given the console's default fg/bg.
///
/// The 256-color palette is computed on the fly: 16 named + a 6×6×6 cube +
/// a 24-step grayscale ramp, exactly as xterm defines it.
pub fn resolve(color: Color, default: Rgb) -> Rgb {
    match color {
        Color::Default => default,
        Color::Rgb(rgb) => rgb,
        Color::Indexed(i) => resolve_indexed(i),
    }
}

/// Maps a 0–255 palette index to RGB.
pub fn resolve_indexed(i: u8) -> Rgb {
    match i {
        0..=15 => ANSI_16[i as usize],
        16..=231 => {
            // 6×6×6 color cube. Each axis step is one of {0,95,135,175,215,255}.
            let c = i - 16;
            let steps = [0u8, 95, 135, 175, 215, 255];
            Rgb::new(
                steps[(c / 36) as usize],
                steps[((c / 6) % 6) as usize],
                steps[(c % 6) as usize],
            )
        }
        232..=255 => {
            // 24-step grayscale ramp from 8 to 238.
            let v = 8 + (i as u16 - 232) * 10;
            Rgb::new(v as u8, v as u8, v as u8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cube_corners_are_exact() {
        assert_eq!(resolve_indexed(16), Rgb::new(0, 0, 0));
        assert_eq!(resolve_indexed(231), Rgb::new(255, 255, 255));
        // Pure-red corner of the cube (index 196).
        assert_eq!(resolve_indexed(196), Rgb::new(255, 0, 0));
    }

    #[test]
    fn grayscale_ramp_endpoints() {
        assert_eq!(resolve_indexed(232), Rgb::new(8, 8, 8));
        assert_eq!(resolve_indexed(255), Rgb::new(238, 238, 238));
    }

    #[test]
    fn pack_is_rgb_order() {
        assert_eq!(Rgb::new(0x12, 0x34, 0x56).pack(), 0x0012_3456);
    }

    #[test]
    fn default_defers_to_console() {
        let base = Rgb::new(1, 2, 3);
        assert_eq!(resolve(Color::Default, base), base);
    }
}
