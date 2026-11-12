//! A single character cell: its glyph and visual attributes.

use crate::color::Color;

/// Visual attribute flags set via SGR.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Flags {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    /// Swap foreground and background when rendered.
    pub reverse: bool,
}

/// The current "pen": the attributes applied to newly written cells.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pen {
    pub fg: Color,
    pub bg: Color,
    pub flags: Flags,
}

impl Default for Pen {
    fn default() -> Self {
        Self { fg: Color::Default, bg: Color::Default, flags: Flags::default() }
    }
}

/// One grid cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: Flags,
}

impl Cell {
    /// A blank cell carrying the given pen's colors (so an erase paints the
    /// current background, as terminals do).
    pub fn blank(pen: Pen) -> Self {
        Self { ch: ' ', fg: pen.fg, bg: pen.bg, flags: pen.flags }
    }

    /// A printed cell: glyph `ch` stamped with `pen`.
    pub fn glyph(ch: char, pen: Pen) -> Self {
        Self { ch, fg: pen.fg, bg: pen.bg, flags: pen.flags }
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self::blank(Pen::default())
    }
}
