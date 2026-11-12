//! The VT/xterm escape-sequence parser driving a [`Grid`].
//!
//! A compact state machine decodes UTF-8 text, C0 control codes, CSI sequences
//! (cursor motion, erase, scroll region, SGR), and DEC private modes (cursor
//! visibility, alternate screen). OSC strings (window title) are recognised and
//! discarded. Anything unrecognised is skipped without corrupting later input,
//! which matters because real programs emit sequences we do not implement yet.

use crate::cell::Pen;
use crate::color::{Color, Rgb};
use crate::grid::Grid;

/// Maximum CSI parameters we retain; xterm's own limit is 16.
const MAX_PARAMS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    CsiParam,
    /// Collecting an OSC string, waiting for BEL or ST.
    OscString,
    /// Saw ESC while in an OSC string; the next byte should be `\` (ST).
    OscEsc,
    /// Saw ESC `(`/`)`/etc.; consume one charset-designation byte and ignore.
    CharsetDesignate,
}

/// Numeric CSI parameters, parsed without allocation.
struct Params {
    values: [u16; MAX_PARAMS],
    len: usize,
    /// Whether the current parameter slot has received any digit.
    building: bool,
}

impl Params {
    fn new() -> Self {
        Self { values: [0; MAX_PARAMS], len: 0, building: false }
    }

    fn clear(&mut self) {
        self.values = [0; MAX_PARAMS];
        self.len = 0;
        self.building = false;
    }

    fn push_digit(&mut self, d: u8) {
        if self.len >= MAX_PARAMS {
            return;
        }
        let v = &mut self.values[self.len];
        *v = v.saturating_mul(10).saturating_add(u16::from(d));
        self.building = true;
    }

    fn next_param(&mut self) {
        if self.len < MAX_PARAMS {
            self.len += 1;
        }
    }

    /// Number of parameters actually present.
    fn count(&self) -> usize {
        self.len + usize::from(self.building)
    }

    /// Parameter `i`, or 0 if absent.
    fn get(&self, i: usize) -> u16 {
        *self.values.get(i).unwrap_or(&0)
    }

    /// Parameter `i` for a movement/count argument: absent or 0 means 1.
    fn get_or_one(&self, i: usize) -> u16 {
        match self.get(i) {
            0 => 1,
            n => n,
        }
    }
}

/// Incremental UTF-8 decoder: fed one byte at a time, yields a `char` when a
/// full scalar value is assembled (or U+FFFD on malformed input).
struct Utf8 {
    acc: u32,
    remaining: u8,
}

impl Utf8 {
    const REPLACEMENT: char = '\u{FFFD}';

    fn new() -> Self {
        Self { acc: 0, remaining: 0 }
    }

    /// Feeds a byte known to be text (>= 0x20). Returns a decoded char when a
    /// sequence completes.
    fn feed(&mut self, byte: u8) -> Option<char> {
        if self.remaining == 0 {
            match byte {
                0x00..=0x7f => Some(byte as char),
                0xc0..=0xdf => {
                    self.acc = u32::from(byte & 0x1f);
                    self.remaining = 1;
                    None
                }
                0xe0..=0xef => {
                    self.acc = u32::from(byte & 0x0f);
                    self.remaining = 2;
                    None
                }
                0xf0..=0xf7 => {
                    self.acc = u32::from(byte & 0x07);
                    self.remaining = 3;
                    None
                }
                // Stray continuation or invalid lead byte.
                _ => Some(Self::REPLACEMENT),
            }
        } else if (0x80..=0xbf).contains(&byte) {
            self.acc = (self.acc << 6) | u32::from(byte & 0x3f);
            self.remaining -= 1;
            if self.remaining == 0 {
                Some(char::from_u32(self.acc).unwrap_or(Self::REPLACEMENT))
            } else {
                None
            }
        } else {
            // Truncated sequence interrupted by a non-continuation byte: emit
            // the replacement and reprocess nothing (the byte is dropped).
            self.remaining = 0;
            Some(Self::REPLACEMENT)
        }
    }
}

/// A terminal: a primary and alternate [`Grid`], plus the parser state that
/// feeds them.
pub struct Terminal {
    primary: Grid,
    alt: Grid,
    on_alt: bool,
    state: State,
    params: Params,
    private: bool,
    utf8: Utf8,
    saved_cursor: (usize, usize),
    saved_pen: Pen,
    cursor_visible: bool,
}

impl Terminal {
    /// Creates a `rows × cols` terminal.
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            primary: Grid::new(rows, cols),
            alt: Grid::new(rows, cols),
            on_alt: false,
            state: State::Ground,
            params: Params::new(),
            private: false,
            utf8: Utf8::new(),
            saved_cursor: (0, 0),
            saved_pen: Pen::default(),
            cursor_visible: true,
        }
    }

    /// The grid currently shown (primary or alternate).
    pub fn grid(&self) -> &Grid {
        if self.on_alt { &self.alt } else { &self.primary }
    }

    /// Mutable access to the active grid (used by the console to clear damage).
    pub fn grid_mut(&mut self) -> &mut Grid {
        if self.on_alt { &mut self.alt } else { &mut self.primary }
    }

    pub fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    fn active(&mut self) -> &mut Grid {
        if self.on_alt { &mut self.alt } else { &mut self.primary }
    }

    /// Feeds a run of bytes through the parser.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.advance(b);
        }
    }

    /// Feeds one byte through the state machine.
    pub fn advance(&mut self, byte: u8) {
        match self.state {
            State::Ground => self.ground(byte),
            State::Escape => self.escape(byte),
            State::CsiParam => self.csi(byte),
            State::OscString => self.osc(byte),
            State::OscEsc => {
                // Only ST (`ESC \`) legitimately ends the string; anything else
                // we treat as the end too, to stay robust.
                self.state = State::Ground;
            }
            State::CharsetDesignate => self.state = State::Ground,
        }
    }

    fn ground(&mut self, byte: u8) {
        match byte {
            0x1b => self.state = State::Escape,
            0x08 => self.active().backspace(),
            0x09 => self.active().tab(),
            0x0a | 0x0b | 0x0c => self.active().line_feed(),
            0x0d => self.active().carriage_return(),
            // Other C0 controls (BEL, etc.) are ignored.
            0x00..=0x1f => {}
            // Text byte: run it through the UTF-8 decoder.
            _ => {
                if let Some(ch) = self.utf8.feed(byte) {
                    self.active().print(ch);
                }
            }
        }
    }

    fn escape(&mut self, byte: u8) {
        match byte {
            b'[' => {
                self.params.clear();
                self.private = false;
                self.state = State::CsiParam;
            }
            b']' => self.state = State::OscString,
            b'7' => {
                self.save_cursor();
                self.state = State::Ground;
            }
            b'8' => {
                self.restore_cursor();
                self.state = State::Ground;
            }
            b'c' => {
                self.full_reset();
                self.state = State::Ground;
            }
            b'D' => {
                self.active().line_feed();
                self.state = State::Ground;
            }
            b'M' => {
                // Reverse index: scroll down when at the top of the region.
                self.active().scroll_down(1);
                self.state = State::Ground;
            }
            b'E' => {
                let g = self.active();
                g.carriage_return();
                g.line_feed();
                self.state = State::Ground;
            }
            b'(' | b')' | b'*' | b'+' => self.state = State::CharsetDesignate,
            _ => self.state = State::Ground,
        }
    }

    fn csi(&mut self, byte: u8) {
        match byte {
            b'0'..=b'9' => self.params.push_digit(byte - b'0'),
            b';' => self.params.next_param(),
            b'?' => self.private = true,
            // Intermediate bytes (e.g. space) — ignored, sequence continues.
            0x20..=0x2f => {}
            0x40..=0x7e => {
                self.dispatch_csi(byte);
                self.state = State::Ground;
            }
            _ => self.state = State::Ground,
        }
    }

    fn osc(&mut self, byte: u8) {
        match byte {
            0x07 => self.state = State::Ground, // BEL terminates
            0x1b => self.state = State::OscEsc, // maybe ST
            _ => {}                             // title bytes discarded
        }
    }

    fn dispatch_csi(&mut self, final_byte: u8) {
        let p0 = self.params.get_or_one(0);
        match final_byte {
            b'A' => self.active().move_up(p0 as usize),
            b'B' => self.active().move_down(p0 as usize),
            b'C' => self.active().move_right(p0 as usize),
            b'D' => self.active().move_left(p0 as usize),
            b'E' => {
                let g = self.active();
                g.carriage_return();
                g.move_down(p0 as usize);
            }
            b'F' => {
                let g = self.active();
                g.carriage_return();
                g.move_up(p0 as usize);
            }
            b'G' => {
                let (row, _) = self.active().cursor();
                self.active().move_to(row, p0 as usize - 1);
            }
            b'd' => {
                let (_, col) = self.active().cursor();
                self.active().move_to(p0 as usize - 1, col);
            }
            b'H' | b'f' => {
                let row = self.params.get_or_one(0) as usize - 1;
                let col = self.params.get_or_one(1) as usize - 1;
                self.active().move_to(row, col);
            }
            b'J' => {
                let m = self.params.get(0);
                self.active().erase_display(m);
            }
            b'K' => {
                let m = self.params.get(0);
                self.active().erase_line(m);
            }
            b'S' => self.active().scroll_up(p0 as usize),
            b'T' => self.active().scroll_down(p0 as usize),
            b'r' => {
                let top = self.params.get_or_one(0) as usize - 1;
                let bottom = self.params.get_or_one(1) as usize - 1;
                self.active().set_scroll_region(top, bottom);
            }
            b'm' => self.apply_sgr(),
            b'h' if self.private => self.set_mode(true),
            b'l' if self.private => self.set_mode(false),
            b's' => self.save_cursor(),
            b'u' => self.restore_cursor(),
            // Unimplemented finals (SM/RM, DSR, insert/delete) are ignored.
            _ => {}
        }
    }

    // --- cursor save/restore & reset -------------------------------------

    fn save_cursor(&mut self) {
        self.saved_cursor = self.active().cursor();
        self.saved_pen = self.active().pen;
    }

    fn restore_cursor(&mut self) {
        let (row, col) = self.saved_cursor;
        let pen = self.saved_pen;
        let g = self.active();
        g.move_to(row, col);
        g.pen = pen;
    }

    fn full_reset(&mut self) {
        self.primary.pen = Pen::default();
        self.alt.pen = Pen::default();
        self.primary.reset();
        self.alt.reset();
        self.on_alt = false;
        self.cursor_visible = true;
        self.saved_cursor = (0, 0);
        self.saved_pen = Pen::default();
    }

    // --- DEC private modes ------------------------------------------------

    fn set_mode(&mut self, enable: bool) {
        for i in 0..self.params.count().max(1) {
            match self.params.get(i) {
                25 => self.cursor_visible = enable,
                47 | 1047 | 1049 => self.switch_alt(enable),
                _ => {}
            }
        }
    }

    fn switch_alt(&mut self, to_alt: bool) {
        if to_alt == self.on_alt {
            return;
        }
        if to_alt {
            self.save_cursor();
            self.alt.reset();
            self.on_alt = true;
        } else {
            self.on_alt = false;
            self.restore_cursor();
        }
        // The whole screen changed; force a full repaint.
        self.active().mark_all_dirty();
    }

    // --- SGR --------------------------------------------------------------

    fn apply_sgr(&mut self) {
        if self.params.count() == 0 {
            self.active().pen = Pen::default();
            return;
        }
        let mut i = 0;
        while i < self.params.count() {
            let code = self.params.get(i);
            match code {
                0 => self.active().pen = Pen::default(),
                1 => self.active().pen.flags.bold = true,
                3 => self.active().pen.flags.italic = true,
                4 => self.active().pen.flags.underline = true,
                7 => self.active().pen.flags.reverse = true,
                22 => self.active().pen.flags.bold = false,
                23 => self.active().pen.flags.italic = false,
                24 => self.active().pen.flags.underline = false,
                27 => self.active().pen.flags.reverse = false,
                30..=37 => self.active().pen.fg = Color::Indexed((code - 30) as u8),
                39 => self.active().pen.fg = Color::Default,
                40..=47 => self.active().pen.bg = Color::Indexed((code - 40) as u8),
                49 => self.active().pen.bg = Color::Default,
                90..=97 => self.active().pen.fg = Color::Indexed((code - 90 + 8) as u8),
                100..=107 => self.active().pen.bg = Color::Indexed((code - 100 + 8) as u8),
                38 => {
                    if let Some(c) = self.parse_extended_color(&mut i) {
                        self.active().pen.fg = c;
                    }
                }
                48 => {
                    if let Some(c) = self.parse_extended_color(&mut i) {
                        self.active().pen.bg = c;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// Parses `5;n` (indexed) or `2;r;g;b` (truecolor) following a 38/48 at
    /// index `*i`, advancing `*i` past the consumed sub-parameters.
    fn parse_extended_color(&self, i: &mut usize) -> Option<Color> {
        match self.params.get(*i + 1) {
            5 => {
                let idx = self.params.get(*i + 2) as u8;
                *i += 2;
                Some(Color::Indexed(idx))
            }
            2 => {
                let r = self.params.get(*i + 2) as u8;
                let g = self.params.get(*i + 3) as u8;
                let b = self.params.get(*i + 4) as u8;
                *i += 4;
                Some(Color::Rgb(Rgb::new(r, g, b)))
            }
            _ => None,
        }
    }
}
