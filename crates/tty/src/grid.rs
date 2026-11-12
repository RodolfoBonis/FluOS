//! The cell grid: screen contents, cursor, scroll region, and damage tracking.
//!
//! The grid knows nothing about escape sequences — [`crate::parser`] translates
//! those into the method calls here. Every mutation records which cells changed
//! in a dirty map so the framebuffer console can repaint only what moved, which
//! is what keeps rendering cheap.

use crate::cell::{Cell, Pen};
use alloc::vec;
use alloc::vec::Vec;

/// A rectangular grid of character cells.
pub struct Grid {
    rows: usize,
    cols: usize,
    cells: Vec<Cell>,
    dirty: Vec<bool>,
    cursor_row: usize,
    cursor_col: usize,
    /// Top/bottom (inclusive, 0-based) of the DEC scrolling region.
    scroll_top: usize,
    scroll_bottom: usize,
    /// Deferred wrap: set after writing the last column, so the *next* glyph
    /// wraps. Matches how real terminals avoid an early, spurious scroll.
    pending_wrap: bool,
    /// The pen applied to newly written and erased cells.
    pub pen: Pen,
}

impl Grid {
    /// Builds a `rows × cols` blank grid. Both dimensions must be non-zero.
    pub fn new(rows: usize, cols: usize) -> Self {
        assert!(rows > 0 && cols > 0, "grid must be non-empty");
        Self {
            rows,
            cols,
            cells: vec![Cell::default(); rows * cols],
            dirty: vec![true; rows * cols],
            cursor_row: 0,
            cursor_col: 0,
            scroll_top: 0,
            scroll_bottom: rows - 1,
            pending_wrap: false,
            pen: Pen::default(),
        }
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.cursor_row, self.cursor_col)
    }

    /// The cell at `(row, col)`; panics if out of bounds (a caller bug).
    pub fn cell(&self, row: usize, col: usize) -> &Cell {
        &self.cells[row * self.cols + col]
    }

    pub fn is_dirty(&self, row: usize, col: usize) -> bool {
        self.dirty[row * self.cols + col]
    }

    /// Marks every cell clean after the console has blitted a frame.
    pub fn clear_damage(&mut self) {
        self.dirty.iter_mut().for_each(|d| *d = false);
    }

    /// Marks a single cell dirty so the console repaints it (used for the
    /// cursor, which moves without otherwise changing cell contents).
    pub fn mark_dirty(&mut self, row: usize, col: usize) {
        if row < self.rows && col < self.cols {
            let i = self.idx(row, col);
            self.dirty[i] = true;
        }
    }

    /// Marks every cell dirty, e.g. after switching screen buffers.
    pub fn mark_all_dirty(&mut self) {
        self.dirty.iter_mut().for_each(|d| *d = true);
    }

    fn idx(&self, row: usize, col: usize) -> usize {
        row * self.cols + col
    }

    fn set(&mut self, row: usize, col: usize, cell: Cell) {
        let i = self.idx(row, col);
        self.cells[i] = cell;
        self.dirty[i] = true;
    }

    // --- cursor motion ----------------------------------------------------

    /// Moves the cursor to `(row, col)`, clamping to the grid.
    pub fn move_to(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(self.rows - 1);
        self.cursor_col = col.min(self.cols - 1);
        self.pending_wrap = false;
    }

    pub fn move_up(&mut self, n: usize) {
        self.cursor_row = self.cursor_row.saturating_sub(n.max(1));
        self.pending_wrap = false;
    }

    pub fn move_down(&mut self, n: usize) {
        self.cursor_row = (self.cursor_row + n.max(1)).min(self.rows - 1);
        self.pending_wrap = false;
    }

    pub fn move_left(&mut self, n: usize) {
        self.cursor_col = self.cursor_col.saturating_sub(n.max(1));
        self.pending_wrap = false;
    }

    pub fn move_right(&mut self, n: usize) {
        self.cursor_col = (self.cursor_col + n.max(1)).min(self.cols - 1);
        self.pending_wrap = false;
    }

    pub fn carriage_return(&mut self) {
        self.cursor_col = 0;
        self.pending_wrap = false;
    }

    pub fn backspace(&mut self) {
        self.cursor_col = self.cursor_col.saturating_sub(1);
        self.pending_wrap = false;
    }

    pub fn tab(&mut self) {
        // Advance to the next 8-column tab stop, clamped to the last column.
        let next = ((self.cursor_col / 8) + 1) * 8;
        self.cursor_col = next.min(self.cols - 1);
        self.pending_wrap = false;
    }

    /// Line feed: move down one row, scrolling the region if already at its
    /// bottom.
    pub fn line_feed(&mut self) {
        self.pending_wrap = false;
        if self.cursor_row == self.scroll_bottom {
            self.scroll_up(1);
        } else if self.cursor_row + 1 < self.rows {
            self.cursor_row += 1;
        }
    }

    // --- printing ---------------------------------------------------------

    /// Writes `ch` at the cursor with the current pen, handling deferred wrap
    /// and advancing the cursor.
    pub fn print(&mut self, ch: char) {
        if self.pending_wrap {
            self.carriage_return();
            self.line_feed();
        }
        let (row, col) = (self.cursor_row, self.cursor_col);
        self.set(row, col, Cell::glyph(ch, self.pen));
        if col + 1 < self.cols {
            self.cursor_col += 1;
        } else {
            self.pending_wrap = true;
        }
    }

    // --- erasing ----------------------------------------------------------

    /// Erases part of a row. `mode`: 0 cursor→end, 1 start→cursor, 2 whole row.
    pub fn erase_line(&mut self, mode: u16) {
        let row = self.cursor_row;
        let (lo, hi) = match mode {
            1 => (0, self.cursor_col + 1),
            2 => (0, self.cols),
            _ => (self.cursor_col, self.cols),
        };
        let blank = Cell::blank(self.pen);
        for col in lo..hi {
            self.set(row, col, blank);
        }
    }

    /// Erases part of the screen. `mode`: 0 cursor→end, 1 start→cursor,
    /// 2/3 whole screen.
    pub fn erase_display(&mut self, mode: u16) {
        let blank = Cell::blank(self.pen);
        let cursor = self.idx(self.cursor_row, self.cursor_col);
        let (lo, hi) = match mode {
            1 => (0, cursor + 1),
            2 | 3 => (0, self.cells.len()),
            _ => (cursor, self.cells.len()),
        };
        for i in lo..hi {
            self.cells[i] = blank;
            self.dirty[i] = true;
        }
    }

    // --- scrolling --------------------------------------------------------

    /// Sets the scroll region to the inclusive 0-based rows `[top, bottom]` and
    /// homes the cursor, as DECSTBM specifies.
    pub fn set_scroll_region(&mut self, top: usize, bottom: usize) {
        let bottom = bottom.min(self.rows - 1);
        if top < bottom {
            self.scroll_top = top;
            self.scroll_bottom = bottom;
        } else {
            // An invalid region resets to the full screen.
            self.scroll_top = 0;
            self.scroll_bottom = self.rows - 1;
        }
        self.move_to(0, 0);
    }

    /// Scrolls the region up by `n` rows, blanking the newly exposed bottom.
    pub fn scroll_up(&mut self, n: usize) {
        let n = n.max(1).min(self.scroll_bottom - self.scroll_top + 1);
        let blank = Cell::blank(self.pen);
        for row in self.scroll_top..=self.scroll_bottom {
            for col in 0..self.cols {
                let cell = if row + n <= self.scroll_bottom {
                    self.cells[self.idx(row + n, col)]
                } else {
                    blank
                };
                self.set(row, col, cell);
            }
        }
    }

    /// Scrolls the region down by `n` rows, blanking the newly exposed top.
    pub fn scroll_down(&mut self, n: usize) {
        let n = n.max(1).min(self.scroll_bottom - self.scroll_top + 1);
        let blank = Cell::blank(self.pen);
        for row in (self.scroll_top..=self.scroll_bottom).rev() {
            for col in 0..self.cols {
                let cell = if row >= self.scroll_top + n {
                    self.cells[self.idx(row - n, col)]
                } else {
                    blank
                };
                self.set(row, col, cell);
            }
        }
    }

    /// Clears the whole grid and homes the cursor.
    pub fn reset(&mut self) {
        let blank = Cell::blank(self.pen);
        self.cells.iter_mut().for_each(|c| *c = blank);
        self.mark_all_dirty();
        self.cursor_row = 0;
        self.cursor_col = 0;
        self.scroll_top = 0;
        self.scroll_bottom = self.rows - 1;
        self.pending_wrap = false;
    }
}
