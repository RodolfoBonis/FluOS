//! Host tests for the terminal core, including real starship prompt sequences.

use crate::color::Color;
use crate::color::Rgb;
use crate::parser::Terminal;

/// Builds a terminal of the given size and feeds it `input`.
fn run(rows: usize, cols: usize, input: &[u8]) -> Terminal {
    let mut t = Terminal::new(rows, cols);
    t.write_bytes(input);
    t
}

/// Collects a row's glyphs into a trimmed string.
fn row(t: &Terminal, r: usize) -> String {
    let g = t.grid();
    (0..g.cols())
        .map(|c| g.cell(r, c).ch)
        .collect::<String>()
        .trim_end()
        .to_string()
}

#[test]
fn plain_text_prints_and_advances() {
    let t = run(5, 20, b"hello");
    assert_eq!(row(&t, 0), "hello");
    assert_eq!(t.grid().cursor(), (0, 5));
}

#[test]
fn utf8_portuguese_accents_decode() {
    let t = run(5, 20, "ação coração".as_bytes());
    assert_eq!(row(&t, 0), "ação coração");
    // Each accented character occupies exactly one cell.
    assert_eq!(t.grid().cell(0, 1).ch, 'ç');
    assert_eq!(t.grid().cell(0, 2).ch, 'ã');
}

#[test]
fn invalid_utf8_becomes_replacement() {
    // Lone continuation byte, then valid text.
    let t = run(5, 20, &[0x80, b'o', b'k']);
    assert_eq!(t.grid().cell(0, 0).ch, '\u{FFFD}');
    assert_eq!(t.grid().cell(0, 1).ch, 'o');
}

#[test]
fn carriage_return_and_line_feed() {
    let t = run(5, 20, b"abc\r\ndef");
    assert_eq!(row(&t, 0), "abc");
    assert_eq!(row(&t, 1), "def");
}

#[test]
fn backspace_and_tab() {
    let t = run(5, 20, b"abc\x08X");
    assert_eq!(row(&t, 0), "abX");
    let t = run(5, 20, b"a\tb");
    assert_eq!(t.grid().cell(0, 8).ch, 'b');
}

#[test]
fn line_wrap_defers_to_next_glyph() {
    // Width 3: "abc" fills the row, "d" wraps to the next line.
    let t = run(5, 3, b"abcd");
    assert_eq!(row(&t, 0), "abc");
    assert_eq!(row(&t, 1), "d");
}

#[test]
fn cup_positions_cursor_one_based() {
    let t = run(10, 20, b"\x1b[3;5Hx");
    // Row 3, col 5 (1-based) => (2, 4) 0-based; the glyph lands there.
    assert_eq!(t.grid().cell(2, 4).ch, 'x');
}

#[test]
fn cursor_movement_csi() {
    let t = run(10, 20, b"\x1b[5;5H\x1b[2A\x1b[3CZ");
    // Start (4,4), up 2 => row 2, right 3 => col 7.
    assert_eq!(t.grid().cell(2, 7).ch, 'Z');
}

#[test]
fn erase_display_and_line() {
    let mut t = run(5, 10, b"hello\r\nworld");
    t.write_bytes(b"\x1b[1;1H\x1b[2J");
    assert_eq!(row(&t, 0), "");
    assert_eq!(row(&t, 1), "");

    let mut t = run(5, 10, b"hello");
    t.write_bytes(b"\x1b[1;3H\x1b[0K"); // erase from col 3 to end
    assert_eq!(row(&t, 0), "he");
}

#[test]
fn scroll_region_limits_line_feed() {
    // Scroll region rows 2..4 (1-based). Fill then force a scroll.
    let mut t = Terminal::new(5, 10);
    t.write_bytes(b"\x1b[2;4r"); // DECSTBM -> cursor homes to (0,0)
    t.write_bytes(b"top\r\n");
    // Move into the region bottom and line-feed to scroll only rows 2..4.
    t.write_bytes(b"\x1b[4;1HA\r\n");
    t.write_bytes(b"\x1b[4;1HB");
    // Row 0 (outside region) keeps "top".
    assert_eq!(row(&t, 0), "top");
}

#[test]
fn sgr_basic_colors_and_attributes() {
    let t = run(5, 20, b"\x1b[31;1;4mX\x1b[0mY");
    let x = t.grid().cell(0, 0);
    assert_eq!(x.fg, Color::Indexed(1));
    assert!(x.flags.bold);
    assert!(x.flags.underline);
    let y = t.grid().cell(0, 1);
    assert_eq!(y.fg, Color::Default);
    assert!(!y.flags.bold);
}

#[test]
fn sgr_bright_colors_and_background() {
    let t = run(5, 20, b"\x1b[92;101mX");
    let x = t.grid().cell(0, 0);
    assert_eq!(x.fg, Color::Indexed(10)); // bright green
    assert_eq!(x.bg, Color::Indexed(9)); // bright red bg
}

#[test]
fn sgr_256_color() {
    let t = run(5, 20, b"\x1b[38;5;208mX");
    assert_eq!(t.grid().cell(0, 0).fg, Color::Indexed(208));
}

#[test]
fn sgr_truecolor() {
    let t = run(5, 20, b"\x1b[38;2;10;20;30;48;2;40;50;60mX");
    let x = t.grid().cell(0, 0);
    assert_eq!(x.fg, Color::Rgb(Rgb::new(10, 20, 30)));
    assert_eq!(x.bg, Color::Rgb(Rgb::new(40, 50, 60)));
}

#[test]
fn sgr_italic_reverse_toggle() {
    let t = run(5, 20, b"\x1b[3;7mX\x1b[23;27mY");
    assert!(t.grid().cell(0, 0).flags.italic);
    assert!(t.grid().cell(0, 0).flags.reverse);
    assert!(!t.grid().cell(0, 1).flags.italic);
    assert!(!t.grid().cell(0, 1).flags.reverse);
}

#[test]
fn decset_cursor_visibility() {
    let mut t = Terminal::new(5, 10);
    assert!(t.cursor_visible());
    t.write_bytes(b"\x1b[?25l");
    assert!(!t.cursor_visible());
    t.write_bytes(b"\x1b[?25h");
    assert!(t.cursor_visible());
}

#[test]
fn alt_screen_switch_and_restore() {
    let mut t = Terminal::new(5, 10);
    t.write_bytes(b"primary");
    t.write_bytes(b"\x1b[?1049h"); // enter alt
    t.write_bytes(b"\x1b[1;1Halt");
    assert_eq!(row(&t, 0), "alt");
    t.write_bytes(b"\x1b[?1049l"); // leave alt
    assert_eq!(row(&t, 0), "primary");
}

#[test]
fn osc_title_is_ignored() {
    // OSC set-title terminated by BEL, then normal text.
    let t = run(5, 20, b"\x1b]0;my title\x07done");
    assert_eq!(row(&t, 0), "done");

    // OSC terminated by ST (ESC \).
    let t = run(5, 20, b"\x1b]2;t\x1b\\ok");
    assert_eq!(row(&t, 0), "ok");
}

#[test]
fn damage_tracking_marks_only_changed_cells() {
    let mut t = run(5, 20, b"hi");
    t.grid_mut().clear_damage();
    assert!(!t.grid().is_dirty(0, 0));
    t.write_bytes(b"\x1b[1;5HX");
    // Only the written cell is dirty.
    assert!(t.grid().is_dirty(0, 4));
    assert!(!t.grid().is_dirty(0, 0));
}

#[test]
fn scroll_marks_region_dirty() {
    let mut t = run(3, 5, b"a\r\nb\r\nc");
    t.grid_mut().clear_damage();
    t.write_bytes(b"\r\n"); // at bottom row -> scroll
    // After a scroll, the whole screen is considered damaged.
    assert!(t.grid().is_dirty(0, 0));
}

/// A realistic starship powerline prompt in the user's palette: three colored
/// segments joined by the Nerd Font left-pointing separator (U+E0B0), ending in
/// the character-prompt arrow. This mirrors what `starship` actually emits.
#[test]
fn starship_powerline_prompt() {
    const SEP: &str = "\u{E0B0}"; // powerline  separator
    // palette: #5D3499 (dir bg), #DA627D (git bg), #FCA17D (next), fg white.
    let prompt = format!(
        "\x1b[38;2;255;255;255m\x1b[48;2;93;52;153m \u{F07C} ~/proj {sep1}\
         \x1b[38;2;93;52;153m\x1b[48;2;218;98;125m{sep2}\x1b[38;2;0;0;0m  main \
         \x1b[0m\x1b[38;2;252;161;125m{sep3}\x1b[0m\r\n\u{2771} ",
        sep1 = SEP,
        sep2 = SEP,
        sep3 = SEP,
    );
    let t = run(10, 60, prompt.as_bytes());

    let line0 = row(&t, 0);
    // The directory icon, path, powerline separators, and branch all survive.
    assert!(line0.contains('\u{F07C}'), "missing folder icon in {line0:?}");
    assert!(line0.contains('\u{E0B0}'), "missing powerline separator");
    assert!(line0.contains("~/proj"));
    assert!(line0.contains("main"));

    // The first cell carries the directory segment's truecolor background.
    assert_eq!(t.grid().cell(0, 0).bg, Color::Rgb(Rgb::new(93, 52, 153)));
    assert_eq!(t.grid().cell(0, 0).fg, Color::Rgb(Rgb::new(255, 255, 255)));

    // The prompt arrow landed on the second line.
    assert_eq!(t.grid().cell(1, 0).ch, '\u{2771}');
}

#[test]
fn full_reset_clears_everything() {
    let mut t = run(5, 10, b"\x1b[31mdirty text\x1b[2;3H");
    t.write_bytes(b"\x1bc"); // RIS
    assert_eq!(row(&t, 0), "");
    assert_eq!(t.grid().cursor(), (0, 0));
    assert_eq!(t.grid().pen.fg, Color::Default);
}
