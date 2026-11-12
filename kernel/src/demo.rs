//! End-of-boot demo: a mock starship powerline prompt in the user's palette,
//! rendered on the framebuffer console with Nerd Font glyphs.

use crate::console;
use alloc::format;
use alloc::string::String;

/// The user's starship palette (`starship.toml`).
const PURPLE: (u8, u8, u8) = (0x5D, 0x34, 0x99);
const PINK: (u8, u8, u8) = (0xDA, 0x62, 0x7D);
const ORANGE: (u8, u8, u8) = (0xFC, 0xA1, 0x7D);
const BLUE: (u8, u8, u8) = (0x86, 0xBB, 0xD8);
/// Dark text drawn on the light segment backgrounds.
const TEXT: (u8, u8, u8) = (0x1A, 0x1B, 0x26);

/// Nerd Font powerline right separator.
const SEP: char = '\u{E0B0}';

fn fg(c: (u8, u8, u8)) -> String {
    format!("\x1b[38;2;{};{};{}m", c.0, c.1, c.2)
}

fn bg(c: (u8, u8, u8)) -> String {
    format!("\x1b[48;2;{};{};{}m", c.0, c.1, c.2)
}

/// Prints the mock prompt. The segments mirror a typical starship layout:
/// an OS glyph, the working directory, and the git branch, joined by powerline
/// separators, followed by the character prompt on the next line.
pub fn starship_prompt() {
    let mut s = String::new();

    // Segment 1: OS / penguin on purple.
    s.push_str(&bg(PURPLE));
    s.push_str(&fg(TEXT));
    s.push_str(" \u{F17C} fluos ");

    // Separator purple -> pink, then directory segment.
    s.push_str(&fg(PURPLE));
    s.push_str(&bg(PINK));
    s.push(SEP);
    s.push_str(&fg(TEXT));
    s.push_str(" \u{F07C} ~/FluOs ");

    // Separator pink -> orange, then git branch segment.
    s.push_str(&fg(PINK));
    s.push_str(&bg(ORANGE));
    s.push(SEP);
    s.push_str(&fg(TEXT));
    s.push_str(" \u{E0A0} main ");

    // Tail separator orange -> default background.
    s.push_str("\x1b[0m");
    s.push_str(&fg(ORANGE));
    s.push(SEP);
    s.push_str("\x1b[0m");

    // Second line: the character prompt arrow in blue.
    s.push_str("\r\n");
    s.push_str(&fg(BLUE));
    s.push_str("\u{276F} ");
    s.push_str("\x1b[0m");

    console::write_str(&s);
}

/// Interactive loop: bring up APIC + keyboard interrupts and echo typed keys to
/// the console. Only reached on a real (non-test) boot, after the prompt is on
/// screen.
pub fn input_echo_loop() -> ! {
    use crate::arch::x86_64::{apic, input};
    use x86_64::instructions::{hlt, interrupts};

    apic::drain_ps2();
    interrupts::enable();
    crate::log::info!("keyboard ready — type to echo");

    loop {
        // Pop with interrupts disabled so the IRQ handler and this consumer
        // never deadlock on the ring's spin lock; echo with them back on.
        match interrupts::without_interrupts(input::pop) {
            Some(b) => echo_byte(b),
            None => hlt(),
        }
    }
}

/// Echoes one input byte to the console, turning a backspace into a visible
/// erase.
fn echo_byte(b: u8) {
    match b {
        0x08 => console::write_str("\u{8} \u{8}"),
        _ => {
            let buf = [b];
            if let Ok(s) = core::str::from_utf8(&buf) {
                console::write_str(s);
            }
        }
    }
}
