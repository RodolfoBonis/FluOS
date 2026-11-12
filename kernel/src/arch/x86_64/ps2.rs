//! PS/2 keyboard decoding: scancode set 1 → key bytes (US layout, modifiers).
//!
//! The i8042 controller in QEMU (and most PCs, via translation) delivers set 1:
//! a make code has the high bit clear, its matching break code sets it. An
//! `0xE0` prefix marks the extended keys (arrows, keypad Enter). We track Shift,
//! Ctrl, and Caps Lock and emit the resulting UTF-8 byte or xterm escape
//! sequence through a callback, so the caller decides where the bytes go.

/// Decoder state: the modifier flags and the pending extended-code prefix.
pub struct Keyboard {
    shift: bool,
    ctrl: bool,
    caps: bool,
    extended: bool,
}

impl Keyboard {
    pub const fn new() -> Self {
        Self { shift: false, ctrl: false, caps: false, extended: false }
    }

    /// Feeds one scancode, invoking `emit` for each output byte it produces.
    pub fn feed(&mut self, code: u8, mut emit: impl FnMut(u8)) {
        if code == 0xE0 {
            self.extended = true;
            return;
        }

        let released = code & 0x80 != 0;
        let key = code & 0x7F;

        // Modifier keys update state on both press and release.
        match key {
            0x2A | 0x36 => {
                self.shift = !released;
                self.extended = false;
                return;
            }
            0x1D => {
                self.ctrl = !released;
                self.extended = false;
                return;
            }
            0x3A => {
                if !released {
                    self.caps = !self.caps;
                }
                self.extended = false;
                return;
            }
            _ => {}
        }

        if released {
            self.extended = false;
            return;
        }

        if self.extended {
            self.extended = false;
            self.emit_extended(key, &mut emit);
            return;
        }

        self.emit_key(key, &mut emit);
    }

    /// Emits bytes for an extended (E0-prefixed) key: the arrow keys and keypad
    /// Enter.
    fn emit_extended(&self, key: u8, emit: &mut impl FnMut(u8)) {
        let seq: &[u8] = match key {
            0x48 => b"\x1b[A", // up
            0x50 => b"\x1b[B", // down
            0x4D => b"\x1b[C", // right
            0x4B => b"\x1b[D", // left
            0x1C => b"\n",     // keypad Enter
            _ => return,
        };
        seq.iter().for_each(|&b| emit(b));
    }

    /// Emits bytes for a normal key, applying Shift, Caps Lock, and Ctrl.
    fn emit_key(&self, key: u8, emit: &mut impl FnMut(u8)) {
        // Control keys first.
        match key {
            0x0E => return emit(0x08), // backspace
            0x0F => return emit(b'\t'),
            0x1C => return emit(b'\n'), // Enter
            _ => {}
        }

        let shifted = self.shift;
        let Some(base) = us_layout(key, shifted) else { return };

        // Caps Lock affects letters only.
        let ch = if self.caps && base.is_ascii_alphabetic() {
            if shifted { base.to_ascii_lowercase() } else { base.to_ascii_uppercase() }
        } else {
            base
        };

        if self.ctrl && ch.is_ascii_alphabetic() {
            // Ctrl-A..Ctrl-Z -> 0x01..0x1A.
            emit(ch.to_ascii_uppercase() - b'A' + 1);
        } else {
            emit(ch);
        }
    }
}

/// US-QWERTY scancode-set-1 map for printable keys. Returns the ASCII byte for
/// `key`, honouring `shift`.
fn us_layout(key: u8, shift: bool) -> Option<u8> {
    const UNSHIFTED: &[u8] = b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./";
    const SHIFTED: &[u8] = b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?";
    let table = if shift { SHIFTED } else { UNSHIFTED };
    if key == 0x39 {
        return Some(b' ');
    }
    let byte = *table.get(key as usize)?;
    (byte != 0).then_some(byte)
}
