//! Color resolution and ANSI escaping, matching the gem's Rainbow output.
//!
//! The gem maps a semantic *role* (e.g. `dir`, `read`, `file_large`) to a
//! color *name* (e.g. `dodgerblue`) via `dark_colors.yaml`/`light_colors.yaml`,
//! then Rainbow maps the name to an SGR escape. We resolve role -> name ->
//! SGR-body once at startup and cache it, producing byte-identical escapes.

use std::collections::HashMap;

use crate::tables;

/// Semantic color roles used throughout the output. Values are the YAML keys.
pub mod role {
    pub const UNRECOGNIZED_FILE: &str = "unrecognized_file";
    pub const RECOGNIZED_FILE: &str = "recognized_file";
    pub const EXECUTABLE_FILE: &str = "executable_file";
    pub const DIR: &str = "dir";
    pub const DEAD_LINK: &str = "dead_link";
    pub const LINK: &str = "link";
    pub const SOCKET: &str = "socket";
    pub const BLOCKDEV: &str = "blockdev";
    pub const CHARDEV: &str = "chardev";
    pub const WRITE: &str = "write";
    pub const READ: &str = "read";
    pub const EXEC: &str = "exec";
    pub const NO_ACCESS: &str = "no_access";
    pub const DAY_OLD: &str = "day_old";
    pub const HOUR_OLD: &str = "hour_old";
    pub const NO_MODIFIER: &str = "no_modifier";
    pub const FILE_LARGE: &str = "file_large";
    pub const FILE_MEDIUM: &str = "file_medium";
    pub const FILE_SMALL: &str = "file_small";
    pub const REPORT: &str = "report";
    pub const USER: &str = "user";
    pub const TREE: &str = "tree";
    pub const EMPTY: &str = "empty";
    #[allow(dead_code)] // part of the gem's role set; not yet surfaced
    pub const ERROR: &str = "error";
    pub const NORMAL: &str = "normal";
    pub const INODE: &str = "inode";
    pub const ADDITION: &str = "addition";
    pub const MODIFICATION: &str = "modification";
    pub const DELETION: &str = "deletion";
    pub const UNTRACKED: &str = "untracked";
    pub const UNCHANGED: &str = "unchanged";
}

/// Resolved role -> SGR escape-body map plus the global enable flag.
#[derive(Debug, Clone)]
pub struct Colors {
    enabled: bool,
    /// role -> SGR body (e.g. "38;5;39"). Absent roles render uncolored.
    codes: HashMap<String, String>,
}

impl Colors {
    /// Build from the embedded dark/light scheme, layering user overrides
    /// (role -> color-name) on top before resolving names to escapes.
    pub fn new(light: bool, enabled: bool, user_overrides: &HashMap<String, String>) -> Self {
        let base = if light {
            &tables::LIGHT_COLORS
        } else {
            &tables::DARK_COLORS
        };

        let mut names: HashMap<String, String> = HashMap::new();
        for (role, name) in base.entries() {
            names.insert((*role).to_string(), (*name).to_string());
        }
        for (role, name) in user_overrides {
            names.insert(role.clone(), name.clone());
        }

        let mut codes = HashMap::new();
        for (role, name) in names {
            if let Some(code) = tables::color_code(&name) {
                codes.insert(role, code.to_string());
            }
        }

        Colors { enabled, codes }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// SGR body for a role, if colors are enabled and the role resolves.
    pub fn code(&self, role: &str) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        self.codes.get(role).map(String::as_str)
    }

    /// Wrap `text` in a single role's color (`\e[{body}m…\e[0m`).
    pub fn paint(&self, role: &str, text: &str) -> String {
        match self.code(role) {
            Some(body) => wrap(&[body], text),
            None => text.to_string(),
        }
    }

    /// Wrap `text` with multiple SGR codes emitted as separate escapes, exactly
    /// like Rainbow chaining (e.g. `.bright.color(:lime)` -> `\e[1m\e[38;5;46m`).
    pub fn paint_codes(&self, bodies: &[&str], text: &str) -> String {
        if bodies.is_empty() {
            text.to_string()
        } else {
            wrap(bodies, text)
        }
    }

    /// Entry painter: optional bright (executable) prefix then the file color.
    pub fn paint_entry(&self, role: &str, bright: bool, text: &str) -> String {
        let mut bodies: Vec<&str> = Vec::new();
        if bright && self.enabled {
            bodies.push("1");
        }
        if let Some(body) = self.code(role) {
            bodies.push(body);
        }
        self.paint_codes(&bodies, text)
    }
}

/// Emit one `\e[{body}m` per code, the text, then a single `\e[0m` reset.
fn wrap(bodies: &[&str], text: &str) -> String {
    let mut s = String::with_capacity(text.len() + bodies.len() * 8 + 4);
    for b in bodies {
        s.push_str("\x1b[");
        s.push_str(b);
        s.push('m');
    }
    s.push_str(text);
    s.push_str("\x1b[0m");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn dark_scheme_resolves_to_rainbow_escapes() {
        let c = Colors::new(false, true, &HashMap::new());
        // dir=dodgerblue -> 38;5;39 ; recognized_file=yellow -> base 33.
        assert_eq!(c.paint(role::DIR, "x"), "\x1b[38;5;39mx\x1b[0m");
        assert_eq!(c.paint(role::RECOGNIZED_FILE, "x"), "\x1b[33mx\x1b[0m");
    }

    #[test]
    fn disabled_colors_are_plain() {
        let c = Colors::new(false, false, &HashMap::new());
        assert_eq!(c.paint(role::DIR, "x"), "x");
    }

    #[test]
    fn bright_executable_emits_both_codes() {
        let c = Colors::new(false, true, &HashMap::new());
        // executable_file=lime -> 38;5;46 ; bright prefixes \e[1m.
        assert_eq!(
            c.paint_entry(role::EXECUTABLE_FILE, true, "x"),
            "\x1b[1m\x1b[38;5;46mx\x1b[0m"
        );
    }

    #[test]
    fn user_override_changes_color() {
        let mut ov = HashMap::new();
        ov.insert("dir".to_string(), "red".to_string());
        let c = Colors::new(false, true, &ov);
        assert_eq!(c.paint(role::DIR, "x"), "\x1b[31mx\x1b[0m");
    }

    #[test]
    fn light_scheme_differs() {
        let c = Colors::new(true, true, &HashMap::new());
        // light dir=navyblue -> 38;5;19.
        assert_eq!(c.paint(role::DIR, "x"), "\x1b[38;5;19mx\x1b[0m");
    }
}
