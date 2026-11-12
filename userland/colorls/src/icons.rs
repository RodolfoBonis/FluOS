//! Icon + color-role + count-group resolution, mirroring `Core#options`.
//!
//! Resolution is *extension-only* for files (just like the gem: name-based
//! YAML keys such as `dockerfile` are never reached because `File.extname`
//! returns `""` for them) and *downcased-name* for directories.

use std::collections::HashMap;

use crate::color::role;
use crate::tables;

/// Which running tally a file falls into (drives `--report`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Folders,
    Recognized,
    Unrecognized,
}

/// Outcome of resolving one entry: the glyph, its color role, and its group.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub icon: String,
    pub color_role: &'static str,
    pub group: Group,
}

/// Holds optional user overlays; falls back to the embedded phf tables.
pub struct Icons {
    files: HashMap<String, String>,
    folders: HashMap<String, String>,
    file_aliases: HashMap<String, String>,
    folder_aliases: HashMap<String, String>,
}

impl Icons {
    pub fn load() -> Self {
        Icons {
            files: crate::config::load_user("files.yaml"),
            folders: crate::config::load_user("folders.yaml"),
            file_aliases: crate::config::load_user("file_aliases.yaml"),
            folder_aliases: crate::config::load_user("folder_aliases.yaml"),
        }
    }

    fn files_get(&self, k: &str) -> Option<&str> {
        self.files
            .get(k)
            .map(String::as_str)
            .or_else(|| tables::FILES.get(k).copied())
    }
    fn files_has(&self, k: &str) -> bool {
        self.files.contains_key(k) || tables::FILES.contains_key(k)
    }
    fn folders_get(&self, k: &str) -> Option<&str> {
        self.folders
            .get(k)
            .map(String::as_str)
            .or_else(|| tables::FOLDERS.get(k).copied())
    }
    fn folders_has(&self, k: &str) -> bool {
        self.folders.contains_key(k) || tables::FOLDERS.contains_key(k)
    }
    fn file_alias(&self, k: &str) -> Option<&str> {
        self.file_aliases
            .get(k)
            .map(String::as_str)
            .or_else(|| tables::FILE_ALIASES.get(k).copied())
    }
    fn folder_alias(&self, k: &str) -> Option<&str> {
        self.folder_aliases
            .get(k)
            .map(String::as_str)
            .or_else(|| tables::FOLDER_ALIASES.get(k).copied())
    }

    /// Resolve a directory entry: always the `dir` color, folder group.
    pub fn resolve_dir(&self, name: &str) -> Resolved {
        let lower = name.to_lowercase();
        let key: String = if self.folders_has(&lower) {
            lower
        } else if let Some(aliased) = self.folder_alias(&lower) {
            aliased.to_string()
        } else {
            "folder".to_string()
        };
        let icon = self
            .folders_get(&key)
            .or_else(|| self.folders_get("folder"))
            .unwrap_or("")
            .to_string();
        Resolved {
            icon,
            color_role: role::DIR,
            group: Group::Folders,
        }
    }

    /// Resolve a non-directory entry given its special-file/exec classification.
    pub fn resolve_file(
        &self,
        name: &str,
        chardev: bool,
        blockdev: bool,
        socket: bool,
        executable: bool,
    ) -> Resolved {
        let ext = extname_key(name);
        // key = ext; if files doesn't have it, try alias (may stay unresolved).
        let (key, resolved_alias): (String, bool) = if self.files_has(&ext) {
            (ext.clone(), true)
        } else if let Some(a) = self.file_alias(&ext) {
            (a.to_string(), self.files_has(a))
        } else {
            (ext.clone(), false)
        };

        let recognized = resolved_alias && self.files_has(&key);
        let color_role = if chardev {
            role::CHARDEV
        } else if blockdev {
            role::BLOCKDEV
        } else if socket {
            role::SOCKET
        } else if executable {
            role::EXECUTABLE_FILE
        } else if recognized {
            role::RECOGNIZED_FILE
        } else {
            role::UNRECOGNIZED_FILE
        };
        let group = if recognized {
            Group::Recognized
        } else {
            Group::Unrecognized
        };
        let icon_key = if recognized { key.as_str() } else { "file" };
        let icon = self
            .files_get(icon_key)
            .or_else(|| self.files_get("file"))
            .unwrap_or("")
            .to_string();
        Resolved {
            icon,
            color_role,
            group,
        }
    }
}

/// `File.extname(name).delete_prefix('.').downcase`.
///
/// Ruby's `File.extname` returns the suffix from the final `.` in the basename,
/// but only when that dot is neither the first character nor the last.
pub fn extname_key(name: &str) -> String {
    let bytes = name.as_bytes();
    match name.rfind('.') {
        Some(0) | None => String::new(),
        Some(pos) if pos == bytes.len() - 1 => String::new(),
        Some(pos) => name[pos + 1..].to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extname_matches_ruby() {
        assert_eq!(extname_key("file.rb"), "rb");
        assert_eq!(extname_key("archive.tar.gz"), "gz");
        assert_eq!(extname_key("README.MD"), "md"); // downcased
        assert_eq!(extname_key(".gitignore"), ""); // leading dot -> no ext
        assert_eq!(extname_key("noext"), "");
        assert_eq!(extname_key("trailing."), ""); // trailing dot -> no ext
        assert_eq!(extname_key("Dockerfile"), ""); // name-based keys never hit
    }

    #[test]
    fn file_resolution_recognized_vs_unrecognized() {
        let icons = Icons {
            files: Default::default(),
            folders: Default::default(),
            file_aliases: Default::default(),
            folder_aliases: Default::default(),
        };
        let rb = icons.resolve_file("x.rb", false, false, false, false);
        assert_eq!(rb.color_role, crate::color::role::RECOGNIZED_FILE);
        assert_eq!(rb.group, Group::Recognized);

        let unknown = icons.resolve_file("x.unknownext", false, false, false, false);
        assert_eq!(unknown.color_role, crate::color::role::UNRECOGNIZED_FILE);
        assert_eq!(unknown.group, Group::Unrecognized);

        let exe = icons.resolve_file("x.unknownext", false, false, false, true);
        assert_eq!(exe.color_role, crate::color::role::EXECUTABLE_FILE);
    }

    #[test]
    fn dir_resolution_uses_dir_color() {
        let icons = Icons {
            files: Default::default(),
            folders: Default::default(),
            file_aliases: Default::default(),
            folder_aliases: Default::default(),
        };
        let d = icons.resolve_dir("src");
        assert_eq!(d.color_role, crate::color::role::DIR);
        assert_eq!(d.group, Group::Folders);
    }
}
