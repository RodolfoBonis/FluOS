//! Rendering core, ported from the gem's `ColorLS::Core`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use unicode_width::UnicodeWidthStr;

use crate::cli::{DisplayMode, GroupFirst, Indicator, Options, ReportMode, ShowFilter, Sort};
use crate::color::{Colors, role};
use crate::fileinfo::FileInfo;
use crate::fmt::{self, Users};
use crate::git::{self, GitCache};
use crate::icons::{Group, Icons};
use crate::layout::{self, Mode as LayoutMode};

#[derive(Default)]
struct Counts {
    folders: usize,
    recognized: usize,
    unrecognized: usize,
}

pub struct Core {
    opts: Options,
    colors: Colors,
    icons: Icons,
    users: Users,
    git: GitCache,
    now: i64,
    screen_width: usize,
    counts: Counts,
    // Long-format column widths, recomputed per listing.
    linklength: usize,
    userlength: usize,
    grouplength: usize,
    chars_for_size: usize,
}

impl Core {
    pub fn new(opts: Options, colors: Colors, screen_width: usize) -> Self {
        let now = unsafe { libc::time(std::ptr::null_mut()) } as i64;
        Core {
            opts,
            colors,
            icons: Icons::load(),
            users: Users::default(),
            git: GitCache::default(),
            now,
            screen_width,
            counts: Counts::default(),
            linklength: 0,
            userlength: 0,
            grouplength: 0,
            chars_for_size: 4,
        }
    }

    fn long(&self) -> bool {
        self.opts.mode == DisplayMode::Long
    }
    fn one_per_line(&self) -> bool {
        self.opts.mode == DisplayMode::OnePerLine
    }
    fn horizontal(&self) -> bool {
        self.opts.mode == DisplayMode::Horizontal
    }

    fn additional_chars_per_item(&self) -> usize {
        12 + if self.opts.show_git { 4 } else { 0 } + if self.opts.show_inode { 10 } else { 0 }
    }

    // -- directory / file entry points -----------------------------------

    pub fn ls_files(&mut self, files: Vec<FileInfo>, out: &mut impl Write) -> io::Result<()> {
        self.render(files, out)
    }

    pub fn ls_dir(&mut self, info: &FileInfo, out: &mut impl Write) -> io::Result<()> {
        if self.opts.mode == DisplayMode::Tree {
            writeln!(out)?;
            return self.tree_traverse(Path::new(&info.path), 0, 1, 2, out);
        }

        let dir = PathBuf::from(&info.path);
        let mut names = self.read_entries(&dir)?;
        self.filter_hidden(&mut names);

        let mut contents: Vec<FileInfo> = Vec::with_capacity(names.len());
        for name in names {
            // Skip entries we cannot stat (e.g. races, permission issues).
            if let Ok(fi) = FileInfo::dir_entry(&dir, &name, self.long()) {
                contents.push(fi);
            }
        }

        self.filter_show(&mut contents);
        self.sort_contents(&mut contents);
        self.group_contents(&mut contents);

        if contents.is_empty() {
            // Gem: `print "\n   Nothing to show here\n".colorize(:empty)` — the
            // trailing newline is *inside* the colorized span, with no newline
            // after the reset.
            let msg = self.colors.paint(role::EMPTY, "\n   Nothing to show here\n");
            write!(out, "{msg}")?;
            return Ok(());
        }
        self.render(contents, out)
    }

    fn read_entries(&self, dir: &Path) -> io::Result<Vec<String>> {
        let mut names: Vec<String> = Vec::new();
        if self.opts.all {
            names.push(".".to_string());
            names.push("..".to_string());
        }
        for ent in std::fs::read_dir(dir)? {
            let ent = ent?;
            names.push(ent.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }

    fn filter_hidden(&self, names: &mut Vec<String>) {
        if !self.opts.all {
            names.retain(|n| n != "." && n != "..");
        }
        if !self.opts.all && !self.opts.almost_all {
            names.retain(|n| !n.starts_with('.'));
        }
    }

    fn filter_show(&self, contents: &mut Vec<FileInfo>) {
        match self.opts.show {
            Some(ShowFilter::Dirs) => contents.retain(|c| c.directory()),
            Some(ShowFilter::Files) => contents.retain(|c| !c.directory()),
            None => {}
        }
    }

    fn sort_contents(&self, contents: &mut [FileInfo]) {
        match self.opts.sort {
            Sort::None => {}
            Sort::Time => contents.sort_by_key(|f| std::cmp::Reverse(f.mtime_nanos())),
            Sort::Size => contents.sort_by_key(|f| std::cmp::Reverse(f.size)),
            // `sort_by_cached_key` computes each strxfrm transform once, not
            // on every comparison, which matters for large directories.
            Sort::Extension => contents.sort_by_cached_key(|f| {
                let (ext, stem) = extname_split(&f.name);
                (fmt::strxfrm(&ext), fmt::strxfrm(&stem))
            }),
            Sort::Name => contents.sort_by_cached_key(|f| fmt::strxfrm(&f.name)),
        }
        // The gem reverses only inside `sort_contents`, which is skipped for -U
        // (`@sort == false`); so -U alone never reverses.
        if self.opts.reverse && self.opts.sort != Sort::None {
            contents.reverse();
        }
    }

    fn group_contents(&self, contents: &mut Vec<FileInfo>) {
        let Some(group) = self.opts.group else {
            return;
        };
        let (dirs, files): (Vec<_>, Vec<_>) =
            std::mem::take(contents).into_iter().partition(|c| c.directory());
        match group {
            GroupFirst::Dirs => {
                contents.extend(dirs);
                contents.extend(files);
            }
            GroupFirst::Files => {
                contents.extend(files);
                contents.extend(dirs);
            }
        }
    }

    // -- rendering -------------------------------------------------------

    fn render(&mut self, contents: Vec<FileInfo>, out: &mut impl Write) -> io::Result<()> {
        self.init_column_lengths(&contents);

        let mode = if self.horizontal() {
            LayoutMode::Horizontal
        } else if self.one_per_line() || self.long() {
            LayoutMode::Single
        } else {
            LayoutMode::Vertical
        };

        let add = self.additional_chars_per_item();
        let item_widths: Vec<usize> = contents
            .iter()
            .map(|c| UnicodeWidthStr::width(c.show.as_str()) + add)
            .collect();

        let (rows, widths) = layout::compute(mode, &item_widths, self.screen_width);

        for row in rows {
            self.ls_line(&contents, &row, &widths, out)?;
        }
        Ok(())
    }

    fn init_column_lengths(&mut self, contents: &[FileInfo]) {
        if !self.long() {
            return;
        }
        let (mut maxlink, mut maxuser, mut maxgroup) = (0u64, 0usize, 0usize);
        for c in contents {
            if c.nlink > maxlink {
                maxlink = c.nlink;
            }
            let u = self.users.owner(c.uid).chars().count();
            if u > maxuser {
                maxuser = u;
            }
            let g = self.users.group(c.gid).chars().count();
            if g > maxgroup {
                maxgroup = g;
            }
        }
        self.linklength = maxlink.to_string().len();
        self.userlength = maxuser;
        self.grouplength = maxgroup;

        let sizes: Vec<u64> = contents.iter().map(|c| c.size).collect();
        self.chars_for_size = fmt::chars_for_size(self.opts.long.human_readable_size, &sizes);
    }

    fn ls_line(
        &mut self,
        contents: &[FileInfo],
        row: &[usize],
        widths: &[usize],
        out: &mut impl Write,
    ) -> io::Result<()> {
        let add = self.additional_chars_per_item();
        let mut padding = 0usize;
        let mut line = String::new();
        for (i, &idx) in row.iter().enumerate() {
            let content = &contents[idx];
            let entry = self.fetch_string(content);
            line.push_str(&" ".repeat(padding));
            line.push_str("  ");
            line.push_str(&entry);
            let dw = UnicodeWidthStr::width(content.show.as_str());
            padding = widths
                .get(i)
                .copied()
                .unwrap_or(0)
                .saturating_sub(dw)
                .saturating_sub(add);
        }
        line.push('\n');
        out.write_all(line.as_bytes())
    }

    /// Port of `Core#fetch_string`: the full per-entry rendered string.
    fn fetch_string(&mut self, content: &FileInfo) -> String {
        let resolved = if content.directory() {
            self.icons.resolve_dir(&content.name)
        } else {
            self.icons.resolve_file(
                &content.name,
                content.chardev(),
                content.blockdev(),
                content.socket(),
                content.executable,
            )
        };
        match resolved.group {
            Group::Folders => self.counts.folders += 1,
            Group::Recognized => self.counts.recognized += 1,
            Group::Unrecognized => self.counts.unrecognized += 1,
        }

        let mut name = if self.opts.hyperlink {
            make_link(content)
        } else {
            content.show.clone()
        };
        name.push_str(if content.directory() && self.opts.indicator_style != Indicator::None {
            "/"
        } else {
            " "
        });

        let entry_text = if self.opts.icons {
            format!("{}  {}", resolved.icon, name)
        } else {
            name
        };
        let bright = !content.directory() && content.executable;
        let colored_entry = self.colors.paint_entry(resolved.color_role, bright, &entry_text);

        let symlink_info = self.symlink_info(content);

        // show_symbol_dest: long/inode/git describe the symlink target.
        let target = self.deref_target(content);
        let target_ref = target.as_ref().unwrap_or(content);

        let inode = self.inode(target_ref);
        let long_info = self.long_info(target_ref);
        let git_info = self.git_info(target_ref);

        format!("{inode} {long_info} {git_info} {colored_entry}{symlink_info}")
    }

    fn deref_target(&self, content: &FileInfo) -> Option<FileInfo> {
        if !self.opts.long.show_symbol_dest
            || !content.symlink()
            || content.dead
            || content.link_target.is_none()
        {
            return None;
        }
        let target = content.link_target.as_ref().unwrap();
        let tpath = {
            let p = Path::new(target);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                Path::new(&content.path)
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join(p)
            }
        };
        FileInfo::info_arg(&tpath.to_string_lossy()).ok()
    }

    fn symlink_info(&self, content: &FileInfo) -> String {
        if !self.long() || !content.symlink() {
            return String::new();
        }
        let target = content.link_target.clone().unwrap_or_else(|| "\u{2026}".to_string());
        let link_info = format!(" \u{21d2} {target}"); // " ⇒ target"
        if content.dead {
            self.colors
                .paint(role::DEAD_LINK, &format!("{link_info} [Dead link]"))
        } else {
            self.colors.paint(role::LINK, &link_info)
        }
    }

    fn inode(&self, content: &FileInfo) -> String {
        if !self.opts.show_inode {
            return String::new();
        }
        let s = format!("{:>10}", content.ino);
        self.colors.paint(role::INODE, &s)
    }

    fn long_info(&mut self, content: &FileInfo) -> String {
        if !self.long() {
            return String::new();
        }
        let links = format!("{:>width$}", content.nlink, width = self.linklength);
        let mut parts: Vec<String> = Vec::new();
        parts.push(fmt::mode_string(content.mode, &self.colors));
        if self.opts.long.hard_links_count {
            parts.push(links);
        }
        if self.opts.long.show_user {
            let owner = self.users.owner(content.uid);
            let padded = ljust(&owner, self.userlength);
            parts.push(self.colors.paint(role::USER, &padded));
        }
        if self.opts.long.show_group {
            let group = self.users.group(content.gid);
            let padded = ljust(&group, self.grouplength);
            parts.push(self.colors.paint(role::NORMAL, &padded));
        }
        parts.push(fmt::size_string(
            content.size,
            self.opts.long.human_readable_size,
            self.chars_for_size,
            &self.colors,
        ));
        let mtime_text = if self.opts.long.time_style.starts_with('+') {
            fmt::strftime(content.mtime, &self.opts.long.time_style[1..])
        } else {
            fmt::asctime(content.mtime)
        };
        parts.push(fmt::mtime_string(content.mtime, self.now, &mtime_text, &self.colors));
        parts.join("   ")
    }

    fn git_info(&mut self, content: &FileInfo) -> String {
        if !self.opts.show_git {
            return String::new();
        }
        let parent = Path::new(&content.path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let status = self.git.status_for(&parent);
        if !status.available() {
            return String::new();
        }
        let modes = status.modes_for(&content.name);
        if content.directory() {
            // `git_dir_info`: blank for a clean *and empty* directory; otherwise
            // the status symbols (an empty mode set renders as the ✓ glyph).
            let dir_empty = std::fs::read_dir(&content.path)
                .map(|mut r| r.next().is_none())
                .unwrap_or(false);
            if modes.is_empty() && dir_empty {
                "    ".to_string()
            } else {
                git::colored_status_symbols(&modes, &self.colors)
            }
        } else {
            git::colored_status_symbols(&modes, &self.colors)
        }
    }

    // -- tree ------------------------------------------------------------

    fn tree_traverse(
        &mut self,
        path: &Path,
        prespace: usize,
        depth: usize,
        indent: usize,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let mut names = match self.read_entries(path) {
            Ok(n) => n,
            Err(_) => return Ok(()),
        };
        self.filter_hidden(&mut names);
        let mut contents: Vec<FileInfo> = names
            .into_iter()
            .filter_map(|n| FileInfo::dir_entry(path, &n, self.long()).ok())
            .collect();
        self.filter_show(&mut contents);
        self.sort_contents(&mut contents);
        self.group_contents(&mut contents);

        let len = contents.len();
        for (i, content) in contents.iter().enumerate() {
            let is_last = i == len - 1;
            let icon = if is_last || content.directory() {
                " \u{2514}\u{2500}\u{2500}" // " └──"
            } else {
                " \u{251c}\u{2500}\u{2500}" // " ├──"
            };
            let branch = self.tree_branch_preprint(prespace, indent, icon);
            write!(out, "{}", self.colors.paint(role::TREE, &branch))?;
            writeln!(out, " {} ", self.fetch_string(content))?;

            if content.directory() && self.keep_going(depth) {
                let child = PathBuf::from(&content.path);
                self.tree_traverse(&child, prespace + indent, depth + 1, indent, out)?;
            }
        }
        Ok(())
    }

    fn keep_going(&self, depth: usize) -> bool {
        match self.opts.tree_depth {
            None => true,
            Some(d) => (depth as i64) < d,
        }
    }

    fn tree_branch_preprint(&self, prespace: usize, indent: usize, icon: &str) -> String {
        if prespace == 0 {
            return icon.to_string();
        }
        let mut s = String::new();
        for _ in 0..(prespace / indent) {
            s.push_str(" \u{2502} "); // " │ "
        }
        s.push_str(icon);
        for _ in 0..indent {
            s.push('\u{2500}'); // "─"
        }
        s
    }

    // -- report ----------------------------------------------------------

    pub fn display_report(&mut self, mode: ReportMode, out: &mut impl Write) -> io::Result<()> {
        let text = match mode {
            ReportMode::Short => format!(
                "\n    Folders: {}, Files: {}.\n",
                self.counts.folders,
                self.counts.recognized + self.counts.unrecognized
            ),
            ReportMode::Long => {
                let total = self.counts.folders + self.counts.recognized + self.counts.unrecognized;
                format!(
                    "\n    Found {total} items in total.\n\n\tFolders\t\t\t: {}\n\tRecognized files\t: {}\n\tUnrecognized files\t: {}\n",
                    self.counts.folders, self.counts.recognized, self.counts.unrecognized
                )
            }
        };
        writeln!(out, "{}", self.colors.paint(role::REPORT, &text))
    }
}

/// Left-justify by *display width* padding (owner/group names are ASCII here).
fn ljust(s: &str, width: usize) -> String {
    let w = UnicodeWidthStr::width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - w))
    }
}

/// `[File.extname(name), name.chomp(ext)]` for extension sorting.
fn extname_split(name: &str) -> (String, String) {
    let bytes = name.as_bytes();
    match name.rfind('.') {
        Some(0) | None => (String::new(), name.to_string()),
        Some(pos) if pos == bytes.len() - 1 => (String::new(), name.to_string()),
        Some(pos) => (name[pos..].to_string(), name[..pos].to_string()),
    }
}

/// Build an OSC-8 hyperlink around the shown name (`Core#make_link`).
///
/// The gem uses `File.absolute_path`, which resolves `.`/`..` *lexically* and
/// does NOT follow symlinks or require the path to exist — so we must not use
/// `canonicalize` here.
fn make_link(content: &FileInfo) -> String {
    let mut abs = absolute_path(&content.path);
    // Addressable::URI.convert_path appends a trailing slash when the path
    // resolves (following symlinks) to a directory.
    let resolves_to_dir = std::fs::metadata(&content.path)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if resolves_to_dir && !abs.ends_with('/') {
        abs.push('/');
    }
    let uri = file_uri(&abs);
    format!("\x1b]8;;{uri}\x07{}\x1b]8;;\x07", content.show)
}

/// Lexical `File.absolute_path`: make absolute against `getcwd`, then collapse
/// `.` and `..` without touching the filesystem.
fn absolute_path(path: &str) -> String {
    use std::path::{Component, PathBuf};
    let p = Path::new(path);
    let base = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    };
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut root = String::new();
    for comp in base.components() {
        match comp {
            Component::RootDir => root = "/".to_string(),
            Component::Prefix(pre) => root = pre.as_os_str().to_string_lossy().into_owned(),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(seg) => out.push(seg.to_os_string()),
        }
    }
    let joined = out
        .iter()
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    format!("{root}{joined}")
}

fn file_uri(path: &str) -> String {
    let mut s = String::from("file://");
    for b in path.bytes() {
        match b {
            b'/' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                s.push(b as char)
            }
            _ => s.push_str(&format!("%{b:02X}")),
        }
    }
    s
}
