//! Native git status, WITHOUT spawning `git`.
//!
//! We read `.git/index` and walk the worktree to classify entries, matching the
//! columns the gem derives from `git status --porcelain -unormal --ignored`. To
//! keep the binary small and fully static we deliberately avoid packfile/object
//! decoding:
//!
//! * `M` — worktree differs from the index (size or mtime mismatch);
//! * `D` — a tracked path is missing from the worktree;
//! * `?` — an untracked path (respecting a subset of `.gitignore`);
//! * `!` — an ignored path (rendered blank, exactly like the gem).
//!
//! Staged-vs-HEAD distinctions (the `X` column: `A` for freshly `git add`ed
//! files, and `M`/`D` that have been staged) require reading the HEAD tree out
//! of packfiles and are intentionally not implemented; such entries render by
//! their worktree state (often unchanged). See README for details.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::color::{Colors, role};

/// Per-listed-directory status: first-path-component -> ordered mode chars.
///
/// Order mirrors `git status` output grouping (changes, then untracked, then
/// ignored) so multi-mode columns render identically to the gem.
#[derive(Debug, Default, Clone)]
pub struct DirStatus {
    map: HashMap<String, Vec<char>>,
    available: bool,
}

impl DirStatus {
    /// Modes for a given child name (empty if clean / absent).
    pub fn modes_for(&self, name: &str) -> Vec<char> {
        self.map.get(name).cloned().unwrap_or_default()
    }

    /// Whether a git repo was found for this directory.
    pub fn available(&self) -> bool {
        self.available
    }
}

/// Cache keyed by absolute directory path (mirrors the gem's memoized hash).
#[derive(Default)]
pub struct GitCache {
    by_dir: HashMap<PathBuf, DirStatus>,
}

impl GitCache {
    pub fn status_for(&mut self, dir: &Path) -> DirStatus {
        let abs = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if let Some(s) = self.by_dir.get(&abs) {
            return s.clone();
        }
        let status = compute(&abs);
        self.by_dir.insert(abs, status.clone());
        status
    }
}

/// Render the 4-wide colored status column, like `Git.colored_status_symbols`.
pub fn colored_status_symbols(modes: &[char], colors: &Colors) -> String {
    if modes.is_empty() {
        return colors.paint(role::UNCHANGED, "  \u{2713} "); // "  ✓ "
    }
    // join + unique chars + delete('!'), then rjust(3).ljust(4).
    let mut uniq: Vec<char> = Vec::new();
    for &c in modes {
        if c != '!' && !uniq.contains(&c) {
            uniq.push(c);
        }
    }
    let raw: String = uniq.iter().collect();
    let padded = format!("{:>3}", raw); // rjust(3)
    let padded = format!("{:<4}", padded); // ljust(4)
    let mut out = String::new();
    for ch in padded.chars() {
        match ch {
            '?' => out.push_str(&colors.paint(role::UNTRACKED, "?")),
            'A' => out.push_str(&colors.paint(role::ADDITION, "A")),
            'M' => out.push_str(&colors.paint(role::MODIFICATION, "M")),
            'D' => out.push_str(&colors.paint(role::DELETION, "D")),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Repository discovery + index parsing
// ---------------------------------------------------------------------------

struct Repo {
    worktree: PathBuf,
    git_dir: PathBuf,
}

fn find_repo(start: &Path) -> Option<Repo> {
    let mut dir = start;
    loop {
        let dot = dir.join(".git");
        if dot.is_dir() {
            return Some(Repo {
                worktree: dir.to_path_buf(),
                git_dir: dot,
            });
        }
        if dot.is_file()
            && let Ok(content) = std::fs::read_to_string(&dot)
                && let Some(rest) = content.trim().strip_prefix("gitdir:") {
                    let gp = PathBuf::from(rest.trim());
                    let git_dir = if gp.is_absolute() { gp } else { dir.join(gp) };
                    return Some(Repo {
                        worktree: dir.to_path_buf(),
                        git_dir,
                    });
                }
        dir = dir.parent()?;
    }
}

#[derive(Clone)]
struct IndexEntry {
    size: u32,
    mtime_s: u32,
    mtime_ns: u32,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse `.git/index` (versions 2, 3, and 4) into path -> stat.
fn parse_index(git_dir: &Path) -> Option<BTreeMap<String, IndexEntry>> {
    let data = std::fs::read(git_dir.join("index")).ok()?;
    if data.len() < 12 || &data[0..4] != b"DIRC" {
        return None;
    }
    let version = be32(&data[4..8]);
    let count = be32(&data[8..12]) as usize;
    if !(2..=4).contains(&version) {
        return None;
    }

    let mut entries = BTreeMap::new();
    let mut off = 12usize;
    let mut prev_path: Vec<u8> = Vec::new();

    for _ in 0..count {
        if off + 62 > data.len() {
            break;
        }
        let start = off;
        let mtime_s = be32(&data[off + 8..off + 12]);
        let mtime_ns = be32(&data[off + 12..off + 16]);
        let size = be32(&data[off + 36..off + 40]);
        let flags = u16::from_be_bytes([data[off + 60], data[off + 61]]);
        off += 62;
        let extended = flags & 0x4000 != 0;
        if version >= 3 && extended {
            off += 2;
        }
        let name_len = (flags & 0x0FFF) as usize;

        let path: Vec<u8> = if version < 4 {
            let name = if name_len < 0x0FFF {
                let end = (off + name_len).min(data.len());
                let n = data[off..end].to_vec();
                off = end;
                n
            } else {
                let nul = data[off..].iter().position(|&b| b == 0)?;
                let n = data[off..off + nul].to_vec();
                off += nul;
                n
            };
            let entry_len = off - start;
            off += 8 - (entry_len % 8); // pad to multiple of 8 (>=1 NUL)
            name
        } else {
            let (strip, used) = read_varint(&data[off..])?;
            off += used;
            let nul = data[off..].iter().position(|&b| b == 0)?;
            let suffix = &data[off..off + nul];
            off += nul + 1;
            let keep = prev_path.len().saturating_sub(strip as usize);
            let mut p = prev_path[..keep].to_vec();
            p.extend_from_slice(suffix);
            p
        };

        prev_path = path.clone();
        let path_str = String::from_utf8_lossy(&path).into_owned();
        entries.insert(
            path_str,
            IndexEntry {
                size,
                mtime_s,
                mtime_ns,
            },
        );
    }
    Some(entries)
}

/// Git varint used by index v4 path compression.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut i = 0;
    loop {
        let b = *data.get(i)?;
        val = (val << 7) | (b & 0x7f) as u64;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        val += 1;
    }
    Some((val, i))
}

// ---------------------------------------------------------------------------
// Status computation
// ---------------------------------------------------------------------------

fn compute(dir: &Path) -> DirStatus {
    let Some(repo) = find_repo(dir) else {
        return DirStatus::default();
    };
    let Some(index) = parse_index(&repo.git_dir) else {
        return DirStatus {
            available: true,
            ..Default::default()
        };
    };

    let prefix = dir
        .strip_prefix(&repo.worktree)
        .ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    };

    let mut status = DirStatus {
        available: true,
        ..Default::default()
    };

    // 1) Modified / deleted among tracked files under `prefix` (sorted paths).
    for (path, entry) in &index {
        let Some(rel) = path.strip_prefix(&prefix) else {
            continue;
        };
        if rel.is_empty() {
            continue;
        }
        let component = rel.split('/').next().unwrap_or(rel).to_string();
        let wt_path = repo.worktree.join(path);
        match std::fs::symlink_metadata(&wt_path) {
            Err(_) => add_mode(&mut status, &component, 'D'),
            Ok(meta) => {
                if is_modified(&meta, entry) {
                    add_mode(&mut status, &component, 'M');
                }
            }
        }
    }

    // 2/3) Untracked (?) then ignored (!), matching git's output grouping.
    let ignore = IgnoreRules::load(&repo.worktree, dir);
    let mut untracked: BTreeSet<String> = BTreeSet::new();
    let mut ignored: BTreeSet<String> = BTreeSet::new();
    scan_children(dir, &prefix, &index, &ignore, &mut untracked, &mut ignored);
    for c in &untracked {
        add_mode(&mut status, c, '?');
    }
    for c in &ignored {
        add_mode(&mut status, c, '!');
    }

    status
}

fn add_mode(status: &mut DirStatus, component: &str, mode: char) {
    let v = status.map.entry(component.to_string()).or_default();
    if !v.contains(&mode) {
        v.push(mode);
    }
}

/// Modified if size differs, or mtime (sec+nsec) differs from the index.
fn is_modified(meta: &std::fs::Metadata, entry: &IndexEntry) -> bool {
    use std::os::unix::fs::MetadataExt;
    if meta.size() as u32 != entry.size {
        return true;
    }
    if meta.mtime() as u32 != entry.mtime_s {
        return true;
    }
    // Some checkouts store a zero nsec; treat that as "unknown, assume clean".
    if entry.mtime_ns != 0 && meta.mtime_nsec() as u32 != entry.mtime_ns {
        return true;
    }
    false
}

/// Classify immediate children of `dir`, recording which top-level components
/// contain untracked or ignored entries anywhere in their subtree.
fn scan_children(
    dir: &Path,
    prefix: &str,
    index: &BTreeMap<String, IndexEntry>,
    ignore: &IgnoreRules,
    untracked: &mut BTreeSet<String>,
    ignored: &mut BTreeSet<String>,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            continue;
        }
        let child = ent.path();
        let rel = format!("{prefix}{name}");
        let is_dir = child.is_dir() && !child.is_symlink();
        if ignore.is_ignored(&rel, is_dir) {
            ignored.insert(name);
            continue; // git collapses ignored directories
        }
        if is_dir {
            let mut has_u = false;
            let mut has_i = false;
            subtree(&child, &format!("{rel}/"), index, ignore, &mut has_u, &mut has_i);
            if has_u {
                untracked.insert(name.clone());
            }
            if has_i {
                ignored.insert(name);
            }
        } else if !index.contains_key(&rel) {
            untracked.insert(name);
        }
    }
}

fn subtree(
    dir: &Path,
    prefix: &str,
    index: &BTreeMap<String, IndexEntry>,
    ignore: &IgnoreRules,
    has_untracked: &mut bool,
    has_ignored: &mut bool,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            continue;
        }
        let child = ent.path();
        let rel = format!("{prefix}{name}");
        let is_dir = child.is_dir() && !child.is_symlink();
        if ignore.is_ignored(&rel, is_dir) {
            *has_ignored = true;
            continue;
        }
        if is_dir {
            subtree(&child, &format!("{rel}/"), index, ignore, has_untracked, has_ignored);
        } else if !index.contains_key(&rel) {
            *has_untracked = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal .gitignore support
// ---------------------------------------------------------------------------

struct IgnoreRules {
    patterns: Vec<IgnorePattern>,
}

struct IgnorePattern {
    glob: String,
    dir_only: bool,
    anchored: bool,
    negate: bool,
}

impl IgnoreRules {
    fn load(worktree: &Path, dir: &Path) -> Self {
        let mut patterns = Vec::new();
        for base in [worktree, dir] {
            if let Ok(src) = std::fs::read_to_string(base.join(".gitignore")) {
                for line in src.lines() {
                    if let Some(p) = IgnorePattern::parse(line) {
                        patterns.push(p);
                    }
                }
            }
        }
        IgnoreRules { patterns }
    }

    fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
        let mut ignored = false;
        for p in &self.patterns {
            if p.dir_only && !is_dir {
                continue;
            }
            let hay = if p.anchored { rel_path } else { base };
            if glob_match(&p.glob, hay) {
                ignored = !p.negate;
            }
        }
        ignored
    }
}

impl IgnorePattern {
    fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut s = line;
        let negate = s.starts_with('!');
        if negate {
            s = &s[1..];
        }
        let dir_only = s.ends_with('/');
        let s = s.trim_end_matches('/');
        let anchored = s.contains('/');
        let s = s.strip_prefix('/').unwrap_or(s);
        Some(IgnorePattern {
            glob: s.to_string(),
            dir_only,
            anchored,
            negate,
        })
    }
}

/// Minimal glob matching supporting `*` and `?` (no `**`, no char classes).
fn glob_match(pat: &str, text: &str) -> bool {
    fn helper(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        match p[0] {
            b'*' => helper(&p[1..], t) || (!t.is_empty() && helper(p, &t[1..])),
            b'?' => !t.is_empty() && helper(&p[1..], &t[1..]),
            c => !t.is_empty() && t[0] == c && helper(&p[1..], &t[1..]),
        }
    }
    helper(pat.as_bytes(), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Colors;
    use std::collections::HashMap;

    fn plain() -> Colors {
        Colors::new(false, false, &HashMap::new())
    }

    #[test]
    fn clean_renders_check() {
        assert_eq!(colored_status_symbols(&[], &plain()), "  \u{2713} ");
    }

    #[test]
    fn single_modified_column() {
        assert_eq!(colored_status_symbols(&['M'], &plain()), "  M ");
    }

    #[test]
    fn ignored_only_renders_blank() {
        // '!' is deleted from the symbol set -> four spaces.
        assert_eq!(colored_status_symbols(&['!'], &plain()), "    ");
    }

    #[test]
    fn multi_mode_preserves_order() {
        assert_eq!(colored_status_symbols(&['M', '?'], &plain()), " M? ");
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.log", "debug.log"));
        assert!(glob_match("target", "target"));
        assert!(!glob_match("*.log", "debug.txt"));
        assert!(glob_match("foo?bar", "fooxbar"));
    }

    #[test]
    fn gitignore_parse() {
        let p = IgnorePattern::parse("target/").unwrap();
        assert!(p.dir_only);
        assert_eq!(p.glob, "target");
        assert!(IgnorePattern::parse("# comment").is_none());
        assert!(IgnorePattern::parse("").is_none());
        let neg = IgnorePattern::parse("!keep.log").unwrap();
        assert!(neg.negate);
    }
}
