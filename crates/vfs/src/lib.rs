//! `vfs` — an in-memory filesystem (tmpfs) with path resolution, used as the
//! FluOS root filesystem.
//!
//! It is pure data-structure logic — a slab of inodes forming a tree — so it is
//! fully host-tested. Special files (character devices like `/dev/console`) are
//! represented as nodes carrying a `rdev` number; the *kernel* dispatches device
//! I/O on that number, keeping this crate free of any hardware concern.
//!
//! The root tmpfs is populated at boot by [`Vfs::unpack_cpio`] from the newc
//! initramfs the bootloader hands us as a module.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use abi::Errno;
use abi::types;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Inode number (index into the slab).
pub type Ino = u32;

/// The root inode is always index 0.
pub const ROOT: Ino = 0;

/// Maximum symlinks followed before returning `ELOOP`.
const MAX_SYMLINK_DEPTH: u32 = 40;

/// What a node is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Dir,
    File,
    Symlink,
    CharDev,
}

struct Inode {
    kind: Kind,
    mode: u32,
    nlink: u32,
    rdev: u64,
    parent: Ino,
    /// File contents, or the target path for a symlink.
    data: Vec<u8>,
    /// Directory entries (name → inode), empty for non-directories.
    children: BTreeMap<String, Ino>,
}

/// The in-memory filesystem.
pub struct Vfs {
    inodes: Vec<Inode>,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    /// Creates a filesystem with just a root directory.
    #[must_use]
    pub fn new() -> Self {
        let root = Inode {
            kind: Kind::Dir,
            mode: types::S_IFDIR | 0o755,
            nlink: 2,
            rdev: 0,
            parent: ROOT,
            data: Vec::new(),
            children: BTreeMap::new(),
        };
        Self { inodes: alloc::vec![root] }
    }

    fn get(&self, ino: Ino) -> Result<&Inode, Errno> {
        self.inodes.get(ino as usize).ok_or(Errno::ENOENT)
    }

    fn get_mut(&mut self, ino: Ino) -> Result<&mut Inode, Errno> {
        self.inodes.get_mut(ino as usize).ok_or(Errno::ENOENT)
    }

    /// Kind of a node.
    pub fn kind(&self, ino: Ino) -> Result<Kind, Errno> {
        Ok(self.get(ino)?.kind)
    }

    /// Absolute path of `ino`, built by walking `parent` pointers up to [`ROOT`].
    /// This is the single source of truth for `getcwd` — the kernel stores a
    /// process's cwd as an inode, not a string, so the reported path can never
    /// drift from the tree.
    pub fn path_of(&self, ino: Ino) -> Result<String, Errno> {
        self.get(ino)?; // validate
        if ino == ROOT {
            return Ok(String::from("/"));
        }
        let mut parts: Vec<&str> = Vec::new();
        let mut cur = ino;
        // Bounded by inode count: each step moves strictly toward ROOT.
        for _ in 0..=self.inodes.len() {
            if cur == ROOT {
                let mut out = String::new();
                for name in parts.iter().rev() {
                    out.push('/');
                    out.push_str(name);
                }
                return Ok(out);
            }
            let parent = self.get(cur)?.parent;
            let name = self
                .get(parent)?
                .children
                .iter()
                .find_map(|(n, &c)| (c == cur).then_some(n.as_str()))
                .ok_or(Errno::ENOENT)?;
            parts.push(name);
            cur = parent;
        }
        Err(Errno(abi::errno::ELOOP))
    }

    /// Looks up a single `name` within directory `dir` (no symlink following).
    pub fn lookup(&self, dir: Ino, name: &str) -> Result<Ino, Errno> {
        let node = self.get(dir)?;
        if node.kind != Kind::Dir {
            return Err(Errno::ENOTDIR);
        }
        match name {
            "." => Ok(dir),
            ".." => Ok(node.parent),
            _ => node.children.get(name).copied().ok_or(Errno::ENOENT),
        }
    }

    /// Resolves `path` relative to `cwd` (absolute if it starts with `/`),
    /// following symlinks. `follow_final` controls whether a trailing symlink is
    /// resolved (openat vs lstat semantics).
    pub fn resolve(&self, cwd: Ino, path: &str, follow_final: bool) -> Result<Ino, Errno> {
        self.resolve_inner(cwd, path, follow_final, 0)
    }

    fn resolve_inner(&self, cwd: Ino, path: &str, follow_final: bool, depth: u32) -> Result<Ino, Errno> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Errno(abi::errno::ELOOP));
        }
        let mut cur = if path.starts_with('/') { ROOT } else { cwd };
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty() && *c != ".").collect();

        for (i, comp) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let next = self.lookup(cur, comp)?;
            let node = self.get(next)?;
            if node.kind == Kind::Symlink && (!is_last || follow_final) {
                let target = core::str::from_utf8(&node.data).map_err(|_| Errno::EINVAL)?;
                // Symlink target resolves relative to the link's parent directory.
                cur = self.resolve_inner(cur, target, true, depth + 1)?;
            } else {
                cur = next;
            }
        }
        Ok(cur)
    }

    /// Splits `path` into `(parent_dir_ino, final_component)`.
    pub fn split_parent<'a>(&self, cwd: Ino, path: &'a str) -> Result<(Ino, &'a str), Errno> {
        let trimmed = path.trim_end_matches('/');
        let (dir_part, name) = match trimmed.rsplit_once('/') {
            Some((d, n)) => (d, n),
            None => ("", trimmed),
        };
        if name.is_empty() || name == "." || name == ".." {
            return Err(Errno::EINVAL);
        }
        let base = if path.starts_with('/') && dir_part.is_empty() { ROOT } else { cwd };
        let parent = if dir_part.is_empty() { base } else { self.resolve(cwd, dir_part, true)? };
        Ok((parent, name))
    }

    fn alloc_inode(&mut self, node: Inode) -> Ino {
        let ino = self.inodes.len() as Ino;
        self.inodes.push(node);
        ino
    }

    fn insert_child(&mut self, dir: Ino, name: &str, mode: u32, kind: Kind, rdev: u64, data: Vec<u8>) -> Result<Ino, Errno> {
        if self.get(dir)?.kind != Kind::Dir {
            return Err(Errno::ENOTDIR);
        }
        if self.get(dir)?.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let child = self.alloc_inode(Inode {
            kind,
            mode,
            nlink: if kind == Kind::Dir { 2 } else { 1 },
            rdev,
            parent: dir,
            data,
            children: BTreeMap::new(),
        });
        self.get_mut(dir)?.children.insert(name.to_string(), child);
        Ok(child)
    }

    /// Creates a regular file.
    pub fn create(&mut self, dir: Ino, name: &str, mode: u32) -> Result<Ino, Errno> {
        self.insert_child(dir, name, types::S_IFREG | (mode & 0o7777), Kind::File, 0, Vec::new())
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, dir: Ino, name: &str, mode: u32) -> Result<Ino, Errno> {
        self.insert_child(dir, name, types::S_IFDIR | (mode & 0o7777), Kind::Dir, 0, Vec::new())
    }

    /// Creates a character-device node with device number `rdev`.
    pub fn mknod_char(&mut self, dir: Ino, name: &str, mode: u32, rdev: u64) -> Result<Ino, Errno> {
        self.insert_child(dir, name, types::S_IFCHR | (mode & 0o7777), Kind::CharDev, rdev, Vec::new())
    }

    /// Creates a symlink pointing at `target`.
    pub fn symlink(&mut self, dir: Ino, name: &str, target: &str) -> Result<Ino, Errno> {
        self.insert_child(dir, name, types::S_IFLNK | 0o777, Kind::Symlink, 0, target.as_bytes().to_vec())
    }

    /// Removes a non-directory entry (or an empty directory).
    pub fn unlink(&mut self, dir: Ino, name: &str) -> Result<(), Errno> {
        let child = self.lookup(dir, name)?;
        if self.get(child)?.kind == Kind::Dir && !self.get(child)?.children.is_empty() {
            return Err(Errno(abi::errno::ENOTEMPTY));
        }
        self.get_mut(dir)?.children.remove(name);
        Ok(())
    }

    /// Renames `old_name` under `old_dir` to `new_name` under `new_dir`, moving
    /// the inode (and reparenting it). An existing target is replaced if it is a
    /// non-directory or an empty directory; a non-empty target dir is `ENOTEMPTY`.
    pub fn rename(&mut self, old_dir: Ino, old_name: &str, new_dir: Ino, new_name: &str) -> Result<(), Errno> {
        let ino = self.lookup(old_dir, old_name)?;
        if let Ok(existing) = self.lookup(new_dir, new_name) {
            if existing == ino {
                return Ok(());
            }
            if self.get(existing)?.kind == Kind::Dir && !self.get(existing)?.children.is_empty() {
                return Err(Errno(abi::errno::ENOTEMPTY));
            }
            self.get_mut(new_dir)?.children.remove(new_name);
        }
        self.get_mut(old_dir)?.children.remove(old_name);
        self.get_mut(new_dir)?.children.insert(new_name.to_string(), ino);
        self.get_mut(ino)?.parent = new_dir;
        Ok(())
    }

    /// Sets the permission bits (low 12) of `ino`, preserving the type bits.
    pub fn chmod(&mut self, ino: Ino, mode: u32) -> Result<(), Errno> {
        let node = self.get_mut(ino)?;
        node.mode = (node.mode & !0o7777) | (mode & 0o7777);
        Ok(())
    }

    /// Creates a hard link `new_name` under `new_dir` to the existing non-dir
    /// inode `ino` (bumps its link count). The inode keeps its original parent
    /// (adequate for `path_of`, which reports the first link's path).
    pub fn link(&mut self, ino: Ino, new_dir: Ino, new_name: &str) -> Result<Ino, Errno> {
        if self.get(ino)?.kind == Kind::Dir {
            return Err(Errno(abi::errno::EPERM));
        }
        if self.get(new_dir)?.kind != Kind::Dir {
            return Err(Errno::ENOTDIR);
        }
        if self.get(new_dir)?.children.contains_key(new_name) {
            return Err(Errno::EEXIST);
        }
        self.get_mut(ino)?.nlink += 1;
        self.get_mut(new_dir)?.children.insert(new_name.to_string(), ino);
        Ok(ino)
    }

    /// Creates `path` and any missing parent directories, returning the final
    /// inode. Intermediate components become directories.
    pub fn mkpath(&mut self, path: &str, kind: Kind, mode: u32, rdev: u64, data: &[u8]) -> Result<Ino, Errno> {
        let mut cur = ROOT;
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
        for (i, comp) in comps.iter().enumerate() {
            let is_last = i == comps.len() - 1;
            if let Ok(existing) = self.lookup(cur, comp) {
                cur = existing;
                continue;
            }
            cur = if is_last {
                match kind {
                    Kind::Dir => self.mkdir(cur, comp, mode)?,
                    Kind::File => {
                        let f = self.create(cur, comp, mode)?;
                        self.get_mut(f)?.data = data.to_vec();
                        f
                    }
                    Kind::Symlink => {
                        self.symlink(cur, comp, core::str::from_utf8(data).unwrap_or(""))?
                    }
                    Kind::CharDev => self.mknod_char(cur, comp, mode, rdev)?,
                }
            } else {
                self.mkdir(cur, comp, 0o755)?
            };
        }
        Ok(cur)
    }

    /// Reads up to `buf.len()` bytes from a regular file at `offset`.
    pub fn read_at(&self, ino: Ino, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let node = self.get(ino)?;
        if node.kind != Kind::File {
            return Err(Errno::EINVAL);
        }
        let off = offset as usize;
        if off >= node.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(node.data.len() - off);
        buf[..n].copy_from_slice(&node.data[off..off + n]);
        Ok(n)
    }

    /// Writes `buf` to a regular file at `offset`, growing it as needed.
    pub fn write_at(&mut self, ino: Ino, offset: u64, buf: &[u8]) -> Result<usize, Errno> {
        let node = self.get_mut(ino)?;
        if node.kind != Kind::File {
            return Err(Errno::EINVAL);
        }
        let end = offset as usize + buf.len();
        if node.data.len() < end {
            node.data.resize(end, 0);
        }
        node.data[offset as usize..end].copy_from_slice(buf);
        Ok(buf.len())
    }

    /// Current size (bytes) of a file or length of a symlink target.
    pub fn size(&self, ino: Ino) -> Result<u64, Errno> {
        Ok(self.get(ino)?.data.len() as u64)
    }

    /// Device number of a character device node.
    pub fn rdev(&self, ino: Ino) -> Result<u64, Errno> {
        Ok(self.get(ino)?.rdev)
    }

    /// Symlink target.
    pub fn readlink(&self, ino: Ino) -> Result<&str, Errno> {
        let node = self.get(ino)?;
        if node.kind != Kind::Symlink {
            return Err(Errno::EINVAL);
        }
        core::str::from_utf8(&node.data).map_err(|_| Errno::EINVAL)
    }

    /// Fills a [`types::Stat`] for `ino`.
    pub fn stat(&self, ino: Ino) -> Result<types::Stat, Errno> {
        let node = self.get(ino)?;
        let mut st = types::Stat::default();
        st.st_ino = u64::from(ino) + 1;
        st.st_mode = node.mode;
        st.st_nlink = u64::from(node.nlink);
        st.st_rdev = node.rdev;
        st.st_size = node.data.len() as i64;
        st.st_blksize = 4096;
        st.st_blocks = (node.data.len() as i64 + 511) / 512;
        Ok(st)
    }

    /// Directory entries as `(name, inode, d_type)`, including `.` and `..`.
    pub fn readdir(&self, ino: Ino) -> Result<Vec<(String, Ino, u8)>, Errno> {
        let node = self.get(ino)?;
        if node.kind != Kind::Dir {
            return Err(Errno::ENOTDIR);
        }
        let mut out = Vec::new();
        out.push((".".to_string(), ino, types::DT_DIR));
        out.push(("..".to_string(), node.parent, types::DT_DIR));
        for (name, &child) in &node.children {
            let dtype = match self.get(child)?.kind {
                Kind::Dir => types::DT_DIR,
                Kind::File => types::DT_REG,
                Kind::Symlink => types::DT_LNK,
                Kind::CharDev => types::DT_CHR,
            };
            out.push((name.clone(), child, dtype));
        }
        Ok(out)
    }

    /// Populates the filesystem from a newc cpio archive, returning the number
    /// of entries unpacked.
    pub fn unpack_cpio(&mut self, archive: &[u8]) -> Result<usize, Errno> {
        let mut count = 0;
        for entry in cpio::Reader::new(archive) {
            // Normalise `./foo` and leading slashes to a root-relative path.
            let path = entry.name.trim_start_matches("./").trim_start_matches('/');
            if path.is_empty() {
                continue;
            }
            let kind = if entry.is_dir() {
                Kind::Dir
            } else if entry.is_symlink() {
                Kind::Symlink
            } else if entry.mode & cpio::S_IFMT == cpio::S_IFCHR {
                Kind::CharDev
            } else {
                Kind::File
            };
            let rdev = 0; // device nodes in the initramfs are re-created by devfs
            self.mkpath(path, kind, entry.mode & 0o7777, rdev, entry.data)?;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_chmod_link() {
        let mut fs = Vfs::new();
        let d = fs.mkdir(ROOT, "d", 0o755).unwrap();
        let f = fs.create(d, "a", 0o644).unwrap();
        fs.write_at(f, 0, b"hi").unwrap();
        // rename within the same dir
        fs.rename(d, "a", d, "b").unwrap();
        assert!(fs.lookup(d, "a").is_err());
        assert_eq!(fs.resolve(ROOT, "/d/b", true).unwrap(), f);
        // rename across dirs reparents (path_of follows)
        let e = fs.mkdir(ROOT, "e", 0o755).unwrap();
        fs.rename(d, "b", e, "c").unwrap();
        assert_eq!(fs.path_of(f).unwrap(), "/e/c");
        // chmod sets perms, keeps type
        fs.chmod(f, 0o600).unwrap();
        assert_eq!(fs.stat(f).unwrap().st_mode & 0o7777, 0o600);
        // hard link: second name, same inode, nlink bumped
        let l = fs.link(f, ROOT, "hard").unwrap();
        assert_eq!(l, f);
        assert_eq!(fs.resolve(ROOT, "/hard", true).unwrap(), f);
        // cannot hard-link a directory
        assert!(fs.link(e, ROOT, "nope").is_err());
    }

    #[test]
    fn path_of_walks_parents() {
        let mut fs = Vfs::new();
        assert_eq!(fs.path_of(ROOT).unwrap(), "/");
        let a = fs.mkdir(ROOT, "home", 0o755).unwrap();
        let b = fs.mkdir(a, "rodolfo", 0o755).unwrap();
        let c = fs.mkdir(b, ".config", 0o755).unwrap();
        assert_eq!(fs.path_of(a).unwrap(), "/home");
        assert_eq!(fs.path_of(b).unwrap(), "/home/rodolfo");
        assert_eq!(fs.path_of(c).unwrap(), "/home/rodolfo/.config");
        // resolve("..") then path_of agrees.
        let up = fs.resolve(c, "..", true).unwrap();
        assert_eq!(fs.path_of(up).unwrap(), "/home/rodolfo");
    }

    #[test]
    fn create_read_write_file() {
        let mut fs = Vfs::new();
        let f = fs.create(ROOT, "hello.txt", 0o644).unwrap();
        assert_eq!(fs.write_at(f, 0, b"hello world").unwrap(), 11);
        let mut buf = [0u8; 5];
        assert_eq!(fs.read_at(f, 6, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"world");
        assert_eq!(fs.size(f).unwrap(), 11);
    }

    #[test]
    fn nested_directories_and_resolution() {
        let mut fs = Vfs::new();
        let etc = fs.mkdir(ROOT, "etc", 0o755).unwrap();
        fs.create(etc, "hostname", 0o644).unwrap();
        let ino = fs.resolve(ROOT, "/etc/hostname", true).unwrap();
        assert_eq!(fs.kind(ino).unwrap(), Kind::File);
        // Relative with `..`.
        let ino2 = fs.resolve(etc, "../etc/hostname", true).unwrap();
        assert_eq!(ino, ino2);
    }

    #[test]
    fn symlink_following() {
        let mut fs = Vfs::new();
        let bin = fs.mkdir(ROOT, "bin", 0o755).unwrap();
        fs.create(bin, "busybox", 0o755).unwrap();
        fs.symlink(bin, "sh", "busybox").unwrap();
        let target = fs.resolve(ROOT, "/bin/sh", true).unwrap();
        let real = fs.resolve(ROOT, "/bin/busybox", true).unwrap();
        assert_eq!(target, real);
        // Without following, we land on the symlink node itself.
        let link = fs.resolve(ROOT, "/bin/sh", false).unwrap();
        assert_eq!(fs.kind(link).unwrap(), Kind::Symlink);
        assert_eq!(fs.readlink(link).unwrap(), "busybox");
    }

    #[test]
    fn mkpath_creates_parents() {
        let mut fs = Vfs::new();
        fs.mkpath("usr/bin/zsh", Kind::File, 0o755, 0, b"ELF...").unwrap();
        let ino = fs.resolve(ROOT, "/usr/bin/zsh", true).unwrap();
        assert_eq!(fs.size(ino).unwrap(), 6);
        assert_eq!(fs.kind(fs.resolve(ROOT, "/usr/bin", true).unwrap()).unwrap(), Kind::Dir);
    }

    #[test]
    fn readdir_lists_entries() {
        let mut fs = Vfs::new();
        fs.create(ROOT, "a", 0o644).unwrap();
        fs.mkdir(ROOT, "b", 0o755).unwrap();
        let entries = fs.readdir(ROOT).unwrap();
        let names: Vec<&str> = entries.iter().map(|(n, _, _)| n.as_str()).collect();
        assert!(names.contains(&"."));
        assert!(names.contains(&".."));
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }

    #[test]
    fn devfs_char_node() {
        let mut fs = Vfs::new();
        let dev = fs.mkdir(ROOT, "dev", 0o755).unwrap();
        fs.mknod_char(dev, "null", 0o666, (1 << 8) | 3).unwrap();
        let ino = fs.resolve(ROOT, "/dev/null", true).unwrap();
        assert_eq!(fs.kind(ino).unwrap(), Kind::CharDev);
        assert_eq!(fs.rdev(ino).unwrap(), (1 << 8) | 3);
    }

    #[test]
    fn unpack_initramfs() {
        // Build a tiny cpio and unpack it.
        let archive = make_cpio();
        let mut fs = Vfs::new();
        let n = fs.unpack_cpio(&archive).unwrap();
        assert!(n >= 2);
        let sh = fs.resolve(ROOT, "/bin/sh", true).unwrap();
        let mut buf = [0u8; 16];
        let got = fs.read_at(sh, 0, &mut buf).unwrap();
        assert_eq!(&buf[..got], b"#!/bin/sh\n");
    }

    /// Minimal newc cpio with `/bin` and `/bin/sh`.
    fn make_cpio() -> Vec<u8> {
        fn hex8(v: u64) -> [u8; 8] {
            let mut o = [0u8; 8];
            for i in 0..8 {
                o[i] = b"0123456789ABCDEF"[((v >> ((7 - i) * 4)) & 0xF) as usize];
            }
            o
        }
        fn member(buf: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
            let namesize = name.len() as u64 + 1;
            buf.extend_from_slice(b"070701");
            for f in [1u64, u64::from(mode), 0, 0, 1, 0, data.len() as u64, 0, 0, 0, 0, namesize, 0] {
                buf.extend_from_slice(&hex8(f));
            }
            buf.extend_from_slice(name.as_bytes());
            buf.push(0);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
            buf.extend_from_slice(data);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        let mut buf = Vec::new();
        member(&mut buf, "./bin", 0o040000 | 0o755, b"");
        member(&mut buf, "./bin/sh", 0o100000 | 0o755, b"#!/bin/sh\n");
        member(&mut buf, "TRAILER!!!", 0, b"");
        buf
    }
}
