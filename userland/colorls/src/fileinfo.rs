//! Per-entry metadata, mirroring the gem's `FileInfo` (backed by `lstat`).

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

/// File "type" as classified from `lstat` (symlinks are their own type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FType {
    Dir,
    File,
    Symlink,
    Char,
    Block,
    Socket,
    Fifo,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub show: String,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ino: u64,
    pub ftype: FType,
    pub link_target: Option<String>,
    pub dead: bool,
    pub executable: bool,
}

impl FileInfo {
    /// Build from an explicit `path`, `name` (basename) and `show` string.
    pub fn build(path: &Path, name: String, show: String, link_info: bool) -> io::Result<Self> {
        let meta = fs::symlink_metadata(path)?;
        let ft = meta.file_type();
        let ftype = if ft.is_dir() {
            FType::Dir
        } else if ft.is_symlink() {
            FType::Symlink
        } else if ft.is_char_device() {
            FType::Char
        } else if ft.is_block_device() {
            FType::Block
        } else if ft.is_socket() {
            FType::Socket
        } else if ft.is_fifo() {
            FType::Fifo
        } else {
            FType::File
        };

        let mut link_target = None;
        let mut dead = false;
        if link_info && ftype == FType::Symlink {
            match fs::read_link(path) {
                Ok(t) => {
                    link_target = Some(t.to_string_lossy().into_owned());
                    // Dead if the target cannot be followed.
                    dead = fs::metadata(path).is_err();
                }
                Err(e) => {
                    eprintln!("cannot read symbolic link: {e}");
                }
            }
        }

        let mode = meta.mode();
        let executable = ftype != FType::Dir
            && is_executable(mode, meta.uid(), meta.gid());

        Ok(FileInfo {
            name,
            path: path.to_string_lossy().into_owned(),
            show,
            mode,
            nlink: meta.nlink(),
            uid: meta.uid(),
            gid: meta.gid(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ino: meta.ino(),
            ftype,
            link_target,
            dead,
            executable,
        })
    }

    /// Entry inside a directory listing (`FileInfo.dir_entry`): show = basename.
    pub fn dir_entry(dir: &Path, child: &str, link_info: bool) -> io::Result<Self> {
        let path = dir.join(child);
        Self::build(&path, child.to_string(), child.to_string(), link_info)
    }

    /// A path given on the command line (`FileInfo.info`, show_filepath=true):
    /// directories show their basename, everything else shows the given path.
    pub fn info_arg(arg: &str) -> io::Result<Self> {
        let path = Path::new(arg);
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| arg.to_string());
        let mut fi = Self::build(path, name.clone(), arg.to_string(), true)?;
        if fi.directory() {
            fi.show = name;
        }
        Ok(fi)
    }

    pub fn directory(&self) -> bool {
        self.ftype == FType::Dir
    }
    pub fn symlink(&self) -> bool {
        self.ftype == FType::Symlink
    }
    pub fn chardev(&self) -> bool {
        self.ftype == FType::Char
    }
    pub fn blockdev(&self) -> bool {
        self.ftype == FType::Block
    }
    pub fn socket(&self) -> bool {
        self.ftype == FType::Socket
    }

    /// Nanosecond mtime for stable newest-first sorting.
    pub fn mtime_nanos(&self) -> i128 {
        self.mtime as i128 * 1_000_000_000 + self.mtime_nsec as i128
    }
}

/// Replicate `File::Stat#executable?`: effective-uid access check by mode bits.
fn is_executable(mode: u32, uid: u32, gid: u32) -> bool {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        // root: executable if any execute bit is set.
        return mode & 0o111 != 0;
    }
    if uid == euid {
        return mode & 0o100 != 0;
    }
    if in_group(gid) {
        return mode & 0o010 != 0;
    }
    mode & 0o001 != 0
}

fn in_group(gid: u32) -> bool {
    let egid = unsafe { libc::getegid() };
    if gid == egid {
        return true;
    }
    // Supplementary groups.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return false;
    }
    let mut buf = vec![0 as libc::gid_t; n as usize];
    let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
    if got < 0 {
        return false;
    }
    buf[..got as usize].contains(&(gid as libc::gid_t))
}
