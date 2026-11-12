//! The kernel filesystem layer: the global VFS, device files, and per-process
//! file-descriptor tables.
//!
//! Regular files and directories live in the host-tested [`vfs`] tmpfs; special
//! files (`/dev/console`, `/dev/null`, ...) are handled here because they touch
//! hardware (the console, the keyboard queue, the RNG). A [`FdTable`] maps a
//! process's integer descriptors to shared open-file objects so `dup` and
//! `fork` can share offsets.

use abi::types;
use abi::{Errno, SysResult};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicI32, Ordering};
use vfs::{Ino, Vfs};

/// The system-wide root filesystem (tmpfs + devfs), set up at boot.
static VFS: SpinLock<Option<Vfs>> = SpinLock::new(None);

/// The console/tty line-discipline settings (termios).
static TERMIOS: SpinLock<types::Termios> = SpinLock::new(default_termios());

/// Default cooked termios: canonical mode, echo, signals, CR→NL in, NL→CRNL out.
const fn default_termios() -> types::Termios {
    let mut cc = [0u8; types::NCCS];
    cc[types::VERASE] = 0x7f;
    cc[types::VINTR] = 3; // Ctrl-C -> SIGINT
    cc[types::VQUIT] = 0x1c; // Ctrl-\ -> SIGQUIT
    cc[types::VEOF] = 4;
    cc[types::VSUSP] = 0x1a; // Ctrl-Z -> SIGTSTP
    cc[types::VMIN] = 1;
    types::Termios {
        c_iflag: types::ICRNL,
        c_oflag: types::OPOST | types::ONLCR,
        c_cflag: 0,
        c_lflag: types::ICANON | types::ECHO | types::ISIG,
        c_line: 0,
        c_cc: cc,
    }
}

/// Current console termios (for ioctl TCGETS/TCSETS).
pub fn termios() -> types::Termios {
    *TERMIOS.lock()
}

/// Updates the console termios (ioctl TCSETS).
pub fn set_termios(t: types::Termios) {
    *TERMIOS.lock() = t;
}

/// The terminal's foreground process group — the target of terminal-generated
/// signals (Ctrl-C/Ctrl-Z). Zero means "unset" (no signals generated).
static FOREGROUND_PGRP: AtomicI32 = AtomicI32::new(0);

/// Sets the foreground process group of the controlling terminal.
pub fn set_foreground_pgrp(pgid: i32) {
    FOREGROUND_PGRP.store(pgid, Ordering::Relaxed);
}

/// The foreground process group, or 0 if unset.
#[must_use]
pub fn foreground_pgrp() -> i32 {
    FOREGROUND_PGRP.load(Ordering::Relaxed)
}

/// Line-discipline input filter, called for every byte arriving from the
/// keyboard or serial port (in IRQ context). When `ISIG` is enabled and the
/// byte matches a signal-generating control character, the corresponding signal
/// is sent to the foreground process group and the byte is *consumed* (returns
/// `true`) so it never reaches the input queue.
#[must_use]
pub fn tty_input_filter(byte: u8) -> bool {
    let t = *TERMIOS.lock();
    if t.c_lflag & types::ISIG == 0 {
        return false;
    }
    let pgrp = FOREGROUND_PGRP.load(Ordering::Relaxed);
    if pgrp == 0 {
        return false;
    }
    let sig = if byte != 0 && byte == t.c_cc[types::VINTR] {
        types::SIGINT
    } else if byte != 0 && byte == t.c_cc[types::VQUIT] {
        types::SIGQUIT
    } else if byte != 0 && byte == t.c_cc[types::VSUSP] {
        types::SIGTSTP
    } else {
        return false;
    };
    crate::signal::send_to_pgrp(pgrp, sig);
    true
}

/// Device numbers we recognise (`(major << 8) | minor`, Linux-ish).
mod dev {
    pub const NULL: u64 = (1 << 8) | 3;
    pub const ZERO: u64 = (1 << 8) | 5;
    pub const RANDOM: u64 = (1 << 8) | 8;
    pub const URANDOM: u64 = (1 << 8) | 9;
    pub const CONSOLE: u64 = (5 << 8) | 1;
    pub const TTY: u64 = 5 << 8; // /dev/tty
}

/// Builds the root filesystem: unpacks the initramfs (if any) and creates the
/// device nodes under `/dev`.
pub fn init(initramfs: Option<&[u8]>) {
    let mut fs = Vfs::new();
    if let Some(archive) = initramfs {
        match fs.unpack_cpio(archive) {
            Ok(n) => crate::log::info!("vfs: unpacked {n} initramfs entries"),
            Err(e) => crate::log::error!("vfs: initramfs unpack failed: {e:?}"),
        }
    }
    // devfs: create /dev and the standard character devices.
    let dev = fs.resolve(vfs::ROOT, "/dev", true).unwrap_or_else(|_| {
        fs.mkdir(vfs::ROOT, "dev", 0o755).expect("create /dev")
    });
    let _ = fs.mknod_char(dev, "null", 0o666, dev::NULL);
    let _ = fs.mknod_char(dev, "zero", 0o666, dev::ZERO);
    let _ = fs.mknod_char(dev, "random", 0o444, dev::RANDOM);
    let _ = fs.mknod_char(dev, "urandom", 0o444, dev::URANDOM);
    let _ = fs.mknod_char(dev, "console", 0o600, dev::CONSOLE);
    let _ = fs.mknod_char(dev, "tty", 0o666, dev::TTY);
    *VFS.lock() = Some(fs);
}

/// Reads an entire regular file from the VFS into a Vec.
pub fn read_file(path: &str) -> Result<alloc::vec::Vec<u8>, Errno> {
    with_vfs(|v| {
        let ino = v.resolve(vfs::ROOT, path, true)?;
        let size = v.size(ino)? as usize;
        let mut buf = alloc::vec![0u8; size];
        let n = v.read_at(ino, 0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    })
}

/// Runs `f` with the global VFS, or returns `ENOENT` if it is not initialised.
pub fn with_vfs<R>(f: impl FnOnce(&mut Vfs) -> Result<R, Errno>) -> Result<R, Errno> {
    let mut guard = VFS.lock();
    let vfs = guard.as_mut().ok_or(Errno::ENOENT)?;
    f(vfs)
}

/// What an open descriptor refers to.
pub enum FileKind {
    /// A character device, keyed by its device number.
    Device(u64),
    /// A regular file: the inode and the current offset.
    File { ino: Ino, offset: u64 },
    /// A directory open for `getdents64`.
    Dir { ino: Ino, pos: usize },
}

/// An open file (shared between descriptors via `Arc`).
pub struct OpenFile {
    pub kind: FileKind,
    #[allow(dead_code)] // consulted by fcntl once O_* flags are honoured
    pub flags: u64,
    pub readable: bool,
    pub writable: bool,
}

impl OpenFile {
    fn device(dev: u64, readable: bool, writable: bool) -> Arc<SpinLock<OpenFile>> {
        Arc::new(SpinLock::new(OpenFile {
            kind: FileKind::Device(dev),
            flags: 0,
            readable,
            writable,
        }))
    }
}

/// A per-process descriptor table.
pub struct FdTable {
    fds: Vec<Option<Arc<SpinLock<OpenFile>>>>,
}

impl FdTable {
    pub fn new() -> Self {
        Self { fds: Vec::new() }
    }

    /// Wires fds 0/1/2 to the console (stdin/stdout/stderr).
    pub fn with_stdio() -> Self {
        let mut t = Self::new();
        let con = || OpenFile::device(dev::CONSOLE, true, true);
        t.fds.push(Some(con()));
        t.fds.push(Some(con()));
        t.fds.push(Some(con()));
        t
    }

    /// Lowest free descriptor >= `min`.
    fn free_slot(&mut self, min: usize) -> usize {
        for i in min..self.fds.len() {
            if self.fds[i].is_none() {
                return i;
            }
        }
        self.fds.push(None);
        self.fds.len() - 1
    }

    /// Installs `file` at the lowest free descriptor, returning it.
    pub fn alloc(&mut self, file: Arc<SpinLock<OpenFile>>) -> i32 {
        let slot = self.free_slot(0);
        self.fds[slot] = Some(file);
        slot as i32
    }

    pub fn get(&self, fd: i32) -> Result<Arc<SpinLock<OpenFile>>, Errno> {
        if fd < 0 {
            return Err(Errno::EBADF);
        }
        self.fds
            .get(fd as usize)
            .and_then(|slot| slot.clone())
            .ok_or(Errno::EBADF)
    }

    pub fn close(&mut self, fd: i32) -> Result<(), Errno> {
        let slot = self.fds.get_mut(fd as usize).ok_or(Errno::EBADF)?;
        if slot.take().is_none() {
            return Err(Errno::EBADF);
        }
        Ok(())
    }

    /// `dup3(old, new)` — duplicate `old` into exactly `new`.
    pub fn dup3(&mut self, old: i32, new: i32) -> Result<i32, Errno> {
        let file = self.get(old)?;
        let n = new as usize;
        if self.fds.len() <= n {
            self.fds.resize(n + 1, None);
        }
        self.fds[n] = Some(file);
        Ok(new)
    }

    /// `dup(old)` — duplicate into the lowest free descriptor.
    pub fn dup(&mut self, old: i32) -> Result<i32, Errno> {
        let file = self.get(old)?;
        Ok(self.alloc(file))
    }

    /// Duplicates `old` into the lowest free descriptor >= `min` (F_DUPFD).
    pub fn dup_from(&mut self, old: i32, min: i32) -> Result<u64, Errno> {
        let file = self.get(old)?;
        let slot = self.free_slot(min.max(0) as usize);
        self.fds[slot] = Some(file);
        Ok(slot as u64)
    }

    /// Deep-clones the table for `fork` (shares the underlying open files).
    #[allow(dead_code)] // used by fork
    pub fn fork_clone(&self) -> FdTable {
        FdTable { fds: self.fds.clone() }
    }
}

// --- device and file I/O ---------------------------------------------------

/// Reads from an open file into `buf`, returning the byte count.
pub fn read(file: &Arc<SpinLock<OpenFile>>, buf: &mut [u8]) -> SysResult {
    let mut f = file.lock();
    if !f.readable {
        return Err(Errno::EBADF);
    }
    match &mut f.kind {
        FileKind::Device(dev) => device_read(*dev, buf),
        FileKind::File { ino, offset } => {
            let n = with_vfs(|v| v.read_at(*ino, *offset, buf))?;
            *offset += n as u64;
            Ok(n as u64)
        }
        FileKind::Dir { .. } => Err(Errno::EISDIR),
    }
}

/// Writes `buf` to an open file, returning the byte count.
pub fn write(file: &Arc<SpinLock<OpenFile>>, buf: &[u8]) -> SysResult {
    let mut f = file.lock();
    if !f.writable {
        return Err(Errno::EBADF);
    }
    match &mut f.kind {
        FileKind::Device(dev) => device_write(*dev, buf),
        FileKind::File { ino, offset } => {
            let n = with_vfs(|v| v.write_at(*ino, *offset, buf))?;
            *offset += n as u64;
            Ok(n as u64)
        }
        FileKind::Dir { .. } => Err(Errno::EISDIR),
    }
}

/// Opens a path, returning a shared open file.
pub fn open(cwd: Ino, path: &str, flags: u64, mode: u32) -> Result<Arc<SpinLock<OpenFile>>, Errno> {
    let readable = flags & 0b11 != types::O_WRONLY;
    let writable = flags & 0b11 != types::O_RDONLY;
    with_vfs(|v| {
        let ino = match v.resolve(cwd, path, true) {
            Ok(ino) => ino,
            Err(e) if flags & types::O_CREAT != 0 && e == Errno::ENOENT => {
                let (dir, name) = v.split_parent(cwd, path)?;
                v.create(dir, name, mode)?
            }
            Err(e) => return Err(e),
        };
        let kind = match v.kind(ino)? {
            vfs::Kind::Dir => FileKind::Dir { ino, pos: 0 },
            vfs::Kind::CharDev => FileKind::Device(v.rdev(ino)?),
            _ => FileKind::File { ino, offset: 0 },
        };
        Ok(Arc::new(SpinLock::new(OpenFile { kind, flags, readable, writable })))
    })
}

fn device_write(dev: u64, buf: &[u8]) -> SysResult {
    match dev {
        dev::CONSOLE | dev::TTY => {
            // Serial first, then console — same order the logger uses, so the two
            // never invert lock order under SMP.
            crate::arch::x86_64::serial::write_bytes(buf);
            crate::console::write_bytes(buf);
            Ok(buf.len() as u64)
        }
        dev::NULL => Ok(buf.len() as u64),
        dev::ZERO => Ok(buf.len() as u64),
        _ => Ok(buf.len() as u64),
    }
}

fn device_read(dev: u64, buf: &mut [u8]) -> SysResult {
    match dev {
        dev::CONSOLE | dev::TTY => {
            let t = *TERMIOS.lock();
            let echo = t.c_lflag & types::ECHO != 0;
            let n = if t.c_lflag & types::ICANON != 0 {
                crate::console::read_line(buf, echo)
            } else {
                crate::console::read_raw(buf, echo)
            };
            Ok(n as u64)
        }
        dev::NULL => Ok(0),
        dev::ZERO => {
            buf.fill(0);
            Ok(buf.len() as u64)
        }
        dev::RANDOM | dev::URANDOM => {
            crate::rng::fill(buf);
            Ok(buf.len() as u64)
        }
        _ => Ok(0),
    }
}
