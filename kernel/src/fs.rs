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
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::scheduler::WaitQueue;
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
    crate::log::info!(
        "tty: line discipline ICANON={} ECHO={} ISIG={}",
        t.c_lflag & types::ICANON != 0,
        t.c_lflag & types::ECHO != 0,
        t.c_lflag & types::ISIG != 0,
    );
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
    /// One end of an anonymous pipe. `write_end` distinguishes the two ends;
    /// both share the same [`Pipe`].
    Pipe { pipe: Arc<Pipe>, write_end: bool },
}

/// Maximum bytes buffered in a pipe before writers block.
const PIPE_CAP: usize = 64 * 1024;

/// An anonymous pipe: a bounded byte buffer with reader/writer end counts and
/// two wait queues (readers waiting for data, writers waiting for space).
pub struct Pipe {
    inner: SpinLock<PipeInner>,
    read_wq: WaitQueue,
    write_wq: WaitQueue,
}

struct PipeInner {
    buf: VecDeque<u8>,
    readers: u32,
    writers: u32,
}

impl Pipe {
    fn new() -> Arc<Pipe> {
        Arc::new(Pipe {
            inner: SpinLock::new(PipeInner { buf: VecDeque::new(), readers: 1, writers: 1 }),
            read_wq: WaitQueue::new(),
            write_wq: WaitQueue::new(),
        })
    }
}

/// Reads from the read end, blocking while the pipe is empty and writers remain.
/// Returns 0 at EOF (all write ends closed) and `ERESTARTSYS` if a signal is
/// pending (so it can be delivered on the syscall-return path).
fn pipe_read(pipe: &Arc<Pipe>, buf: &mut [u8]) -> SysResult {
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        let inner = pipe.inner.lock();
        if !inner.buf.is_empty() {
            let mut g = inner;
            let n = buf.len().min(g.buf.len());
            for slot in buf.iter_mut().take(n) {
                *slot = g.buf.pop_front().unwrap();
            }
            drop(g);
            crate::scheduler::wake_all(&pipe.write_wq); // space freed
            return Ok(n as u64);
        }
        if inner.writers == 0 {
            return Ok(0); // EOF: no writers and buffer drained
        }
        if crate::signal::current_has_deliverable() {
            return Err(Errno::ERESTARTSYS);
        }
        // Block until a writer adds data or closes. The pipe lock guards the
        // condition; `block_on` captures the wait-queue generation before the
        // closure releases it, so a wake in the gap cannot be lost.
        crate::scheduler::block_on(&pipe.read_wq, move || drop(inner));
    }
}

/// Writes to the write end, blocking while the pipe is full and readers remain.
/// Returns the number of bytes written (>=1 once it makes progress), `EPIPE`
/// (after raising SIGPIPE) if all readers have gone, or `ERESTARTSYS`.
fn pipe_write(pipe: &Arc<Pipe>, buf: &[u8]) -> SysResult {
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        let inner = pipe.inner.lock();
        if inner.readers == 0 {
            drop(inner);
            // Writing to a pipe with no readers: SIGPIPE + EPIPE.
            if let Some(p) = crate::process::current() {
                let pid = p.lock().pid;
                crate::signal::send_to_pid(pid, abi::types::SIGPIPE);
            }
            return Err(Errno::EPIPE);
        }
        let space = PIPE_CAP - inner.buf.len();
        if space > 0 {
            let mut g = inner;
            let n = buf.len().min(space);
            g.buf.extend(buf[..n].iter().copied());
            drop(g);
            crate::scheduler::wake_all(&pipe.read_wq); // data available
            return Ok(n as u64);
        }
        if crate::signal::current_has_deliverable() {
            return Err(Errno::ERESTARTSYS);
        }
        crate::scheduler::block_on(&pipe.write_wq, move || drop(inner));
    }
}

/// Creates a pipe and returns its (read end, write end) open files.
pub fn make_pipe(flags: u64) -> (Arc<SpinLock<OpenFile>>, Arc<SpinLock<OpenFile>>) {
    let pipe = Pipe::new();
    let rd = Arc::new(SpinLock::new(OpenFile {
        kind: FileKind::Pipe { pipe: pipe.clone(), write_end: false },
        flags,
        readable: true,
        writable: false,
    }));
    let wr = Arc::new(SpinLock::new(OpenFile {
        kind: FileKind::Pipe { pipe, write_end: true },
        flags,
        readable: false,
        writable: true,
    }));
    (rd, wr)
}

/// An open file (shared between descriptors via `Arc`).
pub struct OpenFile {
    pub kind: FileKind,
    #[allow(dead_code)] // consulted by fcntl once O_* flags are honoured
    pub flags: u64,
    pub readable: bool,
    pub writable: bool,
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        // Closing a pipe end updates the end count and wakes the peer so it sees
        // EOF (reader) or that writers remain/left (writer).
        if let FileKind::Pipe { pipe, write_end } = &self.kind {
            {
                let mut inner = pipe.inner.lock();
                if *write_end {
                    inner.writers = inner.writers.saturating_sub(1);
                } else {
                    inner.readers = inner.readers.saturating_sub(1);
                }
            }
            if *write_end {
                crate::scheduler::wake_all(&pipe.read_wq);
            } else {
                crate::scheduler::wake_all(&pipe.write_wq);
            }
        }
    }
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
    // A pipe read can block, so extract the shared pipe and release the
    // (interrupt-disabling) OpenFile lock before blocking on it.
    let pipe = {
        let f = file.lock();
        if !f.readable {
            return Err(Errno::EBADF);
        }
        match &f.kind {
            FileKind::Pipe { pipe, write_end: false } => Some(pipe.clone()),
            FileKind::Pipe { .. } => return Err(Errno::EBADF),
            _ => None,
        }
    };
    if let Some(pipe) = pipe {
        return pipe_read(&pipe, buf);
    }

    let mut f = file.lock();
    match &mut f.kind {
        FileKind::Device(dev) => device_read(*dev, buf),
        FileKind::File { ino, offset } => {
            let n = with_vfs(|v| v.read_at(*ino, *offset, buf))?;
            *offset += n as u64;
            Ok(n as u64)
        }
        FileKind::Dir { .. } => Err(Errno::EISDIR),
        FileKind::Pipe { .. } => unreachable!("pipe handled above"),
    }
}

/// Writes `buf` to an open file, returning the byte count.
pub fn write(file: &Arc<SpinLock<OpenFile>>, buf: &[u8]) -> SysResult {
    let pipe = {
        let f = file.lock();
        if !f.writable {
            return Err(Errno::EBADF);
        }
        match &f.kind {
            FileKind::Pipe { pipe, write_end: true } => Some(pipe.clone()),
            FileKind::Pipe { .. } => return Err(Errno::EBADF),
            _ => None,
        }
    };
    if let Some(pipe) = pipe {
        return pipe_write(&pipe, buf);
    }

    let mut f = file.lock();
    match &mut f.kind {
        FileKind::Device(dev) => device_write(*dev, buf),
        FileKind::File { ino, offset } => {
            let n = with_vfs(|v| v.write_at(*ino, *offset, buf))?;
            *offset += n as u64;
            Ok(n as u64)
        }
        FileKind::Dir { .. } => Err(Errno::EISDIR),
        FileKind::Pipe { .. } => unreachable!("pipe handled above"),
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
            let read = if t.c_lflag & types::ICANON != 0 {
                crate::console::read_line(buf, echo)
            } else {
                crate::console::read_raw(buf, echo)
            };
            match read {
                Some(n) => Ok(n as u64),
                // Interrupted by a signal before any byte: restart or EINTR.
                None => Err(Errno::ERESTARTSYS),
            }
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
