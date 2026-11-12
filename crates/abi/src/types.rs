//! Kernel ABI structs with the exact Linux x86_64 layout musl expects.

#![allow(missing_docs)]

/// `struct timespec` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `struct stat` for x86_64 (144 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

// File mode type bits (`st_mode`).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

/// `struct winsize` (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// Number of control characters in `termios`.
pub const NCCS: usize = 19;

/// `struct termios` (kernel form, 36 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
}

impl Default for Termios {
    fn default() -> Self {
        Self { c_iflag: 0, c_oflag: 0, c_cflag: 0, c_lflag: 0, c_line: 0, c_cc: [0; NCCS] }
    }
}

// termios flag bits used by the line discipline.
pub const ICANON: u32 = 0o0000002;
pub const ECHO: u32 = 0o0000010;
pub const ISIG: u32 = 0o0000001;
pub const ICRNL: u32 = 0o0000400;
pub const OPOST: u32 = 0o0000001;
pub const ONLCR: u32 = 0o0000004;
// c_cc indices.
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VEOF: usize = 4;
pub const VMIN: usize = 6;
pub const VTIME: usize = 5;
pub const VSUSP: usize = 10;

/// `struct iovec` (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

/// Kernel `struct sigaction` (rt_sigaction form, 32 bytes). `sa_mask` is the
/// 64-bit signal set.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Sigaction {
    pub sa_handler: u64,
    pub sa_flags: u64,
    pub sa_restorer: u64,
    pub sa_mask: u64,
}

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

// rt_sigprocmask `how` values.
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_RESTART: u64 = 0x1000_0000;

// A few signal numbers.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGWINCH: i32 = 28;

/// Fixed header of `struct linux_dirent64`; `d_name` follows inline.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Dirent64Header {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
}

// `d_type` values.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

/// `struct utsname` (six 65-byte NUL-terminated fields).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

// Open flags (`openat`).
pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0o100;
pub const O_EXCL: u64 = 0o200;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;
pub const O_NONBLOCK: u64 = 0o4000;
pub const O_DIRECTORY: u64 = 0o200000;
pub const O_CLOEXEC: u64 = 0o2000000;

/// `AT_FDCWD`, the special dirfd meaning "current working directory".
pub const AT_FDCWD: i32 = -100;

// mmap protection and flags.
pub const PROT_NONE: u64 = 0;
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;

// ELF auxiliary vector types.
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;

// ioctl request numbers (terminal).
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TCSETSF: u64 = 0x5404;
pub const TIOCGPGRP: u64 = 0x540F;
pub const TIOCSPGRP: u64 = 0x5410;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const TIOCSWINSZ: u64 = 0x5414;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn struct_sizes_match_linux_abi() {
        assert_eq!(size_of::<Timespec>(), 16);
        assert_eq!(size_of::<Stat>(), 144);
        assert_eq!(size_of::<Winsize>(), 8);
        assert_eq!(size_of::<Termios>(), 36);
        assert_eq!(size_of::<Iovec>(), 16);
        assert_eq!(size_of::<Sigaction>(), 32);
        assert_eq!(size_of::<Utsname>(), 390);
        assert_eq!(size_of::<Dirent64Header>(), 24);
    }

    #[test]
    fn stat_field_offsets() {
        let s = Stat::default();
        let base = core::ptr::from_ref(&s) as usize;
        assert_eq!(core::ptr::from_ref(&s.st_size) as usize - base, 48);
        assert_eq!(core::ptr::from_ref(&s.st_mode) as usize - base, 24);
    }
}
