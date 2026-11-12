//! Linux errno values (the subset FluOS returns).
//!
//! Syscalls report errors as the negated errno in the return register, which is
//! exactly how musl decodes them. [`Errno`] is a thin newtype so kernel code
//! can return `Result<T, Errno>` and convert at the ABI boundary.

#![allow(missing_docs)]

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const ENXIO: i64 = 6;
pub const E2BIG: i64 = 7;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const ECHILD: i64 = 10;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EBUSY: i64 = 16;
pub const EEXIST: i64 = 17;
pub const EXDEV: i64 = 18;
pub const ENODEV: i64 = 19;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const ENFILE: i64 = 23;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const EPIPE: i64 = 32;
pub const ERANGE: i64 = 34;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;
pub const ELOOP: i64 = 40;
pub const ETIMEDOUT: i64 = 110;

/// A Linux errno, stored as its positive value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Errno(pub i64);

impl Errno {
    pub const EBADF: Errno = Errno(EBADF);
    pub const EFAULT: Errno = Errno(EFAULT);
    pub const EINVAL: Errno = Errno(EINVAL);
    pub const ENOENT: Errno = Errno(ENOENT);
    pub const ENOSYS: Errno = Errno(ENOSYS);
    pub const ENOMEM: Errno = Errno(ENOMEM);
    pub const ENOTDIR: Errno = Errno(ENOTDIR);
    pub const EISDIR: Errno = Errno(EISDIR);
    pub const ERANGE: Errno = Errno(ERANGE);
    pub const ESPIPE: Errno = Errno(ESPIPE);
    pub const ENOTTY: Errno = Errno(ENOTTY);
    pub const EEXIST: Errno = Errno(EEXIST);
    pub const EACCES: Errno = Errno(EACCES);
    pub const ESRCH: Errno = Errno(ESRCH);
    pub const ECHILD: Errno = Errno(ECHILD);
    pub const EPERM: Errno = Errno(EPERM);
    pub const EAGAIN: Errno = Errno(EAGAIN);

    /// The value a syscall returns for this error: the negated errno.
    #[must_use]
    pub fn as_ret(self) -> i64 {
        -self.0
    }
}

/// A syscall result: a non-negative value on success, or an [`Errno`].
pub type SysResult = Result<u64, Errno>;

/// Encodes a [`SysResult`] into the raw value a syscall returns in `rax`.
#[must_use]
pub fn encode(result: SysResult) -> u64 {
    match result {
        Ok(v) => v,
        Err(e) => e.as_ret() as u64,
    }
}
