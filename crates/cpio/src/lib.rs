//! A `no_std` reader for the newc (SVR4) cpio archive format, used to carry the
//! initramfs that populates the root tmpfs.
//!
//! Each entry is a 110-byte ASCII-hex header, a NUL-terminated name padded to a
//! 4-byte boundary, then the file data padded to a 4-byte boundary. The archive
//! ends with an entry named `TRAILER!!!`. The reader borrows the archive bytes
//! and yields each entry without copying.

#![cfg_attr(not(test), no_std)]

/// newc magic.
const MAGIC: &[u8] = b"070701";
/// Fixed header length: magic (6) + 13 eight-hex fields.
const HEADER_LEN: usize = 110;
/// Sentinel name ending the archive.
const TRAILER: &str = "TRAILER!!!";

/// `st_mode` file-type mask and directory/regular/symlink bits (octal).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;

/// One archive member.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    /// Path (as stored, e.g. `./bin/sh` or `dev/null`).
    pub name: &'a str,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    /// File contents (empty for directories).
    pub data: &'a [u8],
}

impl Entry<'_> {
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    #[must_use]
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

/// Streaming reader over a newc cpio archive.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Reader<'a> {
    /// Wraps an archive. Parsing happens lazily as entries are iterated.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, done: false }
    }

    /// Rounds `n` up to the next multiple of 4 (newc padding).
    fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    /// Parses one 8-hex field at `off` within the current header.
    fn field(&self, field_index: usize) -> Option<u64> {
        let start = self.pos + 6 + field_index * 8;
        let bytes = self.data.get(start..start + 8)?;
        let mut value: u64 = 0;
        for &b in bytes {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return None,
            };
            value = value * 16 + u64::from(digit);
        }
        Some(value)
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        if self.done {
            return None;
        }
        // Header bounds and magic.
        let header = self.data.get(self.pos..self.pos + HEADER_LEN)?;
        if &header[0..6] != MAGIC {
            self.done = true;
            return None;
        }

        let ino = self.field(0)?;
        let mode = self.field(1)? as u32;
        let nlink = self.field(3)? as u32;
        let filesize = self.field(6)? as usize;
        let namesize = self.field(11)? as usize;

        // Name follows the header; its length includes the trailing NUL, and the
        // header+name region is padded to 4 bytes.
        let name_start = self.pos + HEADER_LEN;
        let name_bytes = self.data.get(name_start..name_start + namesize)?;
        let name = core::str::from_utf8(&name_bytes[..namesize.saturating_sub(1)]).ok()?;

        if name == TRAILER {
            self.done = true;
            return None;
        }

        let data_start = Self::align4(name_start + namesize);
        let data = self.data.get(data_start..data_start + filesize)?;
        self.pos = Self::align4(data_start + filesize);

        Some(Entry { name, ino, mode, nlink, data })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Builds a minimal newc archive from `(name, mode, data)` members.
    fn build(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        fn hex8(v: u64) -> [u8; 8] {
            let mut out = [0u8; 8];
            for i in 0..8 {
                let nibble = (v >> ((7 - i) * 4)) & 0xF;
                out[i] = b"0123456789ABCDEF"[nibble as usize];
            }
            out
        }
        fn pad4(buf: &mut Vec<u8>) {
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        fn member(buf: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
            let namesize = name.len() as u64 + 1;
            buf.extend_from_slice(MAGIC);
            // ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
            // rdevmajor, rdevminor, namesize, check
            let fields = [
                1u64,
                u64::from(mode),
                0,
                0,
                1,
                0,
                data.len() as u64,
                0,
                0,
                0,
                0,
                namesize,
                0,
            ];
            for f in fields {
                buf.extend_from_slice(&hex8(f));
            }
            buf.extend_from_slice(name.as_bytes());
            buf.push(0);
            pad4(buf);
            buf.extend_from_slice(data);
            pad4(buf);
        }

        let mut buf = Vec::new();
        for &(name, mode, data) in entries {
            member(&mut buf, name, mode, data);
        }
        member(&mut buf, "TRAILER!!!", 0, &[]);
        buf
    }

    #[test]
    fn reads_files_and_dirs() {
        let archive = build(&[
            ("./bin", S_IFDIR | 0o755, b""),
            ("./bin/sh", S_IFREG | 0o755, b"#!/bin/sh\n"),
            ("./etc/hostname", S_IFREG | 0o644, b"fluos\n"),
        ]);
        let entries: Vec<Entry> = Reader::new(&archive).collect();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].name, "./bin");
        assert!(entries[0].is_dir());

        assert_eq!(entries[1].name, "./bin/sh");
        assert!(entries[1].is_file());
        assert_eq!(entries[1].data, b"#!/bin/sh\n");

        assert_eq!(entries[2].name, "./etc/hostname");
        assert_eq!(entries[2].data, b"fluos\n");
    }

    #[test]
    fn stops_at_trailer() {
        let archive = build(&[("a", S_IFREG | 0o644, b"x")]);
        let count = Reader::new(&archive).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn empty_archive_is_empty() {
        let archive = build(&[]);
        assert_eq!(Reader::new(&archive).count(), 0);
    }

    #[test]
    fn truncated_archive_does_not_panic() {
        let mut archive = build(&[("a", S_IFREG | 0o644, b"hello")]);
        archive.truncate(50);
        // Should simply stop rather than read out of bounds.
        let _ = Reader::new(&archive).count();
    }

    #[test]
    fn odd_sized_payload_padding() {
        // 5-byte and 3-byte payloads exercise the 4-byte padding math.
        let archive = build(&[
            ("f5", S_IFREG | 0o644, b"abcde"),
            ("f3", S_IFREG | 0o644, b"xyz"),
        ]);
        let entries: Vec<Entry> = Reader::new(&archive).collect();
        assert_eq!(entries[0].data, b"abcde");
        assert_eq!(entries[1].data, b"xyz");
    }
}
