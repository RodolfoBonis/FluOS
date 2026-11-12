//! Formatting helpers: permissions, sizes, dates, locale collation, owner/group.

use std::collections::HashMap;
use std::ffi::{CStr, CString};

use crate::color::{Colors, role};

/// Cache of uid/gid -> name, mirroring the gem's `@@users`/`@@groups`.
#[derive(Default)]
pub struct Users {
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
}

impl Users {
    pub fn owner(&mut self, uid: u32) -> String {
        if let Some(n) = self.users.get(&uid) {
            return n.clone();
        }
        let name = lookup_user(uid).unwrap_or_else(|| uid.to_string());
        self.users.insert(uid, name.clone());
        name
    }

    pub fn group(&mut self, gid: u32) -> String {
        if let Some(n) = self.groups.get(&gid) {
            return n.clone();
        }
        let name = lookup_group(gid).unwrap_or_else(|| gid.to_string());
        self.groups.insert(gid, name.clone());
        name
    }
}

fn lookup_user(uid: u32) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0i8; 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        let r = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if r == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if r != 0 || result.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        return Some(name.to_string_lossy().into_owned());
    }
}

fn lookup_group(gid: u32) -> Option<String> {
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0i8; 1024];
    let mut result: *mut libc::group = std::ptr::null_mut();
    loop {
        let r = unsafe {
            libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), buf.len(), &mut result)
        };
        if r == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if r != 0 || result.is_null() {
            return None;
        }
        let name = unsafe { CStr::from_ptr(grp.gr_name) };
        return Some(name.to_string_lossy().into_owned());
    }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Render the 9 permission characters, each colorized like `Core#mode_info`.
pub fn mode_string(mode: u32, colors: &Colors) -> String {
    let setuid = mode & 0o4000 != 0;
    let setgid = mode & 0o2000 != 0;
    let sticky = mode & 0o1000 != 0;
    let mut s = String::new();
    s.push_str(&format_mode(mode >> 6, setuid, 's', colors));
    s.push_str(&format_mode(mode >> 3, setgid, 's', colors));
    s.push_str(&format_mode(mode, sticky, 't', colors));
    s
}

fn mode_color(ch: char) -> &'static str {
    match ch {
        'r' => role::READ,
        'w' => role::WRITE,
        '-' => role::NO_ACCESS,
        'x' | 's' | 'S' | 't' | 'T' => role::EXEC,
        _ => role::NORMAL,
    }
}

fn paint_char(ch: char, colors: &Colors) -> String {
    colors.paint(mode_color(ch), &ch.to_string())
}

fn format_mode(rwx: u32, special: bool, ch: char, colors: &Colors) -> String {
    let r = if rwx & 4 == 0 { '-' } else { 'r' };
    let w = if rwx & 2 == 0 { '-' } else { 'w' };
    let x = if special {
        if rwx & 1 == 0 {
            ch.to_ascii_uppercase()
        } else {
            ch
        }
    } else if rwx & 1 == 0 {
        '-'
    } else {
        'x'
    };
    let mut s = String::new();
    s.push_str(&paint_char(r, colors));
    s.push_str(&paint_char(w, colors));
    s.push_str(&paint_char(x, colors));
    s
}

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

const KIB: f64 = 1024.0;
const BINARY_UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

/// Replicate `Filesize#pretty`: "%.2f UNIT" in binary (1024) units.
fn pretty(bytes: u64) -> (String, String) {
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= KIB && unit < BINARY_UNITS.len() - 1 {
        value /= KIB;
        unit += 1;
    }
    (format!("{value:.2}"), BINARY_UNITS[unit].to_string())
}

/// Integer portion of a "%.2f" string: strip the trailing `.NN` (gem's `[0..-4]`).
fn strip_decimals(num: &str) -> String {
    match num.find('.') {
        Some(i) => num[..i].to_string(),
        None => num.to_string(),
    }
}

/// Columns reserved for the numeric part (`Core#chars_for_size`).
pub fn chars_for_size(human: bool, sizes: &[u64]) -> usize {
    const MIN: usize = 4;
    if human {
        MIN
    } else {
        let max = sizes.iter().copied().max().unwrap_or(0);
        max.to_string().len().max(MIN)
    }
}

/// Render and colorize a size like `Core#size_info` + `justify_size_info`.
pub fn size_string(bytes: u64, human: bool, chars: usize, colors: &Colors) -> String {
    let (num, unit) = if human {
        pretty(bytes)
    } else {
        (format!("{bytes}.00"), "B".to_string())
    };
    let num = strip_decimals(&num);
    let size_num = format!("{num:>width$}", width = chars);
    let size_unit = if human {
        format!("{unit:<3}")
    } else {
        unit
    };
    let text = format!("{size_num} {size_unit}");

    let role = if bytes >= 512 * 1024 * 1024 {
        role::FILE_LARGE
    } else if bytes >= 128 * 1024 * 1024 {
        role::FILE_MEDIUM
    } else {
        role::FILE_SMALL
    };
    colors.paint(role, &text)
}

// ---------------------------------------------------------------------------
// Dates
// ---------------------------------------------------------------------------

const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn localtime(secs: i64) -> libc::tm {
    let t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    tm
}

/// `Time#asctime`: "Www Mmm _d HH:MM:SS YYYY" (day space-padded to width 2).
pub fn asctime(secs: i64) -> String {
    let tm = localtime(secs);
    let wday = WDAYS.get(tm.tm_wday as usize).copied().unwrap_or("???");
    let mon = MONTHS.get(tm.tm_mon as usize).copied().unwrap_or("???");
    format!(
        "{wday} {mon} {day:>2} {h:02}:{m:02}:{s:02} {year}",
        day = tm.tm_mday,
        h = tm.tm_hour,
        m = tm.tm_min,
        s = tm.tm_sec,
        year = tm.tm_year + 1900,
    )
}

/// `strftime(format)` for `--time-style=+FORMAT`.
pub fn strftime(secs: i64, format: &str) -> String {
    let tm = localtime(secs);
    let fmt = match CString::new(format) {
        Ok(f) => f,
        Err(_) => return asctime(secs),
    };
    let mut buf = vec![0i8; 256];
    let n = unsafe {
        libc::strftime(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), &tm)
    };
    if n == 0 {
        return String::new();
    }
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    s.to_string_lossy().into_owned()
}

/// Colorize an mtime string by age, like `Core#mtime_info`.
pub fn mtime_string(mtime: i64, now: i64, text: &str, colors: &Colors) -> String {
    let age = now - mtime;
    let role = if age < 60 * 60 {
        role::HOUR_OLD
    } else if age < 24 * 60 * 60 {
        role::DAY_OLD
    } else {
        role::NO_MODIFIER
    };
    colors.paint(role, text)
}

// ---------------------------------------------------------------------------
// Locale collation
// ---------------------------------------------------------------------------

/// `strxfrm` transform for locale-correct sorting (matches the gem's CLocale).
pub fn strxfrm(s: &str) -> Vec<u8> {
    let c = match CString::new(s.as_bytes()) {
        Ok(c) => c,
        // Interior NUL can't occur in a real filename; fall back to raw bytes.
        Err(_) => return s.as_bytes().to_vec(),
    };
    let needed = unsafe { libc::strxfrm(std::ptr::null_mut(), c.as_ptr(), 0) };
    let cap = needed + 1;
    let mut buf = vec![0i8; cap];
    unsafe { libc::strxfrm(buf.as_mut_ptr(), c.as_ptr(), cap) };
    // Reinterpret as bytes and truncate at the terminating NUL.
    let bytes: Vec<u8> = buf.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
    bytes
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
    fn human_sizes_match_gem() {
        let c = plain();
        // chars_for_size is 4 for human-readable; unit ljust(3).
        assert_eq!(size_string(0, true, 4, &c), "   0 B  ");
        assert_eq!(size_string(64, true, 4, &c), "  64 B  ");
        assert_eq!(size_string(1024, true, 4, &c), "   1 KiB");
        assert_eq!(size_string(1536, true, 4, &c), "   1 KiB"); // 1.50 -> "1"
        assert_eq!(size_string(1048576, true, 4, &c), "   1 MiB");
        assert_eq!(size_string(5 * 1024 * 1024 * 1024, true, 4, &c), "   5 GiB");
    }

    #[test]
    fn byte_sizes_non_human() {
        let c = plain();
        let chars = chars_for_size(false, &[0, 1048576]);
        assert_eq!(chars, 7); // "1048576".len()
        assert_eq!(size_string(0, false, chars, &c), "      0 B");
        assert_eq!(size_string(1048576, false, chars, &c), "1048576 B");
    }

    #[test]
    fn chars_for_size_minimum_is_four() {
        assert_eq!(chars_for_size(true, &[999999]), 4);
        assert_eq!(chars_for_size(false, &[5]), 4); // "5" -> max(1,4)=4
    }

    #[test]
    fn mode_string_permissions() {
        let c = plain();
        assert_eq!(mode_string(0o755, &c), "rwxr-xr-x");
        assert_eq!(mode_string(0o644, &c), "rw-r--r--");
        assert_eq!(mode_string(0o000, &c), "---------");
        // setuid without exec -> 'S'; sticky with exec on other -> 't'
        assert_eq!(mode_string(0o4644, &c), "rwSr--r--");
        assert_eq!(mode_string(0o1711, &c), "rwx--x--t");
    }

    #[test]
    fn strxfrm_orders_names() {
        // Deterministic and orders same-case names lexically in any locale.
        let mut v = vec!["banana", "cherry", "apple"];
        v.sort_by(|a, b| strxfrm(a).cmp(&strxfrm(b)));
        assert_eq!(v, vec!["apple", "banana", "cherry"]);
        // Transform is stable across calls.
        assert_eq!(strxfrm("apple"), strxfrm("apple"));
    }
}
