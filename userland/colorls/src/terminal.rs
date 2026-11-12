//! Terminal width + tty detection, mirroring `ColorLS.terminal_width`.

/// True if `fd` refers to a terminal.
pub fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Screen width: `TIOCGWINSZ` on stdout, then `$COLUMNS`, then 80.
pub fn screen_width() -> usize {
    if let Some(w) = ioctl_width(libc::STDOUT_FILENO) {
        return w;
    }
    if let Some(w) = ioctl_width(libc::STDERR_FILENO) {
        return w;
    }
    if let Ok(cols) = std::env::var("COLUMNS")
        && let Ok(n) = cols.trim().parse::<usize>()
            && n > 0 {
                return n;
            }
    80
}

fn ioctl_width(fd: i32) -> Option<usize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if r == 0 && ws.ws_col > 0 {
        Some(ws.ws_col as usize)
    } else {
        None
    }
}
