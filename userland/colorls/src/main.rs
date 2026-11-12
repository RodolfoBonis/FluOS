//! colorls — a fast Rust reimplementation of the colorls Ruby gem for FluOS.

mod cli;
mod color;
mod config;
mod core;
mod fileinfo;
mod fmt;
mod git;
mod icons;
mod layout;
mod tables;
mod terminal;

use std::ffi::CString;
use std::io::{self, Write};

use cli::{ColorWhen, Options, Parsed};
use color::Colors;
use core::Core;
use fileinfo::FileInfo;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let stdout_tty = terminal::isatty(libc::STDOUT_FILENO);

    let opts = match cli::parse(&args, stdout_tty) {
        Parsed::Run(o) => *o,
        Parsed::Exit(code) => std::process::exit(code),
    };

    // Initialize locale for strxfrm-based collation (gem's `init_locale`).
    if let Ok(empty) = CString::new("") {
        unsafe { libc::setlocale(libc::LC_COLLATE, empty.as_ptr()) };
    }

    let color_enabled = match opts.color {
        ColorWhen::Always => true,
        ColorWhen::Never => false,
        ColorWhen::Auto => stdout_tty && color_allowed_by_env(),
    };
    let user_colors = config::load_user(if opts.light {
        "light_colors.yaml"
    } else {
        "dark_colors.yaml"
    });
    let colors = Colors::new(opts.light, color_enabled, &user_colors);

    let code = run(opts, colors, stdout_tty);
    std::process::exit(code);
}

/// Respect `NO_COLOR` and `TERM=dumb` in auto mode (like Rainbow).
fn color_allowed_by_env() -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
        return false;
    }
    true
}

fn run(mut opts: Options, colors: Colors, _stdout_tty: bool) -> i32 {
    let mut exit_code = 0;

    let mut paths = std::mem::take(&mut opts.paths);
    if paths.is_empty() {
        paths.push(".".to_string());
    }
    let multi = paths.len() > 1;

    let report = opts.report;
    let screen_width = terminal::screen_width();
    let mut core = Core::new(opts, colors.clone(), screen_width);

    // Group args into directories and files (gem's group_files_and_directories).
    let mut dirs: Vec<FileInfo> = Vec::new();
    let mut files: Vec<FileInfo> = Vec::new();
    for arg in &paths {
        match FileInfo::info_arg(arg) {
            Ok(fi) => {
                if fi.directory() {
                    dirs.push(fi);
                } else {
                    files.push(fi);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let msg = format!("colorls: Specified path '{arg}' doesn't exist.");
                eprintln!("{}", paint_error(&colors, &msg));
                exit_code = 2;
            }
            Err(e) => {
                let msg = format!("{arg}: {e}");
                eprintln!("{}", paint_error(&colors, &msg));
                exit_code = 2;
            }
        }
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    // Files first, then directories (sorted by name), matching the gem.
    if !files.is_empty() {
        let _ = core.ls_files(files, &mut out);
    }

    dirs.sort_by_key(|a| fmt::strxfrm(&a.name));
    for dir in &dirs {
        if multi {
            let _ = writeln!(out, "\n{}:", dir.show);
        }
        let _ = core.ls_dir(dir, &mut out);
    }

    if let Some(mode) = report {
        let _ = core.display_report(mode, &mut out);
    }

    let _ = out.flush();
    exit_code
}

fn paint_error(colors: &Colors, msg: &str) -> String {
    // Errors use Rainbow `:red` (SGR 31) regardless of the color scheme.
    if colors.enabled() {
        format!("\x1b[31m{msg}\x1b[0m")
    } else {
        msg.to_string()
    }
}