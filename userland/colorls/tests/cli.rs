//! Integration tests: run the built binary against temp directories and assert
//! on the exact bytes, including ANSI escapes. `HOME` is redirected to the temp
//! dir so a developer's real `~/.config/colorls` can't perturb the output.

use std::fs;
use std::process::Command;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_colorls"));
    // Deterministic environment.
    c.env_remove("NO_COLOR");
    c.env("COLUMNS", "80");
    c
}

/// Run colorls in `dir` with `args`, returning stdout as a String.
fn run(dir: &std::path::Path, args: &[&str]) -> String {
    let out = bin()
        .args(args)
        .current_dir(dir)
        .env("HOME", dir) // isolate from real user config
        .output()
        .expect("spawn colorls");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn single_column_colored_entry() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("file.rb"), b"x").unwrap();

    let out = run(tmp.path(), &["-1", "--color=always"]);
    // 5 leading spaces, yellow (SGR 33) for a recognized .rb file, trailing
    // space after the name, single reset. The icon glyph sits between.
    assert!(out.starts_with("     \x1b[33m"), "got: {out:?}");
    assert!(out.ends_with("file.rb \x1b[0m\n"), "got: {out:?}");
}

#[test]
fn without_icons_has_no_glyph() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("file.rb"), b"x").unwrap();

    let out = run(tmp.path(), &["-1", "--color=always", "--without-icons"]);
    assert_eq!(out, "     \x1b[33mfile.rb \x1b[0m\n");
}

#[test]
fn color_never_is_plain() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("file.rb"), b"x").unwrap();

    let out = run(tmp.path(), &["-1", "--color=never", "--without-icons"]);
    assert_eq!(out, "     file.rb \n");
}

#[test]
fn no_color_env_disables_color_in_auto() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("file.rb"), b"x").unwrap();
    // Even without --color, NO_COLOR + non-tty => plain output.
    let out = bin()
        .args(["-1", "--without-icons"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "     file.rb \n");
}

#[test]
fn directories_get_trailing_slash_and_dir_color() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("src")).unwrap();

    let out = run(tmp.path(), &["-1", "--color=always", "--without-icons"]);
    // dir color = dodgerblue (38;5;39), trailing slash.
    assert_eq!(out, "     \x1b[38;5;39msrc/\x1b[0m\n");
}

#[test]
fn long_format_starts_with_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("file.txt");
    fs::write(&f, b"hello").unwrap();
    let mut perms = fs::metadata(&f).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o644);
    fs::set_permissions(&f, perms).unwrap();

    let out = run(tmp.path(), &["-l", "--color=never"]);
    // "   rw-r--r--   1   <user> ..." — 3 leading spaces then mode.
    assert!(out.starts_with("   rw-r--r--"), "got: {out:?}");
    assert!(out.contains("5 B"), "size missing: {out:?}");
}

#[test]
fn hidden_files_filtered_without_all() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join(".secret"), b"x").unwrap();
    fs::write(tmp.path().join("visible.txt"), b"x").unwrap();

    let plain = run(tmp.path(), &["-1", "--color=never", "--without-icons"]);
    assert!(!plain.contains(".secret"));
    assert!(plain.contains("visible.txt"));

    let all = run(tmp.path(), &["-1", "-a", "--color=never", "--without-icons"]);
    assert!(all.contains(".secret"));
    assert!(all.contains("."));
}

#[test]
fn sort_by_size_descending() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("small.txt"), b"a").unwrap();
    fs::write(tmp.path().join("big.txt"), vec![b'x'; 1000]).unwrap();

    let out = run(tmp.path(), &["-1", "-S", "--color=never", "--without-icons"]);
    let big = out.find("big.txt").unwrap();
    let small = out.find("small.txt").unwrap();
    assert!(big < small, "big should come first: {out:?}");
}

#[test]
fn report_short_counts_items() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("a.rb"), b"x").unwrap();
    fs::create_dir(tmp.path().join("d")).unwrap();

    let out = run(tmp.path(), &["--report=short", "--color=never"]);
    assert!(out.contains("Folders: 1, Files: 1."), "got: {out:?}");
}

#[test]
fn nonexistent_path_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    let status = bin()
        .args(["does-not-exist", "--color=never"])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
