//! `cargo xtask rootfs`: assemble the FluOS userland root filesystem.
//!
//! Pipeline:
//!   1. ensure the ports sysroot exists (runs `ports/build.sh` if missing);
//!   2. fetch oh-my-zsh, zinit and the three zinit plugins at pinned commits
//!      into `build/rootfs-cache` (cached across runs);
//!   3. assemble `build/rootfs/` by merging the committed skel, the ports
//!      sysroot, oh-my-zsh and the pre-cloned zinit plugins, and create the
//!      runtime mount points (/dev /proc /sys /tmp /run);
//!   4. emit `build/initramfs.cpio` (newc, written by the tiny cpio writer
//!      below — no external tool needed on macOS) AND `build/disk.img`
//!      (ext2, via Homebrew `mke2fs -d`) holding the persistent /home.
//!
//! Ownership is synthesised, not taken from the host: everything is root-owned
//! except `/home/rodolfo`, which is uid/gid 1000 in both the cpio and the ext2
//! image. The host (an arm64 Mac) cannot chown to 1000, so the cpio writer sets
//! uids directly and the ext2 image is fixed up with `debugfs` after creation.

use crate::{root, run_cmd};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

// --- Pinned upstreams (commit SHAs resolved at authoring time) --------------
const OMZ_REPO: &str = "https://github.com/ohmyzsh/ohmyzsh";
const OMZ_COMMIT: &str = "6010fb6260f359e71d99ba25f05f9215809b3ed2";
const ZINIT_REPO: &str = "https://github.com/zdharma-continuum/zinit";
const ZINIT_COMMIT: &str = "d7b10fcab51ea034aa7df5d241604b3e6bf46449";

/// A zinit plugin, pre-cloned into the exact directory zinit expects:
/// `~/.local/share/zinit/plugins/<user>---<repo>`.
struct Plugin {
    user: &'static str,
    repo: &'static str,
    commit: &'static str,
}

const PLUGINS: &[Plugin] = &[
    Plugin {
        user: "zdharma-continuum",
        repo: "fast-syntax-highlighting",
        commit: "4672ad5dd9ad68a7effc1476d65afb7c584ce2b3",
    },
    Plugin {
        user: "zsh-users",
        repo: "zsh-autosuggestions",
        commit: "85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5",
    },
    Plugin {
        user: "zsh-users",
        repo: "zsh-completions",
        commit: "989b23277ab33e8d5e82df6aed936e846db9d8b8",
    },
];

/// The two users that get a full shell environment on the image.
/// `root` lives on the initramfs; `rodolfo` lives on the persistent ext2 /home.
const HOME_DIRS: &[(&str, u32)] = &[("root", 0), ("home/rodolfo", 1000)];

/// Homebrew e2fsprogs (not on PATH by default on macOS).
const E2FS_SBIN: &str = "/opt/homebrew/opt/e2fsprogs/sbin";

pub fn build() -> Result<()> {
    let root = root();
    let build = root.join("build");
    fs::create_dir_all(&build)?;

    let sysroot = build.join("sysroot");
    ensure_sysroot(&root, &sysroot)?;

    let cache = build.join("rootfs-cache");
    fetch_sources(&cache)?;

    let rootfs = build.join("rootfs");
    assemble(&root, &sysroot, &cache, &rootfs)?;

    let cpio = build.join("initramfs.cpio");
    write_initramfs(&rootfs, &cpio)?;

    let disk = build.join("disk.img");
    write_ext2(&rootfs, &disk)?;

    eprintln!("\n[rootfs] done:");
    report_size(&rootfs, "rootfs tree");
    report_size(&cpio, "initramfs.cpio");
    report_size(&disk, "disk.img (ext2 /home)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 1 — ports sysroot
// ---------------------------------------------------------------------------
fn ensure_sysroot(root: &Path, sysroot: &Path) -> Result<()> {
    if sysroot.join("usr/bin/zsh").exists() {
        eprintln!("[rootfs] ports sysroot present, skipping build.");
        return Ok(());
    }
    eprintln!("[rootfs] ports sysroot missing — running ports/build.sh…");
    let script = root.join("ports/build.sh");
    run_cmd(Command::new("bash").arg(&script).current_dir(root))
        .context("ports/build.sh failed")?;
    if !sysroot.join("usr/bin/zsh").exists() {
        bail!("ports build finished but {} has no usr/bin/zsh", sysroot.display());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2 — fetch oh-my-zsh, zinit and plugins at pinned commits (cached)
// ---------------------------------------------------------------------------
fn fetch_sources(cache: &Path) -> Result<()> {
    fs::create_dir_all(cache)?;
    clone_pinned(ZINIT_REPO, ZINIT_COMMIT, &cache.join("zinit"))?;
    clone_pinned(OMZ_REPO, OMZ_COMMIT, &cache.join("ohmyzsh"))?;
    for p in PLUGINS {
        let url = format!("https://github.com/{}/{}", p.user, p.repo);
        clone_pinned(&url, p.commit, &cache.join(format!("{}---{}", p.user, p.repo)))?;
    }
    Ok(())
}

/// Clone `repo` at exactly `commit` into `dest`, idempotently. If `dest`
/// already sits at `commit`, nothing happens (offline-friendly reruns).
fn clone_pinned(repo: &str, commit: &str, dest: &Path) -> Result<()> {
    if dest.join(".git").is_dir() {
        let head = Command::new("git")
            .args(["-C", &dest.to_string_lossy(), "rev-parse", "HEAD"])
            .output()?;
        if head.status.success() && String::from_utf8_lossy(&head.stdout).trim() == commit {
            eprintln!("[rootfs] cached {} @ {}", dest.display(), &commit[..12]);
            return Ok(());
        }
        fs::remove_dir_all(dest).ok();
    }
    eprintln!("[rootfs] cloning {repo} @ {}", &commit[..12]);
    // Full clone then hard-checkout the pin: robust against shallow-fetch of
    // non-tip commits, and the result is a normal working tree.
    run_cmd(Command::new("git").args(["clone", "--quiet", repo, &dest.to_string_lossy()]))
        .with_context(|| format!("git clone {repo}"))?;
    run_cmd(Command::new("git").args([
        "-C",
        &dest.to_string_lossy(),
        "checkout",
        "--quiet",
        commit,
    ]))
    .with_context(|| format!("git checkout {commit} in {}", dest.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 3 — assemble build/rootfs
// ---------------------------------------------------------------------------
fn assemble(root: &Path, sysroot: &Path, cache: &Path, rootfs: &Path) -> Result<()> {
    eprintln!("[rootfs] assembling {}", rootfs.display());
    if rootfs.exists() {
        fs::remove_dir_all(rootfs).context("clearing old rootfs")?;
    }
    fs::create_dir_all(rootfs)?;

    // Skel (committed source) first, then the ports sysroot over it.
    copy_tree(&root.join("rootfs"), rootfs).context("copy skel")?;
    copy_tree(sysroot, rootfs).context("copy sysroot")?;

    // Per-user shell environment: oh-my-zsh + zinit + the three plugins.
    for (home, _) in HOME_DIRS {
        let home = rootfs.join(home);
        fs::create_dir_all(&home)?;

        copy_tree(&cache.join("ohmyzsh"), &home.join(".oh-my-zsh")).context("copy oh-my-zsh")?;
        strip_git(&home.join(".oh-my-zsh"));

        let zinit = home.join(".local/share/zinit");
        copy_tree(&cache.join("zinit"), &zinit.join("zinit.git")).context("copy zinit")?;
        strip_git(&zinit.join("zinit.git"));

        for p in PLUGINS {
            let name = format!("{}---{}", p.user, p.repo);
            let dst = zinit.join("plugins").join(&name);
            copy_tree(&cache.join(&name), &dst).with_context(|| format!("copy plugin {name}"))?;
            strip_git(&dst);
        }
    }

    // Convenience symlinks: /bin, /sbin → usr/bin; sh → zsh (zsh self-emulates
    // sh when invoked as `sh`), so #!/bin/sh scripts work.
    make_symlink("usr/bin", &rootfs.join("bin"))?;
    make_symlink("usr/bin", &rootfs.join("sbin"))?;
    make_symlink("bin", &rootfs.join("usr/sbin"))?;
    make_symlink("zsh", &rootfs.join("usr/bin/sh"))?;

    // Runtime mount points (empty dirs; the kernel/init mounts over them).
    for (dir, mode) in [
        ("dev", 0o755),
        ("proc", 0o755),
        ("sys", 0o755),
        ("tmp", 0o1777),
        ("run", 0o755),
        ("home", 0o755),
        ("mnt", 0o755),
        ("var/tmp", 0o1777),
        ("var/log", 0o755),
    ] {
        let p = rootfs.join(dir);
        fs::create_dir_all(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(mode))?;
    }

    // Tighten a couple of sensitive modes.
    set_mode(&rootfs.join("etc/shadow"), 0o640);
    set_mode(&rootfs.join("root"), 0o700);
    Ok(())
}

fn strip_git(dir: &Path) {
    fs::remove_dir_all(dir.join(".git")).ok();
    fs::remove_file(dir.join(".gitignore")).ok();
}

fn make_symlink(target: &str, link: &Path) -> Result<()> {
    if link.exists() || fs::symlink_metadata(link).is_ok() {
        return Ok(());
    }
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    symlink(target, link).with_context(|| format!("symlink {} -> {target}", link.display()))?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) {
    if path.exists() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
}

/// Recursively copy `src` into `dst`, merging into an existing tree and
/// preserving symlinks (recreated, never followed) and permission bits.
///
/// Hardlink clusters (e.g. the ~100 uutils applets that are all hardlinks to a
/// single multicall binary) are collapsed to one real file plus relative
/// symlinks, so the tree — and the initramfs/ext2 built from it — stay small
/// while multicall dispatch (argv[0] basename) still works.
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let mut seen: HashMap<(u64, u64), PathBuf> = HashMap::new();
    copy_tree_inner(src, dst, &mut seen)
}

fn copy_tree_inner(src: &Path, dst: &Path, seen: &mut HashMap<(u64, u64), PathBuf>) -> Result<()> {
    // Never ship macOS Finder droppings.
    if src.file_name().and_then(|n| n.to_str()) == Some(".DS_Store") {
        return Ok(());
    }
    let meta = fs::symlink_metadata(src)
        .with_context(|| format!("stat {}", src.display()))?;
    let ft = meta.file_type();

    if ft.is_symlink() {
        let target = fs::read_link(src)?;
        if dst.exists() || fs::symlink_metadata(dst).is_ok() {
            return Ok(());
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        symlink(&target, dst)
            .with_context(|| format!("symlink {} -> {}", dst.display(), target.display()))?;
    } else if ft.is_dir() {
        fs::create_dir_all(dst)?;
        fs::set_permissions(dst, fs::Permissions::from_mode(meta.mode() & 0o7777)).ok();
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_tree_inner(&entry.path(), &dst.join(entry.file_name()), seen)?;
        }
    } else if ft.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        // Collapse hardlink clusters to one real file + relative symlinks.
        if meta.nlink() > 1 {
            let key = (meta.dev(), meta.ino());
            if let Some(first) = seen.get(&key) {
                let same_dir = dst.parent() == first.parent();
                let target: PathBuf = match (first.file_name(), same_dir) {
                    (Some(name), true) => PathBuf::from(name),
                    _ => first.clone(),
                };
                symlink(&target, dst).with_context(|| {
                    format!("hardlink-symlink {} -> {}", dst.display(), target.display())
                })?;
                return Ok(());
            }
            seen.insert(key, dst.to_path_buf());
        }
        fs::copy(src, dst).with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4a — initramfs (newc cpio) with synthesised ownership
// ---------------------------------------------------------------------------
// newc "070701" format. 110-byte ASCII-hex header, NUL-terminated name padded
// to 4 bytes, file data padded to 4 bytes, terminated by a TRAILER!!! entry.

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

struct CpioWriter<W: Write> {
    out: W,
    ino: u32,
}

impl<W: Write> CpioWriter<W> {
    fn new(out: W) -> Self {
        Self { out, ino: 1 }
    }

    fn field(&mut self, v: u32) -> std::io::Result<()> {
        write!(self.out, "{v:08x}")
    }

    fn pad4(&mut self, written: usize) -> std::io::Result<()> {
        let pad = (4 - (written % 4)) % 4;
        self.out.write_all(&[0u8; 4][..pad])
    }

    /// Emit one entry. `name` must be relative (no leading '/').
    fn entry(&mut self, name: &str, mode: u32, uid: u32, gid: u32, data: &[u8]) -> std::io::Result<()> {
        let nlink = if mode & S_IFDIR != 0 { 2 } else { 1 };
        let namesize = name.len() + 1;
        self.out.write_all(b"070701")?;
        for v in [
            self.ino, mode, uid, gid, nlink,
            0,                  // mtime — fixed for reproducibility
            data.len() as u32,  // filesize
            0, 0, 0, 0,         // dev/rdev major/minor
            namesize as u32,
            0,                  // check (unused in newc)
        ] {
            self.field(v)?;
        }
        self.ino += 1;
        self.out.write_all(name.as_bytes())?;
        self.out.write_all(&[0])?; // NUL
        self.pad4(110 + namesize)?;
        self.out.write_all(data)?;
        self.pad4(data.len())?;
        Ok(())
    }

    fn trailer(&mut self) -> std::io::Result<()> {
        let name = "TRAILER!!!";
        let namesize = name.len() + 1;
        self.out.write_all(b"070701")?;
        // ino, mode, uid, gid, nlink=1, mtime, filesize, dev*4, namesize, check
        for v in [0u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, namesize as u32, 0] {
            self.field(v)?;
        }
        self.out.write_all(name.as_bytes())?;
        self.out.write_all(&[0])?;
        self.pad4(110 + namesize)?;
        self.out.flush()
    }
}

fn write_initramfs(rootfs: &Path, out: &Path) -> Result<()> {
    eprintln!("[rootfs] writing {}", out.display());
    let file = BufWriter::new(File::create(out)?);
    let mut cpio = CpioWriter::new(file);
    append_dir(&mut cpio, rootfs, Path::new(""))?;
    cpio.trailer()?;
    Ok(())
}

/// Depth-first, parents-before-children. Ships the ENTIRE tree, including the
/// full /home/rodolfo (uid 1000) — the FluOS kernel has no disk driver until
/// M6, so an initramfs-only boot must carry the complete shell environment.
/// (build/disk.img keeps the same /home for when ext2 mounting lands in M6.)
fn append_dir<W: Write>(cpio: &mut CpioWriter<W>, abs: &Path, rel: &Path) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(abs)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name();
        let child_rel = rel.join(&name);
        let child_abs = entry.path();
        let rel_str = child_rel.to_string_lossy().replace('\\', "/");

        let meta = fs::symlink_metadata(&child_abs)?;
        let ft = meta.file_type();
        let (uid, gid) = owner_of(&rel_str);
        let perm = meta.mode() & 0o7777;

        if ft.is_symlink() {
            let target = fs::read_link(&child_abs)?;
            cpio.entry(&rel_str, S_IFLNK | 0o777, uid, gid, target.to_string_lossy().as_bytes())?;
        } else if ft.is_dir() {
            cpio.entry(&rel_str, S_IFDIR | perm, uid, gid, &[])?;
            append_dir(cpio, &child_abs, &child_rel)?;
        } else if ft.is_file() {
            let data = fs::read(&child_abs)?;
            cpio.entry(&rel_str, S_IFREG | perm, uid, gid, &data)?;
        }
    }
    Ok(())
}

/// uid/gid for a path: everything under /home/rodolfo is 1000, else root.
fn owner_of(rel: &str) -> (u32, u32) {
    if rel == "home/rodolfo" || rel.starts_with("home/rodolfo/") {
        (1000, 1000)
    } else {
        (0, 0)
    }
}

// ---------------------------------------------------------------------------
// Step 4b — ext2 image for the persistent /home (via Homebrew mke2fs + debugfs)
// ---------------------------------------------------------------------------
fn write_ext2(rootfs: &Path, out: &Path) -> Result<()> {
    let mke2fs = PathBuf::from(E2FS_SBIN).join("mke2fs");
    let debugfs = PathBuf::from(E2FS_SBIN).join("debugfs");
    if !mke2fs.exists() {
        bail!(
            "{} not found — install with `brew install e2fsprogs`",
            mke2fs.display()
        );
    }

    let home = rootfs.join("home");
    // Size the filesystem to ~2x the payload plus headroom, min 48 MiB.
    let payload = dir_size(&home);
    let size_mib = ((payload * 2) / (1024 * 1024) + 24).max(48);
    eprintln!(
        "[rootfs] writing {} (ext2, {} MiB, /home payload {} KiB)",
        out.display(),
        size_mib,
        payload / 1024
    );

    if out.exists() {
        fs::remove_file(out)?;
    }
    run_cmd(Command::new(&mke2fs).args([
        "-q",
        "-F",
        "-t",
        "ext2",
        "-L",
        "fluos-home",
        "-d",
        &home.to_string_lossy(),
        &out.to_string_lossy(),
        &format!("{size_mib}M"),
    ]))
    .context("mke2fs -d")?;

    // mke2fs -d copies host uids; rewrite the whole /rodolfo subtree to 1000.
    let script = build_debugfs_chown_script(&home)?;
    let script_path = out.with_extension("debugfs");
    fs::write(&script_path, &script)?;
    run_cmd(
        Command::new(&debugfs)
            .args(["-w", "-f", &script_path.to_string_lossy(), &out.to_string_lossy()]),
    )
    .context("debugfs chown of /home/rodolfo")?;
    fs::remove_file(&script_path).ok();
    Ok(())
}

/// Build a debugfs command script that sets uid/gid 1000 on every inode under
/// the image's `/rodolfo` (which is /home/rodolfo once mounted).
fn build_debugfs_chown_script(home: &Path) -> Result<String> {
    let mut script = String::new();
    let mut stack = vec![home.join("rodolfo")];
    // The home root itself maps to the image root `/rodolfo`.
    script.push_str("sif /rodolfo uid 1000\nsif /rodolfo gid 1000\n");
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(home).unwrap().to_string_lossy().replace('\\', "/");
            script.push_str(&format!("sif /{rel} uid 1000\n"));
            script.push_str(&format!("sif /{rel} gid 1000\n"));
            if fs::symlink_metadata(&path)?.file_type().is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(script)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_dir() => total += dir_size(&p),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

fn report_size(path: &Path, label: &str) {
    let out = Command::new("du").args(["-sh", &path.to_string_lossy()]).output();
    if let Ok(out) = out {
        let s = String::from_utf8_lossy(&out.stdout);
        eprintln!("  {label:<22} {}", s.split_whitespace().next().unwrap_or("?"));
    }
}
