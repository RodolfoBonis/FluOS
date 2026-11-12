//! Build orchestration for FluOS: `cargo xtask <command>`.

mod e2e;
mod image;
mod ksyms;
mod limine;
mod qemu;
mod rootfs;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "\
usage: cargo xtask <command> [--release] [--smp N]

commands:
  build   compile the kernel
  image   build a bootable UEFI ISO at build/fluos.iso
  run     boot the ISO in QEMU (graphical window + serial on stdio)
  test    boot headless and assert the kernel reaches `boot complete`
  e2e     boot and drive the busybox shell over serial, asserting output
  rootfs  build the userland ports + assemble initramfs.cpio and disk.img
";

#[derive(Clone, Copy)]
pub enum Profile {
    Debug,
    Release,
}

impl Profile {
    fn dir(self) -> &'static str {
        match self {
            Profile::Debug => "debug",
            Profile::Release => "release",
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let profile = if args.iter().any(|a| a == "--release") { Profile::Release } else { Profile::Debug };
    // `--smp N` selects the vCPU count (default 4) for `run`/`test`.
    let smp = args
        .iter()
        .position(|a| a == "--smp")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(4);

    match args.first().map(String::as_str) {
        Some("build") => build_kernel(profile).map(drop),
        Some("image") => image::build(profile, "").map(drop),
        Some("run") => qemu::run(&image::build(profile, "")?, qemu::Mode::Interactive, smp),
        // `qemu-exit` makes the kernel signal QEMU's debug-exit device once boot completes.
        Some("test") => qemu::run(&image::build(profile, "qemu-exit")?, qemu::Mode::Test, smp),
        Some("e2e") => e2e::run(&image::build(profile, "")?, smp),
        Some("rootfs") => rootfs::build(),
        _ => {
            eprint!("{USAGE}");
            bail!("missing or unknown command")
        }
    }
}

/// Repository root (parent of the `xtask` crate).
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask lives inside the repo").to_path_buf()
}

/// Compiles the kernel and returns the path to its ELF.
///
/// Builds twice so panic backtraces can be symbolized: the first pass yields an
/// ELF whose function symbols are extracted into a blob; the second embeds that
/// blob (see `kernel/src/ksyms.rs`). Because the blob lands in `.rodata`, after
/// `.text`, the recorded function addresses stay valid. Symbol generation is
/// best-effort: on failure the first-pass ELF is used with raw-address traces.
pub fn build_kernel(profile: Profile) -> Result<PathBuf> {
    let elf = compile_kernel(profile, None)?;
    let blob = root().join("target").join("ksyms.bin");
    match ksyms::generate(&elf, &blob) {
        Ok(count) => {
            eprintln!("xtask: embedding {count} kernel symbols for backtraces");
            let final_elf = compile_kernel(profile, Some(&blob))?;
            // Fixed-point validation: regenerate the blob from the FINAL ELF and
            // byte-compare. If the embedded (pass-1) blob differs, `.text`
            // shifted between passes and the backtrace symbols would be wrong.
            let blob1 = std::fs::read(&blob)?;
            let blob2 = ksyms::extract(&final_elf)?;
            if blob1 != blob2 {
                bail!("ksyms: symbol addresses shifted between passes (blob is not a fixed point)");
            }
            Ok(final_elf)
        }
        Err(e) => {
            eprintln!("xtask: symbol table generation failed ({e:#}); backtraces will show raw addresses");
            Ok(elf)
        }
    }
}

/// Runs one `cargo build` of the kernel, optionally embedding a symbol blob.
fn compile_kernel(profile: Profile, ksyms_blob: Option<&Path>) -> Result<PathBuf> {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(root()).args(["build", "--package", "kernel", "--target", "x86_64-unknown-none"]);
    if let Profile::Release = profile {
        cmd.arg("--release");
    }
    if let Some(blob) = ksyms_blob {
        cmd.env("FLUOS_KSYMS", blob);
    }
    run_cmd(&mut cmd)?;
    Ok(root().join("target/x86_64-unknown-none").join(profile.dir()).join("kernel"))
}

/// Runs a command, failing with its full invocation if it exits unsuccessfully.
pub fn run_cmd(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("failed to spawn {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} exited with {status}");
    }
    Ok(())
}
