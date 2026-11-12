//! Build orchestration for FluOS: `cargo xtask <command>`.

mod image;
mod limine;
mod qemu;

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "\
usage: cargo xtask <command> [--release]

commands:
  build   compile the kernel
  image   build a bootable UEFI ISO at build/fluos.iso
  run     boot the ISO in QEMU (graphical window + serial on stdio)
  test    boot headless and assert the kernel reaches `boot complete`
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

    match args.first().map(String::as_str) {
        Some("build") => build_kernel(profile).map(drop),
        Some("image") => image::build(profile, "").map(drop),
        Some("run") => qemu::run(&image::build(profile, "")?, qemu::Mode::Interactive),
        // `qemu-exit` makes the kernel signal QEMU's debug-exit device once boot completes.
        Some("test") => qemu::run(&image::build(profile, "qemu-exit")?, qemu::Mode::Test),
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
pub fn build_kernel(profile: Profile) -> Result<PathBuf> {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(root()).args(["build", "--package", "kernel", "--target", "x86_64-unknown-none"]);
    if let Profile::Release = profile {
        cmd.arg("--release");
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
