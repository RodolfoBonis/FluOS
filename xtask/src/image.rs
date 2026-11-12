//! Bootable UEFI ISO assembly.

use crate::{Profile, build_kernel, limine, root, run_cmd};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn limine_conf(cmdline: &str) -> String {
    format!(
        "timeout: 0\n\n/FluOS\n    protocol: limine\n    path: boot():/boot/kernel\n    cmdline: {cmdline}\n"
    )
}

/// Builds `build/fluos.iso` with the given kernel command line and returns its path.
pub fn build(profile: Profile, cmdline: &str) -> Result<PathBuf> {
    let kernel = build_kernel(profile)?;
    let limine = limine::dir()?;
    let build = root().join("build");
    let iso_root = build.join("iso_root");

    if iso_root.exists() {
        fs::remove_dir_all(&iso_root)?;
    }
    fs::create_dir_all(iso_root.join("boot/limine"))?;
    fs::create_dir_all(iso_root.join("EFI/BOOT"))?;

    fs::copy(&kernel, iso_root.join("boot/kernel")).with_context(|| format!("copying {}", kernel.display()))?;
    fs::write(iso_root.join("boot/limine/limine.conf"), limine_conf(cmdline))?;
    fs::copy(limine.join("limine-uefi-cd.bin"), iso_root.join("boot/limine/limine-uefi-cd.bin"))?;
    fs::copy(limine.join("BOOTX64.EFI"), iso_root.join("EFI/BOOT/BOOTX64.EFI"))?;

    let iso = build.join("fluos.iso");
    run_cmd(
        Command::new("xorriso")
            .args(["-as", "mkisofs", "-quiet", "-R", "-r", "-J"])
            .args(["--efi-boot", "boot/limine/limine-uefi-cd.bin", "-efi-boot-part", "--efi-boot-image"])
            .arg("--protective-msdos-label")
            .arg(&iso_root)
            .arg("-o")
            .arg(&iso),
    )?;
    Ok(iso)
}
