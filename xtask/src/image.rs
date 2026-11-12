//! Bootable UEFI ISO assembly.

use crate::{Profile, build_kernel, limine, root, run_cmd};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn limine_conf(cmdline: &str, with_initramfs: bool) -> String {
    let module = if with_initramfs {
        "    module_path: boot():/boot/initramfs\n    module_string: initramfs\n"
    } else {
        ""
    };
    format!(
        "timeout: 0\n\n/FluOS\n    protocol: limine\n    path: boot():/boot/kernel\n    cmdline: {cmdline}\n{module}"
    )
}

/// Locates an initramfs to embed: `$FLUOS_INITRAMFS` if set, else prefer the
/// ports-rootfs output, falling back to the kernel test image.
fn initramfs_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("FLUOS_INITRAMFS") {
        return Some(PathBuf::from(path));
    }
    let candidates = [
        root().join("build/initramfs.cpio"),
        root().join("build/kernel-test/initramfs.cpio"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Builds `build/fluos.iso` with the given kernel command line and returns its path.
pub fn build(profile: Profile, cmdline: &str) -> Result<PathBuf> {
    // `$FLUOS_CMDLINE` appends kernel cmdline options (e.g. `strace=zsh`) for
    // debugging, without threading a flag through every xtask subcommand.
    let extra = std::env::var("FLUOS_CMDLINE").unwrap_or_default();
    let cmdline = if extra.is_empty() {
        cmdline.to_string()
    } else if cmdline.is_empty() {
        extra
    } else {
        format!("{cmdline} {extra}")
    };
    let cmdline = cmdline.as_str();
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
    let initramfs = initramfs_path();
    if let Some(ref src) = initramfs {
        fs::copy(src, iso_root.join("boot/initramfs")).with_context(|| format!("copying {}", src.display()))?;
        eprintln!("xtask: bundled initramfs from {}", src.display());
    }
    fs::write(iso_root.join("boot/limine/limine.conf"), limine_conf(cmdline, initramfs.is_some()))?;
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
