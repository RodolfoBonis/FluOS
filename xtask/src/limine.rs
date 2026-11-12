//! Fetches the pinned Limine binary release.

use crate::{root, run_cmd};
use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

const REPO: &str = "https://codeberg.org/Limine/Limine.git";
const TAG: &str = "v11.2.1-binary";

/// Directory with Limine's prebuilt EFI images, cloned on first use.
pub fn dir() -> Result<PathBuf> {
    let dir = root().join("build/limine").join(TAG);
    if !dir.join("BOOTX64.EFI").exists() {
        run_cmd(Command::new("git").args(["clone", "--quiet", "--depth=1", "--branch", TAG, REPO]).arg(&dir))?;
    }
    Ok(dir)
}
