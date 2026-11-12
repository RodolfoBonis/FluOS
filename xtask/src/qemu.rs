//! QEMU launcher for interactive runs and headless boot tests.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub enum Mode {
    Interactive,
    Test,
}

/// QEMU's process exit status for `QemuExitCode::Success` (0x10 << 1 | 1).
const TEST_SUCCESS_STATUS: i32 = 0x21;
/// TCG emulation on Apple Silicon is slow; leave generous headroom.
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

pub fn run(iso: &Path, mode: Mode, smp: u32) -> Result<()> {
    let mut cmd = Command::new("qemu-system-x86_64");
    // `thread=multi` runs each vCPU on its own host thread so SMP code is
    // exercised with real parallelism (not round-robin single-threaded TCG).
    cmd.args(["-machine", "q35", "-cpu", "max", "-m", "1G"])
        .args(["-accel", "tcg,thread=multi"])
        .args(["-smp", &smp.to_string()])
        .args(["-drive", &format!("if=pflash,format=raw,readonly=on,file={}", ovmf()?.display())])
        .arg("-cdrom")
        .arg(iso)
        .args(["-serial", "stdio", "-no-reboot"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);

    match mode {
        Mode::Interactive => crate::run_cmd(&mut cmd),
        Mode::Test => {
            cmd.args(["-display", "none"]);
            let mut child = cmd.spawn().context("failed to spawn qemu-system-x86_64")?;
            let started = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if started.elapsed() > TEST_TIMEOUT {
                    child.kill()?;
                    bail!("boot test timed out after {TEST_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            match status.code() {
                Some(TEST_SUCCESS_STATUS) => {
                    println!("boot test passed");
                    Ok(())
                }
                code => bail!("boot test failed: qemu exited with {code:?}"),
            }
        }
    }
}

/// UEFI firmware shipped with Homebrew's QEMU (or `$OVMF_CODE` if set).
fn ovmf() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("OVMF_CODE") {
        return Ok(path.into());
    }
    let candidates = [
        "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
        "/usr/local/share/qemu/edk2-x86_64-code.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/qemu/OVMF.fd",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .context("OVMF firmware not found; set OVMF_CODE")
}
