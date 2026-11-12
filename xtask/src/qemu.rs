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

/// Headless boot-test deadline. TCG `thread=multi` on Apple Silicon multiplexes
/// every vCPU onto the host's few cores, so the full self-test boot gets slower
/// as `--smp` rises (cross-CPU TLB-shootdown IPI waits and lock contention
/// dominate). We budget a flat base plus a per-extra-vCPU allowance instead of a
/// single flat bound, so smp 8 isn't failed for a slowness that is inherent to
/// emulating 8 CPUs — not a code regression (e2e *command* latencies are
/// measured independently in `e2e.rs` and must not regress).
fn test_timeout(smp: u32) -> Duration {
    Duration::from_secs(120 + 20 * u64::from(smp.saturating_sub(1)))
}

/// Builds the shared QEMU command (machine, accel, firmware, ISO, serial on
/// stdio, debug-exit device). Callers add mode-specific flags.
pub fn base_command(iso: &Path, smp: u32) -> Result<Command> {
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
    Ok(cmd)
}

pub fn run(iso: &Path, mode: Mode, smp: u32) -> Result<()> {
    let mut cmd = base_command(iso, smp)?;

    match mode {
        Mode::Interactive => crate::run_cmd(&mut cmd),
        Mode::Test => {
            cmd.args(["-display", "none"]);
            let timeout = test_timeout(smp);
            let mut child = cmd.spawn().context("failed to spawn qemu-system-x86_64")?;
            let started = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if started.elapsed() > timeout {
                    child.kill()?;
                    bail!("boot test timed out after {timeout:?} (smp {smp})");
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
    let candidates = [        "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
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
