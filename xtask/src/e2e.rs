//! End-to-end shell test: boot FluOS in QEMU, drive the interactive busybox
//! shell over the serial line, and assert on its output.
//!
//! The kernel exposes COM1 both as the log sink *and* (now) as a keyboard: the
//! serial RX interrupt feeds bytes into the console input queue. With QEMU's
//! `-serial stdio`, that means the child's stdin is the shell's keyboard and its
//! stdout carries kernel logs plus shell output interleaved. We wait for the
//! prompt, type commands, and scan the accumulated output for expected markers.

use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Overall ceiling: TCG on Apple Silicon is slow, and we run the full boot
/// (selftests) before the shell starts.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(240);

/// Shared, ever-growing capture of everything QEMU has written to serial.
type Capture = Arc<Mutex<String>>;

struct Console {
    stdin: std::process::ChildStdin,
    capture: Capture,
}

impl Console {
    /// Sends raw bytes to the guest's serial RX (its keyboard).
    fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.stdin.write_all(bytes).context("write to qemu stdin")?;
        self.stdin.flush().ok();
        Ok(())
    }

    /// Types a command line (appends a carriage return, as a terminal would).
    fn send_line(&mut self, line: &str) -> Result<()> {
        println!("[e2e] >> {line}");
        self.send_raw(line.as_bytes())?;
        self.send_raw(b"\r")
    }

    /// The length of the capture right now (a cursor for `wait_for_since`).
    fn mark(&self) -> usize {
        self.capture.lock().unwrap().len()
    }

    /// Waits until `needle` appears anywhere in the capture, or times out.
    fn wait_for(&self, needle: &str, timeout: Duration) -> Result<()> {
        self.wait_for_since(0, needle, timeout)
    }

    /// Waits until `needle` appears in the capture at or after byte offset
    /// `since` (so a command's echo of its own text isn't mistaken for output).
    fn wait_for_since(&self, since: usize, needle: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let cap = self.capture.lock().unwrap();
                if cap.len() >= since && cap[since..].contains(needle) {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                let tail: String = {
                    let cap = self.capture.lock().unwrap();
                    cap.chars().rev().take(600).collect::<String>().chars().rev().collect()
                };
                bail!("timed out waiting for {needle:?}. recent output:\n{tail}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

pub fn run(iso: &Path, smp: u32) -> Result<()> {
    use std::process::Stdio;

    let mut cmd = crate::qemu::base_command(iso, smp)?;
    cmd.args(["-display", "none"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn().context("failed to spawn qemu-system-x86_64")?;
    let stdin = child.stdin.take().context("qemu stdin")?;
    let mut stdout = child.stdout.take().context("qemu stdout")?;

    // Reader thread: drain QEMU's serial output into the shared capture and echo
    // it so a failing run shows the full boot log.
    let capture: Capture = Arc::new(Mutex::new(String::new()));
    let reader_cap = Arc::clone(&capture);
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]);
                    print!("{chunk}");
                    let _ = std::io::stdout().flush();
                    reader_cap.lock().unwrap().push_str(&chunk);
                }
            }
        }
    });

    let mut con = Console { stdin, capture: Arc::clone(&capture) };

    let result = drive(&mut con);

    // Tear down QEMU regardless of outcome.
    let _ = con.send_raw(b"\x01x"); // Ctrl-A x: tell QEMU to quit (best-effort)
    std::thread::sleep(Duration::from_millis(200));
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    result.map(|()| println!("\ne2e: all shell assertions passed"))
}

/// The scripted conversation with the shell. Each step is a small, independent
/// assertion so a failure points at exactly which shell feature broke.
fn drive(con: &mut Console) -> Result<()> {
    let start = Instant::now();
    let remaining = || TOTAL_TIMEOUT.saturating_sub(start.elapsed());

    // 1) Boot must complete and the shell must start.
    con.wait_for("boot complete", remaining())?;
    con.wait_for("init: shell started", remaining())?;
    // Give the shell a beat to print its first prompt.
    std::thread::sleep(Duration::from_millis(300));

    // 2) echo — arithmetic expansion so the expected text ("val=42") cannot be
    // satisfied by the terminal's echo of the typed command itself.
    let m = con.mark();
    con.send_line("echo val=$((21+21))")?;
    con.wait_for_since(m, "val=42", Duration::from_secs(20))?;

    // 3) ls lists the busybox applets directory (the marker is not in the cmd).
    let m = con.mark();
    con.send_line("ls /bin")?;
    con.wait_for_since(m, "busybox", Duration::from_secs(20))?;

    // 4) cat a known file from the initramfs (content, not the command).
    let m = con.mark();
    con.send_line("cat /etc/hostname")?;
    con.wait_for_since(m, "fluos", Duration::from_secs(20))?;

    // 5) a pipeline: echo | cat (exercises pipe2 + blocking pipe read/write and
    // the shell's fork/dup2 plumbing). Arithmetic keeps the marker out of the
    // typed command, so matching proves it flowed echo -> pipe -> cat -> tty.
    let m = con.mark();
    con.send_line("echo p$((6*7))x | cat")?;
    con.wait_for_since(m, "p42x", Duration::from_secs(25))?;

    // 6) Ctrl-C of a foreground job blocked in a tty read: the job must die and
    // the shell must survive and stay responsive. `cat` with no args blocks in
    // a (now signal-interruptible) read of the console; Ctrl-C delivers SIGINT
    // to the foreground group.
    let mcat = con.mark();
    con.send_line("cat")?;
    // Wait until the shell has (a) put the terminal in cooked mode (ISIG on) and
    // (b) handed the foreground to cat's own process group. Only then will the
    // kernel turn Ctrl-C into a SIGINT aimed at cat (not the shell). A fixed
    // delay would race the shell's fork + tcsetattr + tcsetpgrp under slow TCG.
    con.wait_for_since(mcat, "ISIG=true", Duration::from_secs(40))?;
    let mfg = con.mark();
    con.wait_for_since(mfg, "foreground pgrp ->", Duration::from_secs(40))?;
    std::thread::sleep(Duration::from_millis(400));
    let mkill = con.mark();
    con.send_raw(b"\x03")?; // Ctrl-C -> SIGINT to cat's foreground group
    // The foreground job must be killed by SIGINT, and the shell (which is in a
    // different process group) must survive and reclaim the terminal. Both are
    // kernel-side facts we can assert on deterministically, without racing the
    // shell's post-signal prompt handling under slow TCG.
    con.wait_for_since(mkill, "terminated by signal 2", Duration::from_secs(40))?;
    con.wait_for_since(mkill, "foreground pgrp -> 8", Duration::from_secs(40))?;

    // NOTE: a `cmd | cmd` pipeline is deferred to step 3 (pipe2 + blocking
    // reads with real wakeups); it is added here once pipes land.

    Ok(())
}
