# FluOS backlog

Ideas parked for later. The milestone plan (M0–M10) lives in the approved plan; this file holds what comes after or alongside it.

## fluos-utils: our own userland utilities

**When:** after M9 (final shell environment).

**Why:** today the base utilities are third-party:
- uutils/coreutils (MIT) for `ls`, `cat`, `cp` and the rest;
- busybox (GPL), temporarily, while zsh isn't ready.

Writing our own utilities makes more of the system FluOS-native.

**Scope, by value:**
1. **System utilities first:** `ps`, `top`, `free`, `dmesg`, `uptime`, `lscpu`, `mount`. These can read FluOS kernel stats directly (`/proc/fluos/stats`, the log ring buffer) and expose things generic tools can't: per-CPU runqueues, work-steal counters, EEVDF lag, buddy/slab usage.
2. **Base file utilities:** `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir` and so on. Lower value, since uutils is already Rust and well tested. Do these only if the goal is a fully in-house userland.

**Shape:** a single Rust multicall binary at `userland/fluos-utils`, the same pattern as colorls and uutils. It builds static for `x86_64-unknown-linux-musl`.

## Own FluOS syscall ABI (optional)

The kernel implements the Linux syscall ABI so existing binaries run unmodified. A native FluOS ABI could sit alongside it, selected per process, e.g. by an ELF note. New FluOS-specific programs would use it.
