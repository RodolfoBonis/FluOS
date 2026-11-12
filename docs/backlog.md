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

## Native containers that run Docker Hub images

**Decision (2026-11-12):** containers will be FluOS-native, not a reimplementation of Linux namespaces/cgroups/overlayfs. The goal is to pull and run OCI images from Docker Hub and other registries.

**Why native:** Docker/runc depend on Linux-specific kernel machinery: namespaces, cgroups v2, overlayfs, netfilter, seccomp. Reimplementing all of it compatibly is a multi-year effort; WSL1 never managed it. The kernel is ours, so isolation can be designed in from the start. Image compatibility comes from the OCI image format, which is just tarballs plus JSON, together with our Linux syscall ABI that runs the binaries inside them.

**When:** after v1 (M10). It depends on network/TLS (M7) and persistent storage (M6).

**Kernel prerequisites (beyond the v1 plan):**
- **Dynamic linking.** Most images ship dynamically linked binaries (glibc or musl ld.so). We need ELF `PT_INTERP`, file-backed `mmap`, `mprotect` and `MAP_FIXED` semantics good enough for `ld-linux-x86-64.so.2` and `ld-musl-x86_64.so.1`. This is the single biggest compatibility item.
- **Isolation primitives:**
  - per-container root filesystem view (a native equivalent of chroot/mount namespace);
  - PID view: the container sees its own PID 1;
  - hostname/UTS;
  - per-container resource limits: CPU share through the EEVDF weights we already have, a memory cap, a pid cap;
  - optionally a syscall allowlist.
- **Layered filesystem:** a union/overlay of read-only image layers plus a writable layer. It must honor OCI whiteouts (`.wh.` files and opaque dirs).
- **Container networking:** virtual interfaces per container, NAT and port publishing (`-p 8080:80`) on top of the M7 smoltcp stack.
- **Linux userland surface images expect:** `/proc` and `/sys` subsets, `/etc/resolv.conf` and `/etc/hosts` injection, users/uid mapping, and `/dev` basics.

**Userland tooling** (our own, in Rust):
- `flc` CLI (name TBD) with `pull`, `run`, `ps`, `stop`, `rm`, `images`, `logs`, `exec`.
- Registry client for the OCI Distribution API: Docker Hub token auth, manifest lists/multi-arch selection (linux/amd64), layer download with digest verification.
- Image store: content-addressed blobs plus unpacked layers on the persistent disk.
- Image config: Entrypoint/Cmd/Env/WorkingDir/User/ExposedPorts.

**Later / optional:**
- Docker Engine API compatibility, so the stock `docker` CLI and docker-compose can talk to FluOS.
- Kubernetes would need a CRI implementation on top of this. Out of scope until containers are solid.

**First validation targets:** `alpine` (musl, static-ish), then `debian`/`ubuntu` (glibc dynamic), then `nginx` (networking + ports), then `postgres` (heavier syscalls, shared memory).

## Own FluOS syscall ABI (optional)

The kernel implements the Linux syscall ABI so existing binaries run unmodified. A native FluOS ABI could sit alongside it, selected per process, e.g. by an ELF note. New FluOS-specific programs would use it.
