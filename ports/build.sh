#!/usr/bin/env bash
#
# FluOS userland ports driver.
#
#   ports/build.sh            # fetch (cached) + verify + build everything
#   ports/build.sh --verify   # only re-verify cached tarball checksums
#
# Produces build/sysroot/ : a static musl install tree (usr/bin, usr/share/...,
# etc/ssl/certs) that feeds the rootfs assembly in `cargo xtask rootfs`.
#
# Design: checksums are verified on the HOST before any byte enters the Docker
# build context, builds run in linux/amd64 Docker (musl-native Alpine), and the
# final sysroot is exported from a FROM scratch stage. See ports/Dockerfile.
#
# Note on emulation: the host is arm64; the x86_64 compilers run under QEMU
# user emulation, which occasionally segfaults mid-compile. BuildKit caches
# every COMPLETED stage, so we simply retry the whole build a few times — each
# attempt resumes from the last good stage until everything is through.
set -euo pipefail

PORTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${PORTS_DIR}/.." && pwd)"
CACHE_DIR="${REPO_ROOT}/build/ports-cache"
SYSROOT_DIR="${REPO_ROOT}/build/sysroot"
PLATFORM="linux/amd64"
ALPINE="alpine:3.20"
MAX_ATTEMPTS="${PORTS_BUILD_ATTEMPTS:-20}"

# shellcheck disable=SC1091
source "${PORTS_DIR}/versions.env"

log()  { printf '\033[1;34m[ports]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ports:warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ports:error]\033[0m %s\n' "$*" >&2; exit 1; }

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

# fetch <url> <file> <sha256>
fetch() {
  local url="$1" file="$2" want="$3" path="${CACHE_DIR}/$2"
  if [ -f "${path}" ] && [ "$(sha256 "${path}")" = "${want}" ]; then
    log "cached ok: ${file}"
    return
  fi
  log "fetching: ${file}"
  curl -fL --retry 3 -o "${path}" "${url}"
  local got; got="$(sha256 "${path}")"
  [ "${got}" = "${want}" ] || die "checksum mismatch for ${file}: got ${got} want ${want}"
  log "verified: ${file}"
}

verify_all() {
  mkdir -p "${CACHE_DIR}"
  fetch "${ZSH_URL}"       "${ZSH_FILE}"       "${ZSH_SHA256}"
  fetch "${NCURSES_URL}"   "${NCURSES_FILE}"   "${NCURSES_SHA256}"
  fetch "${CURL_URL}"      "${CURL_FILE}"      "${CURL_SHA256}"
  fetch "${GIT_URL}"       "${GIT_FILE}"       "${GIT_SHA256}"
  fetch "${COREUTILS_URL}" "${COREUTILS_FILE}" "${COREUTILS_SHA256}"
  fetch "${FZF_URL}"       "${FZF_FILE}"       "${FZF_SHA256}"
}

# docker_build_retry <description> <docker build args...>
# Retries up to MAX_ATTEMPTS; BuildKit's stage cache makes each retry resume.
docker_build_retry() {
  local desc="$1"; shift
  local attempt=1
  while :; do
    log "${desc} (attempt ${attempt}/${MAX_ATTEMPTS})"
    if DOCKER_BUILDKIT=1 docker build "$@"; then
      return 0
    fi
    if [ "${attempt}" -ge "${MAX_ATTEMPTS}" ]; then
      die "${desc} failed after ${MAX_ATTEMPTS} attempts"
    fi
    warn "${desc} attempt ${attempt} failed (likely an emulation segfault) — retrying…"
    attempt=$((attempt + 1))
    sleep 3
  done
}

if [ "${1:-}" = "--verify" ]; then
  verify_all
  log "all checksums verified."
  exit 0
fi

command -v docker >/dev/null || die "docker not found on PATH"
verify_all

# ---------------------------------------------------------------------------
# Pre-build EVERY compile stage in isolation FIRST, in dependency order, each
# with its own retry. Under QEMU emulation the x86_64 compiler segfaults at
# random points; per-stage builds let BuildKit cache each success, so a retry
# only redoes the one flaky stage instead of the whole pipeline (which never
# converged when one segfault anywhere failed all stages at once).
# ---------------------------------------------------------------------------
for tgt in ncurses curl zsh git fzf starship coreutils; do
  docker_build_retry "stage: ${tgt}" \
    --platform "${PLATFORM}" \
    --target "${tgt}" \
    --build-arg ZSH_FILE="${ZSH_FILE}" \
    --build-arg NCURSES_FILE="${NCURSES_FILE}" \
    --build-arg CURL_FILE="${CURL_FILE}" \
    --build-arg GIT_FILE="${GIT_FILE}" \
    --build-arg COREUTILS_FILE="${COREUTILS_FILE}" \
    --build-arg FZF_FILE="${FZF_FILE}" \
    --build-arg STARSHIP_VERSION="${STARSHIP_VERSION}" \
    -f "${PORTS_DIR}/Dockerfile" \
    "${CACHE_DIR}"
done

# ---------------------------------------------------------------------------
# Build the sysroot. BuildKit exports the FROM scratch `sysroot` stage verbatim.
# ---------------------------------------------------------------------------
log "building ports sysroot (${PLATFORM}) → ${SYSROOT_DIR}"
rm -rf "${SYSROOT_DIR}"
mkdir -p "${SYSROOT_DIR}"
docker_build_retry "ports sysroot" \
  --platform "${PLATFORM}" \
  --target sysroot \
  --build-arg ZSH_FILE="${ZSH_FILE}" \
  --build-arg NCURSES_FILE="${NCURSES_FILE}" \
  --build-arg CURL_FILE="${CURL_FILE}" \
  --build-arg GIT_FILE="${GIT_FILE}" \
  --build-arg COREUTILS_FILE="${COREUTILS_FILE}" \
  --build-arg FZF_FILE="${FZF_FILE}" \
  --build-arg STARSHIP_VERSION="${STARSHIP_VERSION}" \
  -f "${PORTS_DIR}/Dockerfile" \
  -o "type=local,dest=${SYSROOT_DIR}" \
  "${CACHE_DIR}"

# ---------------------------------------------------------------------------
# colorls (userland/colorls) — built here if the crate exists, else skipped.
# ---------------------------------------------------------------------------
COLORLS_SRC="${REPO_ROOT}/userland/colorls"
if [ -d "${COLORLS_SRC}" ] && [ -f "${COLORLS_SRC}/Cargo.toml" ]; then
  # Best-effort: colorls is a concurrently-developed crate, so a failure warns
  # and continues instead of failing the whole ports build.
  colorls_ok=0
  for attempt in 1 2 3 4; do
    log "colorls build (attempt ${attempt}/4)"
    if DOCKER_BUILDKIT=1 docker build \
         --platform "${PLATFORM}" \
         -f "${PORTS_DIR}/Dockerfile.colorls" \
         -o "type=local,dest=${SYSROOT_DIR}" \
         "${COLORLS_SRC}"; then
      colorls_ok=1; break
    fi
    sleep 3
  done
  if [ "${colorls_ok}" = 1 ]; then
    log "colorls built -> ${SYSROOT_DIR}/usr/bin/colorls"
  else
    warn "colorls FAILED to build (WIP crate) - shipping without it; alias ls=colorls no-ops until it builds."
  fi
else
  warn "SKIPPED colorls: ${COLORLS_SRC} not found yet."
  warn "   The rootfs will still ship (alias ls=colorls will no-op until colorls lands)."
  warn "   Re-run ports/build.sh once userland/colorls exists to populate usr/bin/colorls."
fi

# ---------------------------------------------------------------------------
# Verify every shipped ELF is statically linked (no interpreter, no NEEDED).
# ---------------------------------------------------------------------------
log "verifying static linkage of all binaries in sysroot…"
FAIL=0
while IFS= read -r -d '' bin; do
  head -c4 "${bin}" | grep -q $'\x7fELF' || continue
  info="$(docker run --rm --platform "${PLATFORM}" -v "${SYSROOT_DIR}:/s:ro" \
            "${ALPINE}" sh -c "apk add --no-cache file >/dev/null 2>&1; file /s${bin#${SYSROOT_DIR}}" 2>/dev/null || true)"
  if echo "${info}" | grep -q "dynamically linked"; then
    warn "NOT STATIC: ${info}"
    FAIL=1
  else
    log "static ok: ${bin#${SYSROOT_DIR}/}  ($(du -h "${bin}" | awk '{print $1}'))"
  fi
done < <(find "${SYSROOT_DIR}/usr/bin" -maxdepth 1 -type f -print0 2>/dev/null)

[ "${FAIL}" = "0" ] || die "one or more binaries are not statically linked"
log "ports build complete. sysroot at ${SYSROOT_DIR}"
du -sh "${SYSROOT_DIR}" | awk '{print "[ports] sysroot size: "$1}'
