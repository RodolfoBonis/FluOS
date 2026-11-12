#!/usr/bin/env bash
#
# FluOS userland smoke test.
#
# The FluOS kernel can't run these binaries yet, so we prove the userland is
# correct independently: we import the assembled rootfs (build/rootfs/) as the
# root filesystem of a linux/amd64 container and drive `zsh -i` as rodolfo,
# non-interactively.
#
# Verifies:
#   1. oh-my-zsh loads;
#   2. zinit loads the 3 plugins OFFLINE (`--network none`);
#   3. starship renders the prompt;
#   4. colorls runs (skipped with a warning if colorls wasn't built);
#   5. git and curl run.
#
# Also captures the exact syscall set (strace -f -c) that zsh/starship/colorls/
# git/curl touch, into ports/syscalls.txt — the input for kernel milestone M4.
#
# Usage: ports/smoke-test.sh      (assumes `cargo xtask rootfs` already ran)
set -uo pipefail

PORTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${PORTS_DIR}/.." && pwd)"
ROOTFS="${REPO_ROOT}/build/rootfs"
PLATFORM="linux/amd64"
RAW_IMAGE="fluos-rootfs:raw"
IMAGE="fluos-rootfs:smoke"
RUN_ENV=(-e HOME=/home/rodolfo -e USER=rodolfo -e LOGNAME=rodolfo
         -e TERM=xterm-256color -e TERMINFO=/usr/share/terminfo -e ZSH_DISABLE_COMPFIX=true)

pass=0; fail=0
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); }
warn() { printf '  \033[1;33mSKIP\033[0m %s\n' "$*"; }
hd()   { printf '\n\033[1;34m== %s ==\033[0m\n' "$*"; }

[ -d "${ROOTFS}/usr/bin" ] || { echo "no ${ROOTFS}; run 'cargo xtask rootfs' first" >&2; exit 1; }

hd "Building ${IMAGE} from ${ROOTFS}"
# Import the assembled tree, then a one-line build gives /home/rodolfo the right
# ownership (uid 1000 — the import carries the macOS uid) and sets USER rodolfo,
# so the shell truly runs as rodolfo, exactly as on real FluOS.
COPYFILE_DISABLE=1 tar --no-mac-metadata --numeric-owner -C "${ROOTFS}" -cf - . \
  | docker import --platform "${PLATFORM}" - "${RAW_IMAGE}" >/dev/null
printf 'FROM %s\nRUN ["/usr/bin/coreutils","chown","-R","1000:1000","/home/rodolfo"]\nENV PATH=/usr/bin:/bin:/usr/sbin:/sbin\nUSER 1000:1000\n' "${RAW_IMAGE}" \
  | docker build --platform "${PLATFORM}" -t "${IMAGE}" - >/dev/null
echo "built $(docker image inspect "${IMAGE}" --format '{{.Size}}' | awk '{printf "%.1f MiB\n",$1/1048576}')"

# Helper: run a zsh -i -c snippet in the image as rodolfo (offline by default).
zrun() { docker run --rm --network none --platform "${PLATFORM}" "${RUN_ENV[@]}" "${IMAGE}" /usr/bin/zsh -i -c "$1" 2>&1; }

# --- 1. oh-my-zsh -----------------------------------------------------------
hd "1. oh-my-zsh"
out="$(zrun 'echo "OMZ ZSH=$ZSH"; echo "OMZ CACHE=$ZSH_CACHE_DIR"; echo "ZSHVER=$ZSH_VERSION"')"
echo "${out}" | sed 's/^/    /'
echo "${out}" | grep -q 'OMZ ZSH=/home/rodolfo/.oh-my-zsh' && echo "${out}" | grep -q 'ZSHVER=5.9' \
  && ok "oh-my-zsh sourced, zsh 5.9" || bad "oh-my-zsh did not load"

# --- 2. zinit + 3 plugins, OFFLINE -----------------------------------------
hd "2. zinit plugins (offline, --network none)"
out="$(zrun '
  # grep-free, zsh-native checks (uutils ships no grep).
  (( $+functions[_zsh_autosuggest_start] ))                  && echo PLUG_AUTOSUGGEST_OK
  { (( $+functions[fast-theme] )) || [[ -n $FAST_HIGHLIGHT_VERSION ]]; } && echo PLUG_FSH_OK
  { [[ -n ${zsh_loaded_plugins[(r)*zsh-completions*]} ]] \
      || [[ -n ${fpath[(r)*zsh-completions*]} ]]; }         && echo PLUG_COMPLETIONS_OK
  echo "LOADED (zsh_loaded_plugins):"; print -l $zsh_loaded_plugins
')"
echo "${out}" | sed 's/^/    /'
[ "$(echo "${out}" | grep -c PLUG_AUTOSUGGEST_OK)" = 1 ] && ok "zsh-autosuggestions loaded offline" || bad "zsh-autosuggestions missing"
[ "$(echo "${out}" | grep -c PLUG_FSH_OK)" = 1 ]        && ok "fast-syntax-highlighting loaded offline" || bad "fast-syntax-highlighting missing"
[ "$(echo "${out}" | grep -c PLUG_COMPLETIONS_OK)" = 1 ] && ok "zsh-completions on fpath offline" || bad "zsh-completions missing"

# --- 3. starship ------------------------------------------------------------
hd "3. starship prompt"
out="$(zrun 'STARSHIP_CONFIG=$HOME/.config/starship.toml starship prompt --status=0 2>&1 | head -c 400; echo')"
echo "${out}" | sed 's/^/    /'
[ -n "${out//[$'\n\t ']/}" ] && ok "starship rendered a prompt" || bad "starship produced no output"

# --- 4. colorls -------------------------------------------------------------
hd "4. colorls"
if docker run --rm --network none --platform "${PLATFORM}" "${RUN_ENV[@]}" "${IMAGE}" \
     sh -c 'command -v colorls >/dev/null'; then
  out="$(zrun 'colorls --version 2>&1 | head -1; colorls -1 /usr/bin 2>&1 | head -3')"
  echo "${out}" | sed 's/^/    /'
  ok "colorls runs"
else
  warn "colorls not in image (userland/colorls not built) — alias ls=colorls is a no-op for now"
fi

# --- 5. git + curl ----------------------------------------------------------
hd "5. git + curl"
gout="$(zrun 'git --version')";  echo "    ${gout}"
cout="$(zrun 'curl --version | head -1')"; echo "    ${cout}"
echo "${gout}" | grep -q '^git version 2' && ok "git runs" || bad "git failed"
echo "${cout}" | grep -q '^curl 8'        && ok "curl runs" || bad "curl failed"

# --- syscall capture --------------------------------------------------------
hd "Syscall capture (qemu-x86_64 -strace) → ports/syscalls.txt"
# ptrace of Rosetta processes does not work, so we decode guest syscalls with
# `qemu-x86_64 -strace` (native arm64 emulator). Each static tool is traced
# individually (no nested execs) with env/CWD pointed at a copy of the rootfs.
SYSCALLS="${PORTS_DIR}/syscalls.txt"
docker run --rm --platform linux/arm64 \
  -v "${ROOTFS}:/rootfs:ro" \
  alpine:3.20 sh -c '
    apk add --no-cache qemu-x86_64 >/dev/null 2>&1 || { echo NOQEMU; exit 0; }
    cp -a /rootfs /rw
    Q="qemu-x86_64 -strace -L /rw -E HOME=/rw/home/rodolfo -E TERM=xterm-256color -E TERMINFO=/rw/usr/share/terminfo -E STARSHIP_CONFIG=/rw/home/rodolfo/.config/starship.toml -E PATH=/rw/usr/bin"
    # zsh core + the statically-linked modules oh-my-zsh/zinit rely on.
    $Q /rw/usr/bin/zsh -fc "zmodload zsh/system zsh/regex zsh/mathfunc zsh/zutil zsh/stat zsh/datetime zsh/terminfo; sysread -s4 v </rw/etc/os-release 2>/dev/null; strftime \"%Y\" 0 >/dev/null; : \${(L)PATH}; cd / && pwd >/dev/null; typeset -p PATH >/dev/null"
    # starship prompt (reads its toml, queries cwd/git/time).
    cd /rw/home/rodolfo && $Q /rw/usr/bin/starship prompt --status=0
    # git: version + a real init/add/commit to exercise the write path.
    $Q /rw/usr/bin/git --version
    rm -rf /tmp/r; mkdir /tmp/r; cd /tmp/r
    $Q /rw/usr/bin/git init
    echo hi > f; $Q /rw/usr/bin/git add f
    # curl + colorls + a spread of uutils coreutils applets.
    $Q /rw/usr/bin/curl --version
    $Q /rw/usr/bin/colorls -1 /rw/usr/bin 2>/dev/null
    for u in ls cat cp mkdir stat date env uname wc sort head; do $Q /rw/usr/bin/$u --help >/dev/null 2>/dev/null || $Q /rw/usr/bin/$u / >/dev/null 2>/dev/null; done
  ' > "${SYSCALLS}.raw" 2>&1

names="$(sed -nE 's/^[0-9]+ +//; s/^([a-z_][a-z0-9_]*)\(.*/\1/p' "${SYSCALLS}.raw" 2>/dev/null | sort -u | sed '/^$/d')"
count="$(printf '%s\n' "${names}" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "${count:-0}" -ge 20 ] 2>/dev/null; then
  {
    echo "# FluOS userland syscall footprint"
    echo "#"
    echo "# Captured by ports/smoke-test.sh with qemu-x86_64 -strace, tracing the"
    echo "# actual static musl binaries: zsh 5.9 + its modules, starship, git"
    echo "# (version + init + add), curl, colorls, and uutils coreutils applets."
    echo "# ${count} distinct syscalls — the set the FluOS kernel must implement (M4)."
    echo "# Generated $(date -u +%Y-%m-%dT%H:%MZ)."
    echo "#"
    echo "# --- distinct syscalls (sorted) ---"
    printf '%s\n' "${names}"
    echo ""
    echo "# --- one-line list ---"
    printf '%s\n' "${names}" | paste -sd' ' -
  } > "${SYSCALLS}"
  rm -f "${SYSCALLS}.raw"
  ok "syscalls captured → ports/syscalls.txt (${count} distinct)"
else
  rm -f "${SYSCALLS}.raw"
  bad "syscall capture produced too few results (${count:-0})"
fi

hd "Result"
echo "  PASS=${pass}  FAIL=${fail}"
[ "${fail}" = 0 ]
