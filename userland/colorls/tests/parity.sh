#!/usr/bin/env bash
# Diff our colorls output against the real Ruby gem across many flag
# combinations on a target directory. Byte-exact comparison with colors forced.
#
# Usage:
#   tests/parity.sh [TARGET_DIR]
#
# Env:
#   COLORLS_BIN  path to our binary   (default: target/debug/colorls)
#   GEM_BIN      path to the gem's bin (default: `colorls` on PATH)
#
# Exit status is the number of differing cases (0 == full parity).
set -u

TARGET="${1:-.}"
BIN="${COLORLS_BIN:-target/debug/colorls}"
GEM="${GEM_BIN:-colorls}"

# Resolve to absolute paths so `cd` into the target still finds them.
abspath() { case "$1" in /*) printf '%s' "$1";; *) printf '%s/%s' "$(pwd)" "$1";; esac; }
[ -x "$BIN" ] && BIN="$(abspath "$BIN")"
case "$GEM" in */*) GEM="$(abspath "$GEM")";; esac

if ! command -v "$GEM" >/dev/null 2>&1 && [ ! -x "$GEM" ]; then
  echo "reference gem not found (set GEM_BIN); skipping parity check" >&2
  exit 0
fi

# Fixed width so both sides agree when stdout is a pipe.
export COLUMNS=80

CASES=(
  "" "-l" "-la" "-a" "-A" "-1" "-x" "-C" "-d" "-f"
  "-t" "-X" "-U" "-r" "--sd" "--sf" "-l -t" "-l -X"
  "--tree" "--tree=1" "--tree=2" "--report" "--report=short"
  "-l -o" "-l -g" "-l -G" "--without-icons" "-l --non-human-readable"
  "-i" "-l -i" "--light" "-l --light"
)

fails=0
for args in "${CASES[@]}"; do
  if diff \
      <(cd "$TARGET" && "$GEM" $args --color=always 2>&1) \
      <(cd "$TARGET" && "$BIN" $args --color=always 2>&1) >/dev/null 2>&1; then
    printf 'OK    colorls %s\n' "$args"
  else
    printf 'DIFF  colorls %s\n' "$args"
    fails=$((fails + 1))
  fi
done

echo "----"
echo "$fails differing case(s) out of ${#CASES[@]}"
exit "$fails"
