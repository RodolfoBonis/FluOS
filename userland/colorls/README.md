# colorls (Rust)

A fast, dependency-light Rust reimplementation of the Ruby gem
[`colorls` 1.5.0](https://github.com/athityakumar/colorls), built for the FluOS
userland (static musl Linux binaries). It aims to be a **drop-in replacement**:

```sh
alias ls=colorls
```

Output is **byte-for-byte identical** to the reference gem across the supported
feature set (verified with `tests/parity.sh`, see below).

## Why

Ruby `colorls` spends ~250 ms per invocation (interpreter + gem startup) on a
~600-entry directory. This port runs the same listing in ~29 ms — roughly
**8–9× faster** — with no runtime interpreter, no YAML parsing at startup, and a
single static binary suitable for FluOS.

## Features

| Area | Flags |
|------|-------|
| Filtering | `-a/--all`, `-A/--almost-all`, `-d/--dirs`, `-f/--files` |
| Format | `-1`, `-l/--long`, `-x`, `-C`, `--format=WORD`, `--tree[=DEPTH]`, `--without-icons` |
| Long opts | `-o`, `-g`, `-G/--no-group`, `--time-style=FORMAT`, `--no-hardlinks`, `-L`, `--non-human-readable` |
| Sorting | `-t`, `-S`, `-X`, `-U`, `-r/--reverse`, `--sd/--sort-dirs/--group-directories-first`, `--sf/--sort-files`, `--sort=WORD` |
| Git | `--gs/--git-status` (native, no `git` spawn) and the long-format git column |
| Misc | `-i/--inode`, `-p`, `--indicator-style`, `--report[=WORD]`, `--light`/`--dark`, `--hyperlink`, `-h`, `--help`, `--version` |

Also supported: multiple paths, `NO_COLOR`, `--color=always|auto|never`, and user
overrides in `~/.config/colorls/*.yaml` (icons, aliases, and color schemes),
exactly like the gem.

### Icons, colors, and data

The gem's YAML tables (`files.yaml`, `folders.yaml`, `*_aliases.yaml`,
`dark_colors.yaml`, `light_colors.yaml`) are **vendored** under `data/` and
parsed **at build time** (`build.rs`) into static `phf` maps — there is zero
YAML parsing on startup. The color-name → ANSI escape mapping in
`data/colors_x11.tsv` was captured directly from the gem's Rainbow dependency so
our escapes match byte-for-byte (base ANSI names render as `\e[3Nm`, X11 names as
the nearest `\e[38;5;Km`). Nerd Font glyphs are treated as single-width (Mono).

The vendored data is MIT-licensed; see `data/COLORLS-LICENSE.md`.

## Terminal width

Column layout sizes to the terminal width via `TIOCGWINSZ` on stdout/stderr,
falling back to `$COLUMNS`, then `80` — matching the gem. When stdout is not a
TTY the gem (and this port) switch to one-entry-per-line.

## Building

### Host

```sh
cargo build -p colorls --release
# binary at target/release/colorls
```

### Static musl (x86_64) for FluOS

The binary is portable (no macOS-only APIs; all syscalls go through `libc`), so
it cross-compiles to a fully static `x86_64-unknown-linux-musl` binary.

**With Docker (used by the ports pipeline):**

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD/userland/colorls":/src -w /src rust:alpine sh -c '
    apk add --no-cache musl-dev
    cargo build --release --target x86_64-unknown-linux-musl
  '
# binary at target/x86_64-unknown-linux-musl/release/colorls (static)
```

`rust:alpine` targets musl by default, so the result is statically linked
(`file` reports "statically linked"). Verify with `ldd` (should print
"not a dynamic executable").

**With cargo-zigbuild (no Docker):**

```sh
rustup target add x86_64-unknown-linux-musl
cargo zigbuild -p colorls --release --target x86_64-unknown-linux-musl
```

## Testing

```sh
cargo test -p colorls          # 24 unit + 10 integration tests
```

### Parity against the real gem

`tests/parity.sh` diffs our output against the installed gem across 32 flag
combinations on a target directory (colors forced, fixed `COLUMNS`):

```sh
COLORLS_BIN=target/release/colorls \
GEM_BIN=/path/to/gem/bin/colorls \
  bash tests/parity.sh /opt/homebrew/bin
# -> "0 differing case(s) out of 32"
```

## Intentional differences / limitations

These are the only known deviations from the gem; everything else is byte-exact.

1. **Git staged-vs-HEAD (`X` column).** Our native git reader reads `.git/index`
   and walks the worktree to detect **modified (`M`)**, **deleted (`D`)**,
   **untracked (`?`)**, and **ignored (`!`, rendered blank)** — all byte-exact.
   It deliberately does **not** decode packfiles/objects to compare the index
   against `HEAD`, so purely *staged* changes (a freshly `git add`ed new file
   that the gem shows as `A`, or a staged modification shown in the `X` column)
   render by their worktree state instead. This keeps the binary small and fully
   static, as prioritized for FluOS. Worktree status — what matters most for an
   interactive `ls` — is exact.

2. **`.gitignore` subset.** Ignore matching supports comments, `name`, `name/`
   (dir-only), `/anchored`, and `*`/`?` globs. It does not implement `**` or
   character classes. Common patterns (`target/`, `*.log`, `node_modules/`)
   behave correctly.

3. **Tie ordering under `-S`/`-t`.** When multiple entries share a sort key
   (e.g. identical sizes), Ruby's `sort_by` is **not stable**, so its order of
   equal-key entries is unspecified. Ours uses a **stable** sort, so the listing
   is deterministic but may order equal-key entries differently from a given gem
   run. Names (the default sort) are unique, so the default listing is exact.

4. **Locale collation.** Sorting uses the C library `strxfrm` under
   `LC_COLLATE` (as the gem does via `clocale`), so ordering matches the host's
   locale. On musl/FluOS the collation is C-like.
