# syntax=docker/dockerfile:1
#
# FluOS userland ports — reproducible static musl builds.
#
# Everything is built for linux/amd64 on an Alpine (musl-native) base, so the
# resulting binaries are statically linked musl ELFs that the FluOS kernel can
# load directly via its Linux syscall ABI. Build context is build/ports-cache
# (checksum-verified tarballs); the final `sysroot` stage is a FROM scratch
# image whose whole filesystem is exported to build/sysroot/.
#
# The host is arm64, so the x86_64 toolchain runs under QEMU emulation. To keep
# that reliable we (a) cap -j, (b) let build.sh retry around rare emulated-gcc
# segfaults, and (c) take TLS from Alpine's PREBUILT static OpenSSL instead of
# compiling a crypto library under emulation (mbedTLS reliably crashed cc1).
#
# Driver: ports/build.sh. Pins: ports/versions.env (kept in sync with ARGs).

ARG ALPINE=alpine:3.20
ARG RUST=rust:1.95.0-alpine3.22

# ---------------------------------------------------------------------------
# Common C build base: musl toolchain + static libs + size-tuned flags.
# ---------------------------------------------------------------------------
FROM ${ALPINE} AS cbase
RUN apk add --no-cache \
      build-base linux-headers \
      perl file xz \
      zlib-static zlib-dev \
      openssl-dev openssl-libs-static \
      autoconf automake libtool pkgconf mold
# -Os + section gc keeps the static binaries small; -s strips at link time.
ENV CFLAGS="-Os -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables" \
    CXXFLAGS="-Os -fomit-frame-pointer -ffunction-sections -fdata-sections" \
    LDFLAGS="-static -Wl,--gc-sections -s"
WORKDIR /src

# ---------------------------------------------------------------------------
# ncurses 6.5 — static libncursesw + the terminfo database.
# Provides xterm-256color and linux; we add a `fluos` entry aliasing
# xterm-256color so TERM=fluos works on the real console.
# ---------------------------------------------------------------------------
FROM cbase AS ncurses
ARG NCURSES_FILE=ncurses-6.5.tar.gz
COPY ${NCURSES_FILE} .
RUN mkdir ncurses && tar xf ${NCURSES_FILE} -C ncurses --strip-components=1
WORKDIR /src/ncurses
# Widec build for UTF-8; terminfo installed under /usr/share/terminfo.
RUN ./configure --prefix=/usr \
      --without-shared --without-debug --without-cxx-binding --without-ada \
      --without-tests --without-manpages \
      --enable-widec --enable-pc-files=no \
      --with-terminfo-dirs=/usr/share/terminfo \
      --with-default-terminfo-dir=/usr/share/terminfo \
      --enable-term-driver=no \
  && make -j2 \
  && make install DESTDIR=/out
# `fluos` terminal: a straight alias of xterm-256color (truecolor xterm).
# The `find ... -name '[A-Z]'` prune drops uppercase-NAMED terminals (LFT,
# X-hpterm, Eterm, …): on the case-insensitive macOS FS that build/sysroot is
# exported to, dirs like x/ and X/ would otherwise merge and lose xterm-256color.
RUN printf 'fluos|FluOS console (xterm-256color compatible),\n\tuse=xterm-256color,\n' > /tmp/fluos.ti \
  && TERMINFO=/out/usr/share/terminfo /out/usr/bin/tic -x -o /out/usr/share/terminfo /tmp/fluos.ti \
  && TERMINFO=/out/usr/share/terminfo /out/usr/bin/infocmp fluos >/dev/null \
  && find /out/usr/share/terminfo -mindepth 1 -maxdepth 1 -type d -name '[A-Z]' -exec rm -rf {} + \
  && echo "terminfo entries present:" \
  && ls /out/usr/share/terminfo/x | grep -E 'xterm-256color' \
  && ls /out/usr/share/terminfo/l | grep -E '^linux$' \
  && ls /out/usr/share/terminfo/f | grep -E '^fluos$'

# ---------------------------------------------------------------------------
# zsh 5.9 — fully static, all modules linked in (--disable-dynamic).
# ---------------------------------------------------------------------------
FROM cbase AS zsh
ARG ZSH_FILE=zsh-5.9.tar.xz
# ncurses headers + static lib land in /usr.
COPY --from=ncurses /out/ /
COPY ${ZSH_FILE} .
RUN mkdir zsh && tar xf ${ZSH_FILE} -C zsh --strip-components=1
WORKDIR /src/zsh
# Point zsh at ncursesw; statically link libc + ncurses into the binary.
# A non-dynamic zsh links only a small default module set; the rest (zsh/system,
# zsh/regex, zsh/mathfunc, zsh/stat, …) are needed by oh-my-zsh/zinit, so we
# flip every lib-free module to link=static in config.modules (per zsh INSTALL).
# --gc-sections is dropped here so the linker cannot drop the module table.
RUN CPPFLAGS="-I/usr/include/ncursesw" \
    LIBS="-lncursesw" \
    zsh_cv_sys_tcsetpgrp=yes \
    ac_cv_header_fcntl_h=yes \
    ./configure --prefix=/usr \
      --disable-dynamic \
      --enable-cflags="${CFLAGS}" \
      --enable-ldflags="-static -s" \
      --enable-multibyte \
      --disable-gdbm \
      --enable-fndir=/usr/share/zsh/functions \
      --enable-scriptdir=/usr/share/zsh/scripts \
  && ( cd Src && make prep ) \
  && sed -i 's/ link=no / link=static /; s/ auto=yes / auto=no /' config.modules \
  && sed -i -E '/^name=zsh\/(db\/gdbm|pcre|cap) /s/ link=static / link=no /' config.modules \
  && ( cd Src && make prep ) \
  && make -j2 \
  && make install DESTDIR=/out \
  && DESTDIR=/out /out/usr/bin/zsh -fc 'zmodload zsh/system && zmodload zsh/regex && zmodload zsh/mathfunc && zmodload zsh/zutil && echo "built zsh $ZSH_VERSION with modules"'

# ---------------------------------------------------------------------------
# curl 8.11.1 — static, OpenSSL backend (Alpine prebuilt), system CA bundle.
# ---------------------------------------------------------------------------
FROM cbase AS curl
ARG CURL_FILE=curl-8.11.1.tar.xz
COPY ${CURL_FILE} .
RUN mkdir curl && tar xf ${CURL_FILE} -C curl --strip-components=1
WORKDIR /src/curl
RUN ./configure --prefix=/usr \
      --disable-shared --enable-static \
      --with-openssl --without-libpsl --without-libidn2 --without-brotli --without-zstd \
      --without-nghttp2 --without-ngtcp2 \
      --disable-ldap --disable-ldaps --disable-manual --disable-docs \
      --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
  && make -j2 curl_LDFLAGS="-all-static" \
  && make install DESTDIR=/out \
  && file /out/usr/bin/curl

# ---------------------------------------------------------------------------
# git 2.47.1 — static; HTTPS transport via our static curl; blk-sha1.
# ---------------------------------------------------------------------------
FROM cbase AS git
ARG GIT_FILE=git-2.47.1.tar.xz
COPY --from=curl /out/ /
COPY ${GIT_FILE} .
RUN mkdir git && tar xf ${GIT_FILE} -C git --strip-components=1
WORKDIR /src/git
# Static link; pull curl's full static lib set (curl + openssl + z).
RUN make -j2 \
      NO_GETTEXT=1 NO_TCLTK=1 NO_PYTHON=1 NO_PERL=1 NO_OPENSSL=1 NO_EXPAT=1 \
      BLK_SHA1=1 NO_REGEX=NeedsStartEnd NO_INSTALL_HARDLINKS=1 NO_GITWEB=1 \
      CURL_CONFIG=/usr/bin/curl-config \
      CURL_LDFLAGS="$(/usr/bin/curl-config --static-libs)" \
      CFLAGS="${CFLAGS}" LDFLAGS="-static -s" \
      prefix=/usr all \
  && make \
      NO_GETTEXT=1 NO_TCLTK=1 NO_PYTHON=1 NO_PERL=1 NO_OPENSSL=1 NO_EXPAT=1 \
      BLK_SHA1=1 NO_REGEX=NeedsStartEnd NO_INSTALL_HARDLINKS=1 NO_GITWEB=1 \
      CURL_CONFIG=/usr/bin/curl-config \
      CURL_LDFLAGS="$(/usr/bin/curl-config --static-libs)" \
      CFLAGS="${CFLAGS}" LDFLAGS="-static -s" \
      prefix=/usr DESTDIR=/out install \
  && file /out/usr/bin/git

# ---------------------------------------------------------------------------
# fzf — upstream static Go binary (verified in build.sh), just unpacked.
# ---------------------------------------------------------------------------
FROM cbase AS fzf
ARG FZF_FILE=fzf-0.56.3-linux_amd64.tar.gz
COPY ${FZF_FILE} .
RUN mkdir -p /out/usr/bin && tar xf ${FZF_FILE} -C /out/usr/bin fzf \
  && chmod 0755 /out/usr/bin/fzf && file /out/usr/bin/fzf

# ---------------------------------------------------------------------------
# Rust base (amd64 musl → static by default).
# ---------------------------------------------------------------------------
FROM ${RUST} AS rustbase
RUN apk add --no-cache musl-dev make file mold
ENV CARGO_NET_RETRY=5 CARGO_BUILD_JOBS=4 CARGO_PROFILE_RELEASE_LTO=off RUSTFLAGS="-C strip=symbols -C link-arg=-fuse-ld=mold"

# ---------------------------------------------------------------------------
# starship (latest) — built from crates.io for x86_64-unknown-linux-musl.
# ---------------------------------------------------------------------------
FROM rustbase AS starship
ARG STARSHIP_VERSION=1.27.0
RUN cargo install starship --version ${STARSHIP_VERSION} --locked --root /out/usr \
  && rm -rf /out/usr/.crates.toml /out/usr/.crates2.json \
  && file /out/usr/bin/starship

# ---------------------------------------------------------------------------
# uutils-coreutils — multicall `coreutils` binary + per-utility symlinks.
# (stdbuf is skipped: its libstdbuf is a cdylib, impossible on static musl.)
# ---------------------------------------------------------------------------
FROM rustbase AS coreutils
WORKDIR /src
ARG COREUTILS_FILE=coreutils-0.12.0.tar.gz
COPY ${COREUTILS_FILE} .
RUN mkdir coreutils && tar xf ${COREUTILS_FILE} -C coreutils --strip-components=1
WORKDIR /src/coreutils
# MULTICALL=y → single `coreutils` binary; `install` lays down symlinks per util.
# COMPLETIONS/MANPAGES/LOCALES=n: the manpage/completion generator builds a
# second all-utils `uudoc` binary and runs it ~400x, which deadlocks under QEMU
# emulation. We do not ship manpages, so skip it entirely.
RUN make PROFILE=release MULTICALL=y SKIP_UTILS=stdbuf COMPLETIONS=n MANPAGES=n LOCALES=n PREFIX=/usr DESTDIR=/out install \
  && file /out/usr/bin/coreutils \
  && echo "coreutils symlinks:" && ls /out/usr/bin | head

# ---------------------------------------------------------------------------
# CA certificates (Mozilla bundle from Alpine).
# ---------------------------------------------------------------------------
FROM ${ALPINE} AS cacerts
RUN apk add --no-cache ca-certificates && update-ca-certificates 2>/dev/null || true

# ---------------------------------------------------------------------------
# Final sysroot: merge every /out tree into one FROM scratch image.
# Exported verbatim to build/sysroot/ by `docker build -o`.
# ---------------------------------------------------------------------------
FROM scratch AS sysroot
COPY --from=ncurses   /out/ /
COPY --from=zsh       /out/ /
COPY --from=curl      /out/ /
COPY --from=git       /out/ /
COPY --from=fzf       /out/ /
COPY --from=starship  /out/ /
COPY --from=coreutils /out/ /
COPY --from=cacerts   /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=cacerts   /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem
