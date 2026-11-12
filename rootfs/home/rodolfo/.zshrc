# FluOS ~/.zshrc — a sanitized port of the Mac ~/.zshrc.
#
# Everything macOS-specific was dropped (brew, conda, nvm, sdkman, rvm, pyenv,
# Android, fvm/Flutter, iTerm, pnpm, kube, vault, openrouter, gcloud, the ARCHS
# exports, SSH_AUTH_SOCK, Mac-path aliases). What remains is the actual shell
# environment: oh-my-zsh, the three zinit plugins (pre-cloned so the first boot
# needs no network), fzf, `alias ls=colorls`, and starship as the prompt.

# Locale — the whole UI assumes UTF-8.
export LC_ALL="en_US.UTF-8"
export LANG="en_US.UTF-8"

# ---------------------------------------------------------------------------
# oh-my-zsh
# The default theme is disabled on purpose: starship (below) draws the prompt.
# No plugins=() is set, matching the Mac config (oh-my-zsh loads none of its own).
# ---------------------------------------------------------------------------
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME=""                 # starship owns the prompt
DISABLE_AUTO_UPDATE="true"   # no network on boot
source "$ZSH/oh-my-zsh.sh"

# ---------------------------------------------------------------------------
# zinit — plugin manager. zinit itself and the three plugins are pre-cloned at
# build time into ~/.local/share/zinit, so `zinit light` loads them offline.
# ---------------------------------------------------------------------------
if [[ ! -f $HOME/.local/share/zinit/zinit.git/zinit.zsh ]]; then
    print -P "%F{160} zinit not found — the pre-cloned copy is missing.%f"
fi
source "$HOME/.local/share/zinit/zinit.git/zinit.zsh"
autoload -Uz _zinit
(( ${+_comps} )) && _comps[zinit]=_zinit

zinit light zdharma-continuum/fast-syntax-highlighting
zinit light zsh-users/zsh-autosuggestions
zinit light zsh-users/zsh-completions

# ---------------------------------------------------------------------------
# fzf — keybindings (Ctrl-R / Ctrl-T / Alt-C) and fuzzy completion.
# The static fzf binary emits its own zsh integration, so no ~/.fzf.zsh needed.
# ---------------------------------------------------------------------------
if command -v fzf >/dev/null 2>&1; then
  eval "$(fzf --zsh)"
fi

# ---------------------------------------------------------------------------
# colorls — `ls` is colorls, plus its tab completion.
# ---------------------------------------------------------------------------
alias ls="colorls"
# colorls ships a bash-style completion; bashcompinit lets zsh use it.
autoload -Uz bashcompinit && bashcompinit
_colorls_tc=/usr/share/colorls/tab_complete.sh
[ -f "$_colorls_tc" ] && source "$_colorls_tc"

# ---------------------------------------------------------------------------
# starship — the prompt. Must be last so nothing overrides it.
# ---------------------------------------------------------------------------
eval "$(starship init zsh)"
