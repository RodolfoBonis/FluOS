# colorls tab completion (bash-style; usable in zsh via bashcompinit).
# Mirrors the completion shipped by the colorls gem that colorls-rs reimplements.
_colorls() {
  local curr_arg
  curr_arg="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W '-1 -a --all -A --almost-all -d --dirs -f --files \
    -l --long -t -r --report --tree --gs --git-status \
    --sd --sort-dirs --group-directories-first --sf --sort-files \
    --dark --light -h --help' -- "$curr_arg") )
}
complete -F _colorls colorls
