#!/bin/bash
# Vendored from https://github.com/paxtonhare/demo-magic (MIT).
# Provides `pe` (print + execute with simulated typing) and `p` (print only).

TYPE_SPEED=${TYPE_SPEED:-30}
COLOR_RESET="\033[0m"
GREEN="\033[32m"
PURPLE="\033[35m"
DEMO_CMD_COLOR="\033[1m"
DEMO_PROMPT="${GREEN}\$ ${COLOR_RESET}"

function p() {
  if [[ ${1:0:1} == "#" ]]; then
    cmd="${PURPLE}$1${COLOR_RESET}"
  else
    cmd=$1
  fi
  printf "${DEMO_PROMPT}"
  printf "%b" "$cmd" | pv -qL $TYPE_SPEED
  printf "\n"
}

function pe() {
  p "$@"
  eval "$@"
}

function wait() {
  sleep "${1:-1}"
}

function clear_screen() {
  printf "\033[2J\033[H"
}
