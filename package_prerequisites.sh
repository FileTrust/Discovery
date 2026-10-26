#!/usr/bin/env bash
# OS packages are separate from pip packages. Container images provide these.
filetrust_prerequisites() {
  [[ ${FILETRUST_CONTAINER:-0} != 1 ]] || return 0
  local need=() desktop=${1:-0}
  command -v python3 >/dev/null || need+=(python3 python3-venv)
  if command -v python3 >/dev/null && ! python3 -c 'import venv,ensurepip' >/dev/null 2>&1; then need+=(python3-venv); fi
  if [[ $desktop == 1 ]] && ! python3 -c 'import tkinter' >/dev/null 2>&1; then need+=(python3-tk); fi
  command -v flock >/dev/null || need+=(util-linux)
  [[ -s /etc/ssl/certs/ca-certificates.crt ]] || need+=(ca-certificates)
  [[ ${#need[@]} -gt 0 ]] || return 0
  command -v apt-get >/dev/null || { echo "Install the missing prerequisites with your distribution's package manager: ${need[*]}" >&2; return 1; }
  local privilege=()
  if [[ $EUID != 0 ]]; then
    command -v sudo >/dev/null || { echo "Install these OS packages as root: ${need[*]}" >&2; return 1; }
    privilege=(sudo)
  fi
  echo "[Setup] Installing missing OS prerequisites: ${need[*]}"
  "${privilege[@]}" apt-get update && "${privilege[@]}" apt-get install -y --no-install-recommends "${need[@]}"
}
