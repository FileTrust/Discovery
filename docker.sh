#!/usr/bin/env bash
# BEGIN FILETRUST INSTALL BANNER — from root singature.txt
filetrust_install_banner() {
  local banner_dir banner_version='unknown' banner_line
  banner_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -r "$banner_dir/VERSION" ]]; then
    IFS= read -r banner_version < "$banner_dir/VERSION" || [[ -n $banner_version ]]
    banner_version=${banner_version%$'\r'}
  fi
  cat <<'FILETRUST_BANNER_TOP'
███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝


Author: Ali Farahpoor
Company: Electra Sphere Innovations (ElectraSI.es)
Location: Barcelona, Spain
Contact: support@filetrust.io

FILETRUST_BANNER_TOP
  printf 'Version: %s %s\n' 'Discovery' "$banner_version"
  cat <<'FILETRUST_BANNER_BOTTOM'
Release Date: 26 October 2026

Documentation: https://docs.filetrust.io
Website: https://www.filetrust.io
FILETRUST_BANNER_BOTTOM
  printf '\n'
}
if [[ ${1:-help} == install && ${FILETRUST_INSTALL_BANNER_SHOWN:-0} != 1 ]]; then filetrust_install_banner; fi
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
APP_PRODUCT='discovery'
APP_KIND='headless'
set +x
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command_name=${1:-help}
[[ $# -eq 0 ]] || shift
if [[ $command_name == help || $command_name == --help ]]; then
  echo 'Usage: ./docker.sh install [options] | start | stop | restart | status | logs | doctor | check | network-config [check|apply] | configure [--mode desktop|browser] | update | rollback | uninstall [--purge]'
  if [[ $APP_KIND == desktop ]]; then echo 'GUI setup: --mode desktop|browser, --web-port PORT, --vnc-port PORT. Both modes use the same saved account.'; fi
  exit 0
fi
command -v docker >/dev/null || { echo 'Install Docker Engine and Compose: https://docs.docker.com/engine/install/' >&2; exit 1; }
docker compose version >/dev/null || { echo 'Docker Compose plugin is required.' >&2; exit 1; }
platform=$(docker info --format '{{.OSType}}/{{.Architecture}}') || { echo 'Docker is not accessible. Start Docker or use sudo bash docker.sh.' >&2; exit 1; }
[[ $platform =~ ^linux/(amd64|x86_64)$ ]] || { echo 'This release is verified for Linux amd64 Docker hosts.' >&2; exit 1; }
export FILETRUST_DOCKER_PROJECT=${FILETRUST_DOCKER_PROJECT:-filetrust-$APP_PRODUCT}
[[ ${#FILETRUST_DOCKER_PROJECT} -le 64 && $FILETRUST_DOCKER_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo 'Invalid Docker project name.' >&2; exit 1; }
default_uid=10001; default_gid=10001
if [[ $APP_KIND == desktop ]]; then
  default_uid=${SUDO_UID:-$(id -u)}; default_gid=${SUDO_GID:-$(id -g)}
  if [[ $default_uid == 0 ]]; then default_uid=10001; default_gid=10001; fi
fi
export FILETRUST_UID=${FILETRUST_UID:-$default_uid} FILETRUST_GID=${FILETRUST_GID:-$default_gid}
[[ $FILETRUST_UID =~ ^[1-9][0-9]*$ && $FILETRUST_GID =~ ^[1-9][0-9]*$ ]] || { echo 'Choose non-root numeric container uid/gid.' >&2; exit 1; }
export FILETRUST_FILES_DIR=${FILETRUST_FILES_DIR:-$root/files}
compose=(docker compose --project-name "$FILETRUST_DOCKER_PROJECT" --project-directory "$root" -f "$root/compose.yaml")
image="filetrust-$APP_PRODUCT:$FILETRUST_DOCKER_PROJECT"
previous="$image-previous"
tool_container=''
cleanup() { if [[ -n $tool_container ]]; then docker rm -f "$tool_container" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT
container_id() { "${compose[@]}" ps --all -q node; }
stop_node() {
  local cid; cid=$(container_id)
  if [[ -n $cid ]]; then
    echo 'Stopping; waiting for the application and active work to finish...'
    docker stop --timeout -1 "$cid" >/dev/null
    [[ $(docker inspect --format '{{.State.Running}}' "$cid") == false ]] || { echo 'Application is still running; no code/data removed.' >&2; return 1; }
  fi
}
require_stopped() {
  local cid; cid=$(container_id)
  [[ -z $cid || $(docker inspect --format '{{.State.Running}}' "$cid") != true ]] || { echo 'Stop this Docker application before changing setup.' >&2; exit 1; }
}
build_image() {
  [[ -f $root/package-files.json ]] || { echo 'Use the complete independent package checkout or release archive.' >&2; return 1; }
  docker build --network host --target runtime --tag "$image" "$root"
}
init_volume() {
  if ! docker volume inspect "${FILETRUST_DOCKER_PROJECT}_app" >/dev/null 2>&1; then
    docker volume create --label "com.docker.compose.project=$FILETRUST_DOCKER_PROJECT" --label com.docker.compose.volume=app "${FILETRUST_DOCKER_PROJECT}_app" >/dev/null
  fi
  docker run --rm --network host --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    -v "${FILETRUST_DOCKER_PROJECT}_app:/app" "$image" init "$FILETRUST_UID" "$FILETRUST_GID"
}
run_tool() {
  local token='' result=0 flags=(-i)
  [[ ! -t 0 || ! -t 1 ]] || flags+=(-t)
  if command -v python3 >/dev/null; then token=$(python3 "$root/github_auth.py" --print)
  elif [[ -n ${GH_TOKEN:-${GITHUB_TOKEN:-}} ]]; then token=${GH_TOKEN:-$GITHUB_TOKEN}
  elif command -v gh >/dev/null; then token=$(gh auth token 2>/dev/null || gh config get oauth_token --host github.com 2>/dev/null || true)
  fi
  tool_container=$("${compose[@]}" run --detach --no-deps --pull never setup idle)
  if [[ -n $token ]]; then
    printf '%s' "$token" | docker exec -i "$tool_container" python /opt/filetrust-source/container_cli.py stage-token || { cleanup; return 1; }
    unset token
  fi
  if [[ -n ${FILETRUST_BROWSER_PASSWORD_FILE:-} ]]; then
    docker exec -i "$tool_container" python /opt/filetrust-source/container_cli.py stage-browser < "$FILETRUST_BROWSER_PASSWORD_FILE" || { cleanup; return 1; }
  fi
  docker exec "${flags[@]}" "$tool_container" python /opt/filetrust-source/container_cli.py "$@" || result=$?
  docker rm -f "$tool_container" >/dev/null; tool_container=''
  return "$result"
}
node_mode() {
  docker run --rm --network host --user "$FILETRUST_UID:$FILETRUST_GID" \
    -v "${FILETRUST_DOCKER_PROJECT}_app:/app:ro" "$image" settings
}
prepare_files() {
  [[ $APP_KIND == desktop ]] || return 0
  local dir new=0
  for dir in "$FILETRUST_FILES_DIR" "$FILETRUST_FILES_DIR/downloads"; do
    new=0
    if [[ ! -d $dir ]]; then mkdir -p -- "$dir"; chmod 700 "$dir"; new=1; fi
    if [[ $EUID == 0 && $new == 1 ]]; then chown "$FILETRUST_UID:$FILETRUST_GID" "$dir"; fi
  done
}
start_node() {
  local mode web_port vnc_port settings cid cookie
  settings=$(node_mode); read -r mode web_port vnc_port <<< "$settings"
  [[ $mode == desktop || $mode == browser || $mode == headless ]] || { echo 'Invalid saved mode.' >&2; return 1; }
  prepare_files
  local selected=("${compose[@]}")
  if [[ $mode == desktop ]]; then
    [[ ${DISPLAY:-} =~ ^:[0-9]+(\.[0-9]+)?$ ]] || { echo 'Desktop mode needs a local X11/XWayland session. Use browser mode on a headless server.' >&2; return 1; }
    command -v xauth >/dev/null || { echo 'Install the desktop xauth package, then retry. Do not use xhost +.' >&2; return 1; }
    local auth=${XAUTHORITY:-$HOME/.Xauthority}
    [[ -r $auth ]] || { echo 'XAUTHORITY must name your readable desktop authorization file.' >&2; return 1; }
    cookie=$(xauth -f "$auth" nlist "$DISPLAY" | sed 's/^..../ffff/')
    [[ -n $cookie ]] || { echo 'No authorization cookie for this display.' >&2; return 1; }
    selected+=(-f "$root/compose.desktop.yaml")
  fi
  "${selected[@]}" up -d --no-build node
  if [[ $mode == desktop ]]; then
    cid=$(container_id)
    printf '%s\n' "$cookie" | docker exec -i "$cid" python /opt/filetrust-source/container_cli.py stage-xauth
    unset cookie
  fi
  cid=$(container_id)
  local ready=0 attempt
  for attempt in {1..60}; do
    if [[ $(docker inspect --format '{{.State.Running}}' "$cid") != true ]]; then break; fi
    if docker exec "$cid" python /opt/filetrust-source/container_cli.py health >/dev/null 2>&1; then
      sleep 1
      if docker exec "$cid" python /opt/filetrust-source/container_cli.py health >/dev/null 2>&1; then ready=1; break; fi
    fi
    sleep 1
  done
  if [[ $ready != 1 ]]; then
    echo 'Application did not become ready. Startup logs:' >&2
    docker logs --tail 25 "$cid" >&2
    return 1
  fi
  if [[ $mode == browser ]]; then echo "Open http://127.0.0.1:$web_port/vnc.html and enter your separate browser access password."; fi
}
case "$command_name" in
  install) require_stopped; build_image; init_volume; run_tool install "$@" ;;
  start) start_node ;;
  stop) stop_node ;;
  restart) stop_node; start_node ;;
  status) "${compose[@]}" ps --all node ;;
  logs) "${compose[@]}" logs --follow --tail 80 node "$@" ;;
  doctor|check) run_tool "$command_name" "$@" ;;
  configure) require_stopped; run_tool configure "$@" ;;
  network-config)
    if [[ ${1:-check} != check && ${1:-} != status ]]; then require_stopped; fi
    if [[ $# == 0 ]]; then set -- check; fi
    run_tool network-config "$@" ;;
  update)
    cid=$(container_id); [[ -n $cid ]] || { echo 'Install the application first.' >&2; exit 1; }
    old_image=$(docker inspect --format '{{.Image}}' "$cid"); was_running=$(docker inspect --format '{{.State.Running}}' "$cid")
    build_image; docker tag "$old_image" "$previous"; stop_node
    run_tool sync
    "${compose[@]}" create --force-recreate --no-build node
    if [[ $was_running == true ]]; then start_node; fi
    echo 'Image/code updated. Saved accounts, settings and data retained. Previous image: ./docker.sh rollback' ;;
  rollback)
    docker image inspect "$previous" >/dev/null
    cid=$(container_id); was_running=false
    if [[ -n $cid ]]; then was_running=$(docker inspect --format '{{.State.Running}}' "$cid"); fi
    stop_node; docker tag "$previous" "$image"; run_tool sync
    "${compose[@]}" create --force-recreate --no-build node
    if [[ $was_running == true ]]; then start_node; fi
    echo 'Previous code restored. Saved accounts and user data retained.' ;;
  uninstall)
    [[ $# == 0 || ( $# == 1 && $1 == --purge ) ]] || { echo 'Usage: ./docker.sh uninstall [--purge]' >&2; exit 1; }
    if [[ ${1:-} == --purge ]]; then
      [[ -t 0 ]] || { echo 'Purge requires a terminal confirmation.' >&2; exit 1; }
      echo 'This deletes this Docker application account, settings and managed data. Back up and retire duties first. Shared files are kept.'
      read -r -p 'Type DELETE to purge this application: ' answer
      [[ $answer == DELETE ]] || { echo 'Cancelled.'; exit 1; }
    fi
    stop_node; "${compose[@]}" down --timeout -1
    if [[ ${1:-} == --purge ]]; then docker volume rm "${FILETRUST_DOCKER_PROJECT}_app"; echo 'Managed application data purged.'
    else echo 'Container removed; account, settings and data retained.'; fi
    echo 'Source checkout, images, shared files and native installations are kept.' ;;
  *) echo 'Unknown Docker command. Run ./docker.sh help.' >&2; exit 2 ;;
esac
