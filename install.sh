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
if [[ ${FILETRUST_INSTALL_BANNER_SHOWN:-0} != 1 ]]; then filetrust_install_banner; fi
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
#
# One-command setup for the FileTrust discovery nodes.
#
#   ./install.sh             set up and keep it running: a service that starts
#                            with the machine and comes back if it ever stops
#   ./install.sh --no-service  set up only; you start it yourself
#   ./install.sh --user      install the service for this user rather than the
#                            machine (no root needed)
#   ./install.sh --rpc URL   the blockchain node to read the registries from
#   ./install.sh --network-config URL
#                            read the chain address, the registry addresses and
#                            the contract ABIs from the network config service,
#                            e.g. --network-config https://config.example.org/v1/network-config
#   ./install.sh --dry-run   show what would happen, change nothing
#   ./install.sh --verbose   show every check, not only what needs doing
#
# One node, on 4601. That is a whole discovery node: it reads every Vault
# Keeper and Guardian straight from the chain, so it answers the same as any
# other node on the network from the first minute.
#
# To run more than one, add rows to "nodes" in config.json before installing
# -- a second id, a second port. They hold the same answer and gossip changes
# to each other, so a Data Owner that cannot reach one simply asks the next.
# That is worth doing when your node going down has to not matter; it is not
# where anyone needs to start.
#
# Keeping it running is the default, because this runs on a machine nobody is
# watching. A crash, an out-of-memory kill, a power cut, a reboot: in every one
# of those the nodes are started again without anybody noticing they stopped.

set +x
set -euo pipefail
umask 077

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/.venv"
# Preserve all installer options when selecting the Docker backend.
DOCKER_MODE=""
DOCKER_ARGUMENTS=()
for option in "$@"; do
  case "$option" in
    --docker) DOCKER_MODE=docker ;;
    *) DOCKER_ARGUMENTS+=("$option") ;;
  esac
done
if [[ -n $DOCKER_MODE ]]; then
  if [[ $DOCKER_MODE == browser ]]; then DOCKER_ARGUMENTS=(--mode browser "${DOCKER_ARGUMENTS[@]}"); fi
  FILETRUST_INSTALL_BANNER_SHOWN=1 exec bash "$APP_DIR/docker.sh" install "${DOCKER_ARGUMENTS[@]}"
fi
SERVICE_NAME="filetrust-discovery"
WANT_SERVICE=1
USER_UNIT=0
DRY_RUN=0
VERBOSE=0
RPC_URL=""
NETWORK_CONFIG_URL=""
OBSERVE=0
IMPORT_WALLET=0
NODE_PORT=""
NODE_HOST=""
PUBLIC_URL=""

INSTALL_ARGUMENTS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --port) shift; NODE_PORT="${1:-}" ;;
    --host) shift; NODE_HOST="${1:-}" ;;
    --public-url) shift; PUBLIC_URL="${1:-}" ;;
    --service) WANT_SERVICE=1 ;;
    --no-service) WANT_SERVICE=0 ;;
    --user) USER_UNIT=1 ;;
    --rpc) shift; RPC_URL="${1:-}" ;;
    --network-config) shift; NETWORK_CONFIG_URL="${1:-}" ;;
    --dry-run) DRY_RUN=1 ;;
    --verbose|-v) VERBOSE=1 ;;
    -h|--help) printf '%s\n' "Usage: bash install.sh [options]" "Native: --no-service --user --network-config URL --rpc URL --port PORT --host ADDRESS --public-url HTTPS_URL" "Docker: bash docker.sh install" "Uninstall: python3 uninstall.py [--purge]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
step() { [ "$VERBOSE" = 1 ] && say "$*"; return 0; }
note() { [ "$VERBOSE" = 1 ] && printf '%s\n' "$*"; return 0; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

if [ "$DRY_RUN" = 0 ]; then
  source "$APP_DIR/package_prerequisites.sh"
  filetrust_prerequisites 0 || die "Missing operating-system prerequisites"
  if [ "$WANT_SERVICE" = 1 ] && [ "$USER_UNIT" = 0 ] && [ "$EUID" = 0 ] && [ "${FILETRUST_CONTAINER:-0}" != 1 ] && [ "${FILETRUST_NATIVE_INSTALLED:-0}" != 1 ]; then
    python3 "$APP_DIR/ft_package.py" native-deploy "${INSTALL_ARGUMENTS[@]}"
    exit $?
  fi
fi

# ── Python and its packages ──────────────────────────────────────────────────
# Unlike the price service, this one reads the chain: web3 and eth-account are
# needed, and the geo lookup is optional but shipped.
step "Checking Python"
command -v python3 >/dev/null 2>&1 || die \
  "python3 is not installed. Install it with your package manager and run this again."
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')"
[ "$PY_OK" = 1 ] || die "Python 3.10 or newer is needed. This machine has $(python3 -V 2>&1)."
if [ "$DRY_RUN" = 0 ]; then
  python3 "$APP_DIR/ft_update_bootstrap.py" --installer-check
  exec 9< "$APP_DIR/.filetrust-updates/update.lock"
  flock -n 9 || die "Another update or installer is running"
  exec 8< "$APP_DIR/.filetrust-updates/run.lock"
  flock -n 8 || die "Stop Discovery before changing its installation"
  exec 7<> "$APP_DIR/.run.lock"
  flock -n 7 || die "Stop the existing Discovery process before installing"
  # Preflight older processes; network activation takes this lock itself.
  flock -u 7
  exec 7>&-
fi


if [ "$DRY_RUN" = 1 ]; then
  note "  would create $VENV and install requirements.txt"
elif [ "${FILETRUST_CONTAINER:-0}" = 1 ]; then
  "$VENV/bin/python" -m pip check || die "Container dependencies are incomplete"
else
  say "Installing Python packages"
  if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV" 2>/dev/null || die \
      "Could not create a virtual environment. On Debian or Ubuntu: apt install python3-venv"
    say "Python packages"
    echo "  created a virtual environment in .venv"
  fi
  "$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  if ! "$VENV/bin/python" -m pip install --quiet -r "$APP_DIR/requirements.txt"; then
    die "Installing the Python packages failed. The output above says why."
  fi
  "$VENV/bin/python" -m pip check || die "Python dependencies are inconsistent"
  note "  packages are up to date"
fi

# ── Your settings file ───────────────────────────────────────────────────────
step "Checking your settings file"
DEFAULT_CONFIG="$APP_DIR/config.default.json"
CONFIG="$APP_DIR/config.json"
if [ "$DRY_RUN" = 1 ]; then
  note "  would create or update config.json"
elif [ ! -f "$DEFAULT_CONFIG" ]; then
  note "  this copy ships config.json directly; nothing to merge"
elif [ ! -f "$CONFIG" ]; then
  cp "$DEFAULT_CONFIG" "$CONFIG"
  chmod 600 "$CONFIG" 2>/dev/null || true
  say "Your settings file"
  echo "  created config.json from the shipped defaults"
else
  FT_CONFIG="$CONFIG" FT_DEFAULT="$DEFAULT_CONFIG" python3 <<'SETTINGS_MERGE'
import json, os
from pathlib import Path

mine = Path(os.environ["FT_CONFIG"])
shipped = Path(os.environ["FT_DEFAULT"])
# A node's key is its identity to the other nodes. It is never in the shipped
# defaults and must never be taken out of your copy by the tidy-up below.
KEEP_ALWAYS = ("nodes",)
try:
    current = json.loads(mine.read_text(encoding="utf-8"))
    defaults = json.loads(shipped.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    print(f"  could not read the settings files ({exc}); leaving yours alone")
    raise SystemExit(0)

def is_heading(key):
    # Section titles, not settings. Counting them would tell the user that
    # seven settings had appeared when nothing of theirs had changed at all.
    return key.startswith("##")

added = [k for k in defaults if k not in current and not is_heading(k)]
removed = [k for k in current
           if k not in defaults and k not in KEEP_ALWAYS and not is_heading(k)]
rewritten = [k for k in current if is_heading(k) and k not in defaults]
if not added and not removed and not rewritten:
    raise SystemExit(0)
merged = {key: current.get(key, value) for key, value in defaults.items()}
for key in KEEP_ALWAYS:
    if key in current:
        merged[key] = current[key]
mine.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
if added:
    print(f"  added {len(added)} new setting(s): " + ", ".join(added[:4]))
if removed:
    print(f"  removed {len(removed)} setting(s) the service no longer reads")
SETTINGS_MERGE
fi

if [ "$DRY_RUN" = 0 ] && [ -n "$RPC_URL" ]; then
  FT_CONFIG="$CONFIG" FT_RPC="$RPC_URL" python3 - <<'APPLY_RPC'
import json, os
from pathlib import Path
path = Path(os.environ["FT_CONFIG"])
config = json.loads(path.read_text(encoding="utf-8"))
config["rpc_url"] = os.environ["FT_RPC"]
path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
print(f"  reading the chain from {os.environ['FT_RPC']}")
APPLY_RPC
fi

mkdir -p "$APP_DIR/runtime/logs"

# ── Current validated network settings ───────────────────────────────────────
if [ "$DRY_RUN" = 0 ]; then
  FT_DIR="$APP_DIR" FT_URL="$NETWORK_CONFIG_URL" "$VENV/bin/python" - <<'CONFIG_SOURCE'
import os,sys
from pathlib import Path
base=Path(os.environ['FT_DIR']);sys.path.insert(0,str(base))
from ft_network_config import read,atomic,https
cfg=read(base/'config.json');cfg['network_config_url']=https(os.environ['FT_URL'] or cfg.get('network_config_url') or 'https://config.filetrust.io/v1/network-config');atomic(base/'config.json',cfg)
CONFIG_SOURCE
  FILETRUST_NETWORK_INSTALL_LOCK_FD=8 "$VENV/bin/python" "$APP_DIR/network-config.py" bootstrap --home "$APP_DIR" || die "Current network settings could not be validated. Retry installation; completed work is retained."
fi

if [ "$DRY_RUN" = 0 ]; then
  FT_CONFIG="$CONFIG" FT_NODE_PORT="$NODE_PORT" FT_NODE_HOST="$NODE_HOST" FT_PUBLIC_URL="$PUBLIC_URL" "$VENV/bin/python" - <<'NODE_OPTIONS'
import json,os
from pathlib import Path
from urllib.parse import urlsplit
path=Path(os.environ['FT_CONFIG']);data=json.loads(path.read_text())
port=os.environ['FT_NODE_PORT'];host=os.environ['FT_NODE_HOST'];public=os.environ['FT_PUBLIC_URL']
if port or host or public:
    if len(data['nodes'])!=1:raise ValueError('Configure multi-node ports explicitly in config.json')
    node=data['nodes'][0]
    if port:
        port=int(port)
        if not 1<=port<=65535:raise ValueError('Port must be between 1 and 65535')
        node['port']=port
    if host:
        if host not in ('127.0.0.1','0.0.0.0','::1','::'):raise ValueError('Choose a local listen address')
        node['host']=host
    if public:
        u=urlsplit(public)
        if u.scheme!='https' or not u.hostname or u.username or u.password:raise ValueError('Use an HTTPS public URL without credentials')
        node['public_url']=public
    elif port or host:
        node['public_url']='http://'+node.get('host','127.0.0.1')+':'+str(node['port'])
    path.write_text(json.dumps(data,indent=2)+'\n');path.chmod(0o600)
NODE_OPTIONS
fi

# ── Each node's own identity ─────────────────────────────────────────────────
# Nodes sign what they gossip to each other, so each needs a key of its own.
# The published copy of the settings carries none -- three clones sharing three
# identities would let anyone who read the repository sign as any of them -- so
# a fresh install makes its own here.
if [ "$DRY_RUN" = 0 ]; then
  step "Checking each node has an identity"
  FT_CONFIG="$CONFIG" "$VENV/bin/python" - <<'NODE_KEYS'
import json, os
from pathlib import Path

path = Path(os.environ["FT_CONFIG"])
config = json.loads(path.read_text(encoding="utf-8"))
nodes = config.get("nodes", [])
missing = [n for n in nodes if not str(n.get("node_private_key", "") or "").strip()]
if not missing:
    raise SystemExit(0)
try:
    from eth_account import Account
except Exception as exc:
    print(f"  eth_account is not available ({exc}); cannot make node identities")
    raise SystemExit(0)
for node in missing:
    account = Account.create()
    node["node_private_key"] = account.key.hex()
    if not node["node_private_key"].startswith("0x"):
        node["node_private_key"] = "0x" + node["node_private_key"]
    node["node_address"] = account.address
path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
print(f"  made an identity for {len(missing)} node(s); config.json is now 0600")
for node in missing:
    print(f"      {node.get('id', '?')}  {node['node_address']}")
NODE_KEYS
fi

# ── Keeping it running ───────────────────────────────────────────────────────
if [ "$WANT_SERVICE" = 1 ] && ! command -v systemctl >/dev/null 2>&1; then
  warn "  this machine has no systemd, so nothing can start it for you."
  warn "  start it yourself with: $VENV/bin/python $APP_DIR/discovery_nodes.py"
  WANT_SERVICE=0
fi

if [ "$WANT_SERVICE" = 1 ]; then
  if [ "$USER_UNIT" = 1 ]; then
    UNIT_TARGET="default.target"
  else
    UNIT_TARGET="multi-user.target"
  fi
  # A machine-wide unit installed by root would also run as root, and then
  # write its records and logs into a directory somebody else owns -- after
  # which that somebody can no longer manage their own install. So it runs as
  # whoever owns the directory, which is whoever installed it.
  RUN_AS=""
  if [ "$USER_UNIT" = 0 ]; then
    DIR_OWNER="$(stat -c '%U' "$APP_DIR" 2>/dev/null || true)"
    DIR_GROUP="$(stat -c '%G' "$APP_DIR" 2>/dev/null || true)"
    if [ -n "${DIR_OWNER:-}" ] && [ "$DIR_OWNER" != "root" ]; then
      RUN_AS="User=$DIR_OWNER
Group=$DIR_GROUP"
    fi
  fi
  UNIT_BODY="[Unit]
Description=FileTrust discovery nodes
Documentation=https://github.com/FileTrust/Discovery
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
${RUN_AS:+$RUN_AS
}WorkingDirectory=$APP_DIR
ExecStart=$VENV/bin/python -u $APP_DIR/discovery_nodes.py
Restart=always
RestartSec=5
TimeoutStopSec=infinity
SendSIGKILL=no
KillMode=mixed
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=$UNIT_TARGET
"
  if [ "$USER_UNIT" = 1 ]; then
    UNIT_PATH="$HOME/.config/systemd/user/$SERVICE_NAME.service"
    if [ "$DRY_RUN" = 1 ]; then
      note "  would write $UNIT_PATH, enable it, and enable lingering"
    else
      mkdir -p "$(dirname "$UNIT_PATH")"
      printf '%s' "$UNIT_BODY" > "$UNIT_PATH"
      systemctl --user daemon-reload
      systemctl --user enable "$SERVICE_NAME" >/dev/null 2>&1 \
        || warn "  could not enable the user service; see: systemctl --user status $SERVICE_NAME"
      if command -v loginctl >/dev/null 2>&1; then
        loginctl enable-linger "$USER" >/dev/null 2>&1 \
          || sudo loginctl enable-linger "$USER" >/dev/null 2>&1 \
          || warn "  could not enable lingering; the nodes will stop when you log out."
      fi
      say "Service"
      echo "  installed for $USER, enabled for boot; start it explicitly when ready"
      echo "      systemctl --user status $SERVICE_NAME"
    fi
  else
    UNIT_PATH="/etc/systemd/system/$SERVICE_NAME.service"
    if [ "$DRY_RUN" = 1 ]; then
      note "  would write $UNIT_PATH and enable it"
    else
      if [ "$(id -u)" = 0 ]; then
        printf '%s' "$UNIT_BODY" > "$UNIT_PATH"
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 \
          || warn "  could not enable the service; see: systemctl status $SERVICE_NAME"
      elif command -v sudo >/dev/null 2>&1; then
        # -n: never stop at a password prompt. Under a launcher there is nobody
        # to type one, and a prompt on a closed stdin reads as a hang.
        printf '%s' "$UNIT_BODY" | sudo -n tee "$UNIT_PATH" >/dev/null 2>&1 \
          && sudo -n systemctl daemon-reload \
          && sudo -n systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 \
          || true
        # Say it is installed only if it is. This used to report success
        # whatever sudo did, so an install that never wrote the unit still
        # said "starts at boot" -- and nothing started at boot.
        if [ ! -f "$UNIT_PATH" ]; then
          warn "  NOT installed: writing $UNIT_PATH needs root, and this account"
          warn "  could not get it. Run this again as root, or use --user."
          WANT_SERVICE=0
        fi
      else
        warn "  installing a machine-wide service needs root. Run this again as"
        warn "  root, or with --user to install it for $USER only."
        WANT_SERVICE=0
      fi
      if [ "$WANT_SERVICE" = 1 ]; then
        say "Service"
        echo "  installed, enabled for boot; start it explicitly when ready"
        echo "      systemctl status $SERVICE_NAME"
      fi
    fi
  fi
fi

# ── Do they answer? ──────────────────────────────────────────────────────────
if [ "$DRY_RUN" = 0 ]; then
  step "Checking the nodes answer"
  FT_CONFIG="$CONFIG" FT_WAIT="$WANT_SERVICE" python3 - <<'HEALTH'
import json, os, sys, time, urllib.request

config = json.load(open(os.environ["FT_CONFIG"]))
ports = [int(node["port"]) for node in config.get("nodes", [])]
deadline = time.time() + (20 if os.environ.get("FT_WAIT") == "1" else 1)
alive = set()
while time.time() < deadline and len(alive) < len(ports):
    for port in ports:
        if port in alive:
            continue
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                if json.load(response).get("ok"):
                    alive.add(port)
        except Exception:
            pass
    if len(alive) < len(ports):
        time.sleep(1)
print(f"\n\033[1mReady\033[0m")
if alive:
    print(f"  {len(alive)} of {len(ports)} discovery node(s) answering: "
          + ", ".join(str(p) for p in sorted(alive)))
if len(alive) < len(ports):
    print("  not answering yet: " + ", ".join(str(p) for p in ports if p not in alive))
    print("  check the log: tail -f runtime/logs/*.log")
sys.exit(0)
HEALTH
  for node_url in $(FT_CONFIG="$CONFIG" python3 -c "
import json, os
for node in json.load(open(os.environ['FT_CONFIG'])).get('nodes', []):
    print(node.get('public_url', ''))
"); do
    [ -n "$node_url" ] && echo "  published as $node_url"
  done
fi

if [ "$DRY_RUN" = 0 ] && [ "$WANT_SERVICE" = 1 ]; then echo "Installed but not started. Start with systemctl start $SERVICE_NAME (add --user for a user service)."; fi
