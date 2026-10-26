# FileTrust Discovery Nodes

FileTrust discovery nodes map a VaultKeeper peer ID to its current network
multiaddr. They do not store file IDs, piece roots, CIDs, requester data, or
any storage-assignment metadata.

## Installation

```bash
git clone https://github.com/FileTrust/Discovery.git
cd Discovery
sudo bash install.sh --port 4601
```

The system installer checks missing OS prerequisites, installs under
`/opt/filetrust-discovery`, creates the unprivileged `ftdiscovery` service account,
and fetches current contract addresses and ABIs over HTTPS from
`https://config.filetrust.io/v1/network-config`. It creates a new identity only
when none exists. Reinstallation preserves the existing identity and settings.
The service is enabled for reboot but **not started during installation**.
Review settings before starting it:

```bash
sudo systemctl start filetrust-discovery
sudo systemctl status filetrust-discovery
sudo journalctl -u filetrust-discovery -f
sudo systemctl stop filetrust-discovery
sudo systemctl restart filetrust-discovery
```

`journalctl` follows the service's activity and errors. Start/stop/restart
preserve the identity and saved state. Installation also supports `--user` for
a user service, or `--no-service` to run from the source checkout. Use
`bash install.sh --help` for the options.

Native installation requires Linux with Python 3.10 or later; the service
commands require systemd. Missing prerequisites are installed automatically on
Debian/Ubuntu. Other distributions may need their corresponding OS packages.
Docker provides Debian 12 with Python 3.11 and does not require host Python.

## Docker

Install [Docker Engine and its Compose plugin](https://docs.docker.com/engine/install/),
then:

```bash
bash docker.sh install --port 4601
bash docker.sh start
bash docker.sh status
bash docker.sh logs
bash docker.sh stop
bash docker.sh restart
```

This is a headless service; there is no browser or desktop interface. The
supported Docker host is Linux x86_64. Docker uses host networking; choose an
unused port for Discovery. The application's identity, settings and state stay
in its own named `app` volume. Native and Docker installations have separate
state and do not share identities automatically.

While repositories/releases are private, sign in with `gh auth login` before
installation. Public access needs no GitHub login. Setup credentials are passed
through a private temporary input and are not baked into the image.

```bash
bash docker.sh doctor
bash docker.sh check
bash docker.sh network-config check
# Review changes, then apply only while stopped:
bash docker.sh stop
bash docker.sh network-config apply
bash docker.sh start

# Update from the current source checkout:
git pull --ff-only
bash docker.sh update
# Restore previous image/code if needed:
# bash docker.sh rollback
```

Stop/restart and image replacement retain the wallet, identity, settings and
data. Stop waits for current work instead of force-killing it. A separate
`FILETRUST_DOCKER_PROJECT` gives another installation its own volume and
container; keep the same project name for every later command.

## Removal

```bash
# Remove the native runtime/service, keeping identity and settings:
sudo python3 /opt/filetrust-discovery/uninstall.py
# Also purge this native installation's managed state (asks for DELETE):
sudo python3 /opt/filetrust-discovery/uninstall.py --purge

# Remove the Docker container, keeping its volume:
bash docker.sh uninstall
# Also delete this Docker installation's managed volume (asks for DELETE):
bash docker.sh uninstall --purge
```

For user services, run the native uninstaller without sudo and add `--user`.
Source files, shared tools, external files and inactive service accounts are
kept. Back up the identity and retire network duties before purging.

## Settings

`config.json` holds only what a discovery node reads: the chain and the two
contracts it uses, what an announce has to prove, this install's nodes, how
often the directory is re-read, the flood limits, and where files go. Lines
beginning `##` are section titles, not settings.

It needs two contracts, and only two. `VaultKeeperRegistry` answers "is this
address a registered keeper, and is this the endpoint it registered" when one
announces. `NetworkDirectoryReader` returns the whole network -- keepers *and*
guardians -- a page per call, which is why there is no guardian registry here:
guardians never announce, they are read from the chain with everyone else.

### Behind a reverse proxy

A node can be run behind a proxy, with the proxy reached by name and the node
listening on localhost. Three settings cover it:

```json
"trust_proxy_header": true,
"client_ip_header": "X-Forwarded-For",
"nodes": [
  { "port": 4601, "host": "127.0.0.1",
    "public_url": "https://discovery1.example.org",
    "sync_url":   "http://127.0.0.1:4601" }
]
```

`public_url` is what the node publishes: in `/health`, to the Vault Keepers
announcing, and to the Data Owners reading the directory. `sync_url` is how
its neighbours reach it, which for nodes on one machine is loopback -- out to
the proxy and back would be slower and would make them depend on the proxy to
talk to each other.

`client_ip_header` matters most. Behind a proxy every request appears to come
from the proxy, so without it every caller in the world shares one rate-limit
bucket and a single sender can lock out the rest. Only set
`trust_proxy_header` when a proxy really is in front and the node cannot be
reached around it: otherwise a caller names any address it likes and spends
somebody else's allowance.

Default local run:

```bash
.venv/bin/python discovery_nodes.py
```

This starts one node on port `4601`. It accepts VK announcements and answers
the directory, which it reads from the chain -- so one node is already a
complete answer about who is on the network.

Add rows to `nodes` in `config.json` to run more in the same process, each
with its own id and port. They accept announcements independently and pass
accepted records to each other, so a Data Owner that cannot reach one asks
the next. That is what FileTrust runs for the network's first nodes. It is a
choice about surviving your own node's absence, not a requirement.

Main endpoints:

- `POST /v1/announce` - VK-signed reachability record.
- `GET /v1/peers/<peerId>` - current record for one VK peer.
- `GET /v1/records` - current non-expired records.
- `GET /v1/directory` - every Vault Keeper and Guardian with full details, read from the chain.
- `GET /health` - node health.

`/v1/directory` is the read every Data Owner makes before choosing keepers and
guardians. The node reads the chain through the `NetworkDirectoryReader`
contract: one `eth_call` per 100 rows, all pages pinned to one block. It checks
for change every 60 seconds with one log query over the new blocks only, reads
in full when something was written, and reads in full every 5 minutes anyway.
It never searches old chain history.

The answer is compact JSON: column names once, each row an array. A caller that
already holds a version asks `?since=<version>&epoch=<epoch>` and gets only the
rows changed since then, or `304` when nothing changed. Without those, or with a
version from another node or run, it gets the full document, which carries an
`ETag` and a `max-age`. Bodies are gzip when the caller accepts it. The full
document is also written to `runtime/public/<node>.directory.json` (and `.gz`)
so a web server or CDN can serve it. Before the first chain read the node
answers `503`, never an empty network.

Keeper rows include the keeper's `multiaddr` and its real location, looked up
with the GeoIP database (`ip2location_db`) from its public IP. A keeper that
announces a private or loopback address -- on the same server or LAN as this
node, as on a one-server test network -- is placed where this server is, by this
server's public IP. That IP is learned once at startup from a public "what is my
IP" service, or set with `"public_ip"` in `config.json`.

The GeoIP file is too large for git, so the node downloads DB-IP's free monthly
city database ("IP Geolocation by DB-IP", CC BY 4.0) itself, in the background,
when the file is missing or older than 35 days, and starts using it without a
restart. It needs the `geoip2` Python package and outbound HTTPS. Everything here is a **hint**: the document
says `"authoritative": false`, and a client checks on chain the keepers it
actually pays.

Config: `network_directory_reader_address` (from `deployed_addresses.json`),
`network_directory_reader_json` (default `contracts/NetworkDirectoryReader.json`),
and optionally `directory_page_size` (100), `directory_check_seconds` (60) and
`directory_full_refresh_seconds` (300).

VK records are signed with the VK Ethereum key and contain only:

`peerId`, `multiaddr`, `vkAddress`, `seq`, `expiresAt`, and `signature`.

When `verify_registry` is enabled in `config.json`, the node also checks
`VaultKeeperRegistry` and accepts only active registered VKs whose on-chain
peerID matches the announcement. This is a read-only RPC check; the discovery
node does not need its own private key for this.

Read-only registry checks are also written as zero-cost transaction log lines:

- `reports/transaction_logs/discovery_transactions.jsonl`

Each entry in `nodes` can have its own `node_address` and `node_private_key`.
If `sign_node_sync` is enabled, that node signs `/v1/sync` payloads with its
own key. If `verify_node_sync_signatures` is enabled, peers accept sync payloads
only from configured discovery-node addresses with valid signatures.

These discovery-node keys are not used to verify VK announcements. VK
announcements are still verified by the VK signature plus the on-chain
`VaultKeeperRegistry` check. The sample config uses local development keys;
replace them for real deployments and do not expose production private keys.

## Running it for real

**See [DISCOVERY_DEPLOYMENT.md](DISCOVERY_DEPLOYMENT.md) before exposing a node.**
It has the go-live checklist, nginx and Caddy configurations, and the one
setting that is wrong in both directions if it is set at the wrong time.

This is a Python development HTTP server. In production a web server terminates
the outside connection and the node listens on loopback behind it. `host`
already defaults to `127.0.0.1`; binding anywhere else warns at startup.

Protections in the node itself:

| Setting | Default | What it does |
| --- | --- | --- |
| `announce_rate_limit_per_minute` | 30 | Per-caller `POST /v1/announce` limit; `0` disables |
| `sync_rate_limit_per_minute` | 240 | Per-caller `POST /v1/sync` limit; `0` disables |
| `trust_proxy_header` | `false` | Read the caller from a forwarded header |
| `trusted_proxy_hops` | `1` | Trusted machines in front — `2` with a CDN |
| `client_ip_header` | *(none)* | A header naming the caller, e.g. `CF-Connecting-IP` |

Request bodies over 1 MiB are refused with `413`, and a connection that stops
making progress is dropped after 15 seconds. Neither is configurable.

`trust_proxy_header` must be `true` **only** once a proxy is genuinely in front,
and must not stay `false` after one is. Off with a proxy: every request looks
like the proxy, so one flood empties the shared allowance and every honest keeper
is refused. On without one: any caller can send the header and get a fresh
allowance per request. The deployment guide covers the order.

To check a node is answering:

```bash
curl -s http://127.0.0.1:4601/health
```

Human-readable runtime files are written under `runtime/`, one pair per node:

- `runtime/logs/discovery-1.log`
- `runtime/records/discovery-1.records.json`

The records JSON shows active VK records plus `lastSeenAtIso` and
`expiresAtIso`, so it is easy to confirm that VK heartbeats and node sync are
working.


## Signed native application updates

The native service checks signed release metadata at startup and about daily.
Checks notify only; the operator chooses whether to prepare and apply a
compatible release. Use the installed application's environment:

```bash
cd /opt/filetrust-discovery
sudo .venv/bin/python update.py --check
sudo .venv/bin/python upgrade.py prepare
sudo .venv/bin/python upgrade.py apply --service
```

Use sudo for a system service; user services add `--user-service`. Stop and
update checks preserve identities and working data. Docker uses `docker.sh
update` and `rollback` instead of the native environment updater.

## Network settings updates

Code releases and network settings are checked separately. The node checks for
network changes daily alongside code update checks. Checks only notify; they
never change contracts, ABIs, storage allocation, identities or running work.
A normal restart uses the saved settings.

```sh
python3 network-config.py check
python3 network-config.py status
```

Review the reported changes. Stop the node normally before applying:

```sh
python3 network-config.py apply
# Start the node again using its usual service or launcher command.
```

Use the installed application's Python environment and the account that owns its
settings (or sudo where required). Public Guardian and Vaultkeeper commands use
their installed state directories by default; `--home PATH` selects another node.
Application and proof-artifact compatibility checks remain mandatory. If a change
requires a new application or signed artifact release, install that release first.
To undo the last settings activation while stopped:

```sh
python3 network-config.py rollback
```

Previous settings and ABI generations are retained in the node's private
`.network-updates` directory. Wallets, transport keys, shares, pieces and capacity
state are preserved. Failed checks keep the last working settings. User-selected
Discovery peers remain unchanged; `network_config_manage_discovery: true` opts
into managing that list from the network service.
