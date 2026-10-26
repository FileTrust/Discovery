#!/usr/bin/env python3
"""Run FileTrust VK discovery nodes.

Discovery records are file-agnostic:
peerId -> current VK multiaddr/IP/port.
"""

from __future__ import annotations

import argparse
import signal
import hashlib
import ipaddress
import itertools
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import network_directory as ND

# All nodes in one process share a logs folder, so only the first starts the
# archiver.
_LOG_ARCHIVER_STARTED = False

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except Exception:  # pragma: no cover - dependency presence is runtime-specific.
    Account = None
    encode_defunct = None

try:
    from web3 import Web3
except Exception:  # pragma: no cover - dependency presence is runtime-specific.
    Web3 = None

try:
    import IP2Location as _ip2loc_module
except Exception:  # pragma: no cover - optional dependency.
    _ip2loc_module = None

try:
    import geoip2.database as _geoip2_db
except Exception:  # pragma: no cover - optional dependency.
    _geoip2_db = None


BASE_DIR = Path(__file__).resolve().parent
if __name__ == '__main__':
    from ft_update_bootstrap import enter
    enter(BASE_DIR)
DEFAULT_CONFIG = BASE_DIR / "config.json"
DEFAULT_TTL_SECONDS = 300
SYNC_INTERVAL_SECONDS = 20
# How often the network directory checks the chain for change (one block-number
# call and one log query over the new blocks), and the longest it goes without a
# full read regardless. See network_directory.DirectoryRefresher.
DIRECTORY_CHECK_SECONDS = 60
DIRECTORY_FULL_REFRESH_SECONDS = 300
DIRECTORY_PAGE_SIZE = 100
HTTP_TIMEOUT_SECONDS = 4
DEFAULT_TRANSACTION_LOG_PATH = BASE_DIR / "runtime" / "logs" / "discovery_transactions.jsonl"


def label_discovery_log(line: str) -> str:
    if " listening at " in line:
        return f"[START] {line}"
    if " announce peerId=" in line or "accepted" in line:
        return f"[ANNOUNCE] {line}"
    if "rejected" in line or " failed" in line or " error" in line:
        return f"[WARN] {line}"
    if "Stopping discovery nodes" in line:
        return f"[STOP] {line}"
    if ' - "GET /health ' in line or ' - "GET /v1/records ' in line or ' - "GET /v1/vk-geo/' in line:
        return f"[READ] {line}"
    if ' - "POST /v1/sync ' in line:
        return f"[SYNC] {line}"
    return line


# Escape control characters the way the standard library's HTTP server does
# before writing a request to its log. Overriding log_message dropped that, and
# the request line is attacker-controlled before any check has run.
_CONTROL_CHARS = str.maketrans(
    {c: f"\\x{c:02x}" for c in itertools.chain(range(0x20), range(0x7F, 0xA0))}
)
_CONTROL_CHARS[ord("\\")] = "\\\\"

# Far above any real log line, far below what a flood could write.
LOG_LINE_LIMIT = 2000

# Generous next to a real record and small next to a 1 MiB request body.
MAX_PEER_ID_LENGTH = 256
MAX_MULTIADDR_LENGTH = 512
MAX_LOCATION_LENGTH = 128


def safe_for_log(message: str) -> str:
    """Make a value safe to write into a line-based log.

    Two things arrive here that a caller chose. The request line reaches the log
    before anything has been checked at all, and an announced peer id and
    multiaddr reach it after the signature but still as free text.

    A newline in either forges whole log lines that read as genuine, which turns
    the record of an attack into part of it. An escape sequence does worse: these
    lines are printed to the terminal of whoever is watching, where the sequence
    is executed rather than shown, so a caller can clear the screen or colour its
    own line green. The length cap is the same argument applied to volume.
    """
    text = str(message).translate(_CONTROL_CHARS)
    if len(text) > LOG_LINE_LIMIT:
        text = text[:LOG_LINE_LIMIT] + f"... [{len(text) - LOG_LINE_LIMIT} more characters]"
    return text


def local_now_epoch() -> int:
    return int(time.time())


def utc_now() -> int:
    # Backward-compatible helper name; value is epoch seconds (timezone-neutral).
    return local_now_epoch()


def iso_ts(ts: int | None = None) -> str:
    value = local_now_epoch() if ts is None else int(ts)
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(value))


def json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    return str(value)


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=json_default, separators=(",", ":")) + "\n")


def normalize_url(url: str) -> str:
    return str(url or "").strip().rstrip("/")


def resolve_config_path(value: str | Path | None) -> Path:
    raw = Path(str(value or "")).expanduser()
    if raw.is_absolute():
        return raw
    candidates = [
        (BASE_DIR / raw).resolve(),
        (BASE_DIR.parent / raw).resolve(),
        (BASE_DIR.parent.parent / raw).resolve(),
        (Path.cwd() / raw).resolve(),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def peer_id_from_peer(value: str) -> str:
    text = str(value or "").strip()
    if "/p2p/" in text:
        return text.rsplit("/p2p/", 1)[-1].strip()
    return text


def canonical_message(record: dict[str, Any]) -> str:
    return "\n".join(
        [
            "FileTrust VK Discovery Record",
            "version=1",
            f"peerId={record.get('peerId', '')}",
            f"multiaddr={record.get('multiaddr', '')}",
            f"vkAddress={record.get('vkAddress', '')}",
            f"seq={int(record.get('seq', 0))}",
            f"expiresAt={int(record.get('expiresAt', 0))}",
        ]
    )


def endpoint_canonical_message(record: dict[str, Any]) -> str:
    return "\n".join(
        [
            "FileTrust VK Discovery Endpoint",
            "version=1",
            f"peerId={record.get('peerId', '')}",
            f"multiaddr={record.get('multiaddr', '')}",
            f"vkAddress={record.get('vkAddress', '')}",
            f"seq={int(record.get('seq', 0))}",
        ]
    )


def endpoint_hash(record: dict[str, Any]) -> str:
    text = endpoint_canonical_message(record)
    if Web3 is not None:
        value = Web3.keccak(text=text).hex()
        return value if str(value).startswith("0x") else "0x" + str(value)
    return "0x" + hashlib.sha3_256(text.encode("utf-8")).hexdigest()


def normalize_bytes32_hex(value: Any) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    text = str(value or "").strip()
    if not text:
        return "0x" + ("0" * 64)
    if text.startswith("0x") and len(text) == 66:
        return text.lower()
    clean = text.removeprefix("0x")
    if len(clean) <= 64:
        return "0x" + clean.rjust(64, "0").lower()
    return text.lower()


def is_endpoint_unsupported_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "function selector" in text
        or "not recognized" in text
        or "function does not exist" in text
        or "could not decode" in text
        or "return data: b''" in text
    )


def verify_signature(record: dict[str, Any]) -> tuple[bool, str]:
    if Account is None or encode_defunct is None:
        return False, "eth_account is required for signature verification"

    signature = str(record.get("signature", "")).strip()
    vk_address = str(record.get("vkAddress", "")).strip()
    if not signature or not vk_address:
        return False, "missing signature or vkAddress"

    try:
        recovered = Account.recover_message(
            encode_defunct(text=canonical_message(record)),
            signature=signature,
        )
    except Exception as exc:
        return False, f"signature recovery failed: {exc}"

    if recovered.lower() != vk_address.lower():
        return False, f"signature recovered {recovered}, expected {vk_address}"
    return True, "ok"


def extract_ip_from_multiaddr(multiaddr: str) -> str:
    """Return the IP address embedded in a multiaddr string (/ip4/x.x.x.x/... or /ip6/...)."""
    parts = multiaddr.strip().strip("/").split("/")
    for i, part in enumerate(parts):
        if part in ("ip4", "ip6") and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def is_routable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified)
    except ValueError:
        return False


# Asked once at startup for this host's own public address. Plain-text answers,
# HTTPS only, short timeouts; any one of them is enough.
PUBLIC_IP_SERVICES = (
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
)


def detect_public_ip(timeout: float = 3.0) -> str:
    """This host's public IP address, or "" if no service answered."""
    for url in PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "filetrust-discovery"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read(64).decode("ascii", "replace").strip()
        except Exception:
            continue
        if is_routable_ip(ip):
            return ip
    return ""


# DB-IP's free city database ("IP Geolocation by DB-IP", CC BY 4.0), published
# monthly. It is too large for git, so a node fetches it itself and refreshes it
# when it is older than GEOIP_MAX_AGE_DAYS.
GEOIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
GEOIP_MAX_AGE_DAYS = 35


def _geoip_months(now: float) -> list[str]:
    """This month and the one before: a new month's file appears a few days in."""
    t = time.gmtime(now)
    prev_year, prev_month = (t.tm_year, t.tm_mon - 1) if t.tm_mon > 1 else (t.tm_year - 1, 12)
    return [f"{t.tm_year:04d}-{t.tm_mon:02d}", f"{prev_year:04d}-{prev_month:02d}"]


def download_geoip_db(path: Path, now: float | None = None, timeout: float = 300) -> str:
    """Fetch the latest free DB-IP city database into path. Returns the URL used.

    Written to a temporary file, unpacked, opened once to prove it reads, and
    only then moved into place, so a failed or partial download never replaces
    a working file.
    """
    import gzip
    import shutil

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    errors = []
    for month in _geoip_months(time.time() if now is None else now):
        url = GEOIP_URL.format(month=month)
        tmp_gz = path.with_name(path.name + ".download.gz")
        tmp_db = path.with_name(path.name + ".download")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "filetrust-discovery"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, tmp_gz.open("wb") as out:
                shutil.copyfileobj(resp, out, 1024 * 1024)
            with gzip.open(tmp_gz, "rb") as src, tmp_db.open("wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
            if _geoip2_db is not None:
                _geoip2_db.Reader(str(tmp_db)).close()
            os.replace(tmp_db, path)
            return url
        except Exception as exc:
            errors.append(f"{url}: {exc}")
        finally:
            for leftover in (tmp_gz, tmp_db):
                try:
                    leftover.unlink()
                except FileNotFoundError:
                    pass
    raise RuntimeError("; ".join(errors))


# Tried in order until one works: a plain install (venv or root), then the same
# past a distro's "externally managed" guard (PEP 668), then per-user installs
# for a node running as an ordinary account.
GEOIP2_INSTALL_ATTEMPTS = (
    [],
    ["--break-system-packages"],
    ["--user"],
    ["--user", "--break-system-packages"],
)


def ensure_geoip2(log=print) -> bool:
    """Make the geoip2 package importable, installing it with pip if missing.

    Keeper locations need it and Discovery itself does not, so a server set up
    without it used to run with every city empty and nothing saying why. The
    install uses the same Python that runs this node.
    """
    global _geoip2_db
    if _geoip2_db is not None:
        return True
    import importlib
    import site
    import subprocess

    errors = []
    for extra in GEOIP2_INSTALL_ATTEMPTS:
        cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", *extra, "geoip2"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except Exception as exc:
            errors.append(f"{' '.join(extra) or 'plain'}: {exc}")
            continue
        if result.returncode != 0:
            last = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["failed"]
            errors.append(f"{' '.join(extra) or 'plain'}: {last[0]}")
            continue
        importlib.invalidate_caches()
        try:
            # A --user install lands in a folder that may not have existed when
            # this process started, so it is not on the path yet.
            site.addsitedir(site.getusersitepackages())
        except Exception:
            pass
        try:
            _geoip2_db = importlib.import_module("geoip2.database")
            log(f"[INFO] installed the geoip2 package ({' '.join(extra) or 'pip install geoip2'})")
            return True
        except Exception as exc:
            errors.append(f"installed but not importable: {exc}")
            break
    log("[WARN] keeper locations are off: could not install the geoip2 Python package; "
        f"install it by hand (pip install geoip2). Tried: {'; '.join(errors)}")
    return False


def keep_geoip_fresh(
    locator: "GeoLocator",
    config: dict[str, Any],
    stop_event: threading.Event,
    log=print,
    on_ready=None,
) -> None:
    """Make keeper locations real without anyone copying files by hand.

    Learns this host's public IP (for keepers on the same machine or LAN), then
    makes sure the database file exists and is recent, downloading it when it
    is missing or old, and reopens it. Runs beside the servers so a slow
    download never delays startup; checks again once a day.
    """
    if not locator.host_public_ip:
        locator.host_public_ip = str(config.get("public_ip", "") or "").strip() or detect_public_ip()
        if locator.host_public_ip:
            log(f"[INFO] this host's public IP for local keepers: {locator.host_public_ip}")
        else:
            log("[WARN] could not learn this host's public IP; keepers on this host will show as Localhost")
    path = locator.db_path
    if path is None or path.suffix.lower() != ".mmdb":
        return
    if _geoip2_db is None:
        log("[INFO] the geoip2 Python package is missing; installing it ...")
        if not ensure_geoip2(log):
            return
    while True:
        try:
            age_days = (time.time() - path.stat().st_mtime) / 86400 if path.is_file() else None
            if age_days is None or age_days > GEOIP_MAX_AGE_DAYS:
                log(f"[INFO] downloading the GeoIP database to {path} ...")
                url = download_geoip_db(path)
                log(f"[INFO] GeoIP database ready from {url}")
            if locator.load():
                log(f"[INFO] keeper locations on, from {path}")
                if on_ready is not None:
                    # Keepers announce rarely (every few hours), so ones that
                    # announced before the file was ready are located now.
                    on_ready()
        except Exception as exc:
            log(f"[WARN] GeoIP database download failed; locations stay empty until it works: {exc}")
        if stop_event.wait(86400):
            return


def relocate_records(state: "DiscoveryState") -> int:
    """Give a location to every stored record that has none yet. Returns how many.

    A location is normally set when a keeper announces, and keepers announce
    only every few hours. One that announced before the database was ready, or
    before this host's public IP was known, would otherwise show no city until
    its next announcement.
    """
    locator = state.geo_locator
    if not locator.enabled:
        return 0
    changed = 0
    with state.lock:
        for rec in state.records.values():
            if str(rec.get("location") or "") not in ("", "Localhost"):
                continue
            ip = location_ip(extract_ip_from_multiaddr(str(rec.get("multiaddr", ""))), "", locator.host_public_ip)
            geo = locator.lookup_full(ip) if ip else {"location": ""}
            if geo["location"] and geo["location"] != rec.get("location"):
                rec["location"] = geo["location"]
                rec["latitude"] = geo["lat"]
                rec["longitude"] = geo["lon"]
                changed += 1
        if changed:
            state._rebuild_geo_index()
    if changed:
        state.dump_records()
        state.log(f"located {changed} keeper record(s) that had no city yet")
    return changed


def location_ip(multiaddr_ip: str, client_ip: str, host_public_ip: str) -> str:
    """The address to look a keeper's location up by.

    1. The IP in its multiaddr, when that is a public address.
    2. Otherwise the address its announcement came from, when public: the
       keeper sits behind NAT and announced its private address.
    3. Otherwise this host's own public address: the keeper is on this machine
       or this LAN -- every keeper on one test server is this case -- so it is
       where this server is.
    4. Otherwise whatever there is, which looks up as Localhost or unknown.
    """
    for ip in (multiaddr_ip, client_ip):
        if ip and is_routable_ip(ip):
            return ip
    if host_public_ip:
        return host_public_ip
    return multiaddr_ip or client_ip


@dataclass
class GeoLocator:
    """Geolocation lookup backed by either an MMDB file (geoip2) or an IP2Location BIN file.

    Auto-detects format from the file extension:
      *.mmdb  — uses geoip2 (DB-IP, MaxMind GeoLite2, …)
      *.BIN   — uses IP2Location binary database
    """

    db_path: Path | None = None
    # This server's own public address, used for keepers that announce from a
    # private or loopback address (see location_ip).
    host_public_ip: str = ""
    _db: Any = field(default=None, init=False, repr=False)
    _backend: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.load()

    def load(self) -> bool:
        """(Re)open the database file. True when lookups now work.

        Called again after a fresh download, so a node that started before the
        file existed begins locating keepers without a restart.
        """
        if not self.db_path or not Path(self.db_path).is_file():
            return False
        suffix = self.db_path.suffix.lower()
        db, backend = None, ""
        if suffix == ".mmdb":
            if _geoip2_db is not None:
                try:
                    db, backend = _geoip2_db.Reader(str(self.db_path)), "mmdb"
                except Exception:
                    db = None
        else:
            if _ip2loc_module is not None:
                try:
                    db, backend = _ip2loc_module.IP2Location(str(self.db_path)), "ip2location"
                except Exception:
                    db = None
        if db is None:
            return False
        self._db, self._backend = db, backend
        return True

    @property
    def enabled(self) -> bool:
        return self._db is not None

    def lookup(self, ip: str) -> str:
        """Return 'Country, City', 'Localhost', or '' if lookup fails or IP is private."""
        return self.lookup_full(ip)["location"]

    def lookup_full(self, ip: str) -> dict[str, Any]:
        """Return {'location': str, 'lat': float, 'lon': float}."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback:
                return {"location": "Localhost", "lat": 0.0, "lon": 0.0}
        except ValueError:
            pass
        if not self._db or not is_routable_ip(ip):
            return {"location": "", "lat": 0.0, "lon": 0.0}
        try:
            if self._backend == "mmdb":
                resp = self._db.city(ip)
                country = str(resp.country.name or "").strip()
                city = str(resp.city.name or "").strip()
                lat = float(resp.location.latitude or 0.0)
                lon = float(resp.location.longitude or 0.0)
            else:
                rec = self._db.get_all(ip)
                country = str(rec.country_long or "").strip()
                city = str(rec.city or "").strip()
                lat = float(getattr(rec, "latitude", 0.0) or 0.0)
                lon = float(getattr(rec, "longitude", 0.0) or 0.0)
            if not country or country == "-":
                return {"location": "", "lat": 0.0, "lon": 0.0}
            location = f"{country}, {city}" if city and city != "-" else country
            return {"location": location, "lat": lat, "lon": lon}
        except Exception:
            return {"location": "", "lat": 0.0, "lon": 0.0}


@dataclass
class RegistryValidator:
    enabled: bool = False
    rpc_url: str = ""
    registry_address: str = ""
    registry_json: Path | None = None
    transaction_log_path: Path = DEFAULT_TRANSACTION_LOG_PATH
    cache_ttl_seconds: int = 30
    verify_endpoint_hash: bool = True
    require_endpoint_hash: bool = True
    cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    endpoint_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_loaded_at: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)
    w3: Any = None
    contract: Any = None
    endpoint_hash_supported: bool = False

    def __post_init__(self) -> None:
        if not self.enabled:
            return
        if Web3 is None:
            raise RuntimeError("web3 is required when verify_registry=true")
        if not self.rpc_url:
            raise RuntimeError("rpc_url is required when verify_registry=true")
        if not self.registry_address:
            raise RuntimeError("vault_keeper_registry_address is required when verify_registry=true")
        if self.registry_json is None:
            raise RuntimeError("vault_keeper_registry_json is required when verify_registry=true")
        artifact_path = resolve_config_path(self.registry_json)
        if not artifact_path.is_file():
            raise RuntimeError(f"VaultKeeperRegistry artifact not found: {artifact_path}")
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        abi_items = artifact.get("abi", [])
        self.endpoint_hash_supported = any(
            item.get("type") == "function" and item.get("name") == "getVaultKeeperEndpoint"
            for item in abi_items
            if isinstance(item, dict)
        )
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(self.registry_address),
            abi=abi_items,
        )
        self.transaction_log_path = resolve_config_path(self.transaction_log_path)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "RegistryValidator":
        return cls(
            enabled=bool(config.get("verify_registry", True)),
            rpc_url=str(config.get("rpc_url", "") or "").strip(),
            registry_address=str(config.get("vault_keeper_registry_address", "") or "").strip(),
            registry_json=Path(str(config.get("vault_keeper_registry_json", "") or "")),
            transaction_log_path=Path(
                str(config.get("transaction_log_path") or DEFAULT_TRANSACTION_LOG_PATH)
            ),
            cache_ttl_seconds=int(config.get("registry_cache_ttl_seconds", 30) or 30),
            verify_endpoint_hash=True,
            require_endpoint_hash=True,
        )

    def log_registry_call(
        self,
        *,
        node_id: str,
        function_name: str,
        status: str,
        error: str = "",
        result_count: int | None = None,
    ) -> None:
        if not self.enabled:
            return
        payload = {
            "tag": f"discovery:VaultKeeperRegistry.{function_name}",
            "facility": "discovery",
            "source": "discovery_nodes.py",
            "transaction_kind": "eth_call",
            "network": "",
            "chain_id": "",
            "timestamp": iso_ts(),
            "node_id": node_id,
            "rpc_url": self.rpc_url,
            "actor_address": "",
            "contract_name": "VaultKeeperRegistry",
            "function_name": function_name,
            "contract_address": self.registry_address,
            "to_address": self.registry_address,
            "value_wei": "0",
            "transaction_hash": "",
            "block_number": "",
            "status": status,
            "gas_used": "0",
            "gas_price_wei": "0",
            "effective_gas_price_wei": "0",
            "total_cost_wei": "0",
            "total_cost_eth": "0",
        }
        if result_count is not None:
            payload["result_count"] = int(result_count)
        if error:
            payload["error"] = str(error)
        append_jsonl(self.transaction_log_path, payload)

    def registration_status(self, address: str, node_id: str = "") -> tuple[bool, str]:
        """Is this one address a registered, active, unsuspended Vault Keeper?

        Two current-state reads for an address we have not seen lately, then
        cached. Nothing here grows with the size of the network or the age of
        the chain.

        This used to rebuild a peerId->address table for the entire registry
        every thirty seconds, searching all chain history for each keeper's peer
        id. That is unnecessary -- the peer id arrives inside the keeper's own
        signed record, and the signature is what proves the pair -- and it is
        also unusable: a chain that caps log queries (Cosmos: 10,000 blocks)
        refuses those searches once it is a few hours old, which silently
        emptied the table and shunned every healthy keeper at once.
        """
        checksum = self.w3.to_checksum_address(address)
        key = checksum.lower()
        now = utc_now()

        with self.lock:
            cached = self.cache.get(key)
            if cached and now - int(cached.get("checkedAt", 0)) < max(1, int(self.cache_ttl_seconds)):
                return self._verdict(cached, checksum)

        try:
            registered = bool(
                self.contract.functions.isRegisteredVaultKeeper(checksum).call()
            )
            self.log_registry_call(
                node_id=node_id, function_name="isRegisteredVaultKeeper",
                status="success", result_count=1,
            )
            profile = {"registered": registered, "active": False, "suspendedUntil": 0}
            if registered:
                vk = self.contract.functions.getVaultKeeper(checksum).call()
                self.log_registry_call(
                    node_id=node_id, function_name="getVaultKeeper",
                    status="success", result_count=1,
                )
                profile["active"] = bool(vk[3]) if len(vk) > 3 else True
                profile["suspendedUntil"] = int(vk[6]) if len(vk) > 6 else 0
            profile["checkedAt"] = now
        except Exception as exc:
            self.log_registry_call(
                node_id=node_id, function_name="registrationStatus",
                status="failed", error=str(exc),
            )
            # "I could not ask" is not "the answer is no". A keeper the chain has
            # already vouched for keeps its last verdict; one that was never
            # verified cannot be admitted on faith.
            with self.lock:
                stale = self.cache.get(key)
            if stale:
                return self._verdict(stale, checksum)
            return False, f"registry unreachable and {checksum} was never verified"

        with self.lock:
            self.cache[key] = profile
            self.last_loaded_at = now
        return self._verdict(profile, checksum)

    def _verdict(self, profile: dict[str, Any], checksum: str) -> tuple[bool, str]:
        if not bool(profile.get("registered", False)):
            return False, f"Vault Keeper is not registered: {checksum}"
        if not bool(profile.get("active", False)):
            return False, f"Vault Keeper is inactive: {checksum}"
        if int(profile.get("suspendedUntil", 0) or 0) > utc_now():
            return False, f"Vault Keeper is suspended: {checksum}"
        return True, "ok"

    def validate(self, record: dict[str, Any], node_id: str = "") -> tuple[bool, str]:
        if not self.enabled:
            return True, "registry verification disabled"

        vk_address = str(record.get("vkAddress", "")).strip()
        if not vk_address:
            return False, "vkAddress is required"
        # The signature over this record has already been checked, and it covers
        # both the peer id and the address. So the pairing is proven here, and
        # the only open question is whether the chain knows that address.
        try:
            self.w3.to_checksum_address(vk_address)
        except Exception:
            return False, f"invalid vkAddress: {vk_address}"

        ok, reason = self.registration_status(vk_address, node_id=node_id)
        if not ok:
            return False, reason
        return self.validate_endpoint(record, node_id=node_id)

    def validate_endpoint(self, record: dict[str, Any], node_id: str = "") -> tuple[bool, str]:
        if not self.verify_endpoint_hash:
            return False, "endpoint hash verification is required"
        if not self.endpoint_hash_supported:
            return False, "registry ABI does not support endpoint hashes"

        computed_hash = endpoint_hash(record)
        announced_hash = str(record.get("endpointHash", "") or "").strip()
        if announced_hash and announced_hash.lower() != computed_hash.lower():
            return False, f"endpointHash mismatch: announced={announced_hash} computed={computed_hash}"

        vk_address = str(record.get("vkAddress", "")).strip()
        try:
            checksum = self.w3.to_checksum_address(vk_address)
            record_seq = int(record.get("seq", 0))
        except Exception:
            return False, "invalid vkAddress or seq"

        now = utc_now()
        cache_key = checksum.lower()
        cached = self.endpoint_cache.get(cache_key)
        if (
            cached
            and now - int(cached.get("loadedAt", 0)) < max(1, int(self.cache_ttl_seconds))
            and int(cached.get("seq", 0)) >= record_seq
        ):
            chain_hash = str(cached.get("endpointHash", ""))
            chain_seq = int(cached.get("seq", 0))
        else:
            try:
                endpoint = self.contract.functions.getVaultKeeperEndpoint(checksum).call()
                self.log_registry_call(
                    node_id=node_id,
                    function_name="getVaultKeeperEndpoint",
                    status="success",
                    result_count=1,
                )
            except Exception as exc:
                self.log_registry_call(
                    node_id=node_id,
                    function_name="getVaultKeeperEndpoint",
                    status="failed",
                    error=str(exc),
                )
                return False, "endpoint hash lookup failed; retry later"
            chain_hash = normalize_bytes32_hex(endpoint[0] if len(endpoint) > 0 else "")
            chain_seq = int(endpoint[1] if len(endpoint) > 1 else 0)
            self.endpoint_cache[cache_key] = {
                "endpointHash": chain_hash,
                "seq": chain_seq,
                "updatedAt": int(endpoint[2] if len(endpoint) > 2 else 0),
                "loadedAt": now,
            }

        zero_hash = "0x" + ("0" * 64)
        if chain_seq <= 0 or chain_hash.lower() == zero_hash:
            return False, f"on-chain endpoint hash is not set for {vk_address}"
        if chain_seq != record_seq:
            return False, f"endpoint seq mismatch: record={record_seq} chain={chain_seq}"
        if chain_hash.lower() != computed_hash.lower():
            return False, f"endpoint hash mismatch: record={computed_hash} chain={chain_hash}"
        return True, "ok"


def identity_from_config(raw_node: dict[str, Any], config: dict[str, Any]) -> tuple[str, str, bool]:
    address = str(raw_node.get("node_address") or config.get("node_address") or "").strip()
    private_key = str(raw_node.get("node_private_key") or config.get("node_private_key") or "").strip()

    if not private_key:
        return address, "", False
    if Account is None:
        raise RuntimeError("eth_account is required to validate node_private_key")

    account = Account.from_key(private_key)
    derived = str(account.address)
    if address and address.lower() != derived.lower():
        raise RuntimeError(f"configured node_address {address} does not match node_private_key address {derived}")
    return derived, private_key, True


def collect_trusted_node_addresses(nodes: list[dict[str, Any]], config: dict[str, Any]) -> set[str]:
    addresses: set[str] = set()
    for raw_node in nodes:
        address, _private_key, _key_configured = identity_from_config(raw_node, config)
        if address:
            addresses.add(address.lower())
    return addresses


def validate_record(
    record: dict[str, Any],
    verify_signatures: bool,
    registry_validator: RegistryValidator | None = None,
    node_id: str = "",
) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(record, dict):
        return None, "record must be a JSON object"

    peer_id = str(record.get("peerId", "")).strip()
    multiaddr = str(record.get("multiaddr", "")).strip()
    vk_address = str(record.get("vkAddress", "")).strip()
    signature = str(record.get("signature", "")).strip()

    if not peer_id:
        return None, "peerId is required"
    if not multiaddr:
        return None, "multiaddr is required"
    # A record is kept in memory, written to the records file, gossiped to every
    # peer node and served to every client that asks. Nothing about a real one
    # comes close to these lengths -- a peer id is about 52 characters -- but
    # nothing stopped a registered keeper announcing a record the size of the
    # whole request and having every node hold and repeat it.
    if len(peer_id) > MAX_PEER_ID_LENGTH:
        return None, "peerId is too long"
    if len(multiaddr) > MAX_MULTIADDR_LENGTH:
        return None, "multiaddr is too long"
    if f"/p2p/{peer_id}" not in multiaddr:
        return None, "multiaddr must end with the announced peerId"
    if verify_signatures and not vk_address:
        return None, "vkAddress is required"
    if verify_signatures and not signature:
        return None, "signature is required"

    try:
        seq = int(record.get("seq", 0))
        expires_at = int(record.get("expiresAt", 0))
    except Exception:
        return None, "seq and expiresAt must be integers"

    if seq <= 0:
        return None, "seq must be positive"
    if expires_at <= utc_now():
        return None, "record is already expired"

    normalized = {
        "version": 1,
        "peerId": peer_id,
        "multiaddr": multiaddr,
        "vkAddress": vk_address,
        "seq": seq,
        "endpointHash": str(record.get("endpointHash") or "").strip(),
        "expiresAt": expires_at,
        "signature": signature,
        "location": str(record.get("location", "")).strip()[:MAX_LOCATION_LENGTH],
        "latitude": float(record.get("latitude") or 0.0),
        "longitude": float(record.get("longitude") or 0.0),
    }
    normalized["endpointHash"] = normalized["endpointHash"] or endpoint_hash(normalized)

    if verify_signatures:
        ok, reason = verify_signature(normalized)
        if not ok:
            return None, reason

    if registry_validator is not None:
        ok, reason = registry_validator.validate(normalized, node_id=node_id)
        if not ok:
            return None, reason

    return normalized, "ok"


@dataclass
class DiscoveryState:
    node_id: str
    public_url: str
    # Where this node's peers are actually dialled for gossip. Separate from
    # the addresses it names publicly: an operator who puts these nodes behind
    # a proxy publishes the proxy's names, and the machine they share should
    # still talk to itself over loopback rather than out and back again.
    peer_urls: list[str]
    runtime_dir: Path
    verify_signatures: bool = True
    registry_validator: RegistryValidator | None = None
    geo_locator: GeoLocator = field(default_factory=GeoLocator)
    # The peers as they are named to callers. /health answers with these, so a
    # node behind a proxy does not hand out the address the proxy exists to
    # keep private -- which is the whole point of putting one there.
    peer_public_urls: list[str] = field(default_factory=list)
    node_address: str = ""
    node_private_key: str = ""
    node_private_key_configured: bool = False
    sign_node_sync: bool = False
    verify_node_sync_signatures: bool = False
    trusted_node_addresses: set[str] = field(default_factory=set)
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    seen_at: dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    # Pre-computed geo index; rebuilt on every announce/expire so GET handlers are O(1).
    # Structure: {country: {lat_sum, lon_sum, count, cities: {city: {lat_sum, lon_sum, count, peer_ids}}}}
    geo_index: dict = field(default_factory=dict)
    # Every keeper and guardian with full details, read from the chain once a
    # minute and served to every client. Created in __post_init__.
    directory: "ND.DirectoryStore | None" = None
    # How often one caller may post. Set to None to accept everything, which is
    # only sensible on a closed test network.
    announce_limit: "RateLimiter | None" = None
    sync_limit: "RateLimiter | None" = None
    # Whether a forwarded-for header may be believed. Only true once a trusted
    # web server is in front; on a directly exposed node the header is just
    # something the caller typed.
    trust_proxy_header: bool = False
    # How many trusted proxies stand between this node and the caller. One for a
    # plain web server, two when a CDN sits in front of it. Wrong by one and
    # every caller behind the CDN is counted as the CDN.
    trusted_proxy_hops: int = 1
    # A header the front layer fills in with the caller itself, if it has one --
    # Cloudflare's CF-Connecting-IP, for example. Simpler than counting hops,
    # and preferred when set. Only read when the header above is trusted.
    client_ip_header: str = ""

    def __post_init__(self) -> None:
        if self.directory is None:
            self.directory = ND.DirectoryStore(self.node_id, public_path=self.directory_path)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self._start_log_archiver()
        self.load_records()
        with self.lock:
            self._rebuild_geo_index()
        self.dump_records()

    def _start_log_archiver(self) -> None:
        """Zip finished logs and drop ones past their retention, then daily.

        Only the first node in a process needs to do this -- they all share one
        logs folder -- so a duplicate start is harmless but pointless.
        """
        global _LOG_ARCHIVER_STARTED
        if _LOG_ARCHIVER_STARTED:
            return
        try:
            import log_archive

            options = log_archive.options_from_config(getattr(self, "config", {}) or {})
            log_archive.start_daily(
                self.logs_dir,
                keep_days_by_name={"transactions": 90, "calls": 3},
                **options,
            )
            _LOG_ARCHIVER_STARTED = True
        except Exception:
            pass  # tidying logs must never stop a node starting

    @property
    def logs_dir(self) -> Path:
        return self.runtime_dir / "logs"

    @property
    def records_dir(self) -> Path:
        return self.runtime_dir / "records"

    @property
    def log_path(self) -> Path:
        return self.logs_dir / f"{self.node_id}.log"

    @property
    def records_path(self) -> Path:
        return self.records_dir / f"{self.node_id}.records.json"

    @property
    def public_dir(self) -> Path:
        return self.runtime_dir / "public"

    @property
    def directory_path(self) -> Path:
        """The full network directory as a plain file (plus a .gz beside it) a
        web server or CDN can hand out without this process in the path.

        Named per node because several nodes share one runtime folder in a local
        setup; in production each node has the folder to itself.
        """
        return self.public_dir / f"{self.node_id}.directory.json"

    def log(self, message: str) -> None:
        line = f"{iso_ts()} [{self.node_id}] {safe_for_log(message)}"
        print(label_discovery_log(line))
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def load_records(self) -> None:
        if not self.records_path.exists():
            return
        try:
            data = json.loads(self.records_path.read_text(encoding="utf-8"))
            raw_records = data.get("records", [])
            if not isinstance(raw_records, list):
                return
            now = utc_now()
            for raw in raw_records:
                record, reason = validate_record(
                    raw,
                    self.verify_signatures,
                    self.registry_validator,
                    node_id=self.node_id,
                )
                if record is None:
                    continue
                if int(record["expiresAt"]) <= now:
                    continue
                self.records[record["peerId"]] = record
                self.seen_at[record["peerId"]] = int(raw.get("lastSeenAt") or now)
        except Exception as exc:
            self.log(f"record load failed path={self.records_path} err={exc}")

    def dump_records(self) -> None:
        now = utc_now()
        with self.lock:
            records = []
            for peer_id, record in sorted(self.records.items()):
                enriched = dict(record)
                last_seen = int(self.seen_at.get(peer_id, now))
                enriched["lastSeenAt"] = last_seen
                enriched["lastSeenAtIso"] = iso_ts(last_seen)
                enriched["expiresAtIso"] = iso_ts(int(record["expiresAt"]))
                records.append(enriched)
            payload = {
                "nodeId": self.node_id,
                "nodeAddress": self.node_address,
                "publicUrl": self.public_url,
                "updatedAt": now,
                "updatedAtIso": iso_ts(now),
                "recordCount": len(records),
                "records": records,
            }
            tmp = self.records_path.with_name(
                f"{self.records_path.name}.{threading.get_ident()}.tmp"
            )
            tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.records_path)

    def prune_expired(self) -> None:
        now = utc_now()
        changed = False
        with self.lock:
            expired = [peer_id for peer_id, rec in self.records.items() if int(rec["expiresAt"]) <= now]
            for peer_id in expired:
                del self.records[peer_id]
                self.seen_at.pop(peer_id, None)
                changed = True
            if changed:
                self._rebuild_geo_index()
        if changed:
            self.dump_records()

    def upsert(self, record: dict[str, Any]) -> bool:
        self.prune_expired()
        changed = False
        with self.lock:
            current = self.records.get(record["peerId"])
            if current and int(current["seq"]) > int(record["seq"]):
                return False
            if current and int(current["seq"]) == int(record["seq"]) and int(current["expiresAt"]) >= int(record["expiresAt"]):
                return False
            self.records[record["peerId"]] = dict(record)
            self.seen_at[record["peerId"]] = utc_now()
            self._rebuild_geo_index()
            changed = True
        if changed:
            self.dump_records()
        return True

    def get(self, peer_id: str) -> dict[str, Any] | None:
        self.prune_expired()
        with self.lock:
            rec = self.records.get(peer_id)
            return dict(rec) if rec else None

    def all_records(self) -> list[dict[str, Any]]:
        self.prune_expired()
        with self.lock:
            return [dict(rec) for rec in self.records.values()]

    def _rebuild_geo_index(self) -> None:
        """Rebuild geo_index from self.records. Caller must hold self.lock."""
        index: dict = {}
        localhost_count = 0
        for peer_id, rec in self.records.items():
            loc = str(rec.get("location") or "")
            if not loc or loc == "Localhost":
                localhost_count += 1
                continue
            parts = loc.split(",", 1)
            country = parts[0].strip()
            city = parts[1].strip() if len(parts) > 1 else "Unknown"
            if not country:
                continue
            lat = float(rec.get("latitude") or 0.0)
            lon = float(rec.get("longitude") or 0.0)
            if country not in index:
                index[country] = {"lat_sum": 0.0, "lon_sum": 0.0, "count": 0, "cities": {}}
            cg = index[country]
            cg["lat_sum"] += lat
            cg["lon_sum"] += lon
            cg["count"] += 1
            if city not in cg["cities"]:
                cg["cities"][city] = {"lat_sum": 0.0, "lon_sum": 0.0, "count": 0, "peer_ids": []}
            ci = cg["cities"][city]
            ci["lat_sum"] += lat
            ci["lon_sum"] += lon
            ci["count"] += 1
            ci["peer_ids"].append(peer_id)
        index["__localhost_count__"] = localhost_count  # piggyback for countries endpoint
        self.geo_index = index


def records_digest(records: list[dict[str, Any]]) -> str:
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def node_sync_message(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "FileTrust Discovery Node Sync",
            "version=1",
            f"sourceNode={payload.get('sourceNode', '')}",
            f"sourceNodeAddress={payload.get('sourceNodeAddress', '')}",
            f"issuedAt={int(payload.get('issuedAt', 0))}",
            f"recordsDigest={records_digest(payload.get('records', []) or [])}",
        ]
    )


def build_sync_payload(state: DiscoveryState, records: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {
        "sourceNode": state.node_id,
        "sourceNodeAddress": state.node_address,
        "issuedAt": utc_now(),
        "records": records,
    }
    if not state.sign_node_sync:
        return payload
    if Account is None or encode_defunct is None:
        raise RuntimeError("eth_account is required to sign discovery node sync payloads")
    if not state.node_private_key:
        raise RuntimeError(f"{state.node_id} cannot sign sync payloads: node_private_key is missing")

    signature = Account.from_key(state.node_private_key).sign_message(
        encode_defunct(text=node_sync_message(payload))
    )
    payload["signature"] = signature.signature.hex()
    return payload


def verify_node_sync_payload(state: DiscoveryState, payload: dict[str, Any]) -> tuple[bool, str]:
    if not state.verify_node_sync_signatures:
        return True, "node sync signature verification disabled"
    if Account is None or encode_defunct is None:
        return False, "eth_account is required to verify discovery node sync signatures"

    source_address = str(payload.get("sourceNodeAddress", "")).strip()
    signature = str(payload.get("signature", "")).strip()
    if not source_address:
        return False, "sourceNodeAddress is required"
    if not signature:
        return False, "sync signature is required"
    if state.trusted_node_addresses and source_address.lower() not in state.trusted_node_addresses:
        return False, f"untrusted discovery node address: {source_address}"

    try:
        issued_at = int(payload.get("issuedAt", 0))
    except Exception:
        return False, "issuedAt must be an integer"
    if abs(utc_now() - issued_at) > 300:
        return False, "sync signature expired or from the future"

    try:
        recovered = Account.recover_message(encode_defunct(text=node_sync_message(payload)), signature=signature)
    except Exception as exc:
        return False, f"sync signature recovery failed: {exc}"
    if recovered.lower() != source_address.lower():
        return False, f"sync signature recovered {recovered}, expected {source_address}"
    return True, "ok"


def post_json(url: str, payload: dict[str, Any]) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        resp.read()


def sync_record_to_peers(state: DiscoveryState, record: dict[str, Any]) -> None:
    try:
        payload = build_sync_payload(state, [record])
    except Exception as exc:
        state.log(f"sync payload signing failed: {exc}")
        return
    for peer_url in state.peer_urls:
        try:
            post_json(f"{peer_url}/v1/sync", payload)
        except Exception as exc:
            state.log(f"sync to {peer_url} failed: {exc}")


def periodic_sync(state: DiscoveryState, stop_event: threading.Event) -> None:
    while not stop_event.wait(SYNC_INTERVAL_SECONDS):
        records = state.all_records()
        if not records:
            continue
        try:
            payload = build_sync_payload(state, records)
        except Exception as exc:
            state.log(f"periodic sync payload signing failed: {exc}")
            continue
        for peer_url in state.peer_urls:
            try:
                post_json(f"{peer_url}/v1/sync", payload)
            except Exception as exc:
                state.log(f"periodic sync to {peer_url} failed: {exc}")


def build_directory_refresher(
    state: DiscoveryState, config: dict[str, Any]
) -> "ND.DirectoryRefresher | None":
    """The chain reader for this node's network directory, or None if unset.

    Without a NetworkDirectoryReader address the node still runs -- it accepts
    and serves announcements -- but /v1/directory answers "not ready", and the
    log says why.
    """
    address = str(config.get("network_directory_reader_address", "") or "").strip()
    artifact = str(config.get("network_directory_reader_json", "") or "contracts/NetworkDirectoryReader.json")
    rpc_url = str(config.get("rpc_url", "") or "").strip()
    if not address or not rpc_url or Web3 is None:
        state.log("network directory disabled: network_directory_reader_address or rpc_url not configured")
        return None
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    reader = ND.ChainDirectoryReader.from_artifact(
        w3,
        address,
        resolve_config_path(artifact),
        page_size=_positive_int(config.get("directory_page_size"), DIRECTORY_PAGE_SIZE),
    )

    def records_by_peer() -> dict[str, dict[str, Any]]:
        return {rec["peerId"]: rec for rec in state.all_records()}

    validator = state.registry_validator
    log_path = validator.transaction_log_path if validator is not None else DEFAULT_TRANSACTION_LOG_PATH

    def record_read(calls: int, keepers: int, guardians: int, block: int) -> None:
        # Read-only, so zero cost -- logged like the registry checks so the
        # transaction log shows every call this node makes to the chain.
        append_jsonl(resolve_config_path(log_path), {
            "tag": "discovery:NetworkDirectoryReader.readAll",
            "facility": "discovery",
            "source": "network_directory.py",
            "transaction_kind": "eth_call",
            "timestamp": iso_ts(),
            "node_id": state.node_id,
            "rpc_url": rpc_url,
            "contract_name": "NetworkDirectoryReader",
            "function_name": "vaultKeeperPage+guardianPage",
            "contract_address": address,
            "to_address": address,
            "value_wei": "0",
            "block_number": str(block),
            "status": "success",
            "call_count": calls,
            "result_count": keepers + guardians,
            "gas_used": "0",
            "total_cost_wei": "0",
        })

    return ND.DirectoryRefresher(
        reader,
        state.directory,
        records_by_peer,
        log=state.log,
        on_full_read=record_read,
        check_seconds=_positive_int(config.get("directory_check_seconds"), DIRECTORY_CHECK_SECONDS),
        full_refresh_seconds=_positive_int(
            config.get("directory_full_refresh_seconds"), DIRECTORY_FULL_REFRESH_SECONDS
        ),
    )


def write_public_file(path: Path, body: bytes) -> None:
    """Replace a file in one step, so a reader never sees a half-written one.

    Whatever serves this file is reading it at the same time as it is rewritten.
    Writing in place would let a request land on a truncated file and hand a
    client a broken document; a rename swaps the whole file at once instead.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(body)
    os.replace(tmp, path)


class RateLimiter:
    """How often one caller may post, counted over a moving window.

    Reads can be cached or served as a file, so a flood of them costs nothing.
    Posts cannot: /v1/announce verifies a signature and reads the chain, and
    /v1/sync merges records. Those are the expensive paths, and until now there
    was no limit on them at all.

    Counted per caller rather than in total, so one noisy source cannot use up
    everyone else's allowance. Honest use is far below these numbers: a keeper
    re-announces every few minutes, and nodes gossip on a timer.
    """

    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = max(1, int(limit))
        self.window = max(1, int(window_seconds))
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Record an attempt. Returns (allowed, seconds to wait if refused)."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits.get(key, ()) if t > cutoff]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                return False, max(1, int(self.window - (now - hits[0])))
            hits.append(now)
            self._hits[key] = hits
            # Keys stop being tracked once they go quiet, so a stream of
            # different callers cannot grow this without bound.
            if len(self._hits) > 4096:
                for k in [k for k, v in self._hits.items() if not any(t > cutoff for t in v)]:
                    self._hits.pop(k, None)
            return True, 0


def client_source(
    peer_ip: str,
    forwarded_for: str,
    trust_proxy: bool,
    trusted_proxy_hops: int = 1,
    client_ip_header_value: str = "",
) -> str:
    """Which address a request should be counted against.

    A node in production sits behind a web server, so the socket address is that
    web server for every request. Counting by it would put the whole network in
    one bucket and let a single flood lock out every honest keeper -- the exact
    failure the per-caller limit exists to prevent.

    The forwarded header fixes that, but only when something trustworthy is
    setting it: any client can send the header itself, so trusting it on a
    directly exposed node would let a flood reset its own count at will. Hence
    the switch, off by default, to be turned on only once a proxy is in front.

    Counted from the right, because that end is the one written by machines this
    node trusts. Each proxy appends the address it saw, so the last entry came
    from the nearest proxy, the one before it from the proxy before that, and so
    on. Everything further left was supplied by the caller and is worth nothing
    -- but it also cannot shift the position of the entries that matter, which
    is the whole reason for counting from this end rather than the other.

    So the caller sits `trusted_proxy_hops` from the right. One hop, a plain
    web server: the last entry is the caller. Two hops, a CDN in front of that
    web server: the last entry is the CDN's own edge, and the caller is the one
    before it. Getting this number wrong is not cosmetic -- with a CDN and a
    count of one, every request in the world is attributed to a handful of edge
    addresses, and the per-caller limit stops being per caller.

    A CDN that states the caller in a header of its own is simpler and is
    preferred when configured, since it does not depend on counting anything.
    """
    if not trust_proxy:
        return peer_ip or "unknown"

    stated = (client_ip_header_value or "").split(",")[0].strip()
    if stated:
        return stated

    chain = [part.strip() for part in (forwarded_for or "").split(",") if part.strip()]
    hops = max(1, int(trusted_proxy_hops or 1))
    if len(chain) >= hops:
        return chain[-hops]
    # Fewer entries than there are trusted proxies: something is not forwarding
    # what it claims to. The remaining entries are all caller-supplied at this
    # point, so none of them can be believed.
    return peer_ip or "unknown"


def is_public_bind(host: str) -> bool:
    """Whether this address accepts connections from outside the machine."""
    cleaned = (host or "").strip().strip("[]")
    if cleaned in ("", "0.0.0.0", "::", "*"):
        return True
    try:
        return not ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return True  # a name that has to be resolved is not a loopback bind


def rate_limit_keys(path: str, source: str, payload: dict[str, Any] | None) -> list[str]:
    """Who this request counts against.

    Always the source address, so one host cannot use up the allowance of every
    other caller -- a single shared bucket would let one flood lock out every
    honest keeper, which is a denial of service by a different route.

    An announce is counted against the claimed keeper as well, so one host
    cannot multiply its allowance by rotating through addresses. A forged
    address only ever spends its own count.
    """
    keys = [f"{path}|ip|{source}"]
    if path == "/v1/announce":
        claimed = str((payload or {}).get("vkAddress", "")).strip().lower()
        if claimed:
            keys.append(f"{path}|vk|{claimed}")
    return keys



def public_service_url(value: str) -> str:
    """Service metadata publishes DNS names; private sync endpoints stay private."""
    try:
        url = urllib.parse.urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password:
            return ""
        host = url.hostname.rstrip(".")
        if not host or not host.isascii() or any(not (c.isalnum() or c in ".-") for c in host):
            return ""
        url.port
        try:
            socket.inet_aton(host)
            return ""
        except OSError:
            pass
        try:
            ipaddress.ip_address(host)
            return ""
        except ValueError:
            return value
    except ValueError:
        return ""


class DiscoveryHandler(BaseHTTPRequestHandler):
    server_version = "FileTrustDiscovery"
    # The default appends the exact Python version to every reply. That is a
    # free gift to anyone deciding whether this host is worth attacking: it
    # names an interpreter to look up known vulnerabilities against, before
    # sending a single interesting request. Nothing legitimate reads it.
    sys_version = ""
    # Drop a connection that stops making progress. Without this a sender can
    # open connections and dribble a request slowly, holding a thread each,
    # until there are none left -- no traffic volume required.
    timeout = 15

    @property
    def state(self) -> DiscoveryState:
        return self.server.discovery_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        # The real caller, not the proxy. Behind one, the socket address is the
        # same for every request, so a log written from it names the proxy over
        # and over and cannot tell anyone apart.
        self.state.log(f"{self.request_source()} - {fmt % args}")

    # A discovery record is a few hundred bytes; a sync batch is larger but
    # still small. Anything past this is not a caller that needs help, and
    # reading it would let one request occupy memory and a thread for as long
    # as the sender cares to keep sending.
    max_body_bytes = 1_048_576

    def read_json(self) -> dict[str, Any] | None | int:
        """Parsed body, None for malformed, or 413 when it is too large.

        The declared length is checked before a single byte is read, so an
        oversized request is refused rather than absorbed.
        """
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None
        if length <= 0:
            return {}
        if length > self.max_body_bytes:
            return 413
        try:
            body = self.rfile.read(length)
        except Exception:
            return None
        # A sender that promises more than it delivers must not be treated as
        # having sent valid JSON.
        if len(body) != length:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None

    def write_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def write_directory(self, query: str) -> None:
        """Answer with the network directory, only what changed, or nothing.

        `?since=<version>&epoch=<epoch>` from a caller that already holds a
        version gets only the rows changed since then, or a 304 when nothing
        did. A caller without one -- or holding a version from another node or
        an earlier run -- gets the full document, which is encoded once per
        version and also carries an ETag for plain HTTP caches. gzip is used
        whenever the caller accepts it.
        """
        store = self.state.directory
        qs = urllib.parse.parse_qs(query)
        epoch = (qs.get("epoch") or [""])[0].strip()
        try:
            since: int | None = int((qs.get("since") or [""])[0])
        except ValueError:
            since = None
        gzip_ok = "gzip" in self.headers.get("Accept-Encoding", "").lower()
        max_age = max(10, DIRECTORY_CHECK_SECONDS // 2)

        if since is None and self.headers.get("If-None-Match", "") == store.etag and store.version:
            kind, body = "same", b""
        else:
            kind, body = store.answer(since, epoch, gzip_ok)
        if kind == "same":
            self.send_response(304)
            self.send_header("ETag", store.etag)
            self.send_header("Cache-Control", f"public, max-age={max_age}")
            self.end_headers()
            return
        if not body:
            body = json.dumps({"ok": False, "err": "directory not ready", "version": 0}).encode("utf-8")
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Retry-After", str(DIRECTORY_CHECK_SECONDS))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if gzip_ok:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(body)))
        if kind == "full":
            self.send_header("ETag", store.etag)
            self.send_header("Cache-Control", f"public, max-age={max_age}")
        else:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self.write_json(
                200,
                {
                    "ok": True,
                    "nodeId": self.state.node_id,
                    "publicUrl": public_service_url(self.state.public_url),
                    "records": len(self.state.all_records()),
                    "peers": [named for url in (self.state.peer_public_urls or self.state.peer_urls)
                              if (named := public_service_url(url))],
                    "verifySignatures": self.state.verify_signatures,
                    "verifyRegistry": bool(
                        self.state.registry_validator and self.state.registry_validator.enabled
                    ),
                    "verifyEndpointHash": bool(
                        self.state.registry_validator
                        and self.state.registry_validator.enabled
                        and self.state.registry_validator.verify_endpoint_hash
                    ),
                    "requireEndpointHash": bool(
                        self.state.registry_validator
                        and self.state.registry_validator.require_endpoint_hash
                    ),
                    "nodeAddress": self.state.node_address,
                    "nodePrivateKeyConfigured": self.state.node_private_key_configured,
                    "signNodeSync": self.state.sign_node_sync,
                    "verifyNodeSyncSignatures": self.state.verify_node_sync_signatures,
                    "trustedNodeAddressCount": len(self.state.trusted_node_addresses),
                    # Where the files live is deliberately not here. It used to
                    # be, and it told any anonymous caller the absolute paths on
                    # disk -- the deployment layout and the account the service
                    # runs under -- which is reconnaissance for whatever comes
                    # next. An operator reads those from the startup log, where
                    # they still are, and no client ever read them.
                },
            )
            return

        if path == "/v1/records":
            self.write_json(200, {"ok": True, "records": self.state.all_records()})
            return

        if path == "/v1/directory":
            self.write_directory(self.path.split("?", 1)[1] if "?" in self.path else "")
            return

        prefix = "/v1/peers/"
        if path.startswith(prefix):
            peer_id = urllib.parse.unquote(path[len(prefix) :]).strip()
            record = self.state.get(peer_id)
            if not record:
                self.write_json(404, {"ok": False, "err": "peerId not found"})
                return
            self.write_json(200, {"ok": True, "record": record})
            return

        # ── Geo tier endpoints (pre-computed, served from geo_index) ──────────────

        if path == "/v1/vk-geo/countries":
            with self.state.lock:
                idx = dict(self.state.geo_index)
            localhost_count = idx.pop("__localhost_count__", 0)
            countries = []
            for country, g in idx.items():
                n = g["count"]
                countries.append({
                    "country": country,
                    "count": n,
                    "lat": g["lat_sum"] / n,
                    "lon": g["lon_sum"] / n,
                })
            self.write_json(200, {"ok": True, "countries": countries, "localhostCount": localhost_count})
            return

        if path == "/v1/vk-geo/cities":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            country_filter = (qs.get("country") or [""])[0].strip()
            with self.state.lock:
                idx = dict(self.state.geo_index)
            cg = idx.get(country_filter, {})
            cities = []
            for city, g in cg.get("cities", {}).items():
                n = g["count"]
                cities.append({
                    "city": city,
                    "count": n,
                    "lat": g["lat_sum"] / n,
                    "lon": g["lon_sum"] / n,
                })
            self.write_json(200, {"ok": True, "country": country_filter, "cities": cities})
            return

        if path == "/v1/vk-geo/nodes":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            country_filter = (qs.get("country") or [""])[0].strip()
            city_filter = (qs.get("city") or [""])[0].strip()
            with self.state.lock:
                idx = dict(self.state.geo_index)
                all_recs = dict(self.state.records)
            cg = idx.get(country_filter, {})
            peer_ids = cg.get("cities", {}).get(city_filter, {}).get("peer_ids", [])
            nodes = []
            for pid in peer_ids:
                rec = all_recs.get(pid)
                if rec:
                    nodes.append({
                        "peerId":    rec.get("peerId", ""),
                        "address":   rec.get("vkAddress", ""),   # alias used by DO table
                        "vkAddress": rec.get("vkAddress", ""),
                        "multiaddr": rec.get("multiaddr", ""),
                        "seq":       rec.get("seq", 0),
                        "endpointHash": rec.get("endpointHash", ""),
                        "expiresAt": rec.get("expiresAt", 0),
                        "location":  rec.get("location", ""),
                        "latitude":  rec.get("latitude", 0.0),
                        "longitude": rec.get("longitude", 0.0),
                    })
            self.write_json(200, {"ok": True, "country": country_filter, "city": city_filter, "nodes": nodes})
            return

        self.write_json(404, {"ok": False, "err": "not found"})

    def request_source(self) -> str:
        """The address this request is counted and logged against.

        Tolerant of being called before the request is parsed: a request that
        fails to parse still gets logged, and losing the log line to a missing
        header would hide exactly the requests worth seeing.
        """
        headers = getattr(self, "headers", None)
        named = self.state.client_ip_header
        return client_source(
            self.client_address[0] if self.client_address else "",
            headers.get("X-Forwarded-For", "") if headers else "",
            self.state.trust_proxy_header,
            self.state.trusted_proxy_hops,
            headers.get(named, "") if (headers and named) else "",
        )

    def rate_limited(self, path: str, payload: dict[str, Any]) -> bool:
        """Refuse a caller that is posting far more often than any honest one.

        Checked before the signature and before any chain read, because the
        point is to not spend that work on a flood.

        Counted by source address first. For an announce it is also counted per
        claimed keeper, so one host cannot use up the whole allowance by
        rotating through addresses -- and a forged address only spends its own.
        """
        limiter = self.state.announce_limit if path == "/v1/announce" else self.state.sync_limit
        if limiter is None:
            return False

        source = self.request_source()
        for key in rate_limit_keys(path, source, payload):
            allowed, retry_after = limiter.allow(key)
            if not allowed:
                self.state.log(f"rate limited {path} from {source} (retry in {retry_after}s)")
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", str(retry_after))
                body = json.dumps({"ok": False, "err": "too many requests"}).encode("utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return True
        return False

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        payload = self.read_json()
        if payload == 413:
            self.write_json(413, {"ok": False, "err": "request body too large"})
            return
        if payload is None or not isinstance(payload, dict):
            self.write_json(400, {"ok": False, "err": "invalid JSON"})
            return
        if self.rate_limited(path, payload):
            return

        if path == "/v1/announce":
            record, reason = validate_record(
                payload,
                self.state.verify_signatures,
                self.state.registry_validator,
                node_id=self.state.node_id,
            )
            if record is None:
                self.state.log(f"announce rejected: {reason}")
                self.write_json(400, {"ok": False, "err": reason})
                return

            locator = self.state.geo_locator
            ip = location_ip(
                extract_ip_from_multiaddr(record.get("multiaddr", "")),
                self.client_address[0],
                locator.host_public_ip,
            )
            geo = locator.lookup_full(ip)
            if geo["location"]:
                record = dict(record)
                record["location"] = geo["location"]
                record["latitude"] = geo["lat"]
                record["longitude"] = geo["lon"]

            changed = self.state.upsert(record)
            if changed:
                threading.Thread(target=sync_record_to_peers, args=(self.state, record), daemon=True).start()
            self.state.log(
                f"announce peerId={record['peerId']} multiaddr={record['multiaddr']} "
                f"location={record.get('location', '')} "
                f"expiresAt={record['expiresAt']} recordsFile={self.state.records_path}"
            )
            self.write_json(200, {"ok": True, "nodeId": self.state.node_id, "record": record})
            return

        if path == "/v1/sync":
            sync_ok, sync_reason = verify_node_sync_payload(self.state, payload)
            if not sync_ok:
                self.write_json(400, {"ok": False, "err": sync_reason})
                return

            raw_records = payload.get("records", [])
            if isinstance(raw_records, dict):
                raw_records = [raw_records]
            if not isinstance(raw_records, list):
                self.write_json(400, {"ok": False, "err": "records must be a list"})
                return

            accepted = 0
            errors = []
            for raw in raw_records:
                record, reason = validate_record(
                    raw,
                    self.state.verify_signatures,
                    self.state.registry_validator,
                    node_id=self.state.node_id,
                )
                if record is None:
                    self.state.log(f"sync record rejected: {reason}")
                    errors.append(reason)
                    continue
                if self.state.upsert(record):
                    accepted += 1

            self.write_json(
                200,
                {
                    "ok": len(errors) == 0,
                    "nodeId": self.state.node_id,
                    "accepted": accepted,
                    "errors": errors,
                },
            )
            return

        self.write_json(404, {"ok": False, "err": "not found"})


def _positive_int(value: Any, default: int) -> int:
    """A count that is nonsense falls back rather than disabling the count."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _limiter_from_config(config: dict[str, Any], key: str, default: int) -> "RateLimiter | None":
    """Build a limiter from config. Zero or less means no limit at all."""
    try:
        limit = int(config.get(key, default))
    except (TypeError, ValueError):
        limit = default
    return RateLimiter(limit) if limit > 0 else None


def node_from_config(
    raw_node: dict[str, Any],
    config: dict[str, Any],
    peer_urls: list[str],
    runtime_dir: Path,
    verify_signatures: bool,
    registry_validator: RegistryValidator,
    trusted_node_addresses: set[str],
    geo_locator: GeoLocator | None = None,
    peer_public_urls: list[str] | None = None,
    sync_url: str = "",
) -> ThreadingHTTPServer:
    node_id = str(raw_node.get("id") or f"discovery-{raw_node.get('port')}")
    host = str(raw_node.get("host") or "127.0.0.1")
    port = int(raw_node.get("port"))
    public_url = normalize_url(raw_node.get("public_url") or f"http://{host}:{port}")
    # What this node answers to for gossip. Defaults to its public name, which
    # is what every deployment did before there was a difference.
    own_sync_url = normalize_url(sync_url or raw_node.get("sync_url") or public_url)
    node_address, node_private_key, key_configured = identity_from_config(raw_node, config)
    sign_node_sync = bool(config.get("sign_node_sync", False))
    verify_node_sync_signatures = bool(config.get("verify_node_sync_signatures", False))
    if sign_node_sync and not node_private_key:
        raise RuntimeError(f"{node_id} has sign_node_sync=true but no node_private_key")
    state = DiscoveryState(
        node_id=node_id,
        public_url=public_url,
        peer_urls=[url for url in peer_urls if url not in (public_url, own_sync_url)],
        peer_public_urls=[
            url for url in (peer_public_urls or peer_urls) if url != public_url
        ],
        runtime_dir=runtime_dir,
        verify_signatures=verify_signatures,
        registry_validator=registry_validator,
        geo_locator=geo_locator if geo_locator is not None else GeoLocator(),
        node_address=node_address,
        node_private_key=node_private_key,
        node_private_key_configured=key_configured,
        sign_node_sync=sign_node_sync,
        verify_node_sync_signatures=verify_node_sync_signatures,
        trusted_node_addresses=trusted_node_addresses,
        # Generous next to honest behaviour -- a keeper re-announces every few
        # minutes and nodes gossip on a timer -- but far below what a flood
        # needs to be worth mounting. Set either to 0 to switch the limit off,
        # which only makes sense on a closed network.
        announce_limit=_limiter_from_config(config, "announce_rate_limit_per_minute", 30),
        sync_limit=_limiter_from_config(config, "sync_rate_limit_per_minute", 240),
        trust_proxy_header=bool(config.get("trust_proxy_header", False)),
        trusted_proxy_hops=_positive_int(config.get("trusted_proxy_hops"), 1),
        client_ip_header=str(config.get("client_ip_header", "") or "").strip(),
    )
    # This is a development server. It has no TLS, no connection limit and no
    # protection against a slow or malformed request beyond what is written
    # here, so in production a web server terminates the outside connection and
    # this listens on loopback behind it. Binding it outward is allowed --
    # a closed test network is a fair reason -- but it should never be the
    # thing that quietly happens.
    if is_public_bind(host):
        state.log(
            f"WARNING: {node_id} is bound to {host}, reachable from outside this machine. "
            "In production bind 127.0.0.1 and put a web server in front "
            "(see DISCOVERY_DEPLOYMENT.md)."
        )
        print(label_discovery_log(
            f"[WARN] {node_id} listens on {host}; expose it through a web server, not directly"
        ))
    if state.trust_proxy_header and is_public_bind(host):
        # The header can be set by anyone who can reach the node, so believing
        # it while callers can connect directly hands every one of them a way to
        # look like a different caller on each request.
        state.log(
            f"WARNING: {node_id} trusts X-Forwarded-For while bound to {host}; "
            "any caller can then forge its own source address"
        )
    server = ThreadingHTTPServer((host, port), DiscoveryHandler)
    server.discovery_state = state  # type: ignore[attr-defined]
    return server


def load_config(path: Path | None, ports: str | None) -> dict[str, Any]:
    if path and path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    if DEFAULT_CONFIG.exists() and ports is None:
        return json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))

    port_values = [4601, 4602, 4603]
    if ports:
        port_values = [int(p.strip()) for p in ports.split(",") if p.strip()]
    return {
        "verify_signatures": True,
        "verify_registry": True,
        "verify_endpoint_hash": True,
        "require_endpoint_hash": True,
        "rpc_url": "http://127.0.0.1:8545",
        "vault_keeper_registry_address": "",
        "vault_keeper_registry_json": "contracts/VaultKeeperRegistry.json",
        "network_directory_reader_address": "",
        "network_directory_reader_json": "contracts/NetworkDirectoryReader.json",
        "registry_cache_ttl_seconds": 30,
        "transaction_log_path": str(DEFAULT_TRANSACTION_LOG_PATH),
        "sign_node_sync": False,
        "verify_node_sync_signatures": False,
        "runtime_dir": str(BASE_DIR / "runtime"),
        "nodes": [
            {
                "id": f"discovery-{idx}",
                "host": "127.0.0.1",
                "port": port,
                "public_url": f"http://127.0.0.1:{port}",
            }
            for idx, port in enumerate(port_values, start=1)
        ],
    }


def run_servers(config: dict[str, Any], stop_event=None) -> int:
    nodes = config.get("nodes") or []
    if not nodes:
        raise SystemExit("config must contain at least one discovery node")
    verify_signatures = bool(config.get("verify_signatures", True))
    if not verify_signatures:
        raise SystemExit("verify_signatures=true is required for VK discovery")
    if not bool(config.get("verify_registry", True)):
        raise SystemExit("verify_registry=true is required for VK discovery")
    if not bool(config.get("verify_endpoint_hash", True)):
        raise SystemExit("verify_endpoint_hash=true is required for VK discovery")
    if not bool(config.get("require_endpoint_hash", True)):
        raise SystemExit("require_endpoint_hash=true is required for VK discovery")
    config["verify_registry"] = True
    config["verify_endpoint_hash"] = True
    config["require_endpoint_hash"] = True
    if verify_signatures and (Account is None or encode_defunct is None):
        raise SystemExit("eth_account is required. Run with the App Python environment or set verify_signatures=false.")
    try:
        registry_validator = RegistryValidator.from_config(config)
    except Exception as exc:
        raise SystemExit(f"Discovery registry configuration error: {exc}")
    if registry_validator.enabled and not verify_signatures:
        raise SystemExit("verify_registry=true requires verify_signatures=true")

    runtime_raw = Path(str(config.get("runtime_dir") or (BASE_DIR / "runtime"))).expanduser()
    runtime_dir = runtime_raw if runtime_raw.is_absolute() else (BASE_DIR / runtime_raw).resolve()

    public_urls = [
        normalize_url(node.get("public_url") or f"http://{node.get('host', '127.0.0.1')}:{int(node['port'])}")
        for node in nodes
    ]
    # How these nodes reach each other. A node behind a proxy publishes the
    # proxy's name, and without this the three of them would gossip out to the
    # internet and back to reach a process on the same machine -- slower, and
    # dependent on the proxy being up to talk to itself.
    sync_urls = [
        normalize_url(
            node.get("sync_url")
            or f"http://{node.get('host', '127.0.0.1')}:{int(node['port'])}"
        )
        for node in nodes
    ]
    try:
        trusted_node_addresses = collect_trusted_node_addresses(nodes, config)
    except Exception as exc:
        raise SystemExit(f"Discovery node identity configuration error: {exc}")
    if bool(config.get("verify_node_sync_signatures", False)) and not trusted_node_addresses:
        raise SystemExit("verify_node_sync_signatures=true requires configured node addresses")

    db_path_str = str(config.get("ip2location_db", "") or "").strip()
    geo_locator = GeoLocator(
        db_path=resolve_config_path(db_path_str) if db_path_str else None
    )
    if db_path_str:
        if geo_locator.enabled:
            print(f"[INFO] geolocation database loaded: {db_path_str}")
        else:
            print(f"[INFO] geolocation database not loaded yet ({db_path_str}); fetching it in the background")

    servers = [
        node_from_config(
            node,
            config,
            sync_urls,
            runtime_dir,
            verify_signatures,
            registry_validator,
            trusted_node_addresses,
            geo_locator,
            peer_public_urls=public_urls,
            sync_url=sync_urls[index],
        )
        for index, node in enumerate(nodes)
    ]
    stop_event = stop_event if stop_event is not None else threading.Event()
    threads: list[threading.Thread] = []
    if db_path_str or config.get("public_ip"):
        # Public IP and database fetch run beside the servers, never before them.
        geo_thread = threading.Thread(
            target=keep_geoip_fresh,
            args=(geo_locator, config, stop_event),
            kwargs={
                "log": lambda m: print(m, flush=True),
                "on_ready": lambda: [relocate_records(srv.discovery_state) for srv in servers],
            },
            daemon=True,
        )
        geo_thread.start()
        threads.append(geo_thread)

    for server in servers:
        state = server.discovery_state  # type: ignore[attr-defined]
        state.log(
            f"listening at {state.public_url}; peers={state.peer_urls}; "
            f"verifyRegistry={bool(state.registry_validator and state.registry_validator.enabled)}; "
            f"geoLocation={state.geo_locator.enabled}; hostPublicIp={state.geo_locator.host_public_ip or '(none)'}; "
            f"nodeAddress={state.node_address or '(none)'}; "
            f"signNodeSync={state.sign_node_sync}; verifyNodeSync={state.verify_node_sync_signatures}; "
            f"logFile={state.log_path}; recordsFile={state.records_path}; "
            f"transactionLogFile={state.registry_validator.transaction_log_path if state.registry_validator else ''}"
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
        sync_thread = threading.Thread(target=periodic_sync, args=(state, stop_event), daemon=True)
        sync_thread.start()
        threads.append(sync_thread)
        refresher = build_directory_refresher(state, config)
        if refresher is not None:
            directory_thread = threading.Thread(target=refresher.run, args=(stop_event,), daemon=True)
            directory_thread.start()
            threads.append(directory_thread)

    if __name__ == '__main__':
        from ft_update_bootstrap import ready
        ready(BASE_DIR)
    try:
        while not stop_event.wait(1):
            pass
    except KeyboardInterrupt:
        print(label_discovery_log("\nStopping discovery nodes..."))
    finally:
        stop_event.set()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
        if __name__ == '__main__':
            (BASE_DIR / '.filetrust-node-health.json').unlink(missing_ok=True)
    return 0


def main() -> int:
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    parser = argparse.ArgumentParser(description="Run FileTrust VK discovery nodes")
    parser.add_argument("--config", type=Path, default=None, help="Discovery config JSON path")
    parser.add_argument("--ports", default=None, help="Comma-separated local ports, e.g. 4601,4602,4603")
    args = parser.parse_args()
    config = load_config(args.config, args.ports)
    from ft_updates import start_watcher
    start_watcher(Path(__file__).resolve().parent,
                  log=lambda message: print(label_discovery_log(message), flush=True))
    from ft_network_config import locked
    with locked(Path(__file__).resolve().parent / ".run.lock"):
        return run_servers(config, stop)


if __name__ == "__main__":
    raise SystemExit(main())
