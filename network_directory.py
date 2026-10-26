"""The network directory: every Vault Keeper and Guardian, with full details.

One discovery node reads the chain once a minute and serves the result to every
Data Owner, so the chain answers one caller per discovery node instead of one
per client, and no client ever reads the network row by row.

Three parts:

ChainDirectoryReader
    Reads through the NetworkDirectoryReader contract: a page of 100 full rows
    per eth_call, every page pinned to the same block so the answer is one
    consistent snapshot. Before reading, it asks for logs from the source
    contracts over the new blocks only -- one cheap call -- and skips the read
    when nothing was written. It never searches old history, so the age of the
    chain does not matter.

DirectoryStore
    Holds the current rows, numbers each change as a new version, and remembers
    what changed in recent versions. A client that already holds version N is
    sent only the rows that changed since N, or nothing when nothing changed.

The document format
    Rows are arrays with the column names sent once, gzip is offered, and the
    full document is encoded once per version rather than once per request.

Everything served here is a hint for choosing. A client about to pay checks the
few keepers it chose against the chain itself.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import secrets
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable

FORMAT_VERSION = 1

# Column order is the wire format. Names travel once per document, so they can
# be readable; each row is a plain array in this order.
VK_COLUMNS = [
    "address", "peerId", "multiaddr", "location", "lat", "lon",
    "storageFee", "stake", "active", "registeredAt", "lastHeartbeat",
    "suspendedUntil", "maxServiceDays", "maxPieceSizeBytes",
    "admissionClosed", "admissionClosureReason", "reportedFreeBytes",
    "reputation", "penaltyPoints", "disputeCount", "missedProofs",
    "lastActivityAt", "completedPieces", "lastProofAt",
    "declaredBytes", "registeredFreeBytes", "registeredDataBytes",
    "provedFreeBytes", "provedDataBytes", "conservativeFreeBytes",
    "capacityProofFresh",
]

G_COLUMNS = [
    "address", "active", "stake", "reputation", "completedJobs", "failedJobs",
    "disputes", "dkgFee", "telgFee", "refreshFee", "registeredAt",
    "lastHeartbeat", "pricingSet", "dkgMaterialSu", "dkgShareKeySu",
    "preBatchPartialSu", "dailyShareCustodySu", "maxServiceDays",
    "lastProofAt", "totalProofPenalties", "dkgComplaints", "lastActivityAt",
    "preBadPartial",
]

# Keep chain ABI field order separate from the additive directory fields.
_G_CHAIN_FIELDS = list(G_COLUMNS)
LIVENESS_COLUMNS = ["participation", "heartbeatFresh"]
VK_COLUMNS += LIVENESS_COLUMNS
G_COLUMNS += LIVENESS_COLUMNS
HEARTBEAT_FRESH_SECONDS = 45 * 60


def liveness_row(row, columns, now):
    row = list(row)
    values = dict(zip(columns, row))
    heartbeat = int(values.get("lastHeartbeat", 0) or 0)
    participation = "suspended" if int(values.get("suspendedUntil", 0) or 0) > now else ("enabled" if values.get("active") else "disabled")
    fresh = 0 < heartbeat <= now and now - heartbeat <= HEARTBEAT_FRESH_SECONDS
    base = len(columns) - len(LIVENESS_COLUMNS)
    return row[:base] + [participation, fresh]


META_FIELDS = [
    "blockNumber", "blockTimestamp", "vaultKeeperCount", "guardianCount",
    "vaultKeeperMinStake", "guardianMinStake", "admissionMarginBytes",
    "guardianProofPeriodSeconds",
]

# NetworkDirectoryReader.sources() order. A zero address means that contract was
# not configured and its columns are zero because nothing was read, not because
# the value is zero; meta["sources"] lets a client tell the two apart.
SOURCE_NAMES = [
    "vaultKeeperRegistry", "guardianRegistry", "reputationManager", "vkEscrow",
    "storageProof", "capacityProof", "guardianShareProof", "telgV2",
]

# Chain-side columns of a keeper row, as the contract returns them. The first
# six VK_COLUMNS are identity and location, filled from discovery's records.
_VK_CHAIN_FIELDS = [
    "storageFee", "stake", "active", "registeredAt", "lastHeartbeat",
    "suspendedUntil", "maxServiceDays", "maxPieceSizeBytes",
    "admissionClosed", "admissionClosureReason", "reportedFreeBytes",
    "reputation", "penaltyPoints", "disputeCount", "missedProofs",
    "lastActivityAt", "completedPieces", "lastProofAt",
    "declaredBytes", "registeredFreeBytes", "registeredDataBytes",
    "provedFreeBytes", "provedDataBytes", "conservativeFreeBytes",
    "capacityProofFresh",
]

_ZERO_ADDRESS = "0x" + "0" * 40


def _plain(value: Any) -> Any:
    """Booleans as 0/1, everything else as the int or str it already is."""
    if isinstance(value, bool):
        return 1 if value else 0
    return value


def _field(item: Any, name: str, index: int) -> Any:
    """Read a decoded struct field by name, falling back to position."""
    if isinstance(item, dict):
        return item.get(name)
    try:
        return getattr(item, name)
    except AttributeError:
        return item[index]


# ── chain side ────────────────────────────────────────────────────────────────


class ChainDirectoryReader:
    """Reads the whole network through NetworkDirectoryReader, a page per call."""

    def __init__(
        self,
        w3: Any,
        reader_address: str,
        reader_abi: list[dict[str, Any]],
        page_size: int = 100,
        max_log_range: int = 5_000,
    ) -> None:
        self.w3 = w3
        self.contract = w3.eth.contract(address=w3.to_checksum_address(reader_address), abi=reader_abi)
        self.page_size = max(1, int(page_size))
        # Chains cap how many blocks one log query may span (Cosmos: 10,000).
        # A gap wider than this -- after downtime -- is treated as "changed".
        self.max_log_range = max(1, int(max_log_range))
        self._sources: list[str] | None = None
        self._configured: dict[str, int] = {}
        self.calls = 0  # eth_call / eth_getLogs made, for the refresh log line

    @classmethod
    def from_artifact(cls, w3: Any, reader_address: str, artifact_path: Path, page_size: int = 100):
        artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
        return cls(w3, reader_address, artifact.get("abi", []), page_size=page_size)

    def sources(self) -> list[str]:
        if self._sources is None:
            self.calls += 1
            raw = list(self.contract.functions.sources().call())
            self._configured = {
                name: int(str(a).lower() != _ZERO_ADDRESS) for name, a in zip(SOURCE_NAMES, raw)
            }
            self._sources = [
                self.w3.to_checksum_address(a) for a in raw if str(a).lower() != _ZERO_ADDRESS
            ]
        return self._sources

    def latest_block(self) -> int:
        self.calls += 1
        return int(self.w3.eth.block_number)

    def changed_since(self, from_block: int, to_block: int) -> bool:
        """Did any source contract write anything in [from_block, to_block]?

        One log query over the new blocks only. Never a search of old history.
        """
        if to_block < from_block:
            return False
        if to_block - from_block + 1 > self.max_log_range:
            return True
        self.calls += 1
        logs = self.w3.eth.get_logs({
            "fromBlock": int(from_block),
            "toBlock": int(to_block),
            "address": self.sources(),
        })
        return bool(logs)

    def read_all(self, block: int) -> tuple[dict[str, int], dict[str, dict], dict[str, dict]]:
        """Every keeper and guardian at one block, as plain dicts keyed by address."""
        meta: dict[str, int] = {}
        keepers: dict[str, dict] = {}
        offset = 0
        while True:
            self.calls += 1
            m, rows = self.contract.functions.vaultKeeperPage(offset, self.page_size).call(
                block_identifier=block
            )
            meta = self._meta(m)
            for row in rows:
                if not _field(row, "ok", 1):
                    continue
                address = self.w3.to_checksum_address(_field(row, "vk", 0))
                entry = {"address": address, "peerId": str(_field(row, "peerId", 2))}
                for i, name in enumerate(_VK_CHAIN_FIELDS):
                    entry[name] = _plain(_field(row, name, 3 + i))
                keepers[address] = entry
            offset += len(rows)
            if not rows or offset >= meta.get("vaultKeeperCount", 0):
                break

        guardians: dict[str, dict] = {}
        offset = 0
        while True:
            self.calls += 1
            m, rows = self.contract.functions.guardianPage(offset, self.page_size).call(
                block_identifier=block
            )
            if not meta:
                meta = self._meta(m)
            for row in rows:
                if not _field(row, "ok", 1):
                    continue
                address = self.w3.to_checksum_address(_field(row, "guardian", 0))
                entry = {"address": address}
                for i, name in enumerate(_G_CHAIN_FIELDS[1:]):
                    entry[name] = _plain(_field(row, name, 2 + i))
                guardians[address] = entry
            offset += len(rows)
            if not rows or offset >= self._meta(m).get("guardianCount", 0):
                break
        self.sources()
        meta["sources"] = dict(self._configured)
        return meta, keepers, guardians

    @staticmethod
    def _meta(m: Any) -> dict[str, int]:
        return {name: int(_field(m, name, i)) for i, name in enumerate(META_FIELDS)}


# ── rows ──────────────────────────────────────────────────────────────────────


def keeper_row(chain: dict[str, Any], record: dict[str, Any] | None) -> list[Any]:
    """One keeper as a wire row: chain facts plus discovery's reachability.

    The address, multiaddr and location come from the keeper's own signed
    announcement; a keeper that has not announced has an empty multiaddr and
    cannot be chosen, but is still listed so the table shows it.
    """
    record = record or {}
    lat = round(float(record.get("latitude") or 0.0), 3)
    lon = round(float(record.get("longitude") or 0.0), 3)
    row = [
        chain["address"],
        chain.get("peerId", ""),
        str(record.get("multiaddr", "") or ""),
        str(record.get("location", "") or ""),
        lat,
        lon,
    ]
    row.extend(chain.get(name, 0) for name in _VK_CHAIN_FIELDS)
    return row


def guardian_row(chain: dict[str, Any]) -> list[Any]:
    return [chain.get(name, 0) for name in _G_CHAIN_FIELDS]


# ── versions, deltas, encoding ────────────────────────────────────────────────


class DirectoryStore:
    """Current rows, a version number, and what changed in recent versions.

    A version is only spent when something actually changed, so a client that
    polls an unchanged network is told "no change" and sent nothing. The epoch
    is new every time the process starts: a version number from another node or
    an earlier run means nothing here, and such a client gets the full document.
    """

    def __init__(self, node_id: str, history: int = 240, public_path: Path | None = None) -> None:
        self.node_id = node_id
        self.epoch = secrets.token_hex(6)
        self.version = 0
        self.refreshed_at = 0
        self.meta: dict[str, int] = {}
        self.vk: dict[str, list[Any]] = {}
        self.g: dict[str, list[Any]] = {}
        self._vk_hash: dict[str, bytes] = {}
        self._g_hash: dict[str, bytes] = {}
        self._history: list[tuple[int, set[str], set[str]]] = []
        self._history_limit = max(1, int(history))
        self._full_json = b""
        self._full_gzip = b""
        self._delta_cache: OrderedDict[int, tuple[bytes, bytes]] = OrderedDict()
        self.public_path = public_path
        self.lock = threading.Lock()

    @staticmethod
    def _digest(row: list[Any]) -> bytes:
        return hashlib.blake2b(
            json.dumps(row, separators=(",", ":")).encode("utf-8"), digest_size=12
        ).digest()

    def update(
        self,
        meta: dict[str, int],
        vk_rows: dict[str, list[Any]],
        g_rows: dict[str, list[Any]],
        refreshed_at: int,
        *, now: int | None = None,
    ) -> bool:
        """Replace the rows. Returns True when this made a new version."""
        now = refreshed_at if now is None else now
        vk_rows = {k: liveness_row(v, VK_COLUMNS, now) for k, v in vk_rows.items()}
        g_rows = {k: liveness_row(v, G_COLUMNS, now) for k, v in g_rows.items()}
        meta = {**meta, "heartbeatFreshSeconds": HEARTBEAT_FRESH_SECONDS}
        vk_hash = {k: self._digest(v) for k, v in vk_rows.items()}
        g_hash = {k: self._digest(v) for k, v in g_rows.items()}
        changed_vk = {k for k, h in vk_hash.items() if self._vk_hash.get(k) != h}
        changed_vk |= set(self._vk_hash) - set(vk_hash)
        changed_g = {k for k, h in g_hash.items() if self._g_hash.get(k) != h}
        changed_g |= set(self._g_hash) - set(g_hash)
        # Block number and time move every block; they say how fresh the answer
        # is, not that anything in it changed.
        stable_meta = {k: v for k, v in meta.items() if k not in ("blockNumber", "blockTimestamp")}
        old_stable = {k: v for k, v in self.meta.items() if k not in ("blockNumber", "blockTimestamp")}
        meta_changed = stable_meta != old_stable

        with self.lock:
            self.refreshed_at = refreshed_at
            if not (changed_vk or changed_g or meta_changed) and self.version:
                # Same version, same bytes: the served document stays as it was.
                return False
            self.version += 1
            self.meta = dict(meta)
            self.vk = dict(vk_rows)
            self.g = dict(g_rows)
            self._vk_hash = vk_hash
            self._g_hash = g_hash
            self._history.append((self.version, changed_vk, changed_g))
            if len(self._history) > self._history_limit:
                self._history = self._history[-self._history_limit:]
            self._delta_cache.clear()
            doc = self._document(full=True, vk=list(self.vk.values()), g=list(self.g.values()))
            self._full_json = _encode(doc)
            self._full_gzip = gzip.compress(self._full_json, compresslevel=6, mtime=0)
            full_json, full_gzip = self._full_json, self._full_gzip
        if self.public_path is not None:
            _write_public(self.public_path, full_json)
            _write_public(self.public_path.with_name(self.public_path.name + ".gz"), full_gzip)
        return True

    def _document(self, *, full: bool, vk: list, g: list, removed_vk=(), removed_g=(), since: int = 0) -> dict:
        doc: dict[str, Any] = {
            "format": FORMAT_VERSION,
            "node": self.node_id,
            "epoch": self.epoch,
            "version": self.version,
            "refreshedAt": self.refreshed_at,
            "full": full,
            "authoritative": False,
            "meta": self.meta,
            "vkColumns": VK_COLUMNS,
            "vk": vk,
            "gColumns": G_COLUMNS,
            "g": g,
        }
        if not full:
            # The caller already holds the column names from the full document
            # of this epoch; repeating them would be most of a small delta.
            del doc["vkColumns"], doc["gColumns"]
            doc["since"] = since
            doc["removedVk"] = sorted(removed_vk)
            doc["removedG"] = sorted(removed_g)
        return doc

    @property
    def etag(self) -> str:
        return f'"{self.epoch}-{self.version}"'

    def full_body(self, gzip_ok: bool) -> bytes:
        with self.lock:
            return self._full_gzip if gzip_ok else self._full_json

    def answer(self, since: int | None, epoch: str, gzip_ok: bool) -> tuple[str, bytes]:
        """What to send a caller holding `since` from `epoch`.

        Returns ("same", b"") when they are current, ("delta", body) when the
        changes since their version are still remembered, else ("full", body).
        """
        with self.lock:
            if not self.version:
                return "full", b""
            if since is None or epoch != self.epoch or since > self.version:
                return "full", self._full_gzip if gzip_ok else self._full_json
            if since == self.version:
                return "same", b""
            oldest_known = self._history[0][0] if self._history else self.version + 1
            if since < oldest_known - 1:
                return "full", self._full_gzip if gzip_ok else self._full_json
            cached = self._delta_cache.get(since)
            if cached is None:
                changed_vk: set[str] = set()
                changed_g: set[str] = set()
                for version, cvk, cg in self._history:
                    if version > since:
                        changed_vk |= cvk
                        changed_g |= cg
                doc = self._document(
                    full=False,
                    vk=[self.vk[k] for k in sorted(changed_vk) if k in self.vk],
                    g=[self.g[k] for k in sorted(changed_g) if k in self.g],
                    removed_vk=[k for k in changed_vk if k not in self.vk],
                    removed_g=[k for k in changed_g if k not in self.g],
                    since=since,
                )
                raw = _encode(doc)
                cached = (raw, gzip.compress(raw, compresslevel=6, mtime=0))
                self._delta_cache[since] = cached
                while len(self._delta_cache) > 64:
                    self._delta_cache.popitem(last=False)
            return "delta", cached[1] if gzip_ok else cached[0]


def _encode(doc: dict) -> bytes:
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def _write_public(path: Path, body: bytes) -> None:
    """Replace a served file in one step, so a reader never sees half of it."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(body)
        tmp.replace(path)
    except Exception:
        pass  # the live answer does not depend on the file


# ── refresh loop ──────────────────────────────────────────────────────────────


class DirectoryRefresher:
    """Keeps a DirectoryStore current.

    Every `check_seconds`: one call for the latest block, one log query over the
    blocks since the last read. A full read happens when logs appeared, and at
    least every `full_refresh_seconds` anyway, because a few values (a time
    passing, a contract that writes without an event) can change silently.

    Discovery's own records -- multiaddr and location -- are merged in on every
    check, so a keeper that announces from a new address is current within one
    check even when the chain did not move.
    """

    def __init__(
        self,
        reader: ChainDirectoryReader,
        store: DirectoryStore,
        records: Callable[[], dict[str, dict[str, Any]]],
        log: Callable[[str], None] = print,
        check_seconds: int = 60,
        full_refresh_seconds: int = 300,
        on_full_read: Callable[[int, int, int, int], None] | None = None,
    ) -> None:
        self.reader = reader
        self.store = store
        self.records = records  # peerId -> discovery record
        self.log = log
        self.on_full_read = on_full_read  # (chain calls, keepers, guardians, block)
        self.check_seconds = max(1, int(check_seconds))
        self.full_refresh_seconds = max(self.check_seconds, int(full_refresh_seconds))
        self.last_block = -1
        self.last_full_at = 0.0
        self._meta: dict[str, int] = {}
        self._keepers: dict[str, dict] = {}
        self._guardians: dict[str, dict] = {}

    def tick(self, now: float | None = None) -> bool:
        """One check. Returns True when the chain was read in full."""
        now = time.time() if now is None else now
        calls_before = self.reader.calls
        latest = self.reader.latest_block()
        read = False
        if (
            self.last_block < 0
            or now - self.last_full_at >= self.full_refresh_seconds
            or self.reader.changed_since(self.last_block + 1, latest)
        ):
            meta, keepers, guardians = self.reader.read_all(latest)
            self._meta, self._keepers, self._guardians = meta, keepers, guardians
            self.last_full_at = now
            read = True
            if self.on_full_read is not None:
                try:
                    self.on_full_read(self.reader.calls - calls_before, len(keepers), len(guardians), latest)
                except Exception:
                    pass  # logging a read must never fail the read
        self.last_block = max(self.last_block, latest)
        if not self._meta and not read:
            return False
        meta = dict(self._meta)
        if not read:
            meta["blockNumber"] = latest
        changed = self.store.update(meta, self._rows(), self._g_rows(), int(now))
        if read or changed:
            self.log(
                f"network directory: block={latest} keepers={len(self._keepers)} "
                f"guardians={len(self._guardians)} version={self.store.version} "
                f"read={'full' if read else 'none'} chainCalls={self.reader.calls - calls_before}"
            )
        return read

    def _rows(self) -> dict[str, list[Any]]:
        records = self.records()
        return {
            address: keeper_row(chain, records.get(chain.get("peerId", "")))
            for address, chain in self._keepers.items()
        }

    def _g_rows(self) -> dict[str, list[Any]]:
        return {address: guardian_row(chain) for address, chain in self._guardians.items()}

    def run(self, stop_event: threading.Event) -> None:
        first = True
        while True:
            if not first and stop_event.wait(self.check_seconds):
                return
            first = False
            try:
                self.tick()
            except Exception as exc:
                # A failed check keeps the previous answer: briefly out of date
                # is not the same as knowing nothing.
                # Expire cached heartbeat status even while RPC is unavailable.
                if self._meta:
                    self.store.update(self._meta, self._rows(), self._g_rows(), self.store.refreshed_at, now=int(time.time()))
                self.log(f"network directory check failed; keeping chain data at version {self.store.version}: {exc}")
