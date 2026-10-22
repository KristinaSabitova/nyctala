"""Hash chain over ingested events, one chain per sensor.

Each stored event carries ``integrity.prev_hash`` (the previous event of the
same sensor, or ``GENESIS``) and ``integrity.hash`` = SHA-256 of its canonical
JSON (every field except ``integrity.hash`` itself, keys sorted). Verifying
recomputes every hash and walks the links, which exposes:

* modified events (hash mismatch);
* deleted events in the middle (a ``prev_hash`` that no event has);
* forks or replays (two events claiming the same predecessor);
* several chain heads.

Deleting the newest events leaves a valid but shorter chain. That is caught by
anchors: chain heads exported periodically to a place the SIEM cannot rewrite
(see deploy). Someone able to rewrite both the store and every anchor can
forge a chain; anchors exist so that this requires two compromises.
"""

import hashlib
import json
import threading
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from nyctala.schema import Event
from nyctala.store import EventStore

GENESIS = "0" * 64


def _default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"not serialisable: {type(value).__name__}")


def event_hash(record: dict[str, Any]) -> str:
    content = {k: v for k, v in record.items() if k != "integrity.hash"}
    canonical = json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_default
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class IntegrityChain:
    """Seals events before they are stored. One instance per writing process."""

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self._heads: dict[str, str] = {}
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._guard = threading.Lock()

    def _lock(self, sensor: str) -> threading.Lock:
        with self._guard:
            return self._locks[sensor]

    def _load_head(self, sensor: str) -> str:
        rows = self.store.query(
            'SELECT "integrity.hash" AS h, "integrity.prev_hash" AS p, "event.ingested" AS t '
            'FROM events WHERE "sensor.id" = ? AND "integrity.hash" IS NOT NULL',
            [sensor],
        )
        referenced = {r["p"] for r in rows}
        heads = [r for r in rows if r["h"] not in referenced]
        if not heads:
            return GENESIS
        # Normally exactly one; if the chain is broken, continue from the newest
        # and let verification report the damage.
        return str(max(heads, key=lambda r: r["t"])["h"])

    def append(self, sensor: str, events: Iterable[Event]) -> list[Event]:
        """Link ``events`` to the sensor's chain and store them, atomically per sensor."""
        with self._lock(sensor):
            if sensor not in self._heads:
                self._heads[sensor] = self._load_head(sensor)
            prev = self._heads[sensor]
            sealed = []
            for event in events:
                if event.sensor_id != sensor:
                    raise ValueError("event from another sensor")
                record = event.to_record()
                record["integrity.prev_hash"] = prev
                record["integrity.hash"] = None
                digest = event_hash(record)
                sealed.append(
                    event.model_copy(update={"integrity_prev_hash": prev, "integrity_hash": digest})
                )
                prev = digest
            self.store.append(sealed)
            # Only move the head once the events are on disk.
            self._heads[sensor] = prev
            return sealed


@dataclass
class ChainReport:
    sensor: str
    events: int = 0
    unsealed: int = 0
    head: str | None = None
    tampered: list[str] = field(default_factory=list)  # event ids
    missing_links: list[str] = field(default_factory=list)  # prev hashes nobody has
    forks: list[str] = field(default_factory=list)  # prev hashes claimed twice
    heads: int = 0
    anchor_missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (
            self.tampered
            or self.missing_links
            or self.forks
            or self.heads > 1
            or self.anchor_missing
        )

    def problems(self) -> list[str]:
        out = []
        if self.tampered:
            out.append(f"{len(self.tampered)} modified event(s)")
        if self.missing_links:
            out.append(f"{len(self.missing_links)} gap(s): events deleted")
        if self.forks:
            out.append(f"{len(self.forks)} fork(s): duplicated or replayed events")
        if self.heads > 1:
            out.append(f"{self.heads} chain heads")
        if self.anchor_missing:
            out.append(
                f"{len(self.anchor_missing)} anchored head(s) missing: newest events deleted"
            )
        return out


def verify(store: EventStore, anchors: dict[str, set[str]] | None = None) -> list[ChainReport]:
    """Verify every sensor's chain. ``anchors``: sensor -> head hashes recorded earlier."""
    rows = store.query('SELECT * EXCLUDE (dt) FROM events ORDER BY "sensor.id"')
    by_sensor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_sensor[row["sensor.id"]].append(row)
    for sensor in anchors or {}:
        by_sensor.setdefault(sensor, [])

    reports = []
    for sensor, sensor_rows in sorted(by_sensor.items()):
        report = ChainReport(sensor, events=len(sensor_rows))
        hashes: set[str] = set()
        prevs: Counter[str] = Counter()
        for row in sensor_rows:
            stored = row["integrity.hash"]
            if stored is None:
                report.unsealed += 1
                continue
            record = Event.model_validate(row).to_record()
            record["integrity.hash"] = None
            if event_hash(record) != stored or record["integrity.prev_hash"] is None:
                report.tampered.append(row["event.id"])
            hashes.add(stored)
            prevs[row["integrity.prev_hash"]] += 1
        report.forks = sorted(p for p, n in prevs.items() if n > 1)
        report.missing_links = sorted(p for p in prevs if p != GENESIS and p not in hashes)
        heads = sorted(hashes - set(prevs))
        report.heads = len(heads)
        report.head = heads[0] if len(heads) == 1 else None
        report.anchor_missing = sorted((anchors or {}).get(sensor, set()) - hashes)
        reports.append(report)
    return reports


def anchors_now(store: EventStore) -> list[dict[str, Any]]:
    """Current chain heads, to be shipped somewhere the SIEM cannot rewrite."""
    return [
        {"sensor.id": r.sensor, "integrity.head": r.head, "events": r.events}
        for r in verify(store)
        if r.head is not None
    ]


def read_anchors(lines: Iterable[str]) -> dict[str, set[str]]:
    anchors: dict[str, set[str]] = defaultdict(set)
    for line in lines:
        if line.strip():
            record = json.loads(line)
            anchors[str(record["sensor.id"])].add(str(record["integrity.head"]))
    return dict(anchors)
