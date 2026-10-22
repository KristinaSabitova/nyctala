import json
import shutil
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from nyctala.cli.main import app
from nyctala.health.integrity import (
    GENESIS,
    ChainReport,
    IntegrityChain,
    anchors_now,
    event_hash,
    read_anchors,
    verify,
)
from nyctala.ingest.app import create_app
from nyctala.ingest.sensors import SensorRegistry
from nyctala.schema import Event
from nyctala.store import EventStore

T0 = datetime(2026, 10, 22, 10, 0, tzinfo=UTC)
runner = CliRunner()


def ev(i: int, sensor: str = "vps-a", **fields: Any) -> Event:
    ts = T0 + timedelta(seconds=i)
    return Event.model_validate(
        {
            "@timestamp": ts,
            "event.ingested": ts,
            "event.dataset": "auth_log",
            "sensor.id": sensor,
            "user.name": f"user{i}",
            **fields,
        }
    )


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    return EventStore(tmp_path / "data")


def files(store: EventStore) -> list[Path]:
    return sorted(store.events_dir.rglob("*.parquet"), key=lambda p: p.stat().st_mtime_ns)


def report(store: EventStore, sensor: str = "vps-a", **kw: Any) -> ChainReport:
    return next(r for r in verify(store, **kw) if r.sensor == sensor)


def seal_batches(store: EventStore, batches: int = 3, size: int = 2) -> IntegrityChain:
    chain = IntegrityChain(store)
    for b in range(batches):
        chain.append("vps-a", [ev(b * size + i) for i in range(size)])
    return chain


# --- sealing -----------------------------------------------------------------------


def test_chain_links_from_genesis(store: EventStore) -> None:
    sealed = IntegrityChain(store).append("vps-a", [ev(0), ev(1), ev(2)])
    assert sealed[0].integrity_prev_hash == GENESIS
    assert sealed[1].integrity_prev_hash == sealed[0].integrity_hash
    assert sealed[2].integrity_prev_hash == sealed[1].integrity_hash
    record = sealed[1].to_record()
    record["integrity.hash"] = None
    assert event_hash(record) == sealed[1].integrity_hash


def test_hash_covers_every_field(store: EventStore) -> None:
    (sealed,) = IntegrityChain(store).append("vps-a", [ev(0)])
    base = sealed.to_record()
    base["integrity.hash"] = None
    reference = event_hash(base)
    for field_name, value in [
        ("user.name", "root"),
        ("@timestamp", T0 + timedelta(seconds=1)),
        ("tags", ["x"]),
        ("integrity.prev_hash", "1" * 64),
        ("sensor.id", "vps-b"),
    ]:
        assert event_hash({**base, field_name: value}) != reference, field_name


def test_verify_after_storage_round_trip(store: EventStore) -> None:
    seal_batches(store)
    r = report(store)
    assert r.ok
    assert (r.events, r.heads, r.unsealed) == (6, 1, 0)


def test_restart_continues_the_chain(store: EventStore) -> None:
    seal_batches(store, batches=2)
    IntegrityChain(EventStore(store.root)).append("vps-a", [ev(100)])
    r = report(store)
    assert r.ok
    assert r.heads == 1


def test_sensors_have_independent_chains(store: EventStore) -> None:
    chain = IntegrityChain(store)
    chain.append("vps-a", [ev(0)])
    (b,) = chain.append("vps-b", [ev(1, sensor="vps-b")])
    assert b.integrity_prev_hash == GENESIS
    assert all(r.ok for r in verify(store))


def test_wrong_sensor_rejected(store: EventStore) -> None:
    with pytest.raises(ValueError):
        IntegrityChain(store).append("vps-a", [ev(0, sensor="vps-b")])


def test_concurrent_appends_keep_one_chain(store: EventStore) -> None:
    chain = IntegrityChain(store)

    def worker(n: int) -> None:
        for i in range(5):
            chain.append("vps-a", [ev(n * 100 + i)])

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    r = report(store)
    assert r.ok
    assert (r.events, r.heads) == (20, 1)


def test_unsealed_events_are_reported_but_not_damage(store: EventStore) -> None:
    store.append([ev(0)])
    r = report(store)
    assert r.ok
    assert r.unsealed == 1


# --- tampering is detected ---------------------------------------------------------


def rewrite(path: Path, column: str, value: Any) -> None:
    table = pq.read_table(path)
    rows = table.to_pylist()
    rows[0][column] = value
    pq.write_table(type(table).from_pylist(rows, schema=table.schema), path)


def test_modified_event_detected(store: EventStore) -> None:
    seal_batches(store)
    rewrite(files(store)[1], "user.name", "nobody")
    r = report(store)
    assert not r.ok
    assert len(r.tampered) == 1
    assert "1 modified event(s)" in r.problems()


def test_modified_timestamp_detected(store: EventStore) -> None:
    seal_batches(store)
    rewrite(files(store)[0], "@timestamp", T0 - timedelta(days=1))
    assert len(report(store).tampered) == 1


def test_deleted_events_in_the_middle_detected(store: EventStore) -> None:
    seal_batches(store)
    files(store)[1].unlink()
    r = report(store)
    assert not r.ok
    assert len(r.missing_links) == 1
    assert r.heads == 2  # the segment before the gap now ends without a successor


def test_deleted_first_events_detected(store: EventStore) -> None:
    seal_batches(store)
    files(store)[0].unlink()
    assert report(store).missing_links


def test_replayed_file_detected(store: EventStore) -> None:
    seal_batches(store)
    original = files(store)[1]
    shutil.copy(original, original.with_name("part-replayed.parquet"))
    r = report(store)
    assert not r.ok
    assert len(r.forks) == 2


def test_truncated_tail_needs_anchors(store: EventStore) -> None:
    seal_batches(store)
    anchors = read_anchors(
        [
            json.dumps({"sensor.id": a["sensor.id"], "integrity.head": a["integrity.head"]})
            for a in anchors_now(store)
        ]
    )
    files(store)[-1].unlink()
    assert report(store).ok  # a shorter chain is still a valid chain...
    r = report(store, anchors=anchors)  # ...but the anchored head is gone
    assert not r.ok
    assert "newest events deleted" in r.problems()[0]


def test_anchor_for_vanished_sensor(store: EventStore) -> None:
    r = report(store, "ghost", anchors={"ghost": {"a" * 64}})
    assert not r.ok


# --- ingest seals what it stores ---------------------------------------------------


def test_ingest_seals_events(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "data")
    registry = SensorRegistry(tmp_path / "data" / "sensors.json")
    token = registry.add("vps-a")
    client = TestClient(create_app(store, registry))
    line = (
        '{"message": "Oct 22 10:00:01 vps-a sshd[1]: message repeated 3 times: [ Failed password '
        'for root from 203.0.113.7 port 1 ssh2]", "event.dataset": "auth_log"}'
    )
    for _ in range(3):
        response = client.post(
            "/v1/ingest",
            content=line,
            headers={"authorization": f"Bearer {token}", "content-type": "application/x-ndjson"},
        )
        assert response.json()["accepted"] == 3
    r = report(store)
    assert r.ok
    assert (r.events, r.unsealed, r.heads) == (9, 0, 1)


# --- CLI ---------------------------------------------------------------------------


def test_cli_verify_and_anchor(store: EventStore, tmp_path: Path) -> None:
    seal_batches(store)
    data = ["--data", str(store.root)]
    ok = runner.invoke(app, ["integrity", "verify", *data])
    assert ok.exit_code == 0, ok.output
    assert ok.output.startswith("OK")

    anchor_file = tmp_path / "anchors.ndjson"
    anchor_file.write_text(runner.invoke(app, ["integrity", "anchor", *data]).output)
    assert '"integrity.head"' in anchor_file.read_text()

    files(store)[-1].unlink()
    broken = runner.invoke(app, ["integrity", "verify", *data, "--anchors", str(anchor_file)])
    assert broken.exit_code == 1
    assert "BROKEN" in broken.output
