from datetime import UTC, datetime, timedelta
from pathlib import Path

from nyctala.engine.correlation import Hit
from nyctala.engine.job import DetectionJob
from nyctala.engine.ruleset import load_ruleset
from nyctala.engine.testing import RULES_DIR
from nyctala.ingest.lines import parse_line
from nyctala.store import EventStore

T0 = datetime(2026, 10, 22, 10, 0, tzinfo=UTC)


def fail_line(ts: datetime, ip: str) -> bytes:
    msg = f"Failed password for root from {ip} port 1 ssh2"
    line = f"{ts:%b %d %H:%M:%S} vps-a sshd[1]: {msg}"
    return (
        b'{"event.dataset": "auth_log", "@timestamp": "' + ts.isoformat().encode() + b'", '
        b'"message": "' + line.encode() + b'"}'
    )


def ingest(store: EventStore, *lines: bytes) -> None:
    events = []
    for line in lines:
        result = parse_line(line, "vps-a")
        assert not isinstance(result, str), result
        events.extend(result)
    store.append(events)


def test_job_reports_each_burst_once(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    clock = [T0 + timedelta(minutes=1)]
    reported: list[Hit] = []
    job = DetectionJob(store, load_ruleset(RULES_DIR), reported.extend, clock=lambda: clock[0])
    bruteforce = next(r.id for r in job.ruleset.rules.values() if r.name == "ssh_bruteforce")

    ingest(store, *[fail_line(T0 + timedelta(seconds=s), "203.0.113.7") for s in range(7)])
    assert [h.rule_id for h in job.run_once()] == [bruteforce]

    # Later runs over overlapping windows see the same evidence: nothing new.
    for minutes in (1.5, 3, 6):
        clock[0] = T0 + timedelta(minutes=minutes)
        assert job.run_once() == []

    # A new burst from the same address is a new hit.
    later = T0 + timedelta(minutes=7)
    ingest(store, *[fail_line(later + timedelta(seconds=s), "203.0.113.7") for s in range(5)])
    clock[0] = later + timedelta(minutes=1)
    assert [h.rule_id for h in job.run_once()] == [bruteforce]
    assert len(reported) == 2


def test_job_ignores_events_outside_window(tmp_path: Path) -> None:
    store = EventStore(tmp_path)
    ingest(store, *[fail_line(T0 + timedelta(seconds=s), "203.0.113.7") for s in range(5)])
    job = DetectionJob(
        store, load_ruleset(RULES_DIR), lambda _: None, clock=lambda: T0 + timedelta(days=1)
    )
    assert job.run_once() == []
