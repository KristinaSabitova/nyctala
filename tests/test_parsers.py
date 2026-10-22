import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from nyctala import parsers
from nyctala.schema import Event

FIXTURES = Path(parsers.__file__).parent / "fixtures"
RECEIVED = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
DATASETS = {"auth_log": "auth_log", "nginx": "nginx.access"}


def to_event(fields: dict[str, Any]) -> dict[str, Any]:
    """Run parser output through the real model, as ingest does."""
    record = Event.model_validate({**fields, "sensor.id": "vps-a"}).to_record()
    return {k: v.isoformat() if isinstance(v, datetime) else v for k, v in record.items()}


def fixture_cases() -> list[Any]:
    cases = []
    for name, dataset in DATASETS.items():
        lines = (FIXTURES / f"{name}.log").read_text().splitlines()
        expected = (FIXTURES / f"{name}.expected.jsonl").read_text().splitlines()
        assert len(lines) == len(expected), f"{name}: fixture and expectations out of sync"
        for number, (line, exp) in enumerate(zip(lines, expected, strict=True), start=1):
            cases.append(pytest.param(dataset, line, json.loads(exp), id=f"{name}:{number}"))
    return cases


# --- checkpoint: every fixture line produces the expected events -------------------


@pytest.mark.parametrize(("dataset", "line", "expected"), fixture_cases())
def test_fixture_line(dataset: str, line: str, expected: list[dict[str, Any]]) -> None:
    events = [to_event(f) for f in parsers.parse(dataset, line, received=RECEIVED)]
    assert len(events) == len(expected)
    for event, exp in zip(events, expected, strict=True):
        assert event["event.dataset"] == dataset
        assert event["event.original"] == line
        assert {k: event[k] for k in exp} == exp


# --- hostile input ------------------------------------------------------------------


def test_repeat_count_is_capped() -> None:
    line = (
        "Oct 22 10:00:05 vps-a sshd[1]: message repeated 999999999 times: "
        "[ Failed password for root from 203.0.113.7 port 1 ssh2]"
    )
    assert len(parsers.parse("auth_log", line, received=RECEIVED)) == 100


def test_control_characters_in_username_are_neutralised() -> None:
    line = "Oct 22 10:00:01 vps-a sshd[1]: Invalid user \x1b[31mroot\x1b[0m from 192.0.2.1 port 22"
    (fields,) = parsers.parse("auth_log", line, received=RECEIVED)
    event = Event.model_validate({**fields, "sensor.id": "vps-a"})
    assert event.user_name == "\\x1b[31mroot\\x1b[0m"
    assert event.source_ip == "192.0.2.1"


@pytest.mark.parametrize(
    "line",
    [
        "Oct 22 10:00:01 h sshd[1]: Failed password for " + "a from " * 20_000 + "x",
        "Oct 22 10:00:01 h sshd[1]: Invalid user " + " from 1.1.1.1" * 5_000 + " port x",
        "Oct 22 10:00:01 h sudo: u : TTY=t ; PWD=" + "a ; " * 10_000,
        "Oct 22 10:00:01 h sudo: pam_unix(sudo:auth): authentication failure;" + " a=" * 20_000,
        "Oct 22 10:00:01 h crontab[1]: (" + "(" * 50_000,
        "Oct 22 10:00:01 " + "h" * 60_000,
        '1.2.3.4 - - [22/Oct/2026:10:00:00 +0200] "' + "GET " * 15_000,
        '1.2.3.4 - - [22/Oct/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "' + '\\"' * 30_000,
    ],
    ids=lambda s: s[:40],
)
def test_no_catastrophic_backtracking(line: str) -> None:
    dataset = "nginx.access" if line[0].isdigit() else "auth_log"
    start = time.perf_counter()
    parsers.parse(dataset, line, received=RECEIVED)
    assert time.perf_counter() - start < 0.5


@pytest.mark.parametrize("dataset", sorted(parsers.PARSERS))
@pytest.mark.parametrize("line", ["", " ", "\x00", "‮", "a" * 70_000, "[", '"'])
def test_parsers_never_raise(dataset: str, line: str) -> None:
    for fields in parsers.parse(dataset, line, received=RECEIVED):
        Event.model_validate({**fields, "sensor.id": "vps-a"})
