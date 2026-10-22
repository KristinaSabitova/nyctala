from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from nyctala.schema import Event
from nyctala.schema.event import TEXT_LIMITS, TRUNCATED_TAG
from nyctala.schema.sanitize import TRUNCATION_MARKER, neutralise

BASE = {
    "@timestamp": "2026-10-22T10:00:00+02:00",
    "event.dataset": "auth_log",
    "sensor.id": "vps-a",
}


def make(**fields: object) -> Event:
    return Event.model_validate({**BASE, **fields})


def test_minimal_event_gets_defaults() -> None:
    event = make()
    assert event.timestamp == datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
    assert event.timestamp.tzinfo is UTC
    assert len(event.event_id) == 36
    assert event.event_ingested.tzinfo is UTC
    assert event.tags == []


def test_record_uses_ecs_names() -> None:
    record = make(**{"user.name": "root", "source.ip": "10.0.0.1"}).to_record()
    assert record["user.name"] == "root"
    assert record["source.ip"] == "10.0.0.1"
    assert record["@timestamp"].tzinfo is UTC


def test_roundtrip_from_record() -> None:
    event = make(**{"process.command_line": "bash -c id", "tags": ["ssh"]})
    assert Event.model_validate(event.to_record()) == event


def test_naive_timestamp_rejected() -> None:
    with pytest.raises(ValidationError):
        make(**{"@timestamp": "2026-10-22T10:00:00"})


def test_timestamp_converted_to_utc() -> None:
    ts = datetime(2026, 10, 22, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
    assert make(**{"@timestamp": ts}).timestamp == datetime(2026, 10, 23, 4, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    "field",
    [{"unknown.field": "x"}, {"sensor.id": "../etc"}, {"event.dataset": ""}],
)
def test_strict_validation(field: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        make(**field)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.1.10", "192.168.1.10"),
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("2001:DB8::1", "2001:db8::1"),
    ],
)
def test_ip_normalised(raw: str, expected: str) -> None:
    assert make(**{"source.ip": raw}).source_ip == expected


def test_invalid_ip_rejected() -> None:
    with pytest.raises(ValidationError):
        make(**{"source.ip": "10.0.0.1; DROP TABLE events"})


@pytest.mark.parametrize("code", [-1, 1000])
def test_status_code_range(code: int) -> None:
    with pytest.raises(ValidationError):
        make(**{"http.response.status_code": code})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "Failed password\nAccepted password for root",
            "Failed password\\x0aAccepted password for root",
        ),
        ("\x1b[2Jcleared", "\\x1b[2Jcleared"),
        ("admin\u202egnp.exe", "admin\\u202egnp.exe"),
        ("ro\u200bot", "ro\\u200bot"),
        ("line\u2028sep", "line\\u2028sep"),
        ("tab\tkept", "tab\tkept"),
        ("utf-8 ñandú 日本", "utf-8 ñandú 日本"),
    ],
)
def test_neutralise(raw: str, expected: str) -> None:
    assert neutralise(raw) == expected


def test_lone_surrogate_escaped() -> None:
    assert neutralise("a\ud800b") == "a\\ud800b"


def test_dangerous_chars_neutralised_in_every_text_field() -> None:
    event = make(**{"user.name": "bob\r\nroot", "event.original": "x\x00y", "tags": ["a\nb"]})
    assert event.user_name == "bob\\x0d\\x0aroot"
    assert event.event_original == "x\\x00y"
    assert event.tags == ["a\\x0ab"]


def test_long_text_truncated_and_tagged() -> None:
    limit = TEXT_LIMITS["process.command_line"]
    event = make(**{"process.command_line": "A" * (limit * 2), "tags": ["ssh"]})
    assert event.process_command_line is not None
    assert len(event.process_command_line) == limit
    assert event.process_command_line.endswith(TRUNCATION_MARKER)
    assert event.tags == ["ssh", TRUNCATED_TAG]


def test_escaping_counts_towards_limit() -> None:
    event = make(**{"user.name": "\n" * 1024})
    assert event.user_name is not None
    assert len(event.user_name) == 1024
    assert TRUNCATED_TAG in event.tags


def test_event_is_immutable() -> None:
    with pytest.raises(ValidationError):
        make().user_name = "root"
