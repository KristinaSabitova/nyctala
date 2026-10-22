"""Turning one NDJSON line into events.

Each line is either an ECS-lite event or a raw log line to parse::

    {"@timestamp": "...", "event.dataset": "auth_log", "user.name": "root", ...}
    {"event.dataset": "nginx.access", "message": "<raw line>", "host.name": "web1"}

Used by the ingest endpoint and by rule tests, so fixtures go through exactly
the same validation as live data.
"""

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import AwareDatetime, TypeAdapter, ValidationError

from nyctala import parsers
from nyctala.schema import Event

MAX_LINE_BYTES = 128 << 10

# Set by nyctala, never by the sender: a sensor cannot speak for another sensor,
# pick event ids, backdate ingestion or forge the integrity chain.
SERVER_FIELDS = frozenset(
    {"sensor.id", "event.id", "event.ingested", "integrity.hash", "integrity.prev_hash"}
)
CLIENT_FIELDS = frozenset(f.alias or name for name, f in Event.model_fields.items()) - SERVER_FIELDS
RAW_FIELDS = frozenset({"message", "event.dataset", "host.name", "@timestamp"})

_aware_datetime = TypeAdapter(AwareDatetime)


def _describe(exc: ValidationError) -> str:
    # Location and error type only: the input value is attacker content.
    return "; ".join(
        f"{'.'.join(map(str, e['loc'])) or 'event'}: {e['type']}" for e in exc.errors()
    )


def _raw_events(obj: dict[str, Any], sensor_id: str) -> list[Event] | str:
    if unknown := sorted(obj.keys() - RAW_FIELDS):
        return f"unknown field: {', '.join(unknown)[:200]!r}"
    message, dataset = obj.get("message"), obj.get("event.dataset")
    if not isinstance(message, str):
        return "message must be a string"
    if not isinstance(dataset, str) or dataset not in parsers.PARSERS:
        return "unknown dataset"
    received = datetime.now(UTC)
    if "@timestamp" in obj:
        # When the sender saw the line: reference for headers without year or zone.
        try:
            received = _aware_datetime.validate_python(obj["@timestamp"])
        except ValidationError as exc:
            return f"@timestamp: {exc.errors()[0]['type']}"
    try:
        base = {"host.name": obj["host.name"]} if "host.name" in obj else {}
        fields = parsers.parse(dataset, message, received=received)
        return [Event.model_validate({**base, **f, "sensor.id": sensor_id}) for f in fields]
    except ValidationError as exc:
        return _describe(exc)


def parse_line(raw: bytes, sensor_id: str, max_bytes: int = MAX_LINE_BYTES) -> list[Event] | str:
    """Turn one NDJSON line into events, or return why it was rejected."""
    if len(raw) > max_bytes:
        return "line too long"
    try:
        obj = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return "invalid JSON"
    if not isinstance(obj, dict):
        return "line is not a JSON object"
    if server := sorted(SERVER_FIELDS & obj.keys()):
        return f"server-controlled field: {', '.join(server)}"
    if "message" in obj:
        return _raw_events(obj, sensor_id)
    if unknown := sorted(obj.keys() - CLIENT_FIELDS):
        return f"unknown field: {', '.join(unknown)[:200]!r}"
    try:
        return [Event.model_validate({**obj, "sensor.id": sensor_id})]
    except ValidationError as exc:
        return _describe(exc)
