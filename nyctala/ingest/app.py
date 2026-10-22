"""NDJSON ingest endpoint.

Order of checks, cheapest first and before reading any body from an
unauthenticated client: auth-failure budget of the client address, bearer
token, sensor rate limit, content type/encoding, declared size, streamed size.

Every line is validated on its own: one bad line is reported and dropped, the
rest of the batch is stored. Error reports never echo the submitted content.
"""

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from nyctala.ingest.limits import Limits, RateLimiter
from nyctala.ingest.sensors import SensorRegistry
from nyctala.schema import Event
from nyctala.store import EventStore

NDJSON_TYPES = frozenset({"application/x-ndjson", "application/jsonl", "application/json-seq"})

# Set by nyctala, never by the sender: a sensor cannot speak for another sensor,
# pick event ids, backdate ingestion or forge the integrity chain.
SERVER_FIELDS = frozenset(
    {"sensor.id", "event.id", "event.ingested", "integrity.hash", "integrity.prev_hash"}
)
CLIENT_FIELDS = frozenset(f.alias or name for name, f in Event.model_fields.items()) - SERVER_FIELDS


class _BodyTooLarge(Exception):
    pass


def _error(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status, headers=headers)


def _unauthorized() -> JSONResponse:
    return _error(401, "invalid or missing token", {"WWW-Authenticate": "Bearer"})


def _too_many(retry_after: int) -> JSONResponse:
    return _error(429, "rate limit exceeded", {"Retry-After": str(retry_after)})


def parse_line(raw: bytes, sensor_id: str, limits: Limits) -> Event | str:
    """Turn one NDJSON line into an Event, or return why it was rejected."""
    if len(raw) > limits.max_line_bytes:
        return "line too long"
    try:
        obj = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return "invalid JSON"
    if not isinstance(obj, dict):
        return "line is not a JSON object"
    if server := sorted(SERVER_FIELDS & obj.keys()):
        return f"server-controlled field: {', '.join(server)}"
    if unknown := sorted(obj.keys() - CLIENT_FIELDS):
        return f"unknown field: {', '.join(unknown)[:200]!r}"
    try:
        return Event.model_validate({**obj, "sensor.id": sensor_id})
    except ValidationError as exc:
        # Location and error type only: the input value is attacker content.
        return "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'event'}: {e['type']}" for e in exc.errors()
        )


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise _BodyTooLarge
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise _BodyTooLarge
    return bytes(body)


def create_app(
    store: EventStore, registry: SensorRegistry, limits: Limits | None = None
) -> FastAPI:
    limits = limits or Limits()
    sensor_limiter = RateLimiter(limits.sensor_rate, limits.sensor_burst)
    auth_failures = RateLimiter(limits.auth_failure_rate, limits.auth_failure_burst)

    app = FastAPI(title="nyctala ingest", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.sensor_limiter = sensor_limiter
    app.state.auth_failures = auth_failures

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/ingest", response_model=None)
    async def ingest(request: Request) -> JSONResponse | dict[str, Any]:
        client = request.client.host if request.client else "unknown"
        if not auth_failures.allowed(client):
            return _too_many(auth_failures.retry_after(client))

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        sensor_id = registry.authenticate(token.strip()) if scheme.lower() == "bearer" else None
        if sensor_id is None:
            auth_failures.hit(client)
            return _unauthorized()

        if not sensor_limiter.hit(sensor_id):
            return _too_many(sensor_limiter.retry_after(sensor_id))

        media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if media_type not in NDJSON_TYPES:
            return _error(415, "expected application/x-ndjson")
        if request.headers.get("content-encoding", "identity").lower() != "identity":
            return _error(415, "compressed bodies are not accepted")

        try:
            body = await _read_body(request, limits.max_body_bytes)
        except _BodyTooLarge:
            return _error(413, f"body exceeds {limits.max_body_bytes} bytes")

        lines = [(n, line) for n, line in enumerate(body.split(b"\n"), start=1) if line.strip()]
        if len(lines) > limits.max_lines:
            return _error(413, f"more than {limits.max_lines} lines")

        events: list[Event] = []
        errors: list[dict[str, Any]] = []
        for number, raw in lines:
            result = parse_line(raw, sensor_id, limits)
            if isinstance(result, Event):
                events.append(result)
            else:
                errors.append({"line": number, "error": result})

        if events:
            await run_in_threadpool(store.append, events)
        return {
            "accepted": len(events),
            "rejected": len(errors),
            "errors": errors[: limits.max_reported_errors],
        }

    return app
