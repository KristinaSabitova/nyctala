"""NDJSON ingest endpoint.

Order of checks, cheapest first and before reading any body from an
unauthenticated client: auth-failure budget of the client address, bearer
token, sensor rate limit, content type/encoding, declared size, streamed size.

Lines are parsed by :mod:`nyctala.ingest.lines`. Every line is validated on its
own: one bad line is reported and dropped, the rest of the batch is stored.
Error reports never echo the submitted content.
"""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from nyctala.health.integrity import IntegrityChain
from nyctala.ingest.limits import Limits, RateLimiter
from nyctala.ingest.lines import parse_line
from nyctala.ingest.sensors import SensorRegistry
from nyctala.schema import Event
from nyctala.store import EventStore

NDJSON_TYPES = frozenset({"application/x-ndjson", "application/jsonl", "application/json-seq"})


class _BodyTooLarge(Exception):
    pass


def _error(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status, headers=headers)


def _unauthorized() -> JSONResponse:
    return _error(401, "invalid or missing token", {"WWW-Authenticate": "Bearer"})


def _too_many(retry_after: int) -> JSONResponse:
    return _error(429, "rate limit exceeded", {"Retry-After": str(retry_after)})


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
    store: EventStore,
    registry: SensorRegistry,
    limits: Limits | None = None,
    chain: IntegrityChain | None = None,
) -> FastAPI:
    limits = limits or Limits()
    chain = chain or IntegrityChain(store)
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
            result = parse_line(raw, sensor_id, limits.max_line_bytes)
            if isinstance(result, str):
                errors.append({"line": number, "error": result})
            elif len(events) + len(result) > limits.max_events:
                errors.append({"line": number, "error": "event limit per request reached"})
            else:
                events.extend(result)

        if events:
            # Sealed into the sensor's hash chain as they are written.
            await run_in_threadpool(chain.append, sensor_id, events)
        return {
            "accepted": len(events),
            "rejected": len(errors),
            "errors": errors[: limits.max_reported_errors],
        }

    return app
