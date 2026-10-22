import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from nyctala.ingest.app import create_app
from nyctala.ingest.limits import Limits
from nyctala.ingest.sensors import SensorRegistry
from nyctala.store import EventStore

NDJSON = {"content-type": "application/x-ndjson"}
LIMITS = Limits(max_body_bytes=4096, max_line_bytes=1024, max_lines=10)


def line(**fields: Any) -> str:
    return json.dumps({"@timestamp": "2026-10-22T10:00:00Z", "event.dataset": "auth_log", **fields})


class Env:
    def __init__(self, tmp_path: Path, limits: Limits = LIMITS) -> None:
        self.store = EventStore(tmp_path / "data")
        self.registry = SensorRegistry(tmp_path / "data" / "sensors.json")
        self.token = self.registry.add("vps-a")
        self.client = TestClient(create_app(self.store, self.registry, limits))

    def post(self, body: str | bytes, token: str | None = None, **headers: str) -> Any:
        auth = {"authorization": f"Bearer {token or self.token}"}
        return self.client.post("/v1/ingest", content=body, headers={**NDJSON, **auth, **headers})

    def count(self) -> int:
        return int(self.store.query("SELECT count(*) AS n FROM events")[0]["n"])


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    e = Env(tmp_path)
    yield e
    e.store.close()


def test_accepts_valid_batch(env: Env) -> None:
    body = "\n".join([line(**{"user.name": "root"}), line(**{"user.name": "bob"})]) + "\n"
    response = env.post(body)
    assert response.status_code == 200
    assert response.json() == {"accepted": 2, "rejected": 0, "errors": []}
    rows = env.store.query('SELECT DISTINCT "sensor.id" AS s FROM events')
    assert rows == [{"s": "vps-a"}]
    assert env.count() == 2


# --- checkpoint: invalid tokens are rejected -------------------------------------


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Bearer", "Bearer nyc_wrong", "Basic dXNlcjpwYXNz", "bearer  nyc_"],
)
def test_rejects_missing_or_invalid_token(env: Env, authorization: str | None) -> None:
    headers = dict(NDJSON)
    if authorization is not None:
        headers["authorization"] = authorization
    response = env.client.post("/v1/ingest", content=line(), headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert env.count() == 0


def test_rejects_revoked_token(env: Env) -> None:
    assert env.post(line()).status_code == 200
    env.registry.revoke("vps-a")
    assert env.post(line()).status_code == 401
    assert env.count() == 1


def test_auth_failures_are_rate_limited(env: Env) -> None:
    for _ in range(LIMITS.auth_failure_burst):
        assert env.post(line(), token="nyc_wrong").status_code == 401
    response = env.post(line(), token="nyc_wrong")
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
    # The same address is now blocked even with a valid token.
    assert env.post(line()).status_code == 429


def test_forwarded_header_does_not_bypass_auth_limit(env: Env) -> None:
    for i in range(LIMITS.auth_failure_burst + 1):
        env.post(line(), token="nyc_wrong", **{"x-forwarded-for": f"10.0.0.{i}"})
    assert env.post(line(), token="nyc_wrong").status_code == 429


# --- checkpoint: oversize payloads are rejected ----------------------------------


def test_rejects_oversize_body(env: Env) -> None:
    body = "\n".join([line(**{"user.name": "x" * 500})] * 8)
    assert len(body) > LIMITS.max_body_bytes
    response = env.post(body)
    assert response.status_code == 413
    assert env.count() == 0


def test_rejects_oversize_body_without_content_length(env: Env) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield (line() + "\n").encode() * 10

    auth = {"authorization": f"Bearer {env.token}"}
    response = env.client.post("/v1/ingest", content=chunks(), headers={**NDJSON, **auth})
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
    assert env.count() == 0


def test_rejects_lying_content_length(env: Env) -> None:
    assert env.post(line(), **{"content-length": "abc"}).status_code in (400, 413)


def test_rejects_too_many_lines(env: Env) -> None:
    body = "\n".join([line()] * (LIMITS.max_lines + 1))
    assert len(body) <= LIMITS.max_body_bytes
    assert env.post(body).status_code == 413
    assert env.count() == 0


def test_oversize_line_rejected_alone(env: Env) -> None:
    body = "\n".join([line(), line(**{"user.name": "x" * 2000}), line()])
    response = env.post(body)
    assert response.status_code == 200
    assert response.json()["accepted"] == 2
    assert response.json()["errors"] == [{"line": 2, "error": "line too long"}]


# --- other request checks ----------------------------------------------------------


@pytest.mark.parametrize("content_type", ["application/json", "text/plain", ""])
def test_rejects_wrong_content_type(env: Env, content_type: str) -> None:
    assert env.post(line(), **{"content-type": content_type}).status_code == 415


def test_rejects_compressed_body(env: Env) -> None:
    assert env.post(line(), **{"content-encoding": "gzip"}).status_code == 415


def test_sensor_rate_limit(tmp_path: Path) -> None:
    env = Env(tmp_path, Limits(sensor_rate=0.001, sensor_burst=2))
    assert [env.post(line()).status_code for _ in range(3)] == [200, 200, 429]


# --- per-line validation -----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        ("not json", "invalid JSON"),
        ("[1, 2]", "line is not a JSON object"),
        (b"\xff\xfe\x00garbage".decode("latin-1"), "invalid JSON"),
        ("[" * 2000, "line too long"),
        (line(**{"sensor.id": "vps-b"}), "server-controlled field: sensor.id"),
        (line(**{"integrity.hash": "0" * 64}), "server-controlled field: integrity.hash"),
        (line(sensor_id="vps-b"), "unknown field: 'sensor_id'"),
        (line(**{"source.ip": "1.2.3.4'; --"}), "source.ip: ip_any_address"),
    ],
)
def test_bad_lines_are_reported_and_dropped(env: Env, raw: str, error: str) -> None:
    response = env.post("\n".join([line(), raw, line()]))
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["rejected"] == 1
    assert body["errors"][0]["line"] == 2
    assert body["errors"][0]["error"].startswith(error.split(":")[0])
    assert env.count() == 2


def test_deeply_nested_json_rejected(tmp_path: Path) -> None:
    env = Env(tmp_path, Limits(max_line_bytes=1 << 20, max_body_bytes=1 << 21))
    response = env.post("[" * 200_000 + "]" * 200_000)
    assert response.json()["errors"] == [{"line": 1, "error": "invalid JSON"}]


def test_error_report_does_not_echo_values(env: Env) -> None:
    secret = "AKIA-not-a-real-key"
    response = env.post(line(**{"http.response.status_code": secret}))
    assert secret not in response.text


def test_hostile_content_stored_neutralised(env: Env) -> None:
    env.post(line(**{"user.name": "bob\nAccepted password for root"}))
    (row,) = env.store.query('SELECT "user.name" AS u FROM events')
    assert row["u"] == "bob\\x0aAccepted password for root"


def test_no_api_docs_exposed(env: Env) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert env.client.get(path).status_code == 404


# --- raw log lines -----------------------------------------------------------------

SSH_FAIL = "Oct 22 10:00:01 vps-a sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"
NGINX = '203.0.113.7 - - [22/Oct/2026:10:00:00 +0200] "GET /?id=1 HTTP/1.1" 200 5 "-" "curl/8"'


def raw(message: str, dataset: str = "auth_log", **fields: Any) -> str:
    return json.dumps({"message": message, "event.dataset": dataset, **fields})


def test_raw_lines_are_parsed(env: Env) -> None:
    body = "\n".join(
        [
            raw(SSH_FAIL, **{"@timestamp": "2026-10-22T12:00:00Z"}),
            raw(NGINX, "nginx.access", **{"host.name": "web1"}),
        ]
    )
    assert env.post(body).json() == {"accepted": 2, "rejected": 0, "errors": []}
    rows = env.store.query(
        'SELECT "event.dataset" AS d, "host.name" AS h, "source.ip" AS ip, "sensor.id" AS s '
        "FROM events ORDER BY d"
    )
    assert rows == [
        {"d": "auth_log", "h": "vps-a", "ip": "203.0.113.7", "s": "vps-a"},
        {"d": "nginx.access", "h": "web1", "ip": "203.0.113.7", "s": "vps-a"},
    ]


def test_raw_repeated_line_unfolds(env: Env) -> None:
    line = SSH_FAIL.replace(": Failed", ": message repeated 5 times: [ Failed") + "]"
    assert env.post(raw(line)).json()["accepted"] == 5


def test_event_limit_per_request(tmp_path: Path) -> None:
    env = Env(tmp_path, Limits(max_events=7))
    line = SSH_FAIL.replace(": Failed", ": message repeated 5 times: [ Failed") + "]"
    body = env.post("\n".join([raw(line), raw(line)])).json()
    assert body["accepted"] == 5
    assert body["errors"] == [{"line": 2, "error": "event limit per request reached"}]


@pytest.mark.parametrize(
    ("line", "error"),
    [
        (raw(SSH_FAIL, "windows"), "unknown dataset"),
        (raw(SSH_FAIL, ["auth_log"]), "unknown dataset"),  # type: ignore[arg-type]
        (json.dumps({"message": 1, "event.dataset": "auth_log"}), "message must be a string"),
        (raw(SSH_FAIL, **{"user.name": "root"}), "unknown field"),
        (raw(SSH_FAIL, **{"sensor.id": "vps-b"}), "server-controlled field"),
        (raw(SSH_FAIL, **{"@timestamp": "yesterday"}), "@timestamp"),
    ],
)
def test_bad_raw_lines(env: Env, line: str, error: str) -> None:
    body = env.post(line).json()
    assert body["accepted"] == 0
    assert body["errors"][0]["error"].startswith(error)
