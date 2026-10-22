import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from nyctala.cli.main import app
from nyctala.engine.ruleset import load_ruleset
from nyctala.engine.testing import RULES_DIR
from nyctala.lab import scenario as lab
from nyctala.lab.scenario import Scenario, ScenarioError, load_scenario, run_scenario

runner = CliRunner()
RULES = load_ruleset(RULES_DIR)
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def scenario(line: str, **kw: Any) -> Scenario:
    return Scenario.model_validate(
        {"name": "t", "events": [{"at": 0, "dataset": "auth_log", "line": line, **kw}]}
    )


def test_bundled_scenarios_pass() -> None:
    result = runner.invoke(app, ["lab", "run"])
    assert result.exit_code == 0, result.output
    assert result.output.count("PASS") == len(lab.bundled_scenarios()) >= 4


def test_benign_scenario_raises_nothing() -> None:
    path = next(p for p in lab.bundled_scenarios() if p.stem == "benign_day")
    result = run_scenario(load_scenario(path), RULES)
    assert result.passed
    assert result.alerted == set()
    assert result.events > 50


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "10.0.0.1",
        "::ffff:8.8.8.8",
        "2a00:1450::1",
        "198.51.101.1",
        "host:8.8.8.8",
        "[2a00:1450::1]:443",
        "x8.8.8.8y",
    ],
)
def test_only_synthetic_addresses(ip: str) -> None:
    with pytest.raises(ValueError, match="non-synthetic"):
        scenario(f"{{syslog}} h sshd[1]: Failed password for root from {ip} port 1 ssh2")


@pytest.mark.parametrize(
    "ip", ["192.0.2.1", "198.51.100.255", "203.0.113.7", "2001:db8::5", "127.0.0.1"]
)
def test_documentation_addresses_allowed(ip: str) -> None:
    scenario(f"{{syslog}} h sshd[1]: Failed password for root from {ip} port 1 ssh2")


def test_render_placeholders_and_order() -> None:
    sc = Scenario.model_validate(
        {
            "name": "t",
            "events": [
                {"at": 10, "dataset": "nginx.access", "line": 'x [{nginx}] "{iso}" {syslog}'},
                {"at": 0, "every": 1, "repeat": 2, "dataset": "auth_log", "line": "{syslog} {x}"},
            ],
        }
    )
    lines = [json.loads(raw) for raw in sc.render(NOW)]
    assert [line["message"] for line in lines] == [
        "Oct 22 12:00:00 {x}",
        "Oct 22 12:00:01 {x}",
        'x [22/Oct/2026:12:00:10 +0000] "2026-10-22T12:00:10+00:00" Oct 22 12:00:10',
    ]
    assert lines[0]["@timestamp"] == "2026-10-22T12:00:00+00:00"
    assert sc.duration.total_seconds() == 10


def test_bsd_day_padding() -> None:
    (raw,) = scenario("{syslog} h x").render(datetime(2026, 11, 5, 9, 0, tzinfo=UTC))
    assert json.loads(raw)["message"] == "Nov  5 09:00:00 h x"


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "t", "events": []},
        {"name": "T!", "events": [{"at": 0, "dataset": "auth_log", "line": "x"}]},
        {"name": "t", "events": [{"at": 0, "dataset": "windows", "line": "x"}]},
        {"name": "t", "events": [{"at": 0, "dataset": "auth_log", "line": "x", "shell": "id"}]},
        {"name": "t", "events": [{"at": 0, "dataset": "auth_log", "line": "x", "repeat": 5000}]},
    ],
)
def test_invalid_scenarios(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        Scenario.model_validate(bad)


def test_too_many_events() -> None:
    sc = Scenario.model_validate(
        {
            "name": "t",
            "events": [
                {"at": 0, "dataset": "auth_log", "line": "x", "repeat": 1000} for _ in range(11)
            ],
        }
    )
    with pytest.raises(ScenarioError, match="max"):
        sc.render(NOW)


def test_mismatch_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "s.yml"
    path.write_text(
        "name: s\nexpect: [web_sqli_repeated]\nevents:\n"
        "  - {at: 0, every: 1, repeat: 6, dataset: auth_log,\n"
        '     line: "{syslog} h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"}\n'
    )
    result = runner.invoke(app, ["lab", "run", str(path)])
    assert result.exit_code == 1
    assert "missing:    web_sqli_repeated" in result.output
    assert "unexpected: ssh_bruteforce" in result.output


def test_unknown_scenario_name() -> None:
    assert runner.invoke(app, ["lab", "run", "nope"]).exit_code != 0


def test_replay_needs_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NYCTALA_TOKEN", raising=False)
    result = runner.invoke(app, ["lab", "replay", "web_attack", "--url", "http://127.0.0.1:1/x"])
    assert result.exit_code != 0
    assert "NYCTALA_TOKEN" in result.output


def test_replay_sends_ndjson(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[Any] = []

    class Response:
        def __init__(self, n: int) -> None:
            self.n = n

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"accepted": self.n}).encode()

    def fake_urlopen(request: Any, timeout: float) -> Response:
        sent.append(request)
        return Response(len(request.data.strip().split(b"\n")))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    path = next(p for p in lab.bundled_scenarios() if p.stem == "web_attack")
    assert (
        lab.replay(load_scenario(path), "http://127.0.0.1:8514/v1/ingest", "nyc_x", batch=4) == 10
    )
    assert len(sent) == 3
    assert sent[0].headers["Authorization"] == "Bearer nyc_x"
    assert sent[0].headers["Content-type"] == "application/x-ndjson"


def test_replay_rejects_non_http_url() -> None:
    path = next(p for p in lab.bundled_scenarios() if p.stem == "web_attack")
    with pytest.raises(ScenarioError):
        lab.replay(load_scenario(path), "file:///etc/passwd", "t")
