from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from nyctala.cli.main import app
from nyctala.health.integrity import IntegrityChain
from nyctala.health.monitor import HealthMonitor
from nyctala.health.sources import HealthPolicy, source_health
from nyctala.ingest.sensors import SensorRegistry
from nyctala.schema import Alert, Event
from nyctala.store import EventStore

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
runner = CliRunner()


class Env:
    def __init__(self, root: Path) -> None:
        self.store = EventStore(root)
        self.registry = SensorRegistry(root / "sensors.json")
        self.chain = IntegrityChain(self.store)
        self.alerts: list[Alert] = []

    def send(
        self,
        sensor: str,
        ingested_ago: timedelta,
        n: int = 1,
        dataset: str = "auth_log",
        lag: timedelta = timedelta(0),
        **fields: Any,
    ) -> None:
        ingested = NOW - ingested_ago
        events = [
            Event.model_validate(
                {
                    "@timestamp": ingested - lag,
                    "event.ingested": ingested,
                    "event.dataset": dataset,
                    "sensor.id": sensor,
                    **fields,
                }
            )
            for _ in range(n)
        ]
        self.chain.append(sensor, events)

    def monitor(self, **kw: Any) -> HealthMonitor:
        return HealthMonitor(self.store, self.registry, self.alerts.extend, **kw)

    def status(self) -> dict[str, str]:
        statuses = source_health(self.store, self.monitor().active_sensors(), NOW)
        return {f"{s.sensor}/{s.dataset or '*'}": s.status for s in statuses}


@pytest.fixture
def env(tmp_path: Path) -> Env:
    e = Env(tmp_path)
    for sensor in ("vps-a", "vps-b", "vps-c"):
        e.registry.add(sensor)
    return e


# --- source status -----------------------------------------------------------------


def test_ok_silent_and_never_seen(env: Env) -> None:
    env.send("vps-a", timedelta(minutes=1))
    env.send("vps-b", timedelta(minutes=40))
    assert env.status() == {
        "vps-a/auth_log": "ok",
        "vps-b/auth_log": "silent",
        "vps-c/*": "never_seen",
    }


def test_one_dataset_going_silent_is_noticed(env: Env) -> None:
    env.send("vps-a", timedelta(minutes=1))
    env.send("vps-a", timedelta(hours=2), dataset="nginx.access")
    status = env.status()
    assert status["vps-a/auth_log"] == "ok"
    assert status["vps-a/nginx.access"] == "silent"


def test_silent_for_more_than_history(env: Env) -> None:
    env.send("vps-b", timedelta(days=3))
    assert env.status()["vps-b/*"] == "silent"


def test_revoked_sensor_not_monitored(env: Env) -> None:
    env.registry.revoke("vps-c")
    assert "vps-c/*" not in env.status()


def test_lag_skew_and_unparsed(env: Env) -> None:
    env.send("vps-a", timedelta(minutes=1), n=9, lag=timedelta(seconds=2))
    env.send("vps-a", timedelta(minutes=1), lag=timedelta(seconds=100))
    env.send("vps-a", timedelta(minutes=1), lag=-timedelta(hours=1))  # stamped in the future
    env.send("vps-a", timedelta(minutes=1), tags=["nyctala.unparsed"])
    (st,) = [s for s in source_health(env.store, ["vps-a"], NOW, HealthPolicy()) if s.dataset]
    assert st.events == 12
    assert st.lag_p50 == pytest.approx(2.0)
    assert st.lag_max == pytest.approx(100.0)
    assert st.future == 1
    assert st.unparsed == 1


def test_lag_window_only_counts_recent_events(env: Env) -> None:
    env.send("vps-a", timedelta(hours=5), lag=timedelta(hours=1))
    env.send("vps-a", timedelta(minutes=1), lag=timedelta(seconds=1))
    (st,) = source_health(env.store, ["vps-a"], NOW)
    assert st.events == 1
    assert st.lag_max == pytest.approx(1.0)


# --- monitor -----------------------------------------------------------------------


def test_snapshot_written(env: Env) -> None:
    env.send("vps-a", timedelta(minutes=1))
    env.monitor().tick(NOW)
    rows = env.store.query(
        'SELECT "sensor.id" AS s, "source.status" AS st FROM source_health ORDER BY s'
    )
    assert rows == [
        {"s": "vps-a", "st": "ok"},
        {"s": "vps-b", "st": "never_seen"},
        {"s": "vps-c", "st": "never_seen"},
    ]


def test_silent_source_alerts_once_per_episode(env: Env) -> None:
    env.registry.revoke("vps-a")
    env.registry.revoke("vps-c")
    env.send("vps-b", timedelta(minutes=1))
    env.monitor().tick(NOW)
    assert env.alerts == []

    later = NOW + timedelta(minutes=30)
    env.monitor().tick(later)
    (alert,) = env.alerts
    assert alert.kind == "health"
    assert alert.rule_name == "source_silent"
    assert alert.techniques == ["T1685"]
    assert alert.entities == ["sensor:vps-b"]
    assert "sent nothing for 31 min" in alert.explanation

    env.monitor().tick(later + timedelta(minutes=5))  # still silent, new process: no repeat
    assert len(env.alerts) == 1

    # The source comes back and later goes silent again: a new episode.
    env.send("vps-b", -timedelta(minutes=40))
    env.monitor().tick(NOW + timedelta(hours=2))
    assert len(env.alerts) == 2


def test_never_seen_sensor_alerts(env: Env) -> None:
    env.registry.revoke("vps-b")
    env.registry.revoke("vps-c")
    env.registry.add("vps-new")
    env.monitor().tick(NOW)
    (alert,) = [a for a in env.alerts if "vps-new" in a.rule_title]
    assert "has never sent any event" in alert.explanation


def test_integrity_damage_alerts_once(env: Env) -> None:
    for i in range(3):
        env.send("vps-a", timedelta(minutes=3 - i), user_name=None)
    path = sorted(env.store.events_dir.rglob("*.parquet"))[0]
    table = pq.read_table(path)
    rows = table.to_pylist()
    rows[0]["user.name"] = "forged"
    pq.write_table(type(table).from_pylist(rows, schema=table.schema), path)

    env.monitor().tick(NOW)
    integrity = [a for a in env.alerts if a.rule_name == "integrity_broken"]
    assert len(integrity) == 1
    assert integrity[0].rule_level == "critical"
    assert integrity[0].techniques == ["T1565.001", "T1070"]
    assert "1 modified event(s)" in integrity[0].explanation

    env.monitor().tick(NOW + timedelta(hours=2))
    assert len([a for a in env.alerts if a.rule_name == "integrity_broken"]) == 1


def test_intervals(env: Env) -> None:
    monitor = env.monitor(verify_interval=timedelta(hours=1))
    monitor.tick(NOW)
    monitor.tick(NOW + timedelta(seconds=30))
    monitor.tick(NOW + timedelta(minutes=2))
    snapshots = env.store.query('SELECT count(DISTINCT "check.at") AS n FROM source_health')
    assert snapshots == [{"n": 2}]


def test_health_alerts_do_not_feed_entity_risk(env: Env) -> None:
    from nyctala.engine.alerts import entity_risk

    env.registry.revoke("vps-c")
    env.send("vps-b", timedelta(hours=1))
    env.monitor().tick(NOW)
    assert env.alerts
    assert entity_risk(env.store, NOW + timedelta(minutes=1), timedelta(hours=24)) == []


# --- CLI ---------------------------------------------------------------------------


def test_cli_health_exit_codes(env: Env) -> None:
    env.registry.revoke("vps-b")
    env.registry.revoke("vps-c")
    env.send("vps-a", NOW - (datetime.now(UTC) - timedelta(seconds=5)))  # 5 s ago, real time
    data = ["--data", str(env.store.root)]
    ok = runner.invoke(app, ["health", *data])
    assert ok.exit_code == 0, ok.output
    assert ok.output.startswith("ok")
    env.registry.add("vps-d")
    bad = runner.invoke(app, ["health", *data])
    assert bad.exit_code == 1
    assert "never_seen" in bad.output
