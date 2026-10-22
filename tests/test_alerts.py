import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from nyctala.cli.main import app
from nyctala.engine.alerts import (
    RISK_RULE_ID,
    AlertManager,
    RiskPolicy,
    entity_risk,
    incidents,
    load_alerts,
)
from nyctala.engine.correlation import Hit
from nyctala.engine.job import DetectionJob
from nyctala.engine.ruleset import RuleSet, load_ruleset
from nyctala.engine.testing import RULES_DIR
from nyctala.schema import Alert, Event
from nyctala.store import EventStore

T0 = datetime(2026, 10, 22, 10, 0, tzinfo=UTC)
RULES = load_ruleset(RULES_DIR)
BY_NAME = {r.name: r for r in RULES.rules.values()}


@pytest.fixture
def store(tmp_path: Path) -> Iterator[EventStore]:
    s = EventStore(tmp_path)
    yield s
    s.close()


def event(minute: float, **fields: Any) -> Event:
    ts = T0 + timedelta(minutes=minute)
    return Event.model_validate(
        {
            "@timestamp": ts,
            "event.ingested": ts,
            "event.dataset": "auth_log",
            "sensor.id": "vps-a",
            "event.original": f"line at {minute}",
            **fields,
        }
    )


def hit_for(store: EventStore, rule: str, minute: float, **fields: Any) -> Hit:
    """Store one event and return a hit of ``rule`` on it."""
    ev = event(minute, **fields)
    store.append([ev])
    group = {k: v for k, v in fields.items() if k in ("source.ip",)}
    return Hit(BY_NAME[rule].id, ev.timestamp, ev.timestamp, (ev.event_id,), group)


def manager(store: EventStore, **policy: Any) -> AlertManager:
    return AlertManager(store, RULES, RiskPolicy(**policy))


IP = {"source.ip": "203.0.113.7", "host.name": "vps-a"}


# --- alerts are explainable --------------------------------------------------------


def test_alert_explains_itself(store: EventStore) -> None:
    hit = hit_for(store, "ssh_bruteforce", 0, **IP, **{"user.name": "root"})
    (alert,) = manager(store).handle([hit])
    assert alert.kind == "correlation"
    assert alert.rule_name == "ssh_bruteforce"
    assert alert.techniques == ["T1110.001"]
    assert alert.event_ids == list(hit.event_ids)
    assert alert.entities == ["host:vps-a", "ip:203.0.113.7", "user:root"]
    assert alert.risk_score == 25
    assert alert.risk_accumulated == 25
    assert "source.ip=203.0.113.7" in alert.explanation
    assert "ip:203.0.113.7=25" in alert.explanation


def test_alerts_are_stored(store: EventStore) -> None:
    alerts = manager(store).handle([hit_for(store, "crontab_modification", 0, **IP)])
    assert load_alerts(store, T0 - timedelta(hours=1), T0 + timedelta(hours=1)) == alerts


def test_detection_alert_kind(store: EventStore) -> None:
    (alert,) = manager(store).handle([hit_for(store, "crontab_modification", 0, **IP)])
    assert alert.kind == "detection"
    assert alert.techniques == ["T1053.003"]


def test_no_hits_no_alerts(store: EventStore) -> None:
    assert manager(store).handle([]) == []


# --- entity risk -------------------------------------------------------------------


def test_risk_accumulates_across_runs(store: EventStore) -> None:
    manager(store).handle([hit_for(store, "ssh_bruteforce", 0, **IP)])
    # A new manager (e.g. after a restart) reads the stored history.
    (alert,) = manager(store).handle([hit_for(store, "web_sqli_repeated", 5, **IP)])
    assert alert.risk_accumulated == 25 + 50


def test_risk_window(store: EventStore) -> None:
    manager(store).handle([hit_for(store, "ssh_bruteforce", 0, **IP)])
    (alert,) = manager(store).handle([hit_for(store, "ssh_bruteforce", 60 * 25, **IP)])
    assert alert.risk_accumulated == 25


def test_risk_alert_needs_threshold_and_several_rules(store: EventStore) -> None:
    m = manager(store, threshold=100)
    # Same rule four times: 100 points, but one rule only.
    alerts = m.handle([hit_for(store, "ssh_bruteforce", i, **IP) for i in range(4)])
    assert all(a.kind != "risk" for a in alerts)
    # A second rule pushes the entity over: one risk alert per entity over the threshold.
    alerts = m.handle([hit_for(store, "web_sqli_repeated", 10, **IP)])
    risk = [a for a in alerts if a.kind == "risk"]
    assert sorted(a.risk_entity or "" for a in risk) == ["host:vps-a", "ip:203.0.113.7"]
    ip_risk = next(a for a in risk if a.risk_entity == "ip:203.0.113.7")
    assert ip_risk.rule_id == RISK_RULE_ID
    assert ip_risk.risk_accumulated == 150
    assert ip_risk.techniques == ["T1110.001", "T1190"]
    assert len(ip_risk.related_alert_ids) == 5
    assert len(ip_risk.event_ids) == 5
    assert "from 5 alerts of 2 rules" in ip_risk.explanation


def test_risk_alert_once_per_window(store: EventStore) -> None:
    m = manager(store, threshold=50)
    m.handle(
        [hit_for(store, "ssh_bruteforce", 0, **IP), hit_for(store, "crontab_modification", 1, **IP)]
    )
    later = m.handle([hit_for(store, "web_sqli_repeated", 2, **IP)])
    assert [a for a in later if a.kind == "risk"] == []
    again = m.handle(
        [
            hit_for(store, "ssh_bruteforce", 60 * 30, **IP),
            hit_for(store, "crontab_modification", 60 * 30 + 1, **IP),
        ]
    )
    assert len([a for a in again if a.kind == "risk"]) == 2


def test_risk_alerts_do_not_feed_risk(store: EventStore) -> None:
    m = manager(store, threshold=50)
    m.handle(
        [hit_for(store, "ssh_bruteforce", 0, **IP), hit_for(store, "crontab_modification", 1, **IP)]
    )
    scores = {
        r.entity: r.score for r in entity_risk(store, T0 + timedelta(hours=1), timedelta(hours=24))
    }
    assert scores["ip:203.0.113.7"] == 50


def test_entity_risk_view(store: EventStore) -> None:
    manager(store).handle(
        [
            hit_for(store, "ssh_bruteforce", 0, **IP, **{"user.name": "root"}),
            hit_for(store, "sudo_root_shell", 1, **{"user.name": "kris", "host.name": "vps-a"}),
        ]
    )
    risk = entity_risk(store, T0 + timedelta(hours=1), timedelta(hours=24))
    assert [(r.entity, r.score, r.alerts) for r in risk] == [
        ("host:vps-a", 50, 2),
        ("ip:203.0.113.7", 25, 1),
        ("user:kris", 25, 1),
        ("user:root", 25, 1),
    ]


# --- incidents ---------------------------------------------------------------------


def alert(minute: float, entities: list[str], level: str = "medium") -> Alert:
    ts = T0 + timedelta(minutes=minute)
    return Alert.model_validate(
        {
            "alert.kind": "detection",
            "rule.id": "r",
            "rule.title": f"alert at {minute}",
            "rule.level": level,
            "alert.first": ts,
            "alert.last": ts,
            "alert.entities": entities,
            "risk.score": 25,
        }
    )


def titles(store: EventStore) -> list[list[str]]:
    found = incidents(store, T0 - timedelta(days=1), T0 + timedelta(days=3))
    return sorted(sorted(a.rule_title for a in inc.alerts) for inc in found)


def test_incident_links_by_ip_within_a_day(store: EventStore) -> None:
    store.append_alerts([alert(0, ["ip:1.1.1.1"]), alert(60 * 20, ["ip:1.1.1.1", "user:bob"])])
    store.append_alerts([alert(60 * 21, ["user:bob"])])  # chained through bob
    assert titles(store) == [["alert at 0", "alert at 1200", "alert at 1260"]]


def test_incident_split_after_a_day(store: EventStore) -> None:
    store.append_alerts([alert(0, ["ip:1.1.1.1"]), alert(60 * 25, ["ip:1.1.1.1"])])
    assert titles(store) == [["alert at 0"], ["alert at 1500"]]


def test_host_links_only_within_an_hour(store: EventStore) -> None:
    store.append_alerts(
        [alert(0, ["host:vps-a"]), alert(30, ["host:vps-a"]), alert(200, ["host:vps-a"])]
    )
    assert titles(store) == [["alert at 0", "alert at 30"], ["alert at 200"]]


def test_unrelated_alerts_are_separate_incidents(store: EventStore) -> None:
    store.append_alerts([alert(0, ["ip:1.1.1.1"]), alert(1, ["ip:2.2.2.2"]), alert(2, [])])
    assert len(titles(store)) == 3


def test_incident_summary(store: EventStore) -> None:
    store.append_alerts([alert(0, ["ip:1.1.1.1"], "low"), alert(5, ["ip:1.1.1.1"], "high")])
    (inc,) = incidents(store, T0 - timedelta(days=1), T0 + timedelta(days=1))
    assert inc.level == "high"
    assert inc.risk == 50
    assert inc.entities == ["ip:1.1.1.1"]
    assert (inc.first, inc.last) == (T0, T0 + timedelta(minutes=5))


# --- detection job does not repeat alerts after a restart --------------------------


def fail(store: EventStore, minute: float, n: int) -> None:
    store.append(
        [
            event(
                minute + i / 60,
                **{
                    "event.action": "ssh_login",
                    "event.outcome": "failure",
                    "source.ip": "203.0.113.7",
                    "user.name": "root",
                },
            )
            for i in range(n)
        ]
    )


def run_job(store: EventStore, ruleset: RuleSet, at: datetime) -> list[Alert]:
    m = AlertManager(store, ruleset)
    out: list[Alert] = []
    DetectionJob(
        store, ruleset, lambda hits: out.extend(m.handle(hits)), clock=lambda: at
    ).run_once()
    return out


def test_restart_does_not_repeat_alerts(store: EventStore) -> None:
    fail(store, 0, 6)
    first = run_job(store, RULES, T0 + timedelta(minutes=2))
    assert [a.rule_name for a in first] == ["ssh_bruteforce"]
    assert run_job(store, RULES, T0 + timedelta(minutes=3)) == []
    fail(store, 4, 5)
    assert [a.rule_name for a in run_job(store, RULES, T0 + timedelta(minutes=6))] == [
        "ssh_bruteforce"
    ]


# --- CLI ---------------------------------------------------------------------------

runner = CliRunner()


def test_cli_show_explains_with_events(store: EventStore) -> None:
    hit = hit_for(store, "ssh_bruteforce", 0, **IP, **{"user.name": "root\x1b[2J"})
    (a,) = manager(store).handle([hit])
    result = runner.invoke(app, ["alerts", "show", a.alert_id[:8], "--data", str(store.root)])
    assert result.exit_code == 0, result.output
    assert "SSH brute force" in result.output
    assert "T1110.001" in result.output
    assert "risk       +25, accumulated 25" in result.output
    assert "line at 0" in result.output
    assert "\x1b" not in result.output


@pytest.mark.parametrize("bad", ["'; DROP", "%", "zz", ""])
def test_cli_show_rejects_bad_ids(store: EventStore, bad: str) -> None:
    result = runner.invoke(app, ["alerts", "show", bad, "--data", str(store.root)])
    assert result.exit_code != 0


def test_cli_lists(store: EventStore) -> None:
    now = datetime.now(UTC)
    store.append_alerts([alert(0, ["ip:1.1.1.1"]).model_copy(update={"last": now, "first": now})])
    data = ["--data", str(store.root)]
    listed = runner.invoke(app, ["alerts", "list", *data])
    assert "alert at 0" in listed.output
    assert "incident" in runner.invoke(app, ["incidents", *data]).output
    assert re.search(r"25\s+ip:1\.1\.1\.1", runner.invoke(app, ["risk", *data]).output)
