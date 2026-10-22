from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sigma.correlations import SigmaCorrelationConditionOperator as Op

from nyctala.engine.correlation import Correlation, Hit
from nyctala.engine.ruleset import load_ruleset
from nyctala.engine.testing import RULES_DIR

T0 = datetime(2026, 10, 22, 10, 0, tzinfo=UTC)


def hit(rule: str, minute: float, **fields: Any) -> Hit:
    ts = T0 + timedelta(minutes=minute)
    return Hit(rule, ts, ts, (f"{rule}@{minute}@{sorted(fields.items())}",), fields)


def corr(kind: str, rules: tuple[str, ...] = ("a",), span: float = 10, **kw: Any) -> Correlation:
    return Correlation(
        id="c",
        name="c",
        title="c",
        level="high",
        techniques=(),
        type=kind,
        rules=rules,
        group_by=kw.pop("group_by", ("source.ip",)),
        timespan=timedelta(minutes=span),
        generate=False,
        **kw,
    )


IP = {"source.ip": "203.0.113.7"}


# --- event_count -------------------------------------------------------------------


def test_event_count_fires_once_per_burst() -> None:
    c = corr("event_count", threshold=3)
    out = c.evaluate({"a": [hit("a", m, **IP) for m in range(5)]})
    assert len(out) == 1
    assert len(out[0].event_ids) == 3
    assert out[0].fields == IP
    assert (out[0].first, out[0].last) == (T0, T0 + timedelta(minutes=2))


def test_event_count_second_burst_fires_again() -> None:
    c = corr("event_count", threshold=3)
    assert len(c.evaluate({"a": [hit("a", m, **IP) for m in range(6)]})) == 2


def test_event_count_respects_timespan() -> None:
    c = corr("event_count", threshold=3, span=10)
    spread = [hit("a", m, **IP) for m in (0, 6, 12, 18)]  # any 10 min holds 2
    assert c.evaluate({"a": spread}) == []


def test_event_count_gt_vs_gte() -> None:
    hits = {"a": [hit("a", m, **IP) for m in range(3)]}
    assert len(corr("event_count", threshold=3).evaluate(hits)) == 1
    assert corr("event_count", threshold=3, op=Op.GT).evaluate(hits) == []


def test_groups_are_separate_and_null_groups_ignored() -> None:
    c = corr("event_count", threshold=2)
    hits = [
        hit("a", 0, **{"source.ip": "1.1.1.1"}),
        hit("a", 1, **{"source.ip": "2.2.2.2"}),
        hit("a", 2, **{"source.ip": None}),
        hit("a", 3, **{"source.ip": None}),
    ]
    assert c.evaluate({"a": hits}) == []


def test_unsorted_input() -> None:
    c = corr("event_count", threshold=3, span=2)
    hits = [hit("a", m, **IP) for m in (2, 0, 1)]
    assert len(c.evaluate({"a": hits})) == 1


# --- value_count -------------------------------------------------------------------


def test_value_count_counts_distinct_values() -> None:
    c = corr("value_count", threshold=3, value_field="user.name")
    same_user = [hit("a", m, **IP, **{"user.name": "root"}) for m in range(5)]
    assert c.evaluate({"a": same_user}) == []
    users = [hit("a", m, **IP, **{"user.name": u}) for m, u in enumerate("xyz")]
    assert len(c.evaluate({"a": users})) == 1


# --- temporal ----------------------------------------------------------------------


def test_temporal_any_order() -> None:
    c = corr("temporal", rules=("a", "b"))
    assert len(c.evaluate({"a": [hit("a", 5, **IP)], "b": [hit("b", 1, **IP)]})) == 1


def test_temporal_needs_all_rules() -> None:
    c = corr("temporal", rules=("a", "b"))
    assert c.evaluate({"a": [hit("a", m, **IP) for m in range(5)]}) == []


def test_temporal_ordered_requires_order() -> None:
    c = corr("temporal_ordered", rules=("a", "b"))
    assert len(c.evaluate({"a": [hit("a", 1, **IP)], "b": [hit("b", 2, **IP)]})) == 1
    assert c.evaluate({"a": [hit("a", 2, **IP)], "b": [hit("b", 1, **IP)]}) == []


def test_temporal_ordered_timespan_from_first_step() -> None:
    c = corr("temporal_ordered", rules=("a", "b", "c"), span=10)
    late = {"a": [hit("a", 0, **IP)], "b": [hit("b", 5, **IP)], "c": [hit("c", 11, **IP)]}
    assert c.evaluate(late) == []
    # A fresher first step restarts the chain.
    late["a"].append(hit("a", 4, **IP))
    late["b"].append(hit("b", 6, **IP))
    assert len(c.evaluate(late)) == 1


def test_temporal_ordered_same_group_only() -> None:
    c = corr("temporal_ordered", rules=("a", "b"), group_by=("user.name", "host.name"))
    a = hit("a", 0, **{"user.name": "kris", "host.name": "vps-a"})
    b = hit("b", 1, **{"user.name": "kris", "host.name": "vps-b"})
    assert c.evaluate({"a": [a], "b": [b]}) == []


def test_evidence_is_every_contributing_event() -> None:
    c = corr("temporal_ordered", rules=("a", "b"))
    (out,) = c.evaluate({"a": [hit("a", 0, **IP)], "b": [hit("b", 1, **IP)]})
    assert len(out.event_ids) == 2


# --- rule set ----------------------------------------------------------------------


def write(directory: Path, name: str, body: str) -> None:
    (directory / f"{name}.yml").write_text(body)


BASE = """title: {name}
name: {name}
id: {id}
tags: [attack.t1110.001]
level: {level}
logsource: {{product: linux, service: auth}}
detection: {{s: {{event.action: ssh_login, event.outcome: failure}}, condition: s}}
"""
CORR = """title: {name}
name: {name}
id: {id}
tags: [attack.t1110.001]
correlation:
  type: event_count
  rules: [{ref}]
  group-by: [source.ip]
  timespan: 10m
  generate: {generate}
  condition: {{gte: 2}}
"""
IDS = [f"00000000-0000-4000-8000-00000000000{i}" for i in range(10)]


def test_bundled_ruleset_loads_cleanly() -> None:
    ruleset = load_ruleset(RULES_DIR)
    assert ruleset.errors == {}
    names = {r.name for r in ruleset.rules.values()}
    assert {"ssh_bruteforce", "ssh_bruteforce_success", "web_sqli_repeated"} <= names


def test_alerting_policy() -> None:
    ruleset = load_ruleset(RULES_DIR)
    alerting = {r.name for r in ruleset.alerting()}
    # Building blocks stay quiet; correlations and standalone detections alert.
    assert "ssh_failed_login" not in alerting  # only referenced with generate: false
    assert "ssh_login_success" not in alerting  # informational
    assert "web_sqli_pattern" not in alerting
    assert "sudo_root_shell" in alerting  # referenced with generate: true
    assert {"crontab_modification", "http_large_response", "ssh_bruteforce"} <= alerting


def test_lookback_follows_chains() -> None:
    ruleset = load_ruleset(RULES_DIR)
    by_name = {r.name: r.id for r in ruleset.rules.values()}
    assert ruleset.lookback(by_name["ssh_bruteforce"]) == timedelta(minutes=10)
    assert ruleset.lookback(by_name["ssh_bruteforce_success"]) == timedelta(minutes=40)


def test_unresolved_reference(tmp_path: Path) -> None:
    write(tmp_path, "c", CORR.format(name="c", id=IDS[1], ref="nope", generate="false"))
    ruleset = load_ruleset(tmp_path)
    assert "not found" in ruleset.errors[tmp_path / "c.yml"]


def test_correlation_on_broken_rule_is_dropped(tmp_path: Path) -> None:
    write(
        tmp_path, "b", BASE.format(name="b", id=IDS[0], level="low").replace("event.action", "x.y")
    )
    write(tmp_path, "c", CORR.format(name="c", id=IDS[1], ref="b", generate="false"))
    write(tmp_path, "d", CORR.format(name="d", id=IDS[2], ref="c", generate="false"))
    ruleset = load_ruleset(tmp_path)
    assert ruleset.rules == {}
    assert set(ruleset.errors) == {tmp_path / f"{n}.yml" for n in "bcd"}


def test_reference_cycle_rejected(tmp_path: Path) -> None:
    write(tmp_path, "c", CORR.format(name="c", id=IDS[1], ref="d", generate="false"))
    write(tmp_path, "d", CORR.format(name="d", id=IDS[2], ref="c", generate="false"))
    ruleset = load_ruleset(tmp_path)
    assert all("cycle" in e for e in ruleset.errors.values())
    assert ruleset.rules == {}


@pytest.mark.parametrize(
    ("change", "error"),
    [
        (("group-by: [source.ip]", "group-by: [source.ipp]"), "unknown group-by field"),
        (("condition: {gte: 2}", "condition: {lt: 2}"), "gt or gte"),
    ],
)
def test_bad_correlations(tmp_path: Path, change: tuple[str, str], error: str) -> None:
    write(tmp_path, "b", BASE.format(name="b", id=IDS[0], level="low"))
    body = CORR.format(name="c", id=IDS[1], ref="b", generate="false").replace(*change)
    write(tmp_path, "c", body)
    assert error in load_ruleset(tmp_path).errors[tmp_path / "c.yml"]
