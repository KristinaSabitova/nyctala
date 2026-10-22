from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from nyctala.engine.sigma import Rule, RuleError, compile_rule, load_rule
from nyctala.schema import Event
from nyctala.store import EventStore

HEADER = """
title: test
id: 00000000-0000-4000-8000-000000000000
logsource: {product: linux, service: auth}
"""


def rule(detection: str, header: str = HEADER) -> Rule:
    sigma = SigmaCollection.from_yaml(header + "detection:\n" + detection).rules[0]
    assert isinstance(sigma, SigmaRule)
    return compile_rule(sigma)


def ev(name: str, **fields: Any) -> Event:
    return Event.model_validate(
        {
            "@timestamp": "2026-10-22T10:00:00Z",
            "event.dataset": "auth_log",
            "sensor.id": "s",
            "event.original": name,
            **fields,
        }
    )


EVENTS = [
    ev("root", **{"user.name": "root", "source.ip": "10.1.2.3", "tags": ["ssh", "auth"]}),
    ev("ROOT", **{"user.name": "ROOT", "source.ip": "2001:db8::1"}),
    ev("pct", **{"user.name": "50%_off", "process.command_line": "curl http://x | SH"}),
    ev("big", **{"http.response.bytes": 5000, "http.response.status_code": 200}),
    ev("inject", **{"user.name": "x' OR 1=1 --"}),
    ev("nouser"),
    Event.model_validate(
        {
            "@timestamp": "2026-10-22T10:00:00Z",
            "event.dataset": "nginx.access",
            "sensor.id": "s",
            "event.original": "web",
            "user.name": "root",
        }
    ),
]


@pytest.fixture(scope="module")
def store(tmp_path_factory: pytest.TempPathFactory) -> Iterator[EventStore]:
    s = EventStore(tmp_path_factory.mktemp("sigma"))
    s.append(EVENTS)
    yield s
    s.close()


def matches(store: EventStore, r: Rule) -> list[str]:
    sql, params = r.query()
    ids = {row["id"] for row in store.query(sql, params)}
    return sorted(e.event_original or "" for e in EVENTS if e.event_id in ids)


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        ("  s: {user.name: root}\n  condition: s", ["ROOT", "root"]),
        ("  s: {user.name|cased: root}\n  condition: s", ["root"]),
        ("  s: {user.name: 'r*t'}\n  condition: s", ["ROOT", "root"]),
        ("  s: {user.name: 'ro?t'}\n  condition: s", ["ROOT", "root"]),
        ("  s: {user.name|contains: '%'}\n  condition: s", ["pct"]),
        ("  s: {user.name|contains: '_'}\n  condition: s", ["pct"]),
        ("  s: {user.name: '50%off'}\n  condition: s", []),
        ("  s: {user.name|startswith: 'ro'}\n  condition: s", ["ROOT", "root"]),
        ("  s: {user.name|endswith: 'off'}\n  condition: s", ["pct"]),
        ("  s: {user.name: [nobody, root]}\n  condition: s", ["ROOT", "root"]),
        ("  s: {user.name|contains|all: [o, t]}\n  condition: s", ["ROOT", "root"]),
        ("  s: {user.name|contains|all: [o, r]}\n  condition: s", ["ROOT", "inject", "root"]),
        ("  s: {process.command_line|re: 'curl.*\\| *sh$'}\n  condition: s", []),
        ("  s: {process.command_line|re|i: 'curl.*\\| *sh$'}\n  condition: s", ["pct"]),
        ("  s: {source.ip|cidr: 10.0.0.0/8}\n  condition: s", ["root"]),
        ("  s: {source.ip|cidr: '2001:db8::/32'}\n  condition: s", ["ROOT"]),
        ("  s: {http.response.bytes|gte: 5000}\n  condition: s", ["big"]),
        ("  s: {http.response.bytes|gt: 5000}\n  condition: s", []),
        ("  s: {http.response.status_code: 200}\n  condition: s", ["big"]),
        ("  s: {http.response.status_code: '200'}\n  condition: s", ["big"]),
        ("  s: {user.name: null}\n  condition: s", ["big", "nouser"]),
        ("  s: {user.name|exists: true}\n  condition: s", ["ROOT", "inject", "pct", "root"]),
        ("  s: {tags: ssh}\n  condition: s", ["root"]),
        ("  s: {tags: 'au*'}\n  condition: s", ["root"]),
        ("  s: {tags: null}\n  condition: s", ["ROOT", "big", "inject", "nouser", "pct"]),
        ("  k: [inj]\n  condition: k", ["inject"]),
        ('  s: {user.name: "x\' OR 1=1 --"}\n  condition: s', ["inject"]),
        # Sigma NOT: events without the field match "not user.name: root".
        (
            "  s: {user.name: root}\n  condition: not s",
            ["big", "inject", "nouser", "pct"],
        ),
        (
            "  a: {user.name: root}\n  b: {source.ip|cidr: 10.0.0.0/8}\n  condition: a and not b",
            ["ROOT"],
        ),
        ("  sel_a: {user.name: root}\n  sel_b: {tags: ssh}\n  condition: all of sel_*", ["root"]),
    ],
)
def test_semantics(store: EventStore, detection: str, expected: list[str]) -> None:
    assert matches(store, rule(detection)) == expected


def test_logsource_restricts_dataset(store: EventStore) -> None:
    web = HEADER.replace("{product: linux, service: auth}", "{category: webserver}")
    assert matches(store, rule("  s: {user.name: root}\n  condition: s", web)) == ["web"]


def test_values_are_bound_not_inlined() -> None:
    r = rule('  s: {user.name: "x\' OR 1=1 --"}\n  condition: s')
    assert "OR 1=1" not in r.where
    assert "x' OR 1=1 --" in r.params


def test_metadata() -> None:
    header = HEADER + "level: high\ntags: [attack.t1110.001, attack.credential-access]\n"
    r = rule("  s: {user.name: root}\n  condition: s", header)
    assert r.level == "high"
    assert r.techniques == ("T1110.001",)
    assert r.datasets == ("auth_log", "syslog")


@pytest.mark.parametrize(
    ("detection", "error"),
    [
        ("  s: {user.nmae: root}\n  condition: s", "unknown field"),
        ("  s: {user.name|gte: 5}\n  condition: s", "numeric comparison"),
        ("  s: {http.response.bytes: 'a*'}\n  condition: s", "non-numeric"),
        ("  s: {source.ip|expand: '%internal%'}\n  condition: s", "placeholder"),
    ],
)
def test_compile_errors(detection: str, error: str) -> None:
    with pytest.raises(RuleError, match=error):
        rule(detection)


def test_unsupported_logsource() -> None:
    header = HEADER.replace("{product: linux, service: auth}", "{product: windows}")
    with pytest.raises(RuleError, match="logsource"):
        rule("  s: {user.name: root}\n  condition: s", header)


def test_non_re2_regex_rejected_at_load(tmp_path: Path) -> None:
    # Backreferences and lookarounds need a backtracking engine: refused up front.
    path = tmp_path / "r.yml"
    path.write_text(HEADER + "detection:\n  s: {user.name|re: '(o)\\1'}\n  condition: s\n")
    with pytest.raises(RuleError, match="escape"):
        load_rule(path)


def test_rule_file_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "r.yml"
    path.write_text(
        HEADER + "tags: [attack.t1078]\ndetection:\n  s: {user.name: root}\n  condition: s\n"
    )
    assert load_rule(path).techniques == ("T1078",)
    path.write_text("title: [unclosed")
    with pytest.raises(RuleError):
        load_rule(path)
