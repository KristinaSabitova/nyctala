"""Rule tests: every rule ships positive and negative fixtures.

Layout, next to the rules::

    rules/<name>.yml
    rules/tests/positive/<name>.ndjson   every event here must match
    rules/tests/negative/<name>.ndjson   no event here may match

Fixture lines use the ingest format (ECS-lite events or raw log lines) and go
through the same parsing and validation as live data. A rule passes only if it
compiles, carries an ATT&CK technique, has both fixtures, matches every
positive event and no negative one.
"""

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from nyctala.engine.sigma import Rule, RuleError, load_rule
from nyctala.ingest.lines import parse_line
from nyctala.schema import Event
from nyctala.store import EventStore

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
FIXTURE_SENSOR = "rule-test"


@dataclass
class RuleTestResult:
    name: str
    rule: Rule | None = None
    positive_total: int = 0
    positive_matched: int = 0
    negative_total: int = 0
    negative_matched: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return (
            not self.errors
            and self.positive_total > 0
            and self.negative_total > 0
            and self.positive_matched == self.positive_total
            and self.negative_matched == 0
        )


class FixtureError(ValueError):
    pass


def load_fixture(path: Path) -> list[Event]:
    if not path.is_file():
        raise FixtureError(f"missing fixture {path.parent.name}/{path.name}")
    events: list[Event] = []
    for number, line in enumerate(path.read_bytes().split(b"\n"), start=1):
        if not line.strip():
            continue
        result = parse_line(line, FIXTURE_SENSOR)
        if isinstance(result, str):
            raise FixtureError(f"{path.parent.name}/{path.name}:{number}: {result}")
        events.extend(result)
    if not events:
        raise FixtureError(f"empty fixture {path.parent.name}/{path.name}")
    return events


def count_matches(rule: Rule, events: list[Event]) -> int:
    with tempfile.TemporaryDirectory(prefix="nyctala-rule-test-") as tmp:
        store = EventStore(Path(tmp))
        try:
            store.append(events)
            sql, params = rule.query()
            return len(store.query(sql, params))
        finally:
            store.close()


def run_rule_test(path: Path) -> RuleTestResult:
    name = path.stem
    result = RuleTestResult(name)
    try:
        result.rule = rule = load_rule(path)
    except RuleError as exc:
        result.errors.append(str(exc))
        return result
    if not rule.techniques:
        result.errors.append("no ATT&CK technique tag (attack.tNNNN)")

    tests = path.parent / "tests"
    for polarity in ("positive", "negative"):
        try:
            events = load_fixture(tests / polarity / f"{name}.ndjson")
        except FixtureError as exc:
            result.errors.append(str(exc))
            continue
        try:
            matched = count_matches(rule, events)
        except Exception as exc:  # e.g. a regex RE2 rejects: report, never crash the run
            result.errors.append(f"query failed: {type(exc).__name__}: {exc}")
            continue
        if polarity == "positive":
            result.positive_total, result.positive_matched = len(events), matched
        else:
            result.negative_total, result.negative_matched = len(events), matched
    return result


def run_rule_tests(rules_dir: Path = RULES_DIR) -> list[RuleTestResult]:
    return [run_rule_test(path) for path in sorted(rules_dir.glob("*.yml"))]
