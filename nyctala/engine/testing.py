"""Rule tests: every rule ships positive and negative fixtures.

Layout, next to the rules::

    rules/<name>.yml
    rules/tests/positive/<name>.ndjson
    rules/tests/negative/<name>.ndjson

Fixture lines use the ingest format (ECS-lite events or raw log lines) and go
through the same parsing and validation as live data.

* A detection rule passes if it matches every positive event and no negative one.
* A correlation rule passes if it fires at least once on the positive fixture
  and never on the negative one (e.g. a user who fails twice, then logs in).

Every rule must also compile and carry an ATT&CK technique tag.
"""

import hashlib
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nyctala.engine.correlation import Correlation
from nyctala.engine.ruleset import AnyRule, RuleSet, fetch_hits, load_ruleset
from nyctala.ingest.lines import parse_line
from nyctala.schema import Event
from nyctala.store import EventStore

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
FIXTURE_SENSOR = "rule-test"


def rule_digest(path: Path) -> str:
    """SHA-256 over a rule file and its fixtures: what a test result vouches for."""
    digest = hashlib.sha256()
    tests = path.parent / "tests"
    for part in (
        path,
        tests / "positive" / f"{path.stem}.ndjson",
        tests / "negative" / f"{path.stem}.ndjson",
    ):
        digest.update(part.name.encode() + b"\0")
        digest.update(part.read_bytes() if part.is_file() else b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass
class RuleTestResult:
    name: str
    digest: str = ""
    rule: AnyRule | None = None
    positive_total: int = 0
    positive_matched: int = 0
    negative_total: int = 0
    negative_matched: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def is_correlation(self) -> bool:
        return isinstance(self.rule, Correlation)

    @property
    def passed(self) -> bool:
        if self.errors or not self.positive_total or not self.negative_total:
            return False
        if self.negative_matched:
            return False
        if self.is_correlation:
            return self.positive_matched > 0
        return self.positive_matched == self.positive_total


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


def count_matches(ruleset: RuleSet, rule: AnyRule, events: list[Event]) -> int:
    """Matched events for a detection rule, firings for a correlation."""
    with tempfile.TemporaryDirectory(prefix="nyctala-rule-test-") as tmp:
        store = EventStore(Path(tmp))
        try:
            store.append(events)
            if isinstance(rule, Correlation):
                return len(ruleset.evaluate(store, [rule.id])[rule.id])
            return len(fetch_hits(store, rule, []))
        finally:
            store.close()


def run_rule_tests(rules_dir: Path = RULES_DIR) -> list[RuleTestResult]:
    ruleset = load_ruleset(rules_dir)
    results = []
    for path in sorted(rules_dir.glob("*.yml")):
        result = RuleTestResult(path.stem, rule_digest(path))
        results.append(result)
        if path in ruleset.errors:
            result.errors.append(ruleset.errors[path])
            continue
        result.rule = rule = ruleset.by_path(path)
        if rule is None:
            continue
        if not rule.techniques:
            result.errors.append("no ATT&CK technique tag (attack.tNNNN)")

        tests = path.parent / "tests"
        for polarity in ("positive", "negative"):
            try:
                events = load_fixture(tests / polarity / f"{path.stem}.ndjson")
                matched = count_matches(ruleset, rule, events)
            except FixtureError as exc:
                result.errors.append(str(exc))
                continue
            except Exception as exc:  # report, never crash the whole run
                result.errors.append(f"query failed: {type(exc).__name__}: {exc}")
                continue
            if polarity == "positive":
                result.positive_total, result.positive_matched = len(events), matched
            else:
                result.negative_total, result.negative_matched = len(events), matched
    return results


def result_records(
    results: list[RuleTestResult], run_id: str | None = None
) -> list[dict[str, Any]]:
    """Rows for the ``rule_tests`` table."""
    run_id = run_id or str(uuid.uuid4())
    now = datetime.now(UTC)
    return [
        {
            "run.id": run_id,
            "run.at": now,
            "rule.id": r.rule.id if r.rule else None,
            "rule.name": r.name,
            "rule.title": r.rule.title if r.rule else None,
            "rule.kind": None
            if r.rule is None
            else ("correlation" if r.is_correlation else "detection"),
            "rule.digest": r.digest,
            "threat.technique.id": list(r.rule.techniques) if r.rule else [],
            "test.passed": r.passed,
            "test.positive_total": r.positive_total,
            "test.positive_matched": r.positive_matched,
            "test.negative_total": r.negative_total,
            "test.negative_matched": r.negative_matched,
            "test.errors": r.errors,
        }
        for r in results
    ]
