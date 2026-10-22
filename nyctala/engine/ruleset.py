"""Loading a rules directory and evaluating it against the event store.

One rule per ``*.yml`` file. Correlation rules reference other rules by
``name`` or ``id``; references are resolved across the whole directory. A file
that fails to load or compile is reported on its own and does not stop the
others (except the correlations that depend on it).

Which rules raise alerts on their own:

* correlation rules always do;
* a base rule does unless its level is ``informational`` (a building block),
  or every correlation referencing it has ``generate: false`` (Sigma default).
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from nyctala.engine.correlation import Correlation, Hit, compile_correlation
from nyctala.engine.sigma import Rule, RuleError, compile_rule, load_sigma_file
from nyctala.store import EventStore

AnyRule = Rule | Correlation


@dataclass
class RuleSet:
    rules: dict[str, AnyRule] = field(default_factory=dict)
    paths: dict[str, Path] = field(default_factory=dict)
    errors: dict[Path, str] = field(default_factory=dict)

    def by_path(self, path: Path) -> AnyRule | None:
        return next((self.rules[i] for i, p in self.paths.items() if p == path), None)

    def referrers(self, rule_id: str) -> list[Correlation]:
        return [r for r in self.rules.values() if isinstance(r, Correlation) and rule_id in r.rules]

    def alerting(self) -> list[AnyRule]:
        out: list[AnyRule] = []
        for rule in self.rules.values():
            if isinstance(rule, Correlation):
                out.append(rule)
                continue
            referrers = self.referrers(rule.id)
            if rule.level != "informational" and (
                not referrers or any(c.generate for c in referrers)
            ):
                out.append(rule)
        return out

    def lookback(self, rule_id: str) -> timedelta:
        """How far back events must be read to evaluate ``rule_id`` completely."""
        rule = self.rules[rule_id]
        if isinstance(rule, Rule):
            return timedelta(0)
        return rule.timespan + max((self.lookback(r) for r in rule.rules), default=timedelta(0))

    def _fields(self, rule_id: str) -> list[str]:
        needed: set[str] = set()
        for corr in self.referrers(rule_id):
            needed.update(corr.group_by)
            if corr.value_field:
                needed.add(corr.value_field)
        return sorted(needed)

    def evaluate(
        self,
        store: EventStore,
        targets: Iterable[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> dict[str, list[Hit]]:
        """Hits of ``targets`` (default: every rule) on events in [start, end]."""
        memo: dict[str, list[Hit]] = {}

        def hits(rule_id: str) -> list[Hit]:
            if rule_id not in memo:
                rule = self.rules[rule_id]
                if isinstance(rule, Rule):
                    memo[rule_id] = fetch_hits(store, rule, self._fields(rule_id), start, end)
                else:
                    memo[rule_id] = rule.evaluate({r: hits(r) for r in rule.rules})
            return memo[rule_id]

        return {rule_id: hits(rule_id) for rule_id in (targets or self.rules)}


def fetch_hits(
    store: EventStore,
    rule: Rule,
    fields: list[str],
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[Hit]:
    sql, params = rule.query(fields)
    if start is not None:
        # Partitions are by ingestion day, which is never before the event's own day
        # for sane clocks; one day of margin covers skew.
        sql += ' AND "@timestamp" >= ? AND dt >= ?'
        params += [start, (start - timedelta(days=1)).date()]
    if end is not None:
        sql += ' AND "@timestamp" <= ?'
        params.append(end)
    sql += ' ORDER BY "@timestamp"'
    rows = store.query(sql, params)
    return [
        Hit(rule.id, row["ts"], row["ts"], (row["id"],), {f: row[f] for f in fields})
        for row in rows
    ]


def _has_cycle(rules: dict[str, AnyRule]) -> set[str]:
    cyclic: set[str] = set()

    def visit(rule_id: str, path: tuple[str, ...]) -> None:
        if rule_id in path:
            cyclic.update(path[path.index(rule_id) :])
            return
        rule = rules.get(rule_id)
        if isinstance(rule, Correlation):
            for ref in rule.rules:
                visit(ref, (*path, rule_id))

    for rule_id in rules:
        visit(rule_id, ())
    return cyclic


def load_ruleset(directory: Path) -> RuleSet:
    ruleset = RuleSet()
    loaded: dict[Path, SigmaRule | SigmaCorrelationRule] = {}
    for path in sorted(directory.glob("*.yml")):
        try:
            loaded[path] = load_sigma_file(path)
        except RuleError as exc:
            ruleset.errors[path] = str(exc)
    collection = SigmaCollection(list(loaded.values()), resolve_references=False)

    pending: dict[Path, Any] = {}
    for path, sigma in loaded.items():
        try:
            if isinstance(sigma, SigmaRule):
                compiled: AnyRule = compile_rule(sigma, path)
            else:
                for ref in sigma.rules or []:
                    ref.resolve(collection)
                pending[path] = sigma
                continue
        except (RuleError, SigmaError) as exc:
            ruleset.errors[path] = str(exc)
            continue
        ruleset.rules[compiled.id] = compiled
        ruleset.paths[compiled.id] = path

    for path, sigma in pending.items():
        try:
            corr = compile_correlation(sigma)
        except RuleError as exc:
            ruleset.errors[path] = str(exc)
            continue
        ruleset.rules[corr.id] = corr
        ruleset.paths[corr.id] = path

    # Drop correlations whose references failed to compile (transitively) or loop.
    changed = True
    while changed:
        changed = False
        for rule_id, rule in list(ruleset.rules.items()):
            if isinstance(rule, Correlation) and any(r not in ruleset.rules for r in rule.rules):
                ruleset.errors[ruleset.paths.pop(rule_id)] = "references a rule that failed to load"
                del ruleset.rules[rule_id]
                changed = True
    for rule_id in _has_cycle(ruleset.rules):
        ruleset.errors[ruleset.paths.pop(rule_id)] = "correlation references form a cycle"
        del ruleset.rules[rule_id]
    return ruleset
