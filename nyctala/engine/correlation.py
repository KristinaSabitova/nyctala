"""Sigma correlation rules: thresholds and sequences over rule matches.

Supported types (Sigma correlation specification v2):

* ``event_count``: at least N matches per group within the timespan;
* ``value_count``: at least N distinct values of a field per group;
* ``temporal``: every referenced rule matched per group within the timespan;
* ``temporal_ordered``: same, in the given order.

Correlations can reference other correlations. SQL fetches the matches of each
base rule in the time window; grouping and windowing happen here, on those
matches only. Matches with a missing group-by value are ignored rather than
lumped together. Once a correlation fires, the hits it used are consumed, so a
burst produces one hit, not one per event.
"""

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)

from nyctala.engine.sigma import FIELDS, RuleError, _techniques

_THRESHOLD_OPS: dict[SigmaCorrelationConditionOperator, Callable[[int, int], bool]] = {
    SigmaCorrelationConditionOperator.GTE: lambda n, limit: n >= limit,
    SigmaCorrelationConditionOperator.GT: lambda n, limit: n > limit,
}
TYPES = {
    SigmaCorrelationType.EVENT_COUNT: "event_count",
    SigmaCorrelationType.VALUE_COUNT: "value_count",
    SigmaCorrelationType.TEMPORAL: "temporal",
    SigmaCorrelationType.TEMPORAL_ORDERED: "temporal_ordered",
}


@dataclass(frozen=True)
class Hit:
    """A match of a rule: one event for a base rule, a firing for a correlation."""

    rule_id: str
    first: datetime
    last: datetime
    event_ids: tuple[str, ...]
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Correlation:
    id: str
    name: str | None
    title: str
    level: str
    techniques: tuple[str, ...]
    type: str
    rules: tuple[str, ...]  # ids of the referenced rules, in order
    group_by: tuple[str, ...]
    timespan: timedelta
    generate: bool
    threshold: int = 0
    op: SigmaCorrelationConditionOperator = SigmaCorrelationConditionOperator.GTE
    value_field: str | None = None

    def evaluate(self, hits: Mapping[str, Sequence[Hit]]) -> list[Hit]:
        """Correlate ``hits`` (by referenced rule id) into hits of this rule."""
        groups: dict[tuple[Any, ...], list[tuple[int, Hit]]] = defaultdict(list)
        for index, rule_id in enumerate(self.rules):
            for hit in hits.get(rule_id, ()):
                key = tuple(hit.fields.get(f) for f in self.group_by)
                if None not in key:
                    groups[key].append((index, hit))
        out: list[Hit] = []
        for key, members in groups.items():
            members.sort(key=lambda m: (m[1].last, m[0]))
            group = dict(zip(self.group_by, key, strict=True))
            if self.type in ("event_count", "value_count"):
                out.extend(self._threshold(group, [h for _, h in members]))
            else:
                out.extend(self._temporal(group, members))
        return sorted(out, key=lambda h: h.last)

    def _fire(self, group: dict[str, Any], used: Sequence[Hit]) -> Hit:
        ids = tuple(dict.fromkeys(i for h in used for i in h.event_ids))
        return Hit(self.id, min(h.first for h in used), max(h.last for h in used), ids, group)

    def _threshold(self, group: dict[str, Any], hits: list[Hit]) -> list[Hit]:
        fired: list[Hit] = []
        window: list[Hit] = []
        check = _THRESHOLD_OPS[self.op]
        for hit in hits:
            window = [h for h in window if hit.last - h.last <= self.timespan]
            window.append(hit)
            if self.value_field is None:
                measure = len(window)
            else:
                measure = len({h.fields.get(self.value_field) for h in window} - {None})
            if check(measure, self.threshold):
                fired.append(self._fire(group, window))
                window = []
        return fired

    def _temporal(self, group: dict[str, Any], members: list[tuple[int, Hit]]) -> list[Hit]:
        steps = len(self.rules)
        fired: list[Hit] = []
        if self.type == "temporal_ordered":
            # progress[k]: the latest-starting chain that has completed steps 0..k.
            progress: list[list[Hit] | None] = [None] * steps
            for index, hit in members:
                if index > 0:
                    chain = progress[index - 1]
                    if chain is not None and hit.last - chain[0].first <= self.timespan:
                        progress[index] = [*chain, hit]
                else:
                    progress[0] = [hit]
                done = progress[steps - 1]
                if done is not None:
                    fired.append(self._fire(group, done))
                    progress = [None] * steps
        else:
            latest: dict[int, Hit] = {}
            for index, hit in members:
                latest[index] = hit
                latest = {i: h for i, h in latest.items() if hit.last - h.first <= self.timespan}
                if len(latest) == steps:
                    fired.append(self._fire(group, list(latest.values())))
                    latest = {}
        return fired


def compile_correlation(sigma: SigmaCorrelationRule) -> Correlation:
    if sigma.id is None:
        raise RuleError("rule has no id")
    if sigma.type not in TYPES:
        raise RuleError(f"unsupported correlation type: {sigma.type}")
    if sigma.aliases and sigma.aliases.aliases:
        raise RuleError("correlation aliases are not supported")
    group_by = tuple(sigma.group_by or ())
    for name in group_by:
        if name not in FIELDS:
            raise RuleError(f"unknown group-by field: {name!r}")
    rule_ids = []
    for ref in sigma.rules or []:
        if ref.rule is None or ref.rule.id is None:
            raise RuleError(f"unresolved rule reference: {ref.reference!r}")
        rule_ids.append(str(ref.rule.id))
    kind = TYPES[sigma.type]
    threshold, op, value_field = 0, SigmaCorrelationConditionOperator.GTE, None
    if kind in ("event_count", "value_count"):
        cond = sigma.condition
        if not isinstance(cond, SigmaCorrelationCondition) or cond.op not in _THRESHOLD_OPS:
            raise RuleError("threshold correlations need a single gt or gte condition")
        threshold, op = int(cond.count), cond.op
        if kind == "value_count":
            value_field = cond.fieldref if isinstance(cond.fieldref, str) else None
            if value_field not in FIELDS:
                raise RuleError(f"unknown value_count field: {value_field!r}")
    elif len(set(rule_ids)) != len(rule_ids):
        raise RuleError("temporal correlations cannot reference the same rule twice")
    tags = tuple(str(t) for t in sigma.tags)
    return Correlation(
        id=str(sigma.id),
        name=sigma.name,
        title=sigma.title,
        level=str(sigma.level.name).lower() if sigma.level else "",
        techniques=_techniques(tags),
        type=kind,
        rules=tuple(rule_ids),
        group_by=group_by,
        timespan=timedelta(seconds=sigma.timespan.seconds),
        generate=bool(sigma.generate),
        threshold=threshold,
        op=op,
        value_field=value_field,
    )
