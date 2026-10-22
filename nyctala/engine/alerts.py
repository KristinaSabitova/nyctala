"""Alerts, entity risk and incidents.

Every hit of an alerting rule becomes an :class:`Alert` that explains itself:
rule, ATT&CK techniques, contributing events, entities and the risk those
entities had accumulated when it fired.

Risk is scored per entity (user, host, source IP): each alert adds its level's
score to every entity it involves, over a sliding window. When an entity's risk
crosses the threshold through alerts of at least two different rules, a risk
alert is raised for the entity as a whole, even if no single alert was severe.

Incidents group alerts that share a user or IP within a day, or a host within an
hour (hosts are shared by unrelated activity, so they link only alerts close in
time). Risk and incidents are derived from the alert table, never stored.
"""

import json
import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import pairwise
from typing import Any

from nyctala.engine.correlation import Correlation, Hit
from nyctala.engine.ruleset import RuleSet
from nyctala.schema import Alert
from nyctala.schema.alert import LEVEL_SCORES
from nyctala.store import EventStore

# Event field -> entity kind. user.target.name is left out on purpose: "root" is
# the target of nearly everything and would chain unrelated activity together.
ENTITY_FIELDS = {"user.name": "user", "host.name": "host", "source.ip": "ip"}
RISK_RULE_ID = str(
    uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/KristinaSabitova/nyctala/risk")
)
LEVELS = list(LEVEL_SCORES)
MAX_RISK_EVENT_IDS = 1_000


@dataclass(frozen=True)
class RiskPolicy:
    window: timedelta = timedelta(hours=24)
    threshold: int = 100
    min_rules: int = 2


@dataclass
class _Scored:
    """What risk accounting needs from an alert."""

    alert_id: str
    rule_id: str
    kind: str
    last: datetime
    score: int
    entities: list[str]
    techniques: list[str]
    event_ids: list[str]
    risk_entity: str | None = None


def group_key(fields: dict[str, Any]) -> str:
    return json.dumps(dict(sorted(fields.items())), default=str, ensure_ascii=False)


def _risk_level(score: int, policy: RiskPolicy) -> str:
    return "critical" if score >= 2 * policy.threshold else "high"


@dataclass
class AlertManager:
    store: EventStore
    ruleset: RuleSet
    policy: RiskPolicy = field(default_factory=RiskPolicy)

    def _events(self, ids: Sequence[str]) -> list[dict[str, Any]]:
        columns = ", ".join(f'"{f}"' for f in ENTITY_FIELDS)
        return self.store.query(
            f'SELECT {columns} FROM events WHERE list_contains(?, "event.id")',  # noqa: S608
            [list(ids)],
        )

    def _history(self, entities: set[str], start: datetime, end: datetime) -> list[_Scored]:
        if not entities:
            return []
        rows = self.store.query(
            'SELECT * FROM alerts WHERE "alert.last" > ? AND "alert.last" <= ? '
            'AND len(list_intersect("alert.entities", ?)) > 0',
            [start, end, sorted(entities)],
        )
        return [
            _Scored(
                r["alert.id"],
                r["rule.id"],
                r["alert.kind"],
                r["alert.last"],
                r["risk.score"],
                r["alert.entities"],
                r["threat.technique.id"],
                r["alert.event_ids"],
                r["risk.entity"],
            )
            for r in rows
        ]

    def handle(self, hits: Iterable[Hit]) -> list[Alert]:
        """Turn hits into alerts (plus any risk alerts), store and return them."""
        drafts = []
        for hit in hits:
            rule = self.ruleset.rules[hit.rule_id]
            rows = self._events(hit.event_ids)
            entities = sorted(
                {f"{kind}:{row[f]}" for row in rows for f, kind in ENTITY_FIELDS.items() if row[f]}
            )
            drafts.append((hit, rule, entities))
        if not drafts:
            return []

        touched = {e for _, _, entities in drafts for e in entities}
        start = min(h.last for h, _, _ in drafts) - self.policy.window
        end = max(h.last for h, _, _ in drafts)
        scored = self._history(touched, start, end)

        alerts: list[Alert] = []
        for hit, rule, entities in sorted(drafts, key=lambda d: d[0].last):
            score = LEVEL_SCORES.get(rule.level, 0)
            alert_id = str(uuid.uuid4())
            current = _Scored(
                alert_id,
                rule.id,
                "correlation" if isinstance(rule, Correlation) else "detection",
                hit.last,
                score,
                entities,
                list(rule.techniques),
                list(hit.event_ids),
            )
            scored.append(current)
            risks = {e: self._risk(scored, e, hit.last) for e in entities}
            accumulated = max((r[0] for r in risks.values()), default=0)
            alert = Alert.model_validate(
                {
                    "alert.id": alert_id,
                    "alert.kind": current.kind,
                    "rule.id": rule.id,
                    "rule.name": rule.name,
                    "rule.title": rule.title,
                    "rule.level": rule.level,
                    "threat.technique.id": list(rule.techniques),
                    "alert.first": hit.first,
                    "alert.last": hit.last,
                    "alert.group": group_key(dict(hit.fields)),
                    "alert.event_ids": list(hit.event_ids),
                    "alert.entities": entities,
                    "risk.score": score,
                    "risk.accumulated": accumulated,
                    "alert.explanation": _explain(rule.title, hit, entities, risks, self.policy),
                }
            )
            alerts.append(alert)
            for entity, (risk, contributors) in risks.items():
                risk_alert = self._risk_alert(scored, entity, risk, contributors, hit.last)
                if risk_alert is not None:
                    alerts.append(risk_alert)
                    scored.append(
                        _Scored(
                            risk_alert.alert_id,
                            RISK_RULE_ID,
                            "risk",
                            hit.last,
                            0,
                            [entity],
                            [],
                            [],
                            entity,
                        )
                    )
        self.store.append_alerts(alerts)
        return alerts

    def _risk(self, scored: list[_Scored], entity: str, at: datetime) -> tuple[int, list[_Scored]]:
        contributors = [
            s
            for s in scored
            if s.kind != "risk" and entity in s.entities and at - self.policy.window < s.last <= at
        ]
        return sum(s.score for s in contributors), contributors

    def _risk_alert(
        self,
        scored: list[_Scored],
        entity: str,
        risk: int,
        contributors: list[_Scored],
        at: datetime,
    ) -> Alert | None:
        if risk < self.policy.threshold:
            return None
        if len({c.rule_id for c in contributors}) < self.policy.min_rules:
            return None
        already = any(
            s.kind == "risk" and s.risk_entity == entity and at - self.policy.window < s.last <= at
            for s in scored
        )
        if already:
            return None
        techniques = sorted({t for c in contributors for t in c.techniques})
        event_ids = list(dict.fromkeys(i for c in contributors for i in c.event_ids))
        rules = len({c.rule_id for c in contributors})
        hours = int(self.policy.window.total_seconds() // 3600)
        return Alert.model_validate(
            {
                "alert.kind": "risk",
                "rule.id": RISK_RULE_ID,
                "rule.name": "entity_risk",
                "rule.title": f"Accumulated risk for {entity}",
                "rule.level": _risk_level(risk, self.policy),
                "threat.technique.id": techniques,
                "alert.first": min(c.last for c in contributors),
                "alert.last": at,
                "alert.group": group_key({"entity": entity}),
                "alert.event_ids": event_ids[:MAX_RISK_EVENT_IDS],
                "related.alert_ids": [c.alert_id for c in contributors],
                "alert.entities": [entity],
                "risk.score": 0,
                "risk.accumulated": risk,
                "risk.entity": entity,
                "alert.explanation": (
                    f"{entity} accumulated risk {risk} (threshold {self.policy.threshold}) "
                    f"from {len(contributors)} alerts of {rules} rules in {hours}h. "
                    f"ATT&CK: {', '.join(techniques) or '-'}."
                ),
            }
        )


def _explain(
    title: str,
    hit: Hit,
    entities: list[str],
    risks: dict[str, tuple[int, list[_Scored]]],
    policy: RiskPolicy,
) -> str:
    span = hit.last - hit.first
    parts = [f"{title}: {len(hit.event_ids)} event(s)"]
    if span:
        parts.append(f"over {span}")
    if hit.fields:
        parts.append("for " + ", ".join(f"{k}={v}" for k, v in sorted(hit.fields.items())))
    text = " ".join(parts) + "."
    if entities:
        hours = int(policy.window.total_seconds() // 3600)
        risk = ", ".join(f"{e}={risks[e][0]}" for e in entities)
        text += f" Entity risk ({hours}h): {risk}."
    return text


# --- read side ---------------------------------------------------------------------


@dataclass
class EntityRisk:
    entity: str
    score: int
    alerts: int
    rules: int
    last: datetime


def entity_risk(store: EventStore, at: datetime, window: timedelta) -> list[EntityRisk]:
    rows = store.query(
        """
        SELECT entity, sum("risk.score")::INTEGER AS score, count(*) AS alerts,
               count(DISTINCT "rule.id") AS rules, max("alert.last") AS last
        FROM (SELECT unnest("alert.entities") AS entity, * FROM alerts
              WHERE "alert.kind" != 'risk' AND "alert.last" > ? AND "alert.last" <= ?)
        GROUP BY entity ORDER BY score DESC, entity
        """,
        [at - window, at],
    )
    return [EntityRisk(r["entity"], r["score"], r["alerts"], r["rules"], r["last"]) for r in rows]


@dataclass
class Incident:
    id: str
    alerts: list[Alert]

    @property
    def first(self) -> datetime:
        return min(a.first for a in self.alerts)

    @property
    def last(self) -> datetime:
        return max(a.last for a in self.alerts)

    @property
    def entities(self) -> list[str]:
        return sorted({e for a in self.alerts for e in a.entities})

    @property
    def techniques(self) -> list[str]:
        return sorted({t for a in self.alerts for t in a.techniques})

    @property
    def risk(self) -> int:
        return sum(a.risk_score for a in self.alerts)

    @property
    def level(self) -> str:
        return max((a.rule_level for a in self.alerts), key=_level_rank)


def _level_rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else -1


LINK_GAPS = {"user": timedelta(hours=24), "ip": timedelta(hours=24), "host": timedelta(hours=1)}


def load_alerts(store: EventStore, start: datetime, end: datetime) -> list[Alert]:
    rows = store.query(
        'SELECT * EXCLUDE (dt) FROM alerts WHERE "alert.last" > ? AND "alert.last" <= ? '
        'ORDER BY "alert.last", "alert.id"',
        [start, end],
    )
    return [Alert.model_validate(row) for row in rows]


def incidents(store: EventStore, start: datetime, end: datetime) -> list[Incident]:
    alerts = load_alerts(store, start, end)
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    by_entity: dict[str, list[int]] = defaultdict(list)
    for i, alert in enumerate(alerts):
        for entity in alert.entities:
            by_entity[entity].append(i)
    for entity, members in by_entity.items():
        gap = LINK_GAPS.get(entity.split(":", 1)[0], timedelta(0))
        for a, b in pairwise(members):
            if alerts[b].last - alerts[a].last <= gap:
                parent[find(b)] = find(a)

    groups: dict[int, list[Alert]] = defaultdict(list)
    for i, alert in enumerate(alerts):
        groups[find(i)].append(alert)
    found = [Incident(members[0].alert_id, members) for members in groups.values()]
    return sorted(found, key=lambda inc: (-inc.risk, inc.first))
