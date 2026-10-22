"""Source health: silent sources, ingestion lag, clock skew, parse failures.

A source is a (sensor, dataset) pair seen in the last ``history``. It is
*silent* when nothing arrived for ``silence``: an agent stopped, a log file
rotated away, or someone switched logging off (ATT&CK T1685). A registered
sensor that has never sent anything is ``never_seen``, or ``waiting`` while it
was registered less than ``silence`` ago.

Lag is ``event.ingested - @timestamp``. Events stamped well in the future
(beyond ``skew``) point at a wrong clock or forged timestamps.
"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from nyctala.engine.alerts import group_key
from nyctala.health.integrity import ChainReport
from nyctala.schema import Alert
from nyctala.schema.alert import LEVEL_SCORES
from nyctala.store import EventStore

SILENT_RULE_ID = str(
    uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/KristinaSabitova/nyctala/health/silent")
)
INTEGRITY_RULE_ID = str(
    uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/KristinaSabitova/nyctala/health/integrity")
)


@dataclass(frozen=True)
class HealthPolicy:
    silence: timedelta = timedelta(minutes=15)
    window: timedelta = timedelta(hours=1)
    history: timedelta = timedelta(hours=24)
    skew: timedelta = timedelta(minutes=5)


@dataclass
class SourceStatus:
    sensor: str
    dataset: str | None
    status: str  # ok | waiting | silent | never_seen
    last_ingested: datetime | None = None
    last_event: datetime | None = None
    events: int = 0
    lag_p50: float | None = None
    lag_p95: float | None = None
    lag_max: float | None = None
    future: int = 0
    unparsed: int = 0

    def to_record(self, at: datetime) -> dict[str, Any]:
        return {
            "check.at": at,
            "sensor.id": self.sensor,
            "event.dataset": self.dataset,
            "source.status": self.status,
            "source.last_ingested": self.last_ingested,
            "source.last_event": self.last_event,
            "source.events": self.events,
            "lag.p50": self.lag_p50,
            "lag.p95": self.lag_p95,
            "lag.max": self.lag_max,
            "source.future_events": self.future,
            "source.unparsed": self.unparsed,
        }


def source_health(
    store: EventStore,
    sensors: list[str],
    now: datetime,
    policy: HealthPolicy | None = None,
    registered: dict[str, datetime] | None = None,
) -> list[SourceStatus]:
    """Status of every source of the given (active) sensors.

    ``registered``: when each sensor was added, to give new sensors time to start.
    """
    policy = policy or HealthPolicy()
    window_start = now - policy.window
    rows = store.query(
        """
        WITH e AS (
            SELECT "sensor.id" AS sensor, "event.dataset" AS dataset, "event.ingested" AS ingested,
                   "@timestamp" AS ts, epoch("event.ingested") - epoch("@timestamp") AS lag,
                   list_contains(tags, 'nyctala.unparsed') AS unparsed
            FROM events
            WHERE list_contains(?, "sensor.id") AND "event.ingested" > ? AND "event.ingested" <= ?
              AND dt >= ?
        )
        SELECT sensor, dataset, max(ingested) AS last_ingested, max(ts) AS last_event,
               count(*) FILTER (WHERE ingested > ?) AS events,
               quantile_cont(lag, 0.5) FILTER (WHERE ingested > ?) AS p50,
               quantile_cont(lag, 0.95) FILTER (WHERE ingested > ?) AS p95,
               max(lag) FILTER (WHERE ingested > ?) AS lag_max,
               count(*) FILTER (WHERE ingested > ? AND lag < ?) AS future,
               count(*) FILTER (WHERE ingested > ? AND unparsed) AS unparsed
        FROM e GROUP BY sensor, dataset ORDER BY sensor, dataset
        """,
        [
            sensors,
            now - policy.history,
            now,
            (now - policy.history - timedelta(days=1)).date(),
            *[window_start] * 5,
            -policy.skew.total_seconds(),
            window_start,
        ],
    )
    statuses = []
    for r in rows:
        last = r["last_ingested"].astimezone(UTC)
        statuses.append(
            SourceStatus(
                sensor=r["sensor"],
                dataset=r["dataset"],
                status="silent" if now - last > policy.silence else "ok",
                last_ingested=last,
                last_event=r["last_event"].astimezone(UTC),
                events=r["events"],
                lag_p50=r["p50"],
                lag_p95=r["p95"],
                lag_max=r["lag_max"],
                future=r["future"],
                unparsed=r["unparsed"],
            )
        )
    seen = {s.sensor for s in statuses}
    for sensor in sorted(set(sensors) - seen):
        last = store.query(
            'SELECT max("event.ingested") AS t FROM events WHERE "sensor.id" = ?', [sensor]
        )[0]["t"]
        if last is not None:
            status = "silent"
        elif registered and sensor in registered and now - registered[sensor] < policy.silence:
            status = "waiting"
        else:
            status = "never_seen"
        statuses.append(SourceStatus(sensor, None, status, last.astimezone(UTC) if last else None))
    return statuses


def _existing(store: EventStore, rule_id: str, group: str, since: datetime) -> bool:
    rows = store.query(
        'SELECT count(*) AS n FROM alerts WHERE "rule.id" = ? AND "alert.group" = ? '
        'AND "alert.last" >= ?',
        [rule_id, group, since],
    )
    return bool(rows[0]["n"])


def silent_alerts(
    store: EventStore, statuses: list[SourceStatus], now: datetime, policy: HealthPolicy
) -> list[Alert]:
    """One alert per silence episode of each source."""
    alerts = []
    for s in statuses:
        if s.status in ("ok", "waiting"):
            continue
        source = f"{s.sensor}/{s.dataset or '*'}"
        group = group_key({"sensor": s.sensor, "dataset": s.dataset or "*"})
        since = s.last_ingested or now - policy.history
        if _existing(store, SILENT_RULE_ID, group, since):
            continue
        if s.last_ingested is None:
            what = "has never sent any event"
        else:
            minutes = int((now - s.last_ingested).total_seconds() // 60)
            last = f"{s.last_ingested:%Y-%m-%d %H:%M:%S}"
            what = f"sent nothing for {minutes} min (last event ingested {last} UTC)"
        alerts.append(
            Alert.model_validate(
                {
                    "alert.kind": "health",
                    "rule.id": SILENT_RULE_ID,
                    "rule.name": "source_silent",
                    "rule.title": f"Log source silent: {source}",
                    "rule.level": "medium",
                    "threat.technique.id": ["T1685"],
                    "alert.first": s.last_ingested or now,
                    "alert.last": now,
                    "alert.group": group,
                    "alert.entities": [f"sensor:{s.sensor}"],
                    "risk.score": LEVEL_SCORES["medium"],
                    "risk.accumulated": LEVEL_SCORES["medium"],
                    "alert.explanation": (
                        f"{source} {what}. The agent may have stopped or logging may have "
                        "been disabled on the host."
                    ),
                }
            )
        )
    return alerts


def integrity_alerts(store: EventStore, reports: list[ChainReport], now: datetime) -> list[Alert]:
    """One alert per distinct integrity failure of each sensor's chain."""
    alerts = []
    for report in reports:
        if report.ok:
            continue
        evidence = sorted(
            report.tampered + report.missing_links + report.forks + report.anchor_missing
        )
        signature = hashlib.sha256("\n".join(evidence).encode()).hexdigest()[:16]
        group = group_key({"sensor": report.sensor, "signature": signature})
        if _existing(store, INTEGRITY_RULE_ID, group, datetime.min.replace(tzinfo=UTC)):
            continue
        alerts.append(
            Alert.model_validate(
                {
                    "alert.kind": "health",
                    "rule.id": INTEGRITY_RULE_ID,
                    "rule.name": "integrity_broken",
                    "rule.title": f"Event hash chain broken for sensor {report.sensor}",
                    "rule.level": "critical",
                    "threat.technique.id": ["T1565.001", "T1070"],
                    "alert.first": now,
                    "alert.last": now,
                    "alert.group": group,
                    "alert.event_ids": report.tampered[:1000],
                    "alert.entities": [f"sensor:{report.sensor}"],
                    "risk.score": LEVEL_SCORES["critical"],
                    "risk.accumulated": LEVEL_SCORES["critical"],
                    "alert.explanation": (
                        f"Stored events of {report.sensor} do not match their hash chain: "
                        f"{'; '.join(report.problems())}. Stored data was modified or deleted."
                    ),
                }
            )
        )
    return alerts
