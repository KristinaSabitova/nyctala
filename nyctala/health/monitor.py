"""Periodic health checks, run from the detection loop.

Every ``interval`` the monitor records a ``source_health`` snapshot and alerts
on silent sources; every ``verify_interval`` it verifies the hash chains
(against the anchors file, if any) and alerts on any damage.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from nyctala.health.integrity import read_anchors, verify
from nyctala.health.sources import HealthPolicy, integrity_alerts, silent_alerts, source_health
from nyctala.ingest.sensors import SensorRegistry
from nyctala.schema import Alert
from nyctala.store import EventStore


@dataclass
class HealthMonitor:
    store: EventStore
    registry: SensorRegistry
    on_alerts: Callable[[list[Alert]], None] = lambda _: None
    policy: HealthPolicy = field(default_factory=HealthPolicy)
    interval: timedelta = timedelta(minutes=1)
    verify_interval: timedelta = timedelta(hours=1)
    anchors: Path | None = None
    _last_check: datetime | None = None
    _last_verify: datetime | None = None

    def active_sensors(self) -> list[str]:
        return sorted(s for s, info in self.registry.list().items() if not info.get("revoked"))

    def tick(self, now: datetime) -> list[Alert]:
        alerts: list[Alert] = []
        if self._last_check is None or now - self._last_check >= self.interval:
            self._last_check = now
            statuses = source_health(self.store, self.active_sensors(), now, self.policy)
            self.store.append_records("source_health", now, [s.to_record(now) for s in statuses])
            alerts += silent_alerts(self.store, statuses, now, self.policy)
        if self._last_verify is None or now - self._last_verify >= self.verify_interval:
            self._last_verify = now
            anchors = None
            if self.anchors is not None and self.anchors.is_file():
                anchors = read_anchors(self.anchors.read_text().splitlines())
            alerts += integrity_alerts(self.store, verify(self.store, anchors), now)
        if alerts:
            self.store.append_alerts(alerts)
            self.on_alerts(alerts)
        return alerts
