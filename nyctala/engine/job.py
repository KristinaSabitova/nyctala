"""Periodic detection job.

Every ``interval`` seconds the alerting rules are evaluated over a sliding
window of event time: the longest correlation chain plus an allowance for
ingestion lag. Consecutive runs see overlapping windows, so a hit is reported
only if it shares no event with a hit already reported for the same rule and
group: the same evidence never alerts twice.
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from nyctala.engine.correlation import Hit
from nyctala.engine.ruleset import RuleSet
from nyctala.store import EventStore

log = logging.getLogger(__name__)

Sink = Callable[[list[Hit]], None]


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Reported:
    event_ids: set[str]
    last: datetime


@dataclass
class DetectionJob:
    store: EventStore
    ruleset: RuleSet
    sink: Sink
    interval: float = 10.0
    lag: timedelta = timedelta(minutes=5)
    clock: Callable[[], datetime] = _now
    _reported: dict[tuple[str, tuple[Any, ...]], list[_Reported]] = field(default_factory=dict)

    @property
    def window(self) -> timedelta:
        targets = [r.id for r in self.ruleset.alerting()]
        longest = max((self.ruleset.lookback(t) for t in targets), default=timedelta(0))
        return longest + self.lag

    def run_once(self) -> list[Hit]:
        now = self.clock()
        window = self.window
        targets = [r.id for r in self.ruleset.alerting()]
        results = self.ruleset.evaluate(self.store, targets, start=now - window, end=now)
        new: list[Hit] = []
        for rule_id in targets:
            for hit in results[rule_id]:
                key = (rule_id, tuple(sorted(hit.fields.items())))
                seen = self._reported.setdefault(key, [])
                if any(r.event_ids.intersection(hit.event_ids) for r in seen):
                    continue
                seen.append(_Reported(set(hit.event_ids), hit.last))
                new.append(hit)
        self._forget(now - 2 * window)
        if new:
            self.sink(sorted(new, key=lambda h: h.last))
        return new

    def _forget(self, before: datetime) -> None:
        for key in list(self._reported):
            kept = [r for r in self._reported[key] if r.last >= before]
            if kept:
                self._reported[key] = kept
            else:
                del self._reported[key]

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.run_once()
            except Exception:  # keep detecting; one bad run must not stop the job
                log.exception("detection run failed")
            stop.wait(self.interval)
