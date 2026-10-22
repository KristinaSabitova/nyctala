"""Log line parsers, keyed by ``event.dataset``.

A parser turns one raw line into one or more dicts of ECS-lite fields (aliases),
without the server-controlled fields. It never raises on hostile input: lines it
does not understand come back tagged ``nyctala.unparsed``.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from nyctala.parsers import auth_log, nginx

PARSERS: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "auth_log": auth_log.parse,
    "syslog": auth_log.parse,
    "nginx.access": nginx.parse,
}


def parse(dataset: str, line: str, *, received: datetime) -> list[dict[str, Any]]:
    """Parse ``line`` with the parser registered for ``dataset``."""
    events = PARSERS[dataset](line, received=received)
    return [{**e, "event.dataset": dataset} for e in events]
