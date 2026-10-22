"""Synthetic attack scenarios: replay them and check which rules alert.

A scenario is a YAML file of log lines with relative times and the exact set of
rules expected to alert::

    name: ssh_intrusion
    expect: [ssh_bruteforce, ssh_bruteforce_success]
    events:
      - {at: 0, dataset: auth_log, repeat: 6, every: 3,
         line: "{syslog} vps-a sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"}

Placeholders ``{syslog}``, ``{nginx}`` and ``{iso}`` become the event time in
the matching format; nothing else in the line is interpreted.

The lab only produces synthetic data: every IP address in a scenario must
belong to a documentation range (RFC 5737 / RFC 3849) or loopback, so a
scenario can never point at, or impersonate, a real host. Replay sends lines
only to a nyctala ingest endpoint or to a throwaway local store.
"""

import ipaddress
import json
import re
import tempfile
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from nyctala import parsers
from nyctala.engine.alerts import AlertManager
from nyctala.engine.correlation import Hit
from nyctala.engine.job import DetectionJob
from nyctala.engine.ruleset import RuleSet
from nyctala.ingest.lines import parse_line
from nyctala.store import EventStore

SCENARIOS_DIR = Path(str(resources.files("nyctala.lab").joinpath("scenarios")))
LAB_SENSOR = "lab"
SYNTHETIC_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
        "127.0.0.0/8",
        "::1/128",
    )
]
_IPV4 = re.compile(r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9])")
_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")
MAX_EVENTS = 10_000


class ScenarioError(ValueError):
    pass


def _non_synthetic_ips(text: str) -> list[str]:
    """Every IP address in ``text`` outside the synthetic ranges.

    IPv4 is searched anywhere (also inside ``host:8.8.8.8`` or ``::ffff:8.8.8.8``);
    IPv6 candidates are tried as written and with surrounding separators removed.
    """
    found: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for token in _IPV4.findall(text):
        try:
            found.add(ipaddress.IPv4Address(token))
        except ValueError:
            continue
    for token in _IPV6_CANDIDATE.findall(text):
        for variant in {token, token.strip(".:"), token.rstrip(".:"), token.lstrip(".")}:
            try:
                found.add(ipaddress.ip_address(variant))
            except ValueError:
                continue
    return sorted(str(ip) for ip in found if not any(ip in net for net in SYNTHETIC_NETWORKS))


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    at: float = Field(ge=0, le=86_400)
    dataset: str
    line: str = Field(min_length=1, max_length=16_384)
    repeat: int = Field(default=1, ge=1, le=1_000)
    every: float = Field(default=0, ge=0, le=86_400)

    @field_validator("dataset")
    @classmethod
    def _known_dataset(cls, value: str) -> str:
        if value not in parsers.PARSERS:
            raise ValueError(f"unknown dataset {value!r}")
        return value

    @field_validator("line")
    @classmethod
    def _synthetic_only(cls, value: str) -> str:
        if bad := _non_synthetic_ips(value):
            raise ValueError(f"non-synthetic IP address(es): {', '.join(bad)}")
        return value


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    description: str = ""
    expect: list[str] = Field(default_factory=list)
    events: list[Step] = Field(min_length=1)

    @property
    def duration(self) -> timedelta:
        return timedelta(seconds=max(s.at + s.every * (s.repeat - 1) for s in self.events))

    def render(self, base: datetime) -> list[bytes]:
        """NDJSON lines in the ingest raw format, timed from ``base``."""
        timed: list[tuple[datetime, bytes]] = []
        for step in self.events:
            for i in range(step.repeat):
                ts = (base + timedelta(seconds=step.at + i * step.every)).astimezone(UTC)
                line = (
                    step.line.replace("{syslog}", f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}")
                    .replace("{nginx}", f"{ts:%d/%b/%Y:%H:%M:%S} +0000")
                    .replace("{iso}", ts.isoformat())
                )
                record = {
                    "message": line,
                    "event.dataset": step.dataset,
                    "@timestamp": ts.isoformat(),
                }
                timed.append((ts, json.dumps(record).encode()))
        if len(timed) > MAX_EVENTS:
            raise ScenarioError(f"scenario renders {len(timed)} events (max {MAX_EVENTS})")
        return [line for _, line in sorted(timed, key=lambda t: t[0])]


def load_scenario(path: Path) -> Scenario:
    try:
        return Scenario.model_validate(yaml.safe_load(path.read_text()))
    except (yaml.YAMLError, ValueError) as exc:
        raise ScenarioError(f"{path.name}: {exc}") from exc


@cache
def bundled_scenarios() -> list[Path]:
    return sorted(SCENARIOS_DIR.glob("*.yml"))


@dataclass
class LabResult:
    scenario: str
    expected: set[str]
    alerted: set[str] = field(default_factory=set)
    events: int = 0
    rejected: list[str] = field(default_factory=list)

    @property
    def missing(self) -> set[str]:
        return self.expected - self.alerted

    @property
    def unexpected(self) -> set[str]:
        return self.alerted - self.expected

    @property
    def passed(self) -> bool:
        return not self.rejected and not self.missing and not self.unexpected


def run_scenario(scenario: Scenario, ruleset: RuleSet, now: datetime | None = None) -> LabResult:
    """Ingest the scenario into a throwaway store, run detection once, compare."""
    now = now or datetime.now(UTC)
    base = now - scenario.duration - timedelta(minutes=1)
    result = LabResult(scenario.name, set(scenario.expect))
    with tempfile.TemporaryDirectory(prefix="nyctala-lab-") as tmp:
        store = EventStore(Path(tmp))
        try:
            for number, raw in enumerate(scenario.render(base), start=1):
                parsed = parse_line(raw, LAB_SENSOR)
                if isinstance(parsed, str):
                    result.rejected.append(f"event {number}: {parsed}")
                    continue
                store.append(parsed)
                result.events += len(parsed)
            manager = AlertManager(store, ruleset)
            alerted: list[str] = []

            def sink(hits: list[Hit]) -> None:
                alerted.extend(a.rule_name or a.rule_id for a in manager.handle(hits))

            DetectionJob(store, ruleset, sink, clock=lambda: now).run_once()
            result.alerted = set(alerted)
        finally:
            store.close()
    return result


def replay(scenario: Scenario, url: str, token: str, batch: int = 500) -> int:
    """Send the scenario, timed to end now, to a nyctala ingest endpoint."""
    if not url.startswith(("http://", "https://")):
        raise ScenarioError("url must be http(s)")
    now = datetime.now(UTC)
    lines = scenario.render(now - scenario.duration)
    accepted = 0
    for start in range(0, len(lines), batch):
        body = b"\n".join(lines[start : start + batch]) + b"\n"
        request = urllib.request.Request(  # noqa: S310 (scheme checked above)
            url,
            data=body,
            method="POST",
            headers={"content-type": "application/x-ndjson", "authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            accepted += int(json.loads(response.read())["accepted"])
    return accepted
