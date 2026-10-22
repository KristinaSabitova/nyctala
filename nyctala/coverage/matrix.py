"""ATT&CK coverage measured from rule tests, not declared by rule tags.

A technique counts as covered only when a rule tagged with it passed its tests,
and (for recorded runs) the rule and its fixtures are still byte-for-byte what
was tested. Everything else a rule claims is listed apart and not counted:

* ``failing``: the rule's last test did not pass;
* ``stale``: the rule or its fixtures changed since they were tested;
* ``unknown``: the tag is not a Linux technique in the bundled ATT&CK data.

The ATT&CK data is a Linux-only extract bundled with the package (offline).
"""

import json
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"


@dataclass(frozen=True)
class Attack:
    version: str
    tactics: list[dict[str, str]]
    techniques: dict[str, dict[str, Any]]
    notice: str

    def parent(self, technique: str) -> str:
        return technique.split(".", 1)[0]


@cache
def load_attack() -> Attack:
    raw = json.loads(resources.files("nyctala.coverage").joinpath("attack_linux.json").read_text())
    return Attack(raw["attack_version"], raw["tactics"], raw["techniques"], raw["notice"])


@dataclass(frozen=True)
class RuleRecord:
    """One rule's latest test result, as coverage needs it."""

    name: str
    techniques: tuple[str, ...]
    passed: bool
    digest: str


@dataclass
class Coverage:
    attack: Attack
    covered: dict[str, list[str]] = field(default_factory=dict)  # technique -> rules
    failing: dict[str, list[str]] = field(default_factory=dict)
    stale: dict[str, list[str]] = field(default_factory=dict)
    unknown: dict[str, list[str]] = field(default_factory=dict)
    rules_total: int = 0
    rules_passed: int = 0

    def by_tactic(self) -> list[tuple[dict[str, str], int, list[str]]]:
        """(tactic, techniques in tactic, covered techniques in tactic), in matrix order."""
        totals: dict[str, int] = defaultdict(int)
        covered: dict[str, list[str]] = defaultdict(list)
        for tid, info in self.attack.techniques.items():
            for tactic in info["tactics"]:
                totals[tactic] += 1
                if tid in self.covered:
                    covered[tactic].append(tid)
        return [(t, totals[t["shortname"]], covered[t["shortname"]]) for t in self.attack.tactics]

    def to_json(self) -> dict[str, Any]:
        return {
            "attack_version": self.attack.version,
            "platform": "Linux",
            "rules": {"total": self.rules_total, "passed": self.rules_passed},
            "covered": {
                tid: {
                    "name": self.attack.techniques[tid]["name"],
                    "tactics": self.attack.techniques[tid]["tactics"],
                    "rules": rules,
                }
                for tid, rules in sorted(self.covered.items())
            },
            "not_counted": {
                "failing": self.failing,
                "stale": self.stale,
                "unknown": self.unknown,
            },
            "techniques_total": len(self.attack.techniques),
        }

    def to_navigator(self) -> dict[str, Any]:
        """An ATT&CK Navigator layer: score = number of passing rules per technique."""
        top = max((len(r) for r in self.covered.values()), default=1)
        return {
            "name": "nyctala measured coverage",
            "versions": {
                "attack": self.attack.version.split(".")[0],
                "navigator": NAVIGATOR_VERSION,
                "layer": LAYER_VERSION,
            },
            "domain": "enterprise-attack",
            "description": "Techniques with at least one nyctala rule whose tests pass.",
            "filters": {"platforms": ["Linux"]},
            "gradient": {"colors": ["#c6e2ff", "#1f6fb2"], "minValue": 0, "maxValue": top},
            "techniques": [
                {
                    "techniqueID": tid,
                    "score": len(rules),
                    "comment": "rules: " + ", ".join(rules),
                    "enabled": True,
                }
                for tid, rules in sorted(self.covered.items())
            ],
        }


def measure(records: list[RuleRecord], current_digests: dict[str, str] | None = None) -> Coverage:
    """Coverage from rule test records.

    ``current_digests`` (rule name -> digest of the files now on disk) marks
    records of rules that changed, or no longer exist, as stale.
    """
    attack = load_attack()
    cov = Coverage(attack, rules_total=len(records))
    for record in records:
        stale = current_digests is not None and current_digests.get(record.name) != record.digest
        if record.passed and not stale:
            cov.rules_passed += 1
        for tid in record.techniques:
            if tid not in attack.techniques:
                bucket = cov.unknown
            elif stale:
                bucket = cov.stale
            elif record.passed:
                bucket = cov.covered
            else:
                bucket = cov.failing
            bucket.setdefault(tid, []).append(record.name)
    # A technique covered by one rule is not "failing" because another rule fails.
    for tid in cov.covered:
        cov.failing.pop(tid, None)
        cov.stale.pop(tid, None)
    return cov


def current_digests(rules_dir: Path) -> dict[str, str]:
    from nyctala.engine.testing import rule_digest

    return {path.stem: rule_digest(path) for path in sorted(rules_dir.glob("*.yml"))}
