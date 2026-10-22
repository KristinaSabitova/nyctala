"""Sigma rules compiled to parameterised DuckDB SQL.

pySigma parses the YAML and the condition; this module walks the resulting
condition tree and emits a ``WHERE`` clause whose values are all bound
parameters. Nothing from a rule or an event is ever spliced into SQL text: the
only identifiers written are field names checked against the event schema.

Semantics follow the Sigma specification:

* strings match case-insensitively (``ILIKE``) unless ``|cased`` is used;
  ``*`` and ``?`` are wildcards, ``contains``/``startswith``/``endswith`` add them;
* ``|re`` uses DuckDB's RE2 engine (linear time, so no ReDoS); flags ``i``,
  ``m`` and ``s`` are supported, backreferences and lookarounds are not;
* ``|cidr`` matches IPv4 and IPv6 networks;
* keywords (values without a field) search ``event.original``;
* a value on the ``tags`` list matches if any tag matches.

Unknown fields and unsupported modifiers are compile errors, so a typo in a
rule fails the rule tests instead of silently never matching.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pyarrow as pa
import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from nyctala.store import EVENT_SCHEMA

KEYWORD_FIELD = "event.original"
LIST_FIELDS = frozenset(f.name for f in EVENT_SCHEMA if pa.types.is_list(f.type))
NUMERIC_FIELDS = frozenset(f.name for f in EVENT_SCHEMA if pa.types.is_integer(f.type))
FIELDS = frozenset(EVENT_SCHEMA.names)

# Sigma logsource -> event.dataset values it covers.
LOGSOURCES: dict[tuple[str | None, str | None, str | None], tuple[str, ...]] = {
    # (category, product, service)
    (None, "linux", "auth"): ("auth_log", "syslog"),
    (None, "linux", "cron"): ("auth_log", "syslog"),
    (None, "linux", "sshd"): ("auth_log", "syslog"),
    (None, "linux", "sudo"): ("auth_log", "syslog"),
    ("webserver", None, None): ("nginx.access",),
    ("webserver", "nginx", None): ("nginx.access",),
    (None, "nginx", None): ("nginx.access",),
}

_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
_COMPARE = {
    CompareOperators.LT: "<",
    CompareOperators.LTE: "<=",
    CompareOperators.GT: ">",
    CompareOperators.GTE: ">=",
}
_RE_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: "i",
    SigmaRegularExpressionFlag.MULTILINE: "m",
    SigmaRegularExpressionFlag.DOTALL: "s",
}


class RuleError(ValueError):
    """A rule cannot be loaded or compiled."""


@dataclass(frozen=True)
class Rule:
    id: str
    name: str | None
    title: str
    level: str
    techniques: tuple[str, ...]
    datasets: tuple[str, ...]
    where: str
    params: tuple[Any, ...]
    path: Path | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def query(self, fields: Sequence[str] = ()) -> tuple[str, list[Any]]:
        """``SELECT`` of matching events: ``id``, ``ts`` and the requested fields."""
        for name in fields:
            if name not in FIELDS:
                raise RuleError(f"unknown field: {name!r}")
        extra = "".join(f", {_column(f)} AS {_column(f)}" for f in fields)
        sql = f'SELECT "event.id" AS id, "@timestamp" AS ts{extra} FROM events WHERE {self.where}'  # noqa: S608
        return sql, list(self.params)


@dataclass
class _Compiler:
    params: list[Any] = field(default_factory=list)

    def bind(self, value: Any) -> str:
        self.params.append(value)
        return "?"

    def node(self, node: Any) -> str:
        if isinstance(node, ConditionAND):
            return "(" + " AND ".join(self.node(a) for a in node.args) + ")"
        if isinstance(node, ConditionOR):
            return "(" + " OR ".join(self.node(a) for a in node.args) + ")"
        if isinstance(node, ConditionNOT):
            # Sigma NOT is two-valued: a missing field does not match, so NOT matches.
            return f"(NOT coalesce({self.node(node.args[0])}, false))"
        if isinstance(node, ConditionFieldEqualsValueExpression):
            return self.field_value(node.field, node.value)
        if isinstance(node, ConditionValueExpression):
            return self.keyword(node.value)
        raise RuleError(f"unsupported condition: {type(node).__name__}")

    def keyword(self, value: Any) -> str:
        if not isinstance(value, SigmaString):
            raise RuleError(f"unsupported keyword value: {type(value).__name__}")
        pattern = "%" + _like_pattern(value) + "%"
        op = "LIKE" if isinstance(value, SigmaCasedString) else "ILIKE"
        return f"({_column(KEYWORD_FIELD)} {op} {self.bind(pattern)} ESCAPE '\\')"

    def field_value(self, name: str, value: Any) -> str:
        if name not in FIELDS:
            raise RuleError(f"unknown field: {name!r}")
        col = _column(name)
        if name in LIST_FIELDS:
            return self.list_value(col, value)
        if isinstance(value, SigmaNull):
            return f"({col} IS NULL)"
        if isinstance(value, SigmaExists):
            return f"({col} IS {'NOT ' if value.exists else ''}NULL)"
        if isinstance(value, SigmaCompareExpression):
            if name not in NUMERIC_FIELDS:
                raise RuleError(f"numeric comparison on non-numeric field: {name!r}")
            return f"({col} {_COMPARE[value.op]} {self.bind(value.number.number)})"
        if isinstance(value, SigmaNumber):
            if name in NUMERIC_FIELDS:
                return f"({col} = {self.bind(value.number)})"
            value = SigmaString(str(value.number))
        if isinstance(value, SigmaRegularExpression):
            flags = "".join(sorted(_RE_FLAGS[f] for f in value.flags))
            regexp = str(value.regexp)
            return f"regexp_matches({col}, {self.bind(regexp)}, {self.bind(flags)})"
        if isinstance(value, SigmaCIDRExpression):
            return f"nyctala_cidr_match({col}, {self.bind(str(value.network))})"
        if isinstance(value, SigmaString):
            if name in NUMERIC_FIELDS:
                plain = value.to_plain() if not value.contains_special() else None
                if plain is None or not str(plain).isdigit():
                    raise RuleError(f"non-numeric value for numeric field: {name!r}")
                return f"({col} = {self.bind(int(plain))})"
            op = "LIKE" if isinstance(value, SigmaCasedString) else "ILIKE"
            return f"({col} {op} {self.bind(_like_pattern(value))} ESCAPE '\\')"
        raise RuleError(f"unsupported value for {name!r}: {type(value).__name__}")

    def list_value(self, col: str, value: Any) -> str:
        if isinstance(value, SigmaNull):
            return f"(len({col}) = 0)"
        if not isinstance(value, SigmaString):
            raise RuleError(f"unsupported value for list field: {type(value).__name__}")
        op = "LIKE" if isinstance(value, SigmaCasedString) else "ILIKE"
        pattern = self.bind(_like_pattern(value))
        return f"(len(list_filter({col}, lambda t: t {op} {pattern} ESCAPE '\\')) > 0)"


def _column(name: str) -> str:
    # Only called with names checked against the schema; quoting handles the dots.
    return '"' + name + '"'


def _like_pattern(value: SigmaString) -> str:
    if value.contains_placeholder():
        raise RuleError("placeholders are not supported")
    out = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            out.append("%")
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append("_")
        elif isinstance(part, str):
            out.append(part.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
        else:
            raise RuleError(f"unsupported string part: {part!r}")
    return "".join(out)


def _techniques(tags: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(m[1].upper() for t in tags if (m := _TECHNIQUE.match(t)))


def _datasets(rule: SigmaRule) -> tuple[str, ...]:
    ls = rule.logsource
    key = (ls.category, ls.product, ls.service)
    if key not in LOGSOURCES:
        raise RuleError(f"unsupported logsource: {key}")
    return LOGSOURCES[key]


def compile_rule(sigma: SigmaRule, path: Path | None = None) -> Rule:
    if sigma.id is None:
        raise RuleError("rule has no id")
    datasets = _datasets(sigma)
    compiler = _Compiler()
    dataset_sql = ", ".join(compiler.bind(d) for d in datasets)
    try:
        conditions = [compiler.node(c.parse()) for c in sigma.detection.parsed_condition]
    except SigmaError as exc:
        raise RuleError(str(exc)) from exc
    where = f'("event.dataset" IN ({dataset_sql})) AND ({" OR ".join(conditions)})'
    tags = tuple(str(t) for t in sigma.tags)
    techniques = _techniques(tags)
    return Rule(
        id=str(sigma.id),
        name=sigma.name,
        title=sigma.title,
        level=str(sigma.level.name).lower() if sigma.level else "",
        techniques=techniques,
        datasets=datasets,
        where=where,
        params=tuple(compiler.params),
        path=path,
        tags=tags,
    )


def load_sigma_file(path: Path) -> SigmaRule | SigmaCorrelationRule:
    """Parse one rule file; it must hold exactly one rule with an id."""
    try:
        collection = SigmaCollection.from_yaml(
            path.read_text(), collect_errors=True, resolve_references=False
        )
    except (SigmaError, yaml.YAMLError) as exc:
        raise RuleError(str(exc)) from exc
    if collection.errors:
        raise RuleError(str(collection.errors[0]))
    if len(collection.rules) != 1:
        raise RuleError(f"expected exactly one rule, found {len(collection.rules)}")
    rule = collection.rules[0]
    if rule.id is None:
        raise RuleError("rule has no id")
    return rule


def load_rule(path: Path) -> Rule:
    """Load a single base (non-correlation) rule."""
    sigma = load_sigma_file(path)
    if not isinstance(sigma, SigmaRule):
        raise RuleError("not a detection rule")
    return compile_rule(sigma, path)
