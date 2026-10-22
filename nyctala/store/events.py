"""Event and alert storage: Parquet partitioned by day, queried with DuckDB.

Layout::

    <root>/events/dt=YYYY-MM-DD/part-<uuid>.parquet   (day of ingestion)
    <root>/alerts/dt=YYYY-MM-DD/part-<uuid>.parquet   (day the alert was raised)
    <root>/rule_tests/dt=YYYY-MM-DD/part-<uuid>.parquet  (day of the test run)

Both tables are append-only: files are added, never rewritten.

Partitions use the ingestion day (set by nyctala) rather than ``@timestamp``
(set by the log source): a hostile source cannot spray events over thousands
of fake dates to explode the number of partitions, and late events land in the
current partition instead of rewriting old ones.
"""

import ipaddress
import os
import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import duckdb.func
import duckdb.sqltypes as dt
import pyarrow as pa
import pyarrow.parquet as pq

from nyctala.schema import Alert, Event

_TS = pa.timestamp("us", tz="UTC")

EVENT_SCHEMA = pa.schema(
    [
        ("@timestamp", _TS),
        ("event.id", pa.string()),
        ("event.dataset", pa.string()),
        ("event.category", pa.string()),
        ("event.action", pa.string()),
        ("event.outcome", pa.string()),
        ("event.original", pa.string()),
        ("event.ingested", _TS),
        ("host.name", pa.string()),
        ("sensor.id", pa.string()),
        ("user.name", pa.string()),
        ("user.target.name", pa.string()),
        ("source.ip", pa.string()),
        ("destination.ip", pa.string()),
        ("process.name", pa.string()),
        ("process.command_line", pa.string()),
        ("url.path", pa.string()),
        ("url.query", pa.string()),
        ("http.request.method", pa.string()),
        ("http.response.status_code", pa.int32()),
        ("http.response.bytes", pa.int64()),
        ("user_agent.original", pa.string()),
        ("file.path", pa.string()),
        ("tags", pa.list_(pa.string())),
        ("integrity.hash", pa.string()),
        ("integrity.prev_hash", pa.string()),
    ]
)

ALERT_SCHEMA = pa.schema(
    [
        ("alert.id", pa.string()),
        ("alert.created", _TS),
        ("alert.kind", pa.string()),
        ("rule.id", pa.string()),
        ("rule.name", pa.string()),
        ("rule.title", pa.string()),
        ("rule.level", pa.string()),
        ("threat.technique.id", pa.list_(pa.string())),
        ("alert.first", _TS),
        ("alert.last", _TS),
        ("alert.group", pa.string()),
        ("alert.event_ids", pa.list_(pa.string())),
        ("related.alert_ids", pa.list_(pa.string())),
        ("alert.entities", pa.list_(pa.string())),
        ("risk.score", pa.int32()),
        ("risk.accumulated", pa.int32()),
        ("risk.entity", pa.string()),
        ("alert.explanation", pa.string()),
    ]
)

RULE_TEST_SCHEMA = pa.schema(
    [
        ("run.id", pa.string()),
        ("run.at", _TS),
        ("rule.id", pa.string()),
        ("rule.name", pa.string()),
        ("rule.title", pa.string()),
        ("rule.kind", pa.string()),
        ("rule.digest", pa.string()),
        ("threat.technique.id", pa.list_(pa.string())),
        ("test.passed", pa.bool_()),
        ("test.positive_total", pa.int32()),
        ("test.positive_matched", pa.int32()),
        ("test.negative_total", pa.int32()),
        ("test.negative_matched", pa.int32()),
        ("test.errors", pa.list_(pa.string())),
    ]
)

TABLES = {"events": EVENT_SCHEMA, "alerts": ALERT_SCHEMA, "rule_tests": RULE_TEST_SCHEMA}
PARTITION_COLUMN = "dt"


def _in_network(ip: str | None, network: str | None) -> bool | None:
    if ip is None or network is None:
        return None
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def cidr_match(ips: pa.Array, networks: pa.Array) -> pa.Array:
    """SQL function ``nyctala_cidr_match(ip, cidr)``; the inet extension is not loadable here."""
    pairs = zip(ips.to_pylist(), networks.to_pylist(), strict=True)
    return pa.array([_in_network(ip, net) for ip, net in pairs], pa.bool_())


class QueryError(ValueError):
    """The SQL handed to :meth:`EventStore.query` is not allowed."""


class EventStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        for table in TABLES:
            (self.root / table).mkdir(mode=0o700, parents=True, exist_ok=True)
        self.events_dir = self.root / "events"
        self.alerts_dir = self.root / "alerts"
        self._con = self._connect()

    def _connect(self) -> duckdb.DuckDBPyConnection:
        """In-memory DuckDB confined to the store directory.

        Queries cannot read or write files outside ``root``, attach databases,
        install extensions or undo these settings.
        """
        con = duckdb.connect(
            ":memory:",
            config={
                "autoinstall_known_extensions": False,
                "autoload_known_extensions": False,
            },
        )
        con.execute("SET allowed_directories = [?]", [f"{self.root}/"])
        con.execute("SET enable_external_access = false")
        con.execute("SET lock_configuration = true")
        for table, schema in TABLES.items():
            con.register(f"_empty_{table}", schema.empty_table())
        con.create_function(
            "nyctala_cidr_match",
            cidr_match,
            [dt.VARCHAR, dt.VARCHAR],
            dt.BOOLEAN,
            type=duckdb.func.ARROW,
        )
        return con

    def append(self, events: Iterable[Event]) -> int:
        """Write ``events`` as one new Parquet file per ingestion day."""
        return self._append("events", ((e.event_ingested, e.to_record()) for e in events))

    def append_alerts(self, alerts: Iterable[Alert]) -> int:
        """Write ``alerts`` as one new Parquet file per day of creation."""
        return self._append("alerts", ((a.created, a.to_record()) for a in alerts))

    def append_rule_tests(self, run_at: datetime, records: Iterable[dict[str, Any]]) -> int:
        """Write the results of one ``rules test`` run."""
        return self._append("rule_tests", ((run_at, r) for r in records))

    def _append(self, table: str, rows: Iterable[tuple[datetime, dict[str, Any]]]) -> int:
        by_day: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for when, record in rows:
            by_day[when.date().isoformat()].append(record)
        for day, records in by_day.items():
            self._write(table, day, pa.Table.from_pylist(records, schema=TABLES[table]))
        return sum(len(r) for r in by_day.values())

    def _write(self, table_name: str, day: str, table: pa.Table) -> None:
        partition = self.root / table_name / f"{PARTITION_COLUMN}={day}"
        partition.mkdir(mode=0o700, exist_ok=True)
        name = f"part-{uuid.uuid4()}.parquet"
        tmp = partition / f".{name}.tmp"
        # Write aside and rename, so readers never see a half-written file.
        pq.write_table(table, tmp, compression="zstd")
        os.chmod(tmp, 0o600)
        os.replace(tmp, partition / name)

    def _refresh_views(self) -> None:
        for table in TABLES:
            directory = self.root / table
            if any(directory.glob(f"{PARTITION_COLUMN}=*/*.parquet")):
                pattern = str(directory / "*" / "*.parquet").replace("'", "''")
                source = (
                    f"read_parquet('{pattern}', hive_partitioning = true, "
                    f"hive_types = {{'{PARTITION_COLUMN}': DATE}}, union_by_name = true)"
                )
            else:
                source = f"(SELECT *, NULL::DATE AS {PARTITION_COLUMN} FROM _empty_{table})"  # noqa: S608
            # Only constants and the store's own path are interpolated, never stored content.
            self._con.execute(f"CREATE OR REPLACE TEMP VIEW {table} AS SELECT * FROM {source}")  # noqa: S608

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        """Run one read-only ``SELECT`` against the ``events``, ``alerts`` and ``rule_tests`` views.

        Values must go through ``params``; the statement text is never built
        from event content.
        """
        statements = duckdb.extract_statements(sql)
        if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
            raise QueryError("only a single SELECT statement is allowed")
        self._refresh_views()
        result: list[dict[str, Any]] = (
            self._con.sql(sql, params=list(params or [])).to_arrow_table().to_pylist()
        )
        return result

    def close(self) -> None:
        self._con.close()
