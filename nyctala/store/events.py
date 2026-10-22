"""Event storage: Parquet partitioned by ingestion day, queried with DuckDB.

Layout::

    <root>/events/dt=YYYY-MM-DD/part-<uuid>.parquet

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
from pathlib import Path
from typing import Any

import duckdb
import duckdb.func
import duckdb.sqltypes as dt
import pyarrow as pa
import pyarrow.parquet as pq

from nyctala.schema import Event

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
        self.events_dir = self.root / "events"
        self.events_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
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
        con.register("_empty_events", EVENT_SCHEMA.empty_table())
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
        by_day: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            by_day[event.event_ingested.date().isoformat()].append(event.to_record())
        for day, records in by_day.items():
            self._write(day, pa.Table.from_pylist(records, schema=EVENT_SCHEMA))
        return sum(len(r) for r in by_day.values())

    def _write(self, day: str, table: pa.Table) -> None:
        partition = self.events_dir / f"{PARTITION_COLUMN}={day}"
        partition.mkdir(mode=0o700, exist_ok=True)
        name = f"part-{uuid.uuid4()}.parquet"
        tmp = partition / f".{name}.tmp"
        # Write aside and rename, so readers never see a half-written file.
        pq.write_table(table, tmp, compression="zstd")
        os.chmod(tmp, 0o600)
        os.replace(tmp, partition / name)

    def _refresh_view(self) -> None:
        if any(self.events_dir.glob(f"{PARTITION_COLUMN}=*/*.parquet")):
            pattern = str(self.events_dir / "*" / "*.parquet").replace("'", "''")
            source = (
                f"read_parquet('{pattern}', hive_partitioning = true, "
                f"hive_types = {{'{PARTITION_COLUMN}': DATE}}, union_by_name = true)"
            )
        else:
            source = f"(SELECT *, NULL::DATE AS {PARTITION_COLUMN} FROM _empty_events)"  # noqa: S608
        # Only constants and the store's own path are interpolated here, never event content.
        self._con.execute(f"CREATE OR REPLACE TEMP VIEW events AS SELECT * FROM {source}")  # noqa: S608

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        """Run one read-only ``SELECT`` against the ``events`` view.

        Values must go through ``params``; the statement text is never built
        from event content.
        """
        statements = duckdb.extract_statements(sql)
        if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
            raise QueryError("only a single SELECT statement is allowed")
        self._refresh_view()
        result: list[dict[str, Any]] = (
            self._con.sql(sql, params=list(params or [])).to_arrow_table().to_pylist()
        )
        return result

    def close(self) -> None:
        self._con.close()
