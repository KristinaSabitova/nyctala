import stat
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from nyctala.schema import Event
from nyctala.store import EVENT_SCHEMA, EventStore, QueryError


@pytest.fixture
def store(tmp_path: Path) -> EventStore:
    return EventStore(tmp_path / "data")


def event(ingested: datetime, **fields: object) -> Event:
    return Event.model_validate(
        {
            "@timestamp": ingested,
            "event.ingested": ingested,
            "event.dataset": "auth_log",
            "sensor.id": "vps-a",
            **fields,
        }
    )


DAY1 = datetime(2026, 10, 21, 23, 59, tzinfo=UTC)
DAY2 = datetime(2026, 10, 22, 0, 1, tzinfo=UTC)


def test_schema_matches_model() -> None:
    aliases = [f.alias or name for name, f in Event.model_fields.items()]
    assert EVENT_SCHEMA.names == aliases


def test_empty_store_is_queryable(store: EventStore) -> None:
    assert store.query("SELECT count(*) AS n FROM events") == [{"n": 0}]


def test_append_partitions_by_ingestion_day(store: EventStore) -> None:
    assert store.append([event(DAY1), event(DAY2), event(DAY2)]) == 3
    partitions = sorted(p.name for p in store.events_dir.iterdir())
    assert partitions == ["dt=2026-10-21", "dt=2026-10-22"]
    rows = store.query("SELECT dt, count(*) AS n FROM events GROUP BY dt ORDER BY dt")
    assert rows == [{"dt": date(2026, 10, 21), "n": 1}, {"dt": date(2026, 10, 22), "n": 2}]


def test_partition_ignores_event_timestamp(store: EventStore) -> None:
    store.append([event(DAY2, **{"@timestamp": datetime(1999, 1, 1, tzinfo=UTC)})])
    assert [p.name for p in store.events_dir.iterdir()] == ["dt=2026-10-22"]


def test_roundtrip(store: EventStore) -> None:
    original = event(
        DAY1,
        **{
            "user.name": "root",
            "source.ip": "203.0.113.7",
            "http.response.status_code": 200,
            "http.response.bytes": 10**10,
            "tags": ["ssh", "auth"],
        },
    )
    store.append([original])
    (row,) = store.query("SELECT * EXCLUDE (dt) FROM events")
    assert Event.model_validate(row) == original


def test_query_with_ecs_columns_and_params(store: EventStore) -> None:
    store.append(
        [
            event(DAY1, **{"user.name": "root", "event.outcome": "failure"}),
            event(DAY1, **{"user.name": "root", "event.outcome": "success"}),
            event(DAY1, **{"user.name": "alice", "event.outcome": "failure"}),
        ]
    )
    rows = store.query(
        'SELECT count(*) AS n FROM events WHERE "user.name" = ? AND "event.outcome" = ?',
        ["root", "failure"],
    )
    assert rows == [{"n": 1}]


def test_hostile_value_is_data_not_sql(store: EventStore) -> None:
    payload = "x' OR '1'='1"
    store.append([event(DAY1, **{"user.name": payload}), event(DAY1, **{"user.name": "bob"})])
    rows = store.query('SELECT "user.name" AS u FROM events WHERE "user.name" = ?', [payload])
    assert rows == [{"u": payload}]


def test_new_files_visible_without_reopening(store: EventStore) -> None:
    store.append([event(DAY1)])
    assert store.query("SELECT count(*) AS n FROM events") == [{"n": 1}]
    store.append([event(DAY1)])
    assert store.query("SELECT count(*) AS n FROM events") == [{"n": 2}]


def test_files_private_and_no_leftovers(store: EventStore) -> None:
    store.append([event(DAY1)])
    files = list(store.events_dir.rglob("*"))
    parquet = [f for f in files if f.is_file()]
    assert len(parquet) == 1
    assert parquet[0].suffix == ".parquet"
    assert stat.S_IMODE(parquet[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(store.events_dir.stat().st_mode) == 0o700


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM events",
        "COPY (SELECT 1) TO 'out.csv'",
        "SELECT 1; SELECT 2",
        "ATTACH 'other.db'",
        "SET enable_external_access = true",
        "INSTALL httpfs",
    ],
)
def test_only_single_select_allowed(store: EventStore, sql: str) -> None:
    with pytest.raises(QueryError):
        store.query(sql)


def test_select_cannot_read_outside_store(store: EventStore, tmp_path: Path) -> None:
    secret = tmp_path / "secret.csv"
    secret.write_text("token\nhunter2\n")
    with pytest.raises(Exception, match="Permission"):
        store.query(f"SELECT * FROM read_csv('{secret}')")  # noqa: S608
