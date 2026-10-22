"""nyctala command line."""

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

from nyctala.ingest.sensors import SensorError, SensorRegistry

if TYPE_CHECKING:
    from nyctala.schema import Alert

app = typer.Typer(no_args_is_help=True, help="Lightweight detection-engineering SIEM.")
sensor_app = typer.Typer(no_args_is_help=True, help="Manage sensors and their ingest tokens.")
app.add_typer(sensor_app, name="sensor")
rules_app = typer.Typer(no_args_is_help=True, help="Detection rules.")
app.add_typer(rules_app, name="rules")
alerts_app = typer.Typer(no_args_is_help=True, help="Alerts and their explanation.")
app.add_typer(alerts_app, name="alerts")

DataDir = Annotated[
    Path,
    typer.Option("--data", envvar="NYCTALA_DATA", help="Data directory.", file_okay=False),
]


def _registry(data: Path) -> SensorRegistry:
    return SensorRegistry(data / "sensors.json")


@sensor_app.command("add")
def sensor_add(sensor_id: str, data: DataDir = Path("data")) -> None:
    """Register a sensor and print its token (shown only once)."""
    try:
        token = _registry(data).add(sensor_id)
    except SensorError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(token)
    typer.echo("Store this token now; it cannot be shown again.", err=True)


@sensor_app.command("revoke")
def sensor_revoke(sensor_id: str, data: DataDir = Path("data")) -> None:
    """Revoke a sensor's token. Takes effect without restarting the server."""
    try:
        _registry(data).revoke(sensor_id)
    except SensorError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"revoked {sensor_id}")


@sensor_app.command("list")
def sensor_list(data: DataDir = Path("data")) -> None:
    """List sensors and their status."""
    for sensor_id, info in sorted(_registry(data).list().items()):
        status = "revoked" if info.get("revoked") else "active"
        typer.echo(f"{sensor_id}\t{status}\t{info.get('created', '')}")


@rules_app.command("test")
def rules_test(
    rules_dir: Annotated[
        Path | None, typer.Argument(help="Rules directory (default: bundled rules).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    record: Annotated[
        Path | None,
        typer.Option(
            "--record", help="Also store the results in this data directory.", file_okay=False
        ),
    ] = None,
) -> None:
    """Run every rule against its positive and negative fixtures. Exit 1 on any failure."""
    from nyctala.engine.testing import RULES_DIR, result_records, run_rule_tests

    results = run_rule_tests(rules_dir or RULES_DIR)
    if record is not None:
        from datetime import UTC, datetime

        from nyctala.store import EventStore

        EventStore(record).append_rule_tests(datetime.now(UTC), result_records(results))
    failed = [r for r in results if not r.passed]
    if as_json:
        report = [
            {
                "rule": r.name,
                "id": r.rule.id if r.rule else None,
                "techniques": list(r.rule.techniques) if r.rule else [],
                "kind": "correlation" if r.is_correlation else "detection",
                "passed": r.passed,
                "positive": {"total": r.positive_total, "matched": r.positive_matched},
                "negative": {"total": r.negative_total, "matched": r.negative_matched},
                "errors": r.errors,
            }
            for r in results
        ]
        typer.echo(json.dumps(report, indent=2))
    else:
        for r in results:
            mark = "PASS" if r.passed else "FAIL"
            techniques = ",".join(r.rule.techniques) if r.rule else "-"
            if r.is_correlation:
                counts = f"positive fired {r.positive_matched}  negative fired {r.negative_matched}"
            else:
                counts = (
                    f"positive {r.positive_matched}/{r.positive_total}  "
                    f"negative {r.negative_matched}/{r.negative_total}"
                )
            typer.echo(f"{mark}  {r.name:<30} {techniques:<20} {counts}")
            for error in r.errors:
                typer.echo(f"      error: {error}")
            if r.rule and r.negative_matched:
                unit = "firing(s)" if r.is_correlation else "negative event(s) matched"
                typer.echo(f"      false positives: {r.negative_matched} {unit}")
            if r.rule and r.is_correlation and r.positive_total and not r.positive_matched:
                typer.echo("      false negatives: did not fire on the positive fixture")
            elif r.rule and not r.is_correlation and r.positive_matched < r.positive_total:
                missed = r.positive_total - r.positive_matched
                typer.echo(f"      false negatives: {missed} positive event(s) not matched")
        typer.echo(f"\n{len(results) - len(failed)}/{len(results)} rules passed")
    if not results or failed:
        raise typer.Exit(1)


@app.command()
def detect(
    data: DataDir = Path("data"),
    rules_dir: Annotated[
        Path | None, typer.Option("--rules", help="Rules directory (default: bundled rules).")
    ] = None,
    interval: Annotated[float, typer.Option(help="Seconds between runs.", min=1)] = 10.0,
    once: Annotated[bool, typer.Option("--once", help="Run a single pass and exit.")] = False,
) -> None:
    """Run the detection job: store alerts and print each new one."""
    import threading

    from nyctala.engine.alerts import AlertManager
    from nyctala.engine.correlation import Hit
    from nyctala.engine.job import DetectionJob
    from nyctala.engine.ruleset import load_ruleset
    from nyctala.engine.testing import RULES_DIR
    from nyctala.store import EventStore

    ruleset = load_ruleset(rules_dir or RULES_DIR)
    for path, error in ruleset.errors.items():
        typer.echo(f"skipping {path.name}: {error}", err=True)
    store = EventStore(data)
    manager = AlertManager(store, ruleset)

    def emit(hits: list[Hit]) -> None:
        for alert in manager.handle(hits):
            typer.echo(_alert_line(alert))

    job = DetectionJob(store, ruleset, emit, interval=interval)
    if once:
        job.run_once()
        return
    stop = threading.Event()
    try:
        job.run_forever(stop)
    except KeyboardInterrupt:
        stop.set()


def _alert_line(alert: "Alert") -> str:
    techniques = ",".join(alert.techniques) or "-"
    return (
        f"{alert.last:%Y-%m-%d %H:%M:%S}  {alert.rule_level:<8} risk={alert.risk_accumulated:<4} "
        f"{techniques:<20} {alert.rule_title}  [{alert.alert_id[:8]}]"
    )


Since = Annotated[float, typer.Option("--since", help="Look back this many hours.", min=0)]


@alerts_app.command("list")
def alerts_list(
    data: DataDir = Path("data"),
    since: Since = 24,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List recent alerts, newest last."""
    from datetime import UTC, datetime, timedelta

    from nyctala.engine.alerts import load_alerts
    from nyctala.store import EventStore

    now = datetime.now(UTC)
    for alert in load_alerts(EventStore(data), now - timedelta(hours=since), now):
        if as_json:
            typer.echo(json.dumps(alert.model_dump(mode="json", by_alias=True)))
        else:
            typer.echo(_alert_line(alert))


@alerts_app.command("show")
def alerts_show(alert_id: str, data: DataDir = Path("data")) -> None:
    """Explain one alert: rule, techniques, risk, entities and the events behind it."""
    from datetime import UTC

    from nyctala.schema import Alert
    from nyctala.store import EventStore

    store = EventStore(data)
    if not re.fullmatch(r"[0-9a-f-]{4,36}", alert_id):
        raise typer.BadParameter("expected an alert id (or its prefix)")
    rows = store.query(
        'SELECT * EXCLUDE (dt) FROM alerts WHERE starts_with("alert.id", ?)', [alert_id]
    )
    if len(rows) != 1:
        raise typer.BadParameter(f"{len(rows)} alerts match {alert_id!r}")
    alert = Alert.model_validate(rows[0])
    typer.echo(f"{alert.rule_title}  ({alert.kind}, {alert.rule_level})")
    typer.echo(f"  alert      {alert.alert_id}")
    typer.echo(f"  rule       {alert.rule_name or '-'}  {alert.rule_id}")
    typer.echo(f"  ATT&CK     {', '.join(alert.techniques) or '-'}")
    typer.echo(f"  window     {alert.first:%Y-%m-%d %H:%M:%S} -> {alert.last:%H:%M:%S} UTC")
    typer.echo(f"  entities   {', '.join(alert.entities) or '-'}")
    typer.echo(f"  risk       +{alert.risk_score}, accumulated {alert.risk_accumulated}")
    typer.echo(f"  why        {alert.explanation}")
    if alert.related_alert_ids:
        typer.echo(f"  alerts     {', '.join(a[:8] for a in alert.related_alert_ids)}")
    events = store.query(
        'SELECT "@timestamp" AS ts, "event.dataset" AS ds, "sensor.id" AS sensor, '
        '"event.original" AS original FROM events WHERE list_contains(?, "event.id") '
        'ORDER BY "@timestamp"',
        [alert.event_ids],
    )
    typer.echo(f"  events     {len(events)}")
    for e in events:
        # Stored text is already neutralised: no control characters reach the terminal.
        ts = e["ts"].astimezone(UTC)
        typer.echo(f"    {ts:%H:%M:%S} {e['sensor']}/{e['ds']}  {e['original']}")


@app.command("incidents")
def incidents_list(data: DataDir = Path("data"), since: Since = 72) -> None:
    """Group recent alerts into incidents by shared user, IP or host."""
    from datetime import UTC, datetime, timedelta

    from nyctala.engine.alerts import incidents
    from nyctala.store import EventStore

    now = datetime.now(UTC)
    for inc in incidents(EventStore(data), now - timedelta(hours=since), now):
        typer.echo(
            f"incident {inc.id[:8]}  {inc.level:<8} risk={inc.risk:<4} alerts={len(inc.alerts):<3} "
            f"{inc.first:%Y-%m-%d %H:%M} -> {inc.last:%H:%M}"
        )
        typer.echo(f"  ATT&CK    {', '.join(inc.techniques) or '-'}")
        typer.echo(f"  entities  {', '.join(inc.entities) or '-'}")
        for alert in inc.alerts:
            typer.echo(f"    {_alert_line(alert)}")


@app.command("risk")
def risk_list(data: DataDir = Path("data"), since: Since = 24) -> None:
    """Accumulated risk per entity (user, host, IP)."""
    from datetime import UTC, datetime, timedelta

    from nyctala.engine.alerts import entity_risk
    from nyctala.store import EventStore

    for r in entity_risk(EventStore(data), datetime.now(UTC), timedelta(hours=since)):
        typer.echo(f"{r.score:>5}  {r.entity:<40} alerts={r.alerts} rules={r.rules}")


@app.command()
def serve(
    data: DataDir = Path("data"),
    host: Annotated[str, typer.Option(help="Bind address (use the WireGuard IP).")] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8514,
) -> None:
    """Run the ingest API."""
    import uvicorn

    from nyctala.ingest.app import create_app
    from nyctala.store import EventStore

    os.umask(0o077)
    api = create_app(EventStore(data), _registry(data))
    uvicorn.run(api, host=host, port=port, server_header=False, proxy_headers=False)


if __name__ == "__main__":
    app()
