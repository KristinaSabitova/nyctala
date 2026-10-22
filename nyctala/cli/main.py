"""nyctala command line."""

import json
import os
import re
from pathlib import Path
from typing import Annotated

import typer

from nyctala.ingest.sensors import SensorError, SensorRegistry
from nyctala.schema import Alert

app = typer.Typer(no_args_is_help=True, help="Lightweight detection-engineering SIEM.")
sensor_app = typer.Typer(no_args_is_help=True, help="Manage sensors and their ingest tokens.")
app.add_typer(sensor_app, name="sensor")
rules_app = typer.Typer(no_args_is_help=True, help="Detection rules.")
app.add_typer(rules_app, name="rules")
alerts_app = typer.Typer(no_args_is_help=True, help="Alerts and their explanation.")
app.add_typer(alerts_app, name="alerts")
lab_app = typer.Typer(no_args_is_help=True, help="Synthetic attack scenarios.")
app.add_typer(lab_app, name="lab")
integrity_app = typer.Typer(no_args_is_help=True, help="Hash chain over stored events.")
app.add_typer(integrity_app, name="integrity")

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
def coverage(
    data: Annotated[
        Path | None,
        typer.Option(
            "--data",
            envvar="NYCTALA_DATA",
            file_okay=False,
            help="Use the latest test run recorded in this data directory instead of testing now.",
        ),
    ] = None,
    rules_dir: Annotated[
        Path | None, typer.Option("--rules", help="Rules directory (default: bundled rules).")
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help="text, json or navigator.")] = "text",
) -> None:
    """ATT&CK coverage measured from rule tests: only rules with passing tests count."""
    from nyctala.coverage.matrix import RuleRecord, current_digests, load_attack, measure
    from nyctala.engine.testing import RULES_DIR, run_rule_tests

    directory = rules_dir or RULES_DIR
    if fmt not in ("text", "json", "navigator"):
        raise typer.BadParameter("format must be text, json or navigator")
    if data is None:
        source = "rule tests run now"
        records = [
            RuleRecord(r.name, r.rule.techniques if r.rule else (), r.passed, r.digest)
            for r in run_rule_tests(directory)
        ]
        cov = measure(records)
    else:
        from nyctala.store import EventStore

        rows = EventStore(data).query(
            'SELECT * FROM rule_tests WHERE "run.id" = '
            '(SELECT "run.id" FROM rule_tests ORDER BY "run.at" DESC LIMIT 1)'
        )
        if not rows:
            raise typer.BadParameter("no recorded rule test run; use `rules test --record`")
        source = f"recorded run {rows[0]['run.id'][:8]} at {rows[0]['run.at']:%Y-%m-%d %H:%M} UTC"
        records = [
            RuleRecord(
                r["rule.name"], tuple(r["threat.technique.id"]), r["test.passed"], r["rule.digest"]
            )
            for r in rows
        ]
        cov = measure(records, current_digests(directory))

    if fmt == "json":
        typer.echo(json.dumps(cov.to_json(), indent=2))
        return
    if fmt == "navigator":
        typer.echo(json.dumps(cov.to_navigator(), indent=2))
        return

    attack = load_attack()
    typer.echo(f"ATT&CK Enterprise v{attack.version}, Linux - measured from {source}")
    typer.echo(f"rules passing: {cov.rules_passed}/{cov.rules_total}\n")
    for tactic, total, covered in cov.by_tactic():
        if not total:
            continue  # tactics without Linux techniques (PRE platform)
        bar = "#" * len(covered) + "." * min(total - len(covered), 30 - len(covered))
        typer.echo(f"{tactic['name']:<22} {len(covered):>2}/{total:<3} {bar}")
        for tid in covered:
            name = attack.techniques[tid]["name"]
            typer.echo(f"    {tid:<10} {name:<36} {', '.join(cov.covered[tid])}")
    typer.echo(f"\ncovered: {len(cov.covered)} of {len(attack.techniques)} Linux techniques")
    for label, bucket in (("failing", cov.failing), ("stale", cov.stale), ("unknown", cov.unknown)):
        for tid, rules in sorted(bucket.items()):
            typer.echo(f"not counted ({label}): {tid}  {', '.join(rules)}")
    typer.echo(f"\n{attack.notice}")


@lab_app.command("list")
def lab_list() -> None:
    """List the bundled scenarios."""
    from nyctala.lab.scenario import bundled_scenarios, load_scenario

    for path in bundled_scenarios():
        sc = load_scenario(path)
        typer.echo(f"{sc.name:<20} expect: {', '.join(sc.expect) or '(no alerts)'}")


def _scenario_paths(names: list[str] | None) -> list[Path]:
    from nyctala.lab.scenario import bundled_scenarios

    paths = bundled_scenarios()
    if not names:
        return paths
    by_name = {p.stem: p for p in paths}
    missing = [n for n in names if n not in by_name and not Path(n).is_file()]
    if missing:
        raise typer.BadParameter(f"unknown scenario(s): {', '.join(missing)}")
    return [by_name.get(n) or Path(n) for n in names]


@lab_app.command("run")
def lab_run(
    scenarios: Annotated[
        list[str] | None, typer.Argument(help="Scenario names or files (default: all bundled).")
    ] = None,
    rules_dir: Annotated[
        Path | None, typer.Option("--rules", help="Rules directory (default: bundled rules).")
    ] = None,
) -> None:
    """Replay scenarios in a throwaway store; the alerts must match exactly. Exit 1 if not."""
    from nyctala.engine.ruleset import load_ruleset
    from nyctala.engine.testing import RULES_DIR
    from nyctala.lab.scenario import ScenarioError, load_scenario, run_scenario

    ruleset = load_ruleset(rules_dir or RULES_DIR)
    failed = 0
    for path in _scenario_paths(scenarios):
        try:
            result = run_scenario(load_scenario(path), ruleset)
        except ScenarioError as exc:
            typer.echo(f"FAIL  {path.stem:<20} {exc}")
            failed += 1
            continue
        failed += not result.passed
        mark = "PASS" if result.passed else "FAIL"
        alerted = ", ".join(sorted(result.alerted)) or "(no alerts)"
        typer.echo(f"{mark}  {result.scenario:<20} {result.events:>4} events  -> {alerted}")
        for name in sorted(result.missing):
            typer.echo(f"      missing:    {name}")
        for name in sorted(result.unexpected):
            typer.echo(f"      unexpected: {name}")
        for error in result.rejected:
            typer.echo(f"      rejected:   {error}")
    if failed:
        raise typer.Exit(1)


@lab_app.command("replay")
def lab_replay(
    scenario: Annotated[str, typer.Argument(help="Scenario name or file.")],
    url: Annotated[
        str, typer.Option(help="nyctala ingest URL, e.g. http://10.8.0.1:8514/v1/ingest")
    ],
) -> None:
    """Send a scenario, timed to end now, to a running nyctala. Token from $NYCTALA_TOKEN."""
    from nyctala.lab.scenario import load_scenario, replay

    token = os.environ.get("NYCTALA_TOKEN")
    if not token:
        raise typer.BadParameter(
            "set NYCTALA_TOKEN to the sensor token (never pass it as an argument)"
        )
    (path,) = _scenario_paths([scenario])
    accepted = replay(load_scenario(path), url, token)
    typer.echo(f"accepted {accepted} events")


@app.command()
def health(
    data: DataDir = Path("data"),
    silence: Annotated[float, typer.Option(help="Minutes without events = silent.", min=1)] = 15,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Status of every log source: silent sources, lag, skew, parse failures. Exit 1 on problems."""
    from datetime import UTC, datetime, timedelta

    from nyctala.health.monitor import HealthMonitor
    from nyctala.health.sources import HealthPolicy, source_health
    from nyctala.store import EventStore

    store = EventStore(data)
    now = datetime.now(UTC)
    sensors = HealthMonitor(store, _registry(data)).active_sensors()
    statuses = source_health(store, sensors, now, HealthPolicy(silence=timedelta(minutes=silence)))
    if as_json:
        for st in statuses:
            typer.echo(json.dumps(st.to_record(now), default=str))
    else:
        for st in statuses:
            last = f"{st.last_ingested:%Y-%m-%d %H:%M:%S}" if st.last_ingested else "never"
            lag = f"p50={st.lag_p50:.1f}s p95={st.lag_p95:.1f}s" if st.lag_p95 is not None else "-"
            typer.echo(
                f"{st.status:<10} {st.sensor + '/' + (st.dataset or '*'):<28} last={last}  "
                f"events(1h)={st.events:<6} lag {lag}  future={st.future} unparsed={st.unparsed}"
            )
    if any(st.status != "ok" or st.future for st in statuses):
        raise typer.Exit(1)


@integrity_app.command("verify")
def integrity_verify(
    data: DataDir = Path("data"),
    anchors: Annotated[
        Path | None, typer.Option(help="Anchors recorded earlier (NDJSON from `integrity anchor`).")
    ] = None,
) -> None:
    """Recompute every event hash and walk each sensor's chain. Exit 1 on any damage."""
    from nyctala.health.integrity import read_anchors, verify
    from nyctala.store import EventStore

    recorded = read_anchors(anchors.read_text().splitlines()) if anchors else None
    reports = verify(EventStore(data), recorded)
    for r in reports:
        state = "OK    " if r.ok else "BROKEN"
        head = r.head[:16] if r.head else "-"
        unsealed = f"  ({r.unsealed} unsealed)" if r.unsealed else ""
        typer.echo(f"{state} {r.sensor:<20} events={r.events:<8} head={head}{unsealed}")
        for problem in r.problems():
            typer.echo(f"       {problem}")
    if any(not r.ok for r in reports):
        raise typer.Exit(1)


@integrity_app.command("anchor")
def integrity_anchor(data: DataDir = Path("data")) -> None:
    """Print the current chain heads as NDJSON, to append to an off-host log."""
    from datetime import UTC, datetime

    from nyctala.health.integrity import anchors_now
    from nyctala.store import EventStore

    at = datetime.now(UTC).isoformat()
    for anchor in anchors_now(EventStore(data)):
        typer.echo(json.dumps({"at": at, **anchor}))


@app.command()
def detect(
    data: DataDir = Path("data"),
    rules_dir: Annotated[
        Path | None, typer.Option("--rules", help="Rules directory (default: bundled rules).")
    ] = None,
    interval: Annotated[float, typer.Option(help="Seconds between runs.", min=1)] = 10.0,
    once: Annotated[bool, typer.Option("--once", help="Run a single pass and exit.")] = False,
    anchors: Annotated[
        Path | None,
        typer.Option(help="Anchors file to verify the hash chains against (see integrity anchor)."),
    ] = None,
) -> None:
    """Run the detection job and health checks: store alerts and print each new one."""
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

    from nyctala.health.monitor import HealthMonitor

    def emit_health(alerts: list[Alert]) -> None:
        for alert in alerts:
            typer.echo(_alert_line(alert))

    monitor = HealthMonitor(store, _registry(data), emit_health, anchors=anchors)
    job = DetectionJob(store, ruleset, emit, interval=interval, hooks=[monitor.tick])
    if once:
        job.run_once()
        return
    stop = threading.Event()
    try:
        job.run_forever(stop)
    except KeyboardInterrupt:
        stop.set()


def _alert_line(alert: Alert) -> str:
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
