"""nyctala command line."""

import json
import os
from pathlib import Path
from typing import Annotated

import typer

from nyctala.ingest.sensors import SensorError, SensorRegistry

app = typer.Typer(no_args_is_help=True, help="Lightweight detection-engineering SIEM.")
sensor_app = typer.Typer(no_args_is_help=True, help="Manage sensors and their ingest tokens.")
app.add_typer(sensor_app, name="sensor")
rules_app = typer.Typer(no_args_is_help=True, help="Detection rules.")
app.add_typer(rules_app, name="rules")

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
) -> None:
    """Run every rule against its positive and negative fixtures. Exit 1 on any failure."""
    from nyctala.engine.testing import RULES_DIR, run_rule_tests

    results = run_rule_tests(rules_dir or RULES_DIR)
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
