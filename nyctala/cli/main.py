"""nyctala command line."""

import os
from pathlib import Path
from typing import Annotated

import typer

from nyctala.ingest.sensors import SensorError, SensorRegistry

app = typer.Typer(no_args_is_help=True, help="Lightweight detection-engineering SIEM.")
sensor_app = typer.Typer(no_args_is_help=True, help="Manage sensors and their ingest tokens.")
app.add_typer(sensor_app, name="sensor")

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
