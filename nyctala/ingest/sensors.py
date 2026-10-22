"""Per-sensor ingest tokens.

Only the SHA-256 of each token is stored. Tokens are 256-bit random values, so a
fast hash is enough: there is nothing to brute-force offline. The registry file
is re-read when it changes, so revoking a sensor takes effect without a restart.
"""

import hashlib
import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TOKEN_PREFIX = "nyc_"  # noqa: S105 (prefix, not a secret)
SENSOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class SensorError(ValueError):
    pass


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SensorRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._mtime: int | None = None
        self._by_digest: dict[str, str] = {}

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        sensors: dict[str, dict[str, Any]] = json.loads(self.path.read_text())["sensors"]
        return sensors

    def _write(self, sensors: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"sensors": sensors}, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def _reload(self) -> None:
        mtime = self.path.stat().st_mtime_ns if self.path.exists() else None
        if mtime == self._mtime:
            return
        self._by_digest = {
            s["token_sha256"]: sensor_id
            for sensor_id, s in self._read().items()
            if not s.get("revoked")
        }
        self._mtime = mtime

    def add(self, sensor_id: str) -> str:
        """Register ``sensor_id`` and return its token. The token is not stored."""
        if not SENSOR_ID.match(sensor_id):
            raise SensorError(f"invalid sensor id: {sensor_id!r}")
        sensors = self._read()
        if sensor_id in sensors:
            raise SensorError(f"sensor already exists: {sensor_id}")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        sensors[sensor_id] = {
            "token_sha256": _digest(token),
            "created": datetime.now(UTC).isoformat(),
            "revoked": False,
        }
        self._write(sensors)
        return token

    def revoke(self, sensor_id: str) -> None:
        sensors = self._read()
        if sensor_id not in sensors:
            raise SensorError(f"unknown sensor: {sensor_id}")
        sensors[sensor_id]["revoked"] = True
        sensors[sensor_id]["revoked_at"] = datetime.now(UTC).isoformat()
        self._write(sensors)

    def list(self) -> dict[str, dict[str, Any]]:
        return {
            sensor_id: {k: v for k, v in s.items() if k != "token_sha256"}
            for sensor_id, s in self._read().items()
        }

    def authenticate(self, token: str) -> str | None:
        """Return the sensor id owning ``token``, or None if unknown or revoked."""
        if not token.startswith(TOKEN_PREFIX) or len(token) > 128:
            return None
        self._reload()
        return self._by_digest.get(_digest(token))
