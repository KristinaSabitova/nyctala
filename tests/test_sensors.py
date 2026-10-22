import stat
from pathlib import Path

import pytest

from nyctala.ingest.sensors import TOKEN_PREFIX, SensorError, SensorRegistry


@pytest.fixture
def registry(tmp_path: Path) -> SensorRegistry:
    return SensorRegistry(tmp_path / "sensors.json")


def test_add_and_authenticate(registry: SensorRegistry) -> None:
    token = registry.add("vps-a")
    assert token.startswith(TOKEN_PREFIX)
    assert registry.authenticate(token) == "vps-a"


def test_token_not_stored_in_clear(registry: SensorRegistry) -> None:
    token = registry.add("vps-a")
    assert token not in registry.path.read_text()
    assert stat.S_IMODE(registry.path.stat().st_mode) == 0o600


def test_tokens_are_unique(registry: SensorRegistry) -> None:
    assert registry.add("vps-a") != registry.add("vps-b")


@pytest.mark.parametrize("token", ["", "nyc_wrong", "x" * 1000, TOKEN_PREFIX + "a" * 500])
def test_unknown_token(registry: SensorRegistry, token: str) -> None:
    registry.add("vps-a")
    assert registry.authenticate(token) is None


def test_revoke_takes_effect_on_running_registry(registry: SensorRegistry) -> None:
    token = registry.add("vps-a")
    assert registry.authenticate(token) == "vps-a"
    SensorRegistry(registry.path).revoke("vps-a")  # e.g. from the CLI, another process
    assert registry.authenticate(token) is None
    assert registry.list()["vps-a"]["revoked"] is True


def test_list_hides_digest(registry: SensorRegistry) -> None:
    registry.add("vps-a")
    assert "token_sha256" not in registry.list()["vps-a"]


@pytest.mark.parametrize("sensor_id", ["../etc", "", "a b", "x" * 65])
def test_invalid_sensor_id(registry: SensorRegistry, sensor_id: str) -> None:
    with pytest.raises(SensorError):
        registry.add(sensor_id)


def test_duplicate_and_unknown(registry: SensorRegistry) -> None:
    registry.add("vps-a")
    with pytest.raises(SensorError):
        registry.add("vps-a")
    with pytest.raises(SensorError):
        registry.revoke("vps-z")
