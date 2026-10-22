import importlib

import pytest

import nyctala

SUBPACKAGES = ["ingest", "parsers", "schema", "store", "engine", "coverage", "lab", "health", "cli"]


def test_version() -> None:
    assert nyctala.__version__ == "0.0.1"


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackage_imports(name: str) -> None:
    importlib.import_module(f"nyctala.{name}")
