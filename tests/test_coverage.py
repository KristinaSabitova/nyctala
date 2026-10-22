import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nyctala.cli.main import app
from nyctala.coverage.matrix import RuleRecord, current_digests, load_attack, measure
from nyctala.engine.testing import RULES_DIR

runner = CliRunner()


def test_bundled_attack_data() -> None:
    attack = load_attack()
    assert attack.version.startswith("20")
    assert attack.techniques["T1110.001"]["name"] == "Password Guessing"
    assert "credential-access" in attack.techniques["T1110.001"]["tactics"]
    assert "MITRE" in attack.notice


def test_only_passing_rules_count() -> None:
    cov = measure(
        [
            RuleRecord("good", ("T1110.001",), True, "d1"),
            RuleRecord("bad", ("T1190",), False, "d2"),
            RuleRecord("typo", ("T9999",), True, "d3"),
        ]
    )
    assert set(cov.covered) == {"T1110.001"}
    assert cov.failing == {"T1190": ["bad"]}
    assert cov.unknown == {"T9999": ["typo"]}
    assert (cov.rules_passed, cov.rules_total) == (2, 3)


def test_failing_rule_does_not_hide_a_covered_technique() -> None:
    cov = measure([RuleRecord("a", ("T1190",), True, "x"), RuleRecord("b", ("T1190",), False, "y")])
    assert cov.covered == {"T1190": ["a"]}
    assert cov.failing == {}


def test_changed_rule_is_stale() -> None:
    records = [RuleRecord("a", ("T1190",), True, "old"), RuleRecord("gone", ("T1041",), True, "z")]
    cov = measure(records, {"a": "new"})
    assert cov.covered == {}
    assert cov.stale == {"T1190": ["a"], "T1041": ["gone"]}


def test_by_tactic_places_technique_in_every_tactic() -> None:
    cov = measure([RuleRecord("a", ("T1078",), True, "x")])
    tactics = {t["shortname"]: covered for t, _, covered in cov.by_tactic()}
    for tactic in ("initial-access", "persistence", "privilege-escalation"):
        assert tactics[tactic] == ["T1078"]
    assert tactics["impact"] == []


def test_navigator_layer() -> None:
    layer = measure(
        [RuleRecord("a", ("T1190",), True, "x"), RuleRecord("b", ("T1190",), True, "y")]
    ).to_navigator()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["attack"] == "20"
    assert layer["techniques"] == [
        {"techniqueID": "T1190", "score": 2, "comment": "rules: a, b", "enabled": True}
    ]


def test_cli_coverage_runs_tests_now() -> None:
    result = runner.invoke(app, ["coverage"])
    assert result.exit_code == 0, result.output
    assert "rules passing: 11/11" in result.output
    assert "T1548.003" in result.output
    assert "not counted" not in result.output


def test_cli_coverage_json_and_navigator() -> None:
    data = json.loads(runner.invoke(app, ["coverage", "--format", "json"]).output)
    assert set(data["covered"]) == {
        "T1041",
        "T1053.003",
        "T1078",
        "T1110.001",
        "T1110.003",
        "T1190",
        "T1548.003",
    }
    layer = json.loads(runner.invoke(app, ["coverage", "--format", "navigator"]).output)
    assert len(layer["techniques"]) == 7


def test_recorded_run_and_stale_detection(tmp_path: Path) -> None:
    rules = Path(shutil.copytree(RULES_DIR, tmp_path / "rules"))
    data = tmp_path / "data"
    recorded = runner.invoke(app, ["rules", "test", str(rules), "--record", str(data)])
    assert recorded.exit_code == 0, recorded.output

    result = runner.invoke(app, ["coverage", "--data", str(data), "--rules", str(rules)])
    assert "recorded run" in result.output
    assert "covered: 7 of" in result.output

    # Editing a rule after its test run voids its contribution until re-tested.
    path = rules / "http_large_response.yml"
    path.write_text(path.read_text().replace("104857600", "1"))
    result = runner.invoke(app, ["coverage", "--data", str(data), "--rules", str(rules)])
    assert "covered: 6 of" in result.output
    assert "not counted (stale): T1041  http_large_response" in result.output


def test_digest_covers_fixtures(tmp_path: Path) -> None:
    rules = Path(shutil.copytree(RULES_DIR, tmp_path / "rules"))
    before = current_digests(rules)
    with (rules / "tests/negative/web_sqli_pattern.ndjson").open("a") as f:
        f.write("\n")
    after = current_digests(rules)
    changed = [name for name in before if before[name] != after[name]]
    assert changed == ["web_sqli_pattern"]


def test_cli_coverage_without_recorded_run(tmp_path: Path) -> None:
    result = runner.invoke(app, ["coverage", "--data", str(tmp_path)])
    assert result.exit_code != 0


@pytest.mark.parametrize("fmt", ["xml", ""])
def test_cli_coverage_bad_format(fmt: str) -> None:
    assert runner.invoke(app, ["coverage", "--format", fmt]).exit_code != 0
