import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nyctala.cli.main import app
from nyctala.engine.testing import RULES_DIR, run_rule_tests

runner = CliRunner()
SUDO_BASH = (
    "Oct 22 10:00:01 vps-a sudo:     kris : TTY=pts/0 ; PWD=/home/kris ; "
    "USER=root ; COMMAND=/bin/bash"
)


def raw(line: str) -> str:
    return json.dumps({"message": line, "event.dataset": "auth_log"}) + "\n"


@pytest.fixture
def rules(tmp_path: Path) -> Path:
    return Path(shutil.copytree(RULES_DIR, tmp_path / "rules"))


def test_bundled_rules_pass() -> None:
    results = run_rule_tests()
    assert len(results) >= 5
    assert [r.name for r in results if not r.passed] == []


def test_cli_passes_on_bundled_rules() -> None:
    result = runner.invoke(app, ["rules", "test"])
    assert result.exit_code == 0, result.output
    assert "rules passed" in result.output


# --- checkpoint: a rule with a false positive breaks the run -----------------------


def test_false_positive_fails(rules: Path) -> None:
    # A benign event the rule wrongly flags: the negative fixture now matches.
    with (rules / "tests/negative/sudo_root_shell.ndjson").open("a") as f:
        f.write(raw(SUDO_BASH))
    result = runner.invoke(app, ["rules", "test", str(rules)])
    assert result.exit_code == 1
    assert "FAIL  sudo_root_shell" in result.output
    assert "false positives: 1 negative event(s) matched" in result.output


def test_too_broad_rule_fails(rules: Path) -> None:
    path = rules / "crontab_modification.yml"
    path.write_text(path.read_text().replace("      - crontab_delete\n", "      - crontab_*\n"))
    (result,) = [r for r in run_rule_tests(rules) if r.name == "crontab_modification"]
    assert not result.passed
    assert result.negative_matched > 0


def test_false_negative_fails(rules: Path) -> None:
    with (rules / "tests/positive/sudo_root_shell.ndjson").open("a") as f:
        f.write(raw(SUDO_BASH.replace("/bin/bash", "/usr/bin/id")))
    result = runner.invoke(app, ["rules", "test", str(rules)])
    assert result.exit_code == 1
    assert "false negatives: 1 positive event(s) not matched" in result.output


@pytest.mark.parametrize("polarity", ["positive", "negative"])
def test_missing_fixture_fails(rules: Path, polarity: str) -> None:
    (rules / f"tests/{polarity}/web_sqli_pattern.ndjson").unlink()
    (result,) = [r for r in run_rule_tests(rules) if r.name == "web_sqli_pattern"]
    assert not result.passed
    assert any("missing fixture" in e for e in result.errors)


def test_empty_fixture_fails(rules: Path) -> None:
    (rules / "tests/negative/web_sqli_pattern.ndjson").write_text("\n")
    (result,) = [r for r in run_rule_tests(rules) if r.name == "web_sqli_pattern"]
    assert any("empty fixture" in e for e in result.errors)


def test_invalid_fixture_line_fails(rules: Path) -> None:
    with (rules / "tests/negative/web_sqli_pattern.ndjson").open("a") as f:
        f.write('{"message": "x", "event.dataset": "nope"}\n')
    (result,) = [r for r in run_rule_tests(rules) if r.name == "web_sqli_pattern"]
    assert any("unknown dataset" in e for e in result.errors)


def test_rule_without_technique_fails(rules: Path) -> None:
    path = rules / "http_large_response.yml"
    path.write_text(path.read_text().replace("  - attack.t1041\n", ""))
    (result,) = [r for r in run_rule_tests(rules) if r.name == "http_large_response"]
    assert result.errors == ["no ATT&CK technique tag (attack.tNNNN)"]


def test_broken_rule_is_reported_not_crashing(rules: Path) -> None:
    path = rules / "ssh_failed_login.yml"
    path.write_text(path.read_text().replace("event.outcome:", "event.outcom:"))
    result = runner.invoke(app, ["rules", "test", str(rules)])
    assert result.exit_code == 1
    assert "unknown field: 'event.outcom'" in result.output
    assert "4/5 rules passed" in result.output


def test_no_rules_fails(tmp_path: Path) -> None:
    assert runner.invoke(app, ["rules", "test", str(tmp_path)]).exit_code == 1


def test_json_report() -> None:
    result = runner.invoke(app, ["rules", "test", "--json"])
    report = json.loads(result.output)
    sqli = next(r for r in report if r["rule"] == "web_sqli_pattern")
    assert sqli["passed"] is True
    assert sqli["techniques"] == ["T1190"]
    assert sqli["negative"]["matched"] == 0
