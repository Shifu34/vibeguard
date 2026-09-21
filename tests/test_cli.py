"""CLI-level tests: formats, init, helpers."""
import json

import pytest

from vibeguard import __version__
from vibeguard.cli import _looks_binary, _sarif, build_parser, main
from vibeguard.config import EXAMPLE_CONFIG
from vibeguard.scanners.secrets import Finding


def _findings():
    return [
        Finding(file="src/pay.py", line=14, rule="stripe-live-key",
                severity="high", snippet="sk_live_...",
                description="Stripe live secret key"),
        Finding(file="src/cfg.py", line=3, rule="high-entropy-secret",
                severity="medium", snippet="x = ...",
                description="High-entropy value assigned to 'x'"),
        Finding(file="", line=0, rule="llm/sql-injection",
                severity="high", snippet="",
                description="Possible SQL injection"),
    ]


def test_sarif_is_valid_json_and_schema_shape():
    log = json.loads(json.dumps(_sarif(_findings())))
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "VibeGuard"
    assert run["tool"]["driver"]["version"] == __version__
    assert len(run["results"]) == 3


def test_sarif_result_fields_and_level_mapping():
    run = _sarif(_findings())["runs"][0]
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["stripe-live-key"]["level"] == "error"
    assert by_rule["high-entropy-secret"]["level"] == "warning"
    r = by_rule["stripe-live-key"]
    assert r["message"]["text"] == "Stripe live secret key"
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/pay.py"
    assert loc["region"]["startLine"] == 14


def test_sarif_omits_region_when_line_unknown():
    run = _sarif(_findings())["runs"][0]
    r = next(x for x in run["results"] if x["ruleId"] == "llm/sql-injection")
    assert "locations" not in r  # no file -> no locations at all


def test_sarif_dedupes_rules():
    findings = _findings() + [_findings()[0]]
    rules = _sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules].count("stripe-live-key") == 1


def test_sarif_empty_findings():
    log = _sarif([])
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_parser_accepts_sarif_format():
    args = build_parser().parse_args(["scan", "--format", "sarif"])
    assert args.format == "sarif"


def test_init_writes_example_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    content = (tmp_path / ".vibeguard.toml").read_text()
    assert content == EXAMPLE_CONFIG
    out = capsys.readouterr().out
    assert ".vibeguard.toml" in out


def test_init_is_idempotent(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".vibeguard.toml").write_text('fail_on = "medium"\n')
    assert main(["init"]) == 0
    assert (tmp_path / ".vibeguard.toml").read_text() == 'fail_on = "medium"\n'
    assert "already exists" in capsys.readouterr().out


def test_looks_binary(tmp_path):
    text_file = tmp_path / "a.py"
    text_file.write_text('x = 1\n')
    assert _looks_binary(str(text_file)) is False
    bin_file = tmp_path / "a.bin"
    bin_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01\x02")
    assert _looks_binary(str(bin_file)) is True
    assert _looks_binary(str(tmp_path / "missing")) is True


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_fail_on_flag_overrides_config(tmp_path, monkeypatch):
    """--fail-on medium fails on medium findings; --fail-on high does not."""
    import argparse
    from vibeguard.cli import cmd_scan
    from vibeguard.scanners.secrets import Finding
    # Simulate args with a medium-only finding
    args = argparse.Namespace(
        config=None, all=True, base=None, paths=[],
        format="text", llm=False, no_llm=True, fail_on="high",
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".vibeguard.toml").write_text('fail_on = "medium"\n')
    import vibeguard.cli as cli_mod
    monkeypatch.setattr(cli_mod, "_collect", lambda *a, **k: ("", [
        Finding(file="a.py", line=1, rule="x", severity="medium",
                snippet="", description=""),
    ]))
    # --fail-on high overrides config's medium -> exit 0
    assert cmd_scan(args) == 0
    # --fail-on medium -> exit 1
    args.fail_on = "medium"
    assert cmd_scan(args) == 1
    # No flag -> falls back to config (medium) -> exit 1
    args.fail_on = None
    assert cmd_scan(args) == 1
