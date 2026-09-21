"""Tests for baseline recording and suppression (v0.2.0)."""
import json
import os

import pytest

from vibeguard import cli
from vibeguard.baseline import (
    apply_baseline,
    fingerprint,
    load_baseline,
    save_baseline,
)
from vibeguard.cli import main
from vibeguard.scanners.secrets import Finding


def _finding(**over):
    base = dict(file="src/pay.py", line=14, rule="stripe-live-key",
                severity="high", snippet="sk_live_abc123",
                description="Stripe live secret key")
    base.update(over)
    return Finding(**base)


# --- fingerprint ---

def test_fingerprint_ignores_line_numbers():
    a = _finding(line=14)
    b = _finding(line=87)  # same secret, moved within the file
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_per_secret_and_rule():
    assert fingerprint(_finding()) != fingerprint(_finding(snippet="sk_live_xyz999"))
    assert fingerprint(_finding()) != fingerprint(_finding(rule="generic-secret-assignment"))
    assert fingerprint(_finding()) != fingerprint(_finding(file="src/other.py"))


# --- save / load ---

def test_save_load_roundtrip(tmp_path):
    path = str(tmp_path / "baseline.json")
    findings = [_finding(), _finding(snippet="sk_live_xyz999")]
    saved = save_baseline(path, findings)
    assert saved.count == 2
    loaded = load_baseline(path)
    assert loaded.fingerprints == saved.fingerprints
    # file is human-readable JSON with metadata
    data = json.loads(open(path).read())
    assert data["version"] == 1
    assert data["count"] == 2
    assert len(data["fingerprints"]) == 2


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_baseline(str(tmp_path / "nope.json"))


def test_load_invalid_file_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"fingerprints": "not-a-list"}')
    with pytest.raises(ValueError):
        load_baseline(str(path))


def test_save_empty_findings(tmp_path):
    path = str(tmp_path / "empty.json")
    assert save_baseline(path, []).count == 0
    assert load_baseline(path).count == 0


# --- apply_baseline ---

def test_apply_baseline_partitions(tmp_path):
    known_secret, new_secret = _finding(), _finding(snippet="sk_live_brand_new")
    baseline_path = str(tmp_path / "b.json")
    save_baseline(baseline_path, [known_secret])
    fresh, suppressed = apply_baseline([known_secret, new_secret],
                                       load_baseline(baseline_path))
    assert fresh == [new_secret]
    assert suppressed == 1


# --- CLI wiring (git-free via monkeypatched _collect) ---

@pytest.fixture
def canned_scan(monkeypatch, tmp_path):
    """Run CLI commands in an empty dir with _collect stubbed out."""
    monkeypatch.chdir(tmp_path)
    findings = [_finding(), _finding(file="src/db.py", line=2,
                                     rule="db-connection-string",
                                     snippet="postgres://u:p@host/db",
                                     description="DB conn string")]
    monkeypatch.setattr(cli, "_collect", lambda *a, **k: ("", list(findings)))
    return findings


def test_update_baseline_records_and_exits_zero(canned_scan, tmp_path, capsys):
    path = str(tmp_path / "base.json")
    assert main(["scan", "--update-baseline", path]) == 0
    out = capsys.readouterr().out
    assert "recorded 2 finding(s)" in out
    assert load_baseline(path).count == 2


def test_update_baseline_bare_flag_uses_default_path(canned_scan, tmp_path):
    assert main(["scan", "--update-baseline"]) == 0
    assert load_baseline(str(tmp_path / ".vibeguard-baseline.json")).count == 2


def test_baseline_suppresses_known_findings(canned_scan, tmp_path, capsys):
    path = str(tmp_path / "base.json")
    assert main(["scan", "--update-baseline", path]) == 0
    capsys.readouterr()
    # Same findings -> all suppressed -> exit 0, no failure
    assert main(["scan", "--baseline", path]) == 0
    out = capsys.readouterr().out
    assert "no secrets found" in out
    assert "2 finding(s) suppressed by baseline" in out


def test_baseline_reports_new_findings(canned_scan, tmp_path, monkeypatch, capsys):
    path = str(tmp_path / "base.json")
    assert main(["scan", "--update-baseline", path]) == 0
    capsys.readouterr()
    # A brand-new secret appears alongside the baselined ones
    new = _finding(file="src/new.py", line=1, snippet="sk_live_totally_new")
    monkeypatch.setattr(cli, "_collect",
                        lambda *a, **k: ("", canned_scan + [new]))
    assert main(["scan", "--baseline", path]) == 1  # high severity -> fail
    out = capsys.readouterr().out
    assert "2 finding(s) suppressed by baseline" in out
    assert "src/new.py" in out


def test_baseline_missing_file_errors(canned_scan, tmp_path, capsys):
    assert main(["scan", "--baseline", str(tmp_path / "missing.json")]) == 2
    assert "baseline file not found" in capsys.readouterr().err


def test_baseline_and_update_are_mutually_exclusive(canned_scan, tmp_path, capsys):
    rc = main(["scan", "--baseline", "a.json", "--update-baseline", "b.json"])
    assert rc == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_baseline_from_config(canned_scan, tmp_path, capsys):
    (tmp_path / ".vibeguard.toml").write_text(
        'baseline = "from-config.json"\nallowlist = []\n')
    assert main(["scan", "--update-baseline"]) == 0  # bare flag -> config path
    capsys.readouterr()
    assert main(["scan"]) == 0  # config baseline suppresses everything
    assert "suppressed by baseline" in capsys.readouterr().out


def test_json_format_excludes_baselined(canned_scan, tmp_path, capsys):
    path = str(tmp_path / "base.json")
    assert main(["scan", "--update-baseline", path]) == 0
    capsys.readouterr()
    assert main(["scan", "--baseline", path, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_scan_without_baseline_still_fails_on_secrets(canned_scan):
    assert main(["scan"]) == 1
