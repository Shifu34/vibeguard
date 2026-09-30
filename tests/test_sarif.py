"""Validate VibeGuard's SARIF output against the official SARIF 2.1.0 schema.

The schema is vendored at tests/sarif-2.1.0.schema.json (downloaded from
https://json.schemastore.org/sarif-2.1.0.json) so the test needs no network.
jsonschema is a test-only dependency.
"""
import json
import os

import pytest

jsonschema = pytest.importorskip("jsonschema")

from vibeguard.cli import _sarif
from vibeguard.scanners.secrets import Finding, scan_text

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "sarif-2.1.0.schema.json")


@pytest.fixture(scope="module")
def sarif_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def _validate(findings, schema):
    log = json.loads(json.dumps(_sarif(findings)))  # must survive a JSON round-trip
    jsonschema.validate(log, schema)
    return log


def test_sarif_validates_with_high_and_medium_findings(sarif_schema):
    findings = scan_text('KEY="sk_test_' + "a" * 24 + '"\n', "billing.py")
    findings += scan_text("PuTTY-User-Key-File-2: ssh-rsa\n", "deploy/key.ppk")
    _validate(findings, sarif_schema)


def test_sarif_validates_with_no_findings(sarif_schema):
    _validate([], sarif_schema)


def test_sarif_validates_finding_without_file_or_line(sarif_schema):
    _validate(
        [
            Finding(
                file="",
                line=0,
                rule="private-key",
                severity="high",
                snippet="-----BEGIN RSA PRIVATE KEY-----",
                description="Private key block",
            )
        ],
        sarif_schema,
    )


def test_sarif_validates_every_builtin_rule(sarif_schema):
    """One synthetic finding per rule: the whole rule catalog must serialize."""
    from vibeguard.scanners.secrets import _RULES

    findings = [
        Finding(
            file="app.py",
            line=1,
            rule=rule_id,
            severity=severity,
            snippet="x",
            description=description,
        )
        for rule_id, description, severity, _ in _RULES
    ]
    log = _validate(findings, sarif_schema)
    rule_ids = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {rule_id for rule_id, _, _, _ in _RULES}
