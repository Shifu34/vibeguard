"""Smoke tests for the secret scanner."""
from vibeguard.scanners.secrets import scan_diff, scan_text


def test_aws_access_key_detected():
    findings = scan_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', "app.py")
    assert any(f.rule == "aws-access-key" and f.severity == "high" for f in findings)


def test_stripe_live_key_detected():
    # Key assembled at runtime so the full sk_live_ pattern never appears
    # as a literal in this file (avoids tripping GitHub push protection).
    key = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    findings = scan_text(f'stripe.api_key = "{key}"\n', "pay.py")
    assert any(f.rule == "stripe-live-key" for f in findings)


def test_private_key_block_detected():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----\n", "id_rsa")
    assert any(f.rule == "private-key" for f in findings)


def test_connection_string_detected():
    findings = scan_text('DB = "postgres://admin:s3cret@db.internal:5432/app"\n', "settings.py")
    assert any(f.rule == "db-connection-string" for f in findings)


def test_clean_code_has_no_findings():
    code = 'API_URL = "https://api.example.com/v1"\nTIMEOUT = 30\n'
    assert scan_text(code, "app.py") == []


def test_placeholder_values_not_flagged():
    findings = scan_text('api_key = "xxx-test-key-123"\n', "app.py")
    assert not any(f.rule == "high-entropy-secret" for f in findings)


def test_high_entropy_secret_detected():
    findings = scan_text('my_token = "a9F3kQ7zX2mN8pL5vB6wE1rT4yU"\n', "app.py")
    assert any(f.rule == "high-entropy-secret" for f in findings)


def test_diff_reports_new_file_line_numbers():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " line1\n"
        '+token = "xoxb-1234567890-abcdefghij"\n'
        " line2\n"
    )
    findings = scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].file == "app.py"
    assert findings[0].line == 2
    assert findings[0].rule == "slack-token"


def test_diff_ignores_removed_lines():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,1 @@\n"
        '-old_key = "AKIAIOSFODNN7EXAMPLE"\n'
        " line1\n"
    )
    assert scan_diff(diff) == []
