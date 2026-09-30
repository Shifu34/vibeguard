"""Per-rule detection tests for every VibeGuard secret pattern."""
from vibeguard.scanners.secrets import scan_text


def _has_rule(findings, rule):
    return any(f.rule == rule for f in findings)


def test_npm_token_detected():
    findings = scan_text('NPM_TOKEN="npm_abcdefghij1234567890abcdefghij12345678"\n', "x.js")
    assert _has_rule(findings, "npm-token")


def test_pypi_token_detected():
    findings = scan_text(
        'token = "pypi-AgEIcHlwaS5vcmcuMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw"\n',
        "pypirc",
    )
    assert _has_rule(findings, "pypi-token")


def test_twilio_api_key_detected():
    # Assembled at runtime so the full SK+32-hex pattern never appears as a
    # literal in this file (avoids tripping GitHub push protection).
    key = "SK" + "abcdef12" * 4
    findings = scan_text(f'TWILIO_KEY="{key}"\n', "app.py")
    assert _has_rule(findings, "twilio-api-key")


def test_discord_bot_token_detected():
    token = "Mxxxxxxxxxxxxxxxxxxxxxxx.yyyyyy.zzzzzzzzzzzzzzzzzzzzzzzzzzz"
    findings = scan_text(f'BOT_TOKEN="{token}"\n', "bot.py")
    assert _has_rule(findings, "discord-bot-token")


def test_discord_webhook_detected():
    url = "https://discord.com/api/webhooks/1234567890/AbC_dEf-GhI0123456789jKlMnOp"
    findings = scan_text(f'WEBHOOK="{url}"\n', "bot.py")
    assert _has_rule(findings, "discord-webhook")


def test_sendgrid_api_key_detected():
    key = "SG." + "a" * 22 + "." + "b" * 43
    findings = scan_text(f'SENDGRID_KEY="{key}"\n', "mail.py")
    assert _has_rule(findings, "sendgrid-api-key")


def test_mailgun_api_key_detected():
    # Assembled at runtime so the full key-32-hex pattern never appears as a
    # literal in this file (avoids tripping GitHub push protection).
    key = "key-" + "abcdef12" * 4
    findings = scan_text(f'MAILGUN_KEY="{key}"\n', "mail.py")
    assert _has_rule(findings, "mailgun-api-key")


def test_aws_session_token_detected():
    token = "FQoGZXIvYXdzE" + "a" * 120
    findings = scan_text(f'AWS_SESSION_TOKEN="{token}"\n', "app.py")
    assert _has_rule(findings, "aws-session-token")


def test_azure_storage_key_detected():
    key = "AccountKey=" + "A" * 86 + "=="
    findings = scan_text(f'STORAGE="DefaultEndpointsProtocol=https;{key}"\n', "app.py")
    assert _has_rule(findings, "azure-storage-key")


def test_gcp_service_account_detected():
    findings = scan_text('{\n  "type": "service_account",\n  "project_id": "x"\n}\n', "key.json")
    assert _has_rule(findings, "gcp-service-account")


def test_heroku_api_key_detected():
    findings = scan_text(
        'HEROKU_API_KEY="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"\n', "app.py"
    )
    assert _has_rule(findings, "heroku-api-key")


def test_digitalocean_token_detected():
    findings = scan_text(f'DO_TOKEN="dop_v1_{"a" * 64}"\n', "app.py")
    assert _has_rule(findings, "digitalocean-token")


def test_cloudflare_api_token_detected():
    findings = scan_text(f'CLOUDFLARE_API_TOKEN="{"c" * 40}"\n', "app.py")
    assert _has_rule(findings, "cloudflare-api-token")


def test_anthropic_api_key_detected():
    findings = scan_text(f'ANTHROPIC_KEY="sk-ant-api03-{"d" * 95}"\n', "app.py")
    assert _has_rule(findings, "anthropic-api-key")


def test_huggingface_token_detected():
    findings = scan_text(f'HF_TOKEN="hf_{"e" * 34}"\n', "app.py")
    assert _has_rule(findings, "huggingface-token")


def test_slack_webhook_detected():
    url = "https://hooks.slack.com/services/T12345678/B12345678/" + "f" * 24
    findings = scan_text(f'HOOK="{url}"\n', "app.py")
    assert _has_rule(findings, "slack-webhook")


def test_gitlab_pat_detected():
    findings = scan_text(f'GITLAB_TOKEN="glpat-{"g" * 20}"\n', "app.py")
    assert _has_rule(findings, "gitlab-pat")


def test_openai_api_key_strict_detected():
    findings = scan_text(f'OPENAI_KEY="sk-{"h" * 48}"\n', "app.py")
    assert _has_rule(findings, "openai-api-key")


def test_openai_project_key_detected():
    findings = scan_text(f'OPENAI_KEY="sk-proj-{"i" * 32}"\n', "app.py")
    assert _has_rule(findings, "openai-project-key")


def test_pgp_private_key_block_detected():
    findings = scan_text("-----BEGIN PGP PRIVATE KEY BLOCK-----\n", "key.asc")
    assert _has_rule(findings, "private-key")


def test_encrypted_private_key_detected():
    findings = scan_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "key.pem")
    assert _has_rule(findings, "private-key")


# --- Negatives: things that must NOT be flagged ---


def test_short_openai_like_key_not_flagged():
    assert scan_text('key = "sk-abc123"\n', "app.py") == []


def test_bare_uuid_without_context_not_flagged():
    assert scan_text('id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"\n', "app.py") == []


def test_short_placeholder_password_not_flagged():
    assert scan_text('password = "xxx"\n', "app.py") == []


def test_empty_secret_assignment_not_flagged():
    assert scan_text('api_key = ""\n', "app.py") == []


def test_documentation_example_keys_not_flagged():
    code = (
        "# Get your key at https://example.com — it looks like sk_live_...\n"
        'API_KEY = os.environ["STRIPE_KEY"]\n'
    )
    assert scan_text(code, "app.py") == []


def test_github_server_token_detected():
    # Assembled at runtime so the full ghs_ token never appears as a literal
    # in this file (avoids tripping GitHub push protection).
    findings = scan_text('GH_TOKEN="ghs_' + "a" * 36 + '"\n', "deploy.py")
    assert _has_rule(findings, "github-server-token")


def test_stripe_test_key_detected():
    findings = scan_text('KEY="sk_test_' + "a" * 24 + '"\n', "billing.py")
    assert _has_rule(findings, "stripe-test-key")


def test_stripe_test_key_is_medium_severity():
    findings = scan_text('KEY="sk_test_' + "a" * 24 + '"\n', "billing.py")
    matched = [f for f in findings if f.rule == "stripe-test-key"]
    assert matched and matched[0].severity == "medium"


def test_telegram_bot_token_detected():
    # Bot ID + colon + 35-char secret; assembled at runtime.
    token = "123456789:" + "f4ke" * 8 + "f4k"
    findings = scan_text(f'BOT="{token}"\n', "bot.py")
    assert _has_rule(findings, "telegram-bot-token")


def test_shopify_access_token_detected():
    findings = scan_text('SHOPIFY="shpat_' + "a" * 32 + '"\n', "store.py")
    assert _has_rule(findings, "shopify-access-token")


def test_sentry_auth_token_detected():
    findings = scan_text('SENTRY="sntrys_' + "a" * 64 + '"\n', "errors.py")
    assert _has_rule(findings, "sentry-auth-token")


def test_npmrc_auth_token_detected():
    findings = scan_text("//registry.npmjs.org/:_authToken=npm_" + "a" * 36 + "\n", ".npmrc")
    assert _has_rule(findings, "npmrc-auth-token")


def test_putty_private_key_detected():
    findings = scan_text("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\n", "key.ppk")
    assert _has_rule(findings, "putty-private-key")


def test_linear_api_key_detected():
    findings = scan_text('LINEAR="lin_api_' + "a" * 40 + '"\n', "issues.py")
    assert _has_rule(findings, "linear-api-key")
