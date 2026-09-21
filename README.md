# 🛡️ VibeGuard

**Your AI coding agent writes fast. It also commits AWS keys at 2am.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](pyproject.toml)

VibeGuard is a pre-commit hook and GitHub Action that stops AI-generated code from shipping secrets, hardcoded API keys, and security holes — before they ever reach your repo.

![VibeGuard catching a leaked Stripe key](docs/demo.gif)

> *Record a 20-second terminal GIF of VibeGuard catching a secret and drop it at `docs/demo.gif` — it's the single highest-ROI asset for launch day.*

---

## The problem

AI coding agents are incredible — and they have zero survival instinct. They'll happily:

- Hardcode your Stripe live key "just to get it working"
- Commit a `.env` with production credentials
- Write SQL with string concatenation and call it done

VibeGuard sits between your agent and your repo and says **no**.

## Quickstart

```bash
pip install vibeguard
vibeguard init        # writes .vibeguard.toml
```

Add to your pre-commit config:

```yaml
repos:
  - repo: https://github.com/Shifu34/vibeguard
    rev: v0.1.0
    hooks:
      - id: vibeguard
```

```bash
pre-commit install
```

That's it. The next time your agent stages a secret, the commit is blocked:

```
VibeGuard found 2 potential secret(s):

  HIGH   src/payments.py:14  stripe-live-key
         Stripe live secret key
         stripe.api_key = "sk_live_4eC39HqLyjW..."

  MEDIUM src/config.py:3  high-entropy-secret
         High-entropy value assigned to 'api_token' (possible hardcoded secret)

Remove the secret, or allowlist the path in .vibeguard.toml
```

## What it catches

| Rule | Severity | Example |
|---|---|---|
| AWS access / secret / session keys | high/high/medium | `AKIAIOSFODNN7EXAMPLE` |
| Azure storage keys, GCP service-account keys | high | `AccountKey=...`, `"type": "service_account"` |
| Stripe live & restricted keys | high | `sk_live_...` |
| Twilio, SendGrid, Mailgun keys | high | `SK...`, `SG...`, `key-...` |
| GitHub tokens (PAT, OAuth, app) | high | `ghp_...`, `gho_...` |
| GitLab PATs, npm / PyPI tokens | high | `glpat-...`, `npm_...`, `pypi-...` |
| Heroku, DigitalOcean, Cloudflare tokens | high/high/medium | `dop_v1_...` |
| Slack tokens & webhooks | high | `xoxb-...` |
| Discord bot tokens & webhooks | high | `discord.com/api/webhooks/...` |
| OpenAI, Anthropic, Hugging Face, Google keys | high | `sk-...`, `sk-ant-...`, `hf_...`, `AIza...` |
| Private key blocks | high | `-----BEGIN RSA PRIVATE KEY-----` |
| DB connection strings with credentials | high | `postgres://admin:s3cret@...` |
| High-entropy assignments | medium | `api_token = "a9F3kQ7z..."` (no known prefix needed) |

32 rules total, plus a generic secret-assignment pattern for the long tail.

Plus an **optional LLM review** that reads the actual diff and flags what regexes can't: SQL injection, auth bypass, insecure crypto, SSRF, path traversal. Enable it with:

```toml
[llm]
enabled = true
model = "gpt-4o-mini"   # any OpenAI-compatible endpoint works
```

```bash
export VIBEGUARD_API_KEY="..."
```

## GitHub Action

Scan every PR diff automatically:

```yaml
- uses: Shifu34/vibeguard@v0.1.0
  with:
    base: origin/${{ github.base_ref }}
    # llm-review: "true"
    # api-key: ${{ secrets.VIBEGUARD_API_KEY }}
```

## Configuration

`vibeguard init` writes a `.vibeguard.toml` — all knobs in one place:

```toml
fail_on = "high"   # "high" or "medium"

allowlist = [
  "*.md",
  "docs/**",
  "tests/**",
]

[llm]
enabled = false
model = "gpt-4o-mini"
# base_url = "https://api.openai.com/v1"
```

Manual scans:

```bash
vibeguard scan            # staged changes (what's about to commit)
vibeguard scan --all      # every tracked file
vibeguard scan --base origin/main   # diff against a branch (CI)
vibeguard scan --format json        # machine-readable output
vibeguard scan --format sarif       # SARIF 2.1.0 (e.g. for GitHub code scanning)
```

## Why not gitleaks / trufflehog?

Those are excellent secret scanners — VibeGuard happily stands on their shoulders conceptually. The difference:

- **Built for the agent era**: the threat isn't a tired dev, it's a tireless agent committing at machine speed. VibeGuard is optimized for pre-commit speed and agent workflows.
- **LLM diff review**: catches logic-level vulnerabilities (injection, auth bypass), not just known secret formats.
- **60-second setup**: one pip install, one pre-commit block, zero config required.
- **Zero dependencies**: the core scanner is stdlib-only Python.

## Roadmap

- [ ] More secret rules (Twilio auth tokens, Vault tokens, ...)
- [ ] `.env` and config-file aware scanning
- [ ] VS Code / JetBrains extensions
- [ ] `vibeguard --fix`: auto-move secrets to env vars

## Contributing

PRs welcome — especially new secret rules with tests. See `tests/test_secrets.py` for the pattern: one rule, one test, one line of regex.

```bash
pip install -e ".[dev]" 2>/dev/null || pip install -e .
python -m pytest
```

## License

MIT — go build something safe with it.

---

⭐ **If VibeGuard saves you from one leaked key, give it a star. That's the whole business model.**
