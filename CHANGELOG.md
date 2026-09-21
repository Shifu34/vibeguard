# Changelog

All notable changes to VibeGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] — 2026-09-21

First public release.

### Added
- Secret scanner with 31 detection rules: AWS (access key, secret key,
  session token), Azure storage keys, GCP service-account hints, Stripe
  (live + restricted), Twilio, SendGrid, Mailgun, GitHub tokens (classic,
  fine-grained, OAuth, app), GitLab PATs, npm + PyPI tokens, Heroku,
  DigitalOcean, Cloudflare, Slack tokens + webhooks, Discord bot tokens +
  webhooks, OpenAI (API, project, service-account), Anthropic, Hugging Face,
  Google API keys, private key blocks, database connection strings, plus
  generic secret-assignment and high-entropy heuristics.
- `vibeguard scan` with `--staged` (default), `--all`, and `--base <ref>`
  targets; path limiting; JSON and SARIF 2.1.0 output formats.
- Optional LLM review of diffs via any OpenAI-compatible endpoint
  (`VIBEGUARD_API_KEY`), flagging injection flaws, auth bypass, and other
  logic-level issues regexes can't see.
- Pre-commit hook (`.pre-commit-hooks.yaml`) and GitHub Action (`action.yml`)
  with an example PR workflow.
- `.vibeguard.toml` configuration: `fail_on` severity threshold, `allowlist`
  globs, LLM settings. `vibeguard init` writes a starter config.
- CI workflow: pytest on Python 3.10 / 3.11 / 3.12, plus a dogfood step
  that scans the VibeGuard repo itself.

### Notes
- Python 3.10 installs the tiny `tomli` backport (stdlib `tomllib` on 3.11+).
  The scanner itself is stdlib-only.
