"""Secret detection: curated regex rules plus entropy heuristics.

Zero third-party dependencies. Built to catch what AI coding agents
love to hardcode at 2am: API keys, tokens, connection strings.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str  # "high" | "medium"
    snippet: str
    description: str


# (rule_id, description, severity, pattern)
# Severity discipline: "high" only for patterns that are unambiguous on
# their own (distinctive prefixes/formats). Context-dependent patterns
# (a name + a value) are "medium" even when the name is explicit.
_RULES: list[tuple[str, str, str, str]] = [
    # --- Cloud providers ---
    ("aws-access-key", "AWS access key ID", "high", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret-key", "AWS secret access key", "high",
     r"(?i)aws[\w-]{0,20}(?:secret|token)[\w-]{0,5}['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    ("aws-session-token", "AWS session token", "medium",
     r"(?i)aws_session_token['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]"),
    ("azure-storage-key", "Azure storage account key", "high",
     r"AccountKey=[A-Za-z0-9+/]{86}=="),
    ("gcp-service-account", "GCP service account key", "high",
     r'"type"\s*:\s*"service_account"'),
    # --- Payments / comms ---
    ("stripe-live-key", "Stripe live secret key", "high", r"sk_live_[0-9a-zA-Z]{16,}"),
    ("stripe-restricted-key", "Stripe restricted key", "high", r"rk_live_[0-9a-zA-Z]{16,}"),
    ("twilio-api-key", "Twilio API key", "high", r"SK[0-9a-fA-F]{32}"),
    ("sendgrid-api-key", "SendGrid API key", "high",
     r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    ("mailgun-api-key", "Mailgun API key", "high", r"key-[0-9a-fA-F]{32}"),
    # --- Dev platforms ---
    ("github-pat-classic", "GitHub classic personal access token", "high",
     r"ghp_[A-Za-z0-9]{36}"),
    ("github-oauth-token", "GitHub OAuth access token", "high", r"gho_[A-Za-z0-9]{36}"),
    ("github-app-token", "GitHub app installation token", "high", r"ghu_[A-Za-z0-9]{36}"),
    ("github-pat-finegrained", "GitHub fine-grained personal access token", "high",
     r"github_pat_[A-Za-z0-9_]{22,}"),
    ("gitlab-pat", "GitLab personal access token", "high", r"glpat-[A-Za-z0-9\-_]{20}"),
    ("npm-token", "npm access token", "high", r"npm_[A-Za-z0-9]{36}"),
    ("pypi-token", "PyPI API token", "high", r"pypi-[A-Za-z0-9\-_]{50,}"),
    ("heroku-api-key", "Heroku API key", "high",
     r"(?i)heroku(?:_api)?_key['\"]?\s*[:=]\s*['\"]?"
     r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("digitalocean-token", "DigitalOcean personal access token", "high",
     r"dop_v1_[a-f0-9]{64}"),
    ("cloudflare-api-token", "Cloudflare API token", "medium",
     r"(?i)cloudflare[\w-]{0,20}(?:api[_-]?)?token[\w-]{0,5}['\"]?\s*[:=]\s*['\"]?"
     r"[A-Za-z0-9\-_]{40}['\"]?"),
    # --- Chat / webhooks ---
    ("slack-token", "Slack API token", "high", r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    ("slack-webhook", "Slack incoming webhook URL", "high",
     r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{24,}"),
    ("discord-bot-token", "Discord bot token", "high",
     r"[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}"),
    ("discord-webhook", "Discord webhook URL", "high",
     r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
    # --- AI providers ---
    ("openai-api-key", "OpenAI API key", "high", r"sk-[A-Za-z0-9]{48}"),
    ("openai-project-key", "OpenAI project/service-account key", "high",
     r"sk-(?:proj-|svcacct-)[A-Za-z0-9\-_]{20,}"),
    ("anthropic-api-key", "Anthropic API key", "high",
     r"sk-ant-(?:api\d+-)?[A-Za-z0-9\-_]{20,}"),
    ("huggingface-token", "Hugging Face access token", "high", r"hf_[A-Za-z0-9]{34}"),
    ("google-api-key", "Google API key", "high", r"AIza[0-9A-Za-z\-_]{35}"),
    # --- Generic / crypto material ---
    ("private-key", "Private key block", "high",
     r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ("db-connection-string", "Database connection string with embedded credentials", "high",
     r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:]+:[^/\s@]+@"),
    ("generic-secret-assignment", "Hardcoded secret-like assignment", "medium",
     r"(?i)\b[\w.-]*(?:api[_-]?key|secret|passwd|password|auth[_-]?token)[\w.-]*\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
]

_COMPILED: list[tuple[str, str, str, re.Pattern]] = [
    (rule_id, description, severity, re.compile(pattern))
    for rule_id, description, severity, pattern in _RULES
]

MAX_LINE_LENGTH = 2000  # skip minified / generated blobs

_KEYLIKE_NAME = re.compile(r"(?i)^[\w.-]*(?:key|secret|token|passwd|password|credential)[\w.-]*$")
_ASSIGNMENT = re.compile(r"(?i)([\w.-]+)\s*[:=]\s*['\"]([^'\"]{20,200})['\"]")
_PLACEHOLDER = re.compile(r"(?i)(?:xxx+|example|sample|changeme|your[_-].*key|placeholder|\*+)")


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _entropy_scan_line(line: str, filename: str, lineno: int):
    """Catch secrets with no known prefix: high-entropy values on key-like names."""
    for match in _ASSIGNMENT.finditer(line):
        name, value = match.group(1), match.group(2)
        if not _KEYLIKE_NAME.match(name):
            continue
        if _PLACEHOLDER.search(value):
            continue
        if _shannon_entropy(value) >= 4.5:
            yield Finding(
                file=filename,
                line=lineno,
                rule="high-entropy-secret",
                severity="medium",
                snippet=line.strip()[:160],
                description=f"High-entropy value assigned to '{name}' (possible hardcoded secret)",
            )


def scan_text(text: str, filename: str = "", start_line: int = 1) -> list[Finding]:
    """Scan raw text, returning findings with 1-based line numbers."""
    findings: list[Finding] = []
    for offset, raw_line in enumerate(text.splitlines()):
        lineno = start_line + offset
        if len(raw_line) > MAX_LINE_LENGTH:
            continue
        hits_this_line = 0
        for rule_id, description, severity, rx in _COMPILED:
            for _ in rx.finditer(raw_line):
                findings.append(Finding(
                    file=filename,
                    line=lineno,
                    rule=rule_id,
                    severity=severity,
                    snippet=raw_line.strip()[:160],
                    description=description,
                ))
                hits_this_line += 1
        if hits_this_line == 0:
            findings.extend(_entropy_scan_line(raw_line, filename, lineno))
    return findings


def scan_diff(diff: str) -> list[Finding]:
    """Scan a unified diff, reporting findings against new-file line numbers.

    Binary files are skipped (git emits no text hunks for them, but we stay
    defensive). Renames are attributed to the new path; deleted files
    (``+++ /dev/null``) contribute nothing since only ``-`` lines change.
    """
    findings: list[Finding] = []
    current_file: str | None = None
    new_line = 0
    is_binary = False
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            current_file = None
            is_binary = False
        elif raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            is_binary = True
        elif raw.startswith("+++ "):
            path = raw[4:].strip().split("\t")[0]
            current_file = path[2:] if path.startswith("b/") else path
            if current_file == "/dev/null":
                current_file = None
        elif raw.startswith("@@ "):
            match = re.search(r"\+(\d+)", raw)
            new_line = int(match.group(1)) if match else 0
        elif current_file is None or is_binary:
            continue
        elif raw.startswith("+"):
            findings.extend(scan_text(raw[1:], current_file, start_line=new_line))
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1
        # '-', '---', 'index', 'new file mode', 'rename from/to' etc: intentionally ignored
    return findings
