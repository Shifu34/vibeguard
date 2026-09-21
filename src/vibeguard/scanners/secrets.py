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
_RULES: list[tuple[str, str, str, str]] = [
    ("aws-access-key", "AWS access key ID", "high", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret-key", "AWS secret access key", "high",
     r"(?i)aws[\w-]{0,20}(?:secret|token)[\w-]{0,5}['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    ("stripe-live-key", "Stripe live secret key", "high", r"sk_live_[0-9a-zA-Z]{16,}"),
    ("stripe-restricted-key", "Stripe restricted key", "high", r"rk_live_[0-9a-zA-Z]{16,}"),
    ("github-pat-classic", "GitHub classic personal access token", "high", r"ghp_[A-Za-z0-9]{36}"),
    ("github-oauth-token", "GitHub OAuth access token", "high", r"gho_[A-Za-z0-9]{36}"),
    ("github-app-token", "GitHub app installation token", "high", r"ghu_[A-Za-z0-9]{36}"),
    ("github-pat-finegrained", "GitHub fine-grained personal access token", "high",
     r"github_pat_[A-Za-z0-9_]{22,}"),
    ("slack-token", "Slack API token", "high", r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    ("google-api-key", "Google API key", "high", r"AIza[0-9A-Za-z\-_]{35}"),
    ("openai-api-key", "Possible OpenAI API key", "medium", r"sk-(?:proj-)?[A-Za-z0-9\-_]{20,}"),
    ("private-key", "Private key block", "high",
     r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
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
    """Scan a unified diff, reporting findings against new-file line numbers."""
    findings: list[Finding] = []
    current_file: str | None = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip().split("\t")[0]
            current_file = path[2:] if path.startswith("b/") else path
            if current_file == "/dev/null":
                current_file = None
        elif raw.startswith("@@ "):
            match = re.search(r"\+(\d+)", raw)
            new_line = int(match.group(1)) if match else 0
        elif current_file is None:
            continue
        elif raw.startswith("+"):
            findings.extend(scan_text(raw[1:], current_file, start_line=new_line))
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1
        # '-', 'diff --git', 'index', '---' etc: intentionally ignored
    return findings
