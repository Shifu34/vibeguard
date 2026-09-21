"""Baseline support: record known findings, only report new ones.

A baseline file stores fingerprints of findings you have already triaged.
On later scans, matching findings are suppressed so CI only fails on
*new* secrets. Fingerprints deliberately exclude line numbers, so a
secret that moves within a file stays baselined.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from . import __version__
from .scanners.secrets import Finding

BASELINE_VERSION = 1
DEFAULT_BASELINE_PATH = ".vibeguard-baseline.json"


def fingerprint(finding: Finding) -> str:
    """Stable fingerprint for a finding: rule + file + matched content.

    Line numbers are excluded on purpose: moving a known secret to a
    different line in the same file does not un-baseline it.
    """
    payload = "\x00".join([finding.rule, finding.file, finding.snippet])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Baseline:
    fingerprints: set[str]

    @property
    def count(self) -> int:
        return len(self.fingerprints)


def load_baseline(path: str) -> Baseline:
    """Load a baseline file. Raises FileNotFoundError if it does not exist,
    ValueError if it is not a readable VibeGuard baseline."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"baseline file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read baseline file {path}: {exc}") from exc
    prints = data.get("fingerprints")
    if not isinstance(prints, list) or not all(isinstance(p, str) for p in prints):
        raise ValueError(f"invalid baseline file {path}: 'fingerprints' must be a list of strings")
    return Baseline(fingerprints=set(prints))


def save_baseline(path: str, findings: list[Finding]) -> Baseline:
    """Write current findings as a new baseline file. Returns the baseline."""
    baseline = Baseline(fingerprints={fingerprint(f) for f in findings})
    payload = {
        "version": BASELINE_VERSION,
        "generator": f"vibeguard {__version__}",
        "count": baseline.count,
        "fingerprints": sorted(baseline.fingerprints),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return baseline


def apply_baseline(
    findings: list[Finding], baseline: Baseline
) -> tuple[list[Finding], int]:
    """Split findings into (new_findings, suppressed_count)."""
    fresh = [f for f in findings if fingerprint(f) not in baseline.fingerprints]
    return fresh, len(findings) - len(fresh)
