"""Configuration loading (.vibeguard.toml)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10: provided by the `tomli` dependency
    import tomli as tomllib  # type: ignore[no-redef]

CONFIG_FILENAME = ".vibeguard.toml"

EXAMPLE_CONFIG = """\
# VibeGuard configuration — created by `vibeguard init`
# Docs: https://github.com/Shifu34/vibeguard#configuration

# Fail (exit 1, block commit) on "high" or "medium"+ findings.
fail_on = "high"

# Paths never scanned. Supports fnmatch globs, matched against the
# full relative path and the bare filename.
allowlist = [
  "*.md",
  "docs/**",
  "tests/**",
  "test_*.py",
]

[llm]
# Optional: have an LLM review the diff for security issues regexes miss
# (injection flaws, auth bypass, insecure crypto, SSRF...).
enabled = false
model = "gpt-4o-mini"
# Any OpenAI-compatible endpoint works:
# base_url = "https://api.openai.com/v1"
# Auth comes from the VIBEGUARD_API_KEY environment variable.
"""


@dataclass
class LlmConfig:
    enabled: bool = False
    model: str = "gpt-4o-mini"
    base_url: str = "https://api.openai.com/v1"


@dataclass
class Config:
    allowlist: list[str] = field(default_factory=lambda: ["*.md", "docs/**", "tests/**", "test_*.py"])
    fail_on: str = "high"
    llm: LlmConfig = field(default_factory=LlmConfig)


def load_config(path: str | None = None) -> Config:
    cfg = Config()
    target = path or CONFIG_FILENAME
    if not os.path.exists(target):
        return cfg
    with open(target, "rb") as fh:
        data = tomllib.load(fh)
    if isinstance(data.get("allowlist"), list):
        cfg.allowlist = [str(p) for p in data["allowlist"]]
    if data.get("fail_on") in ("high", "medium"):
        cfg.fail_on = data["fail_on"]
    llm = data.get("llm", {})
    if isinstance(llm, dict):
        cfg.llm.enabled = bool(llm.get("enabled", False))
        cfg.llm.model = str(llm.get("model", cfg.llm.model))
        cfg.llm.base_url = str(llm.get("base_url", cfg.llm.base_url))
    return cfg
