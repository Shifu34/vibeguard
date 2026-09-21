"""Optional LLM review of diffs for security issues regexes miss.

Disabled by default. Enable with `[llm] enabled = true` in .vibeguard.toml
(or the --llm flag) and set VIBEGUARD_API_KEY. Any OpenAI-compatible
chat-completions endpoint works.
"""
from __future__ import annotations

import json
import re
import urllib.request

SYSTEM_PROMPT = (
    "You are a senior application security engineer reviewing a unified diff. "
    "Find REAL security issues introduced by the added lines: hardcoded secrets, "
    "injection flaws (SQL, command, XSS), insecure crypto, authentication bypass, "
    "SSRF, path traversal, dangerous deserialization. Ignore style issues. "
    "Be conservative: only report issues you are confident about.\n\n"
    "Return ONLY a JSON array, no markdown fences, no commentary. Each item:\n"
    '{"file": "<path>", "line": <new-file line number, or 0 if unknown>, '
    '"rule": "<short-slug>", "severity": "high|medium", "description": "<one sentence>"}.\n'
    "Return [] if the diff is clean."
)

_MAX_DIFF_CHARS = 60_000


def _extract_json(text: str) -> list:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    return json.loads(text[start:end + 1])


def review_diff(diff_text: str, model: str, base_url: str, api_key: str,
                timeout: int = 90) -> list[dict]:
    """Send the diff for review. Returns a list of finding dicts.

    Raises RuntimeError on API failure so the caller can warn and continue
    with the regex scan instead of blocking the commit.
    """
    payload = json.dumps({
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Review this diff:\n\n" + diff_text[:_MAX_DIFF_CHARS]},
        ],
    }).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode())
    except Exception as exc:  # network / auth / timeout
        raise RuntimeError(str(exc)) from exc
    try:
        content = body["choices"][0]["message"]["content"]
        items = _extract_json(content)
    except (KeyError, IndexError, ValueError) as exc:
        raise RuntimeError(f"could not parse model response: {exc}") from exc
    return [i for i in items if isinstance(i, dict)]
