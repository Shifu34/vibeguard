"""VibeGuard command line interface."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys

from . import __version__
from .config import EXAMPLE_CONFIG, load_config
from .reviewers.llm import review_diff
from .scanners.secrets import Finding, scan_diff, scan_text

RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

_SEVERITY_ORDER = {"medium": 0, "high": 1}


def _git(args: list[str]) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _is_allowed(path: str, allowlist: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(os.path.basename(path), pat)
        for pat in allowlist
    )


def _collect(target: str, base: str | None, paths: list[str]) -> tuple[str, list[Finding]]:
    """Return (diff_text, findings) for the requested scan target."""
    if paths:  # limit the staged scan to specific paths
        diff = _git(["diff", "--cached", "--no-color", "-U3", "--", *paths])
        return diff, scan_diff(diff)
    if target == "all":
        findings: list[Finding] = []
        for rel in _git(["ls-files"]).splitlines():
            rel = rel.strip()
            if not rel:
                continue
            try:
                with open(rel, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if len(text) > 2_000_000:  # skip huge generated files
                continue
            findings.extend(scan_text(text, rel, start_line=1))
        return "", findings
    if target == "base":
        diff = _git(["diff", "--no-color", "-U3", f"{base}...HEAD"])
        return diff, scan_diff(diff)
    diff = _git(["diff", "--cached", "--no-color", "-U3"])  # staged (default)
    return diff, scan_diff(diff)


def _print_text(findings: list[Finding]) -> None:
    if not findings:
        print(f"{GREEN}✓ VibeGuard: no secrets found.{RESET}")
        return
    print(f"{BOLD}VibeGuard found {len(findings)} potential secret(s):{RESET}\n")
    for f in sorted(findings, key=lambda x: (x.file, x.line)):
        color = RED if f.severity == "high" else YELLOW
        loc = f"{f.file}:{f.line}" if f.line else f.file or "(diff)"
        print(f"  {color}{f.severity.upper():6}{RESET} {BOLD}{loc}{RESET}  {DIM}{f.rule}{RESET}")
        print(f"         {f.description}")
        if f.snippet:
            print(f"         {DIM}{f.snippet[:140]}{RESET}")
    print(f"\n{DIM}Remove the secret, or allowlist the path in .vibeguard.toml{RESET}")


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    target, base = "staged", None
    if args.all:
        target = "all"
    elif args.base:
        target, base = "base", args.base

    try:
        diff_text, findings = _collect(target, base, args.paths)
    except RuntimeError as exc:
        print(f"{RED}error:{RESET} {exc}", file=sys.stderr)
        return 2

    findings = [f for f in findings if not _is_allowed(f.file, config.allowlist)]

    use_llm = args.llm or (config.llm.enabled and not args.no_llm)
    if use_llm and diff_text.strip():
        api_key = os.environ.get("VIBEGUARD_API_KEY", "")
        if not api_key:
            print(f"{DIM}LLM review skipped: set VIBEGUARD_API_KEY to enable.{RESET}",
                  file=sys.stderr)
        else:
            try:
                items = review_diff(diff_text, config.llm.model, config.llm.base_url, api_key)
            except RuntimeError as exc:
                print(f"{YELLOW}warning:{RESET} LLM review failed ({exc}); "
                      f"continuing with pattern scan.", file=sys.stderr)
            else:
                for item in items:
                    findings.append(Finding(
                        file=str(item.get("file") or ""),
                        line=int(item.get("line") or 0),
                        rule="llm/" + str(item.get("rule") or "issue"),
                        severity=str(item.get("severity") or "medium"),
                        snippet="",
                        description=str(item.get("description") or ""),
                    ))

    if args.format == "json":
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        _print_text(findings)

    threshold = _SEVERITY_ORDER.get(config.fail_on, 1)
    failed = any(_SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)
    return 1 if failed else 0


def cmd_init(_args: argparse.Namespace) -> int:
    if os.path.exists(".vibeguard.toml"):
        print(".vibeguard.toml already exists — leaving it alone.")
    else:
        with open(".vibeguard.toml", "w", encoding="utf-8") as fh:
            fh.write(EXAMPLE_CONFIG)
        print(f"{GREEN}✓{RESET} wrote .vibeguard.toml")
    print("\nAdd VibeGuard to pre-commit (.pre-commit-config.yaml):\n")
    print("""\
repos:
  - repo: https://github.com/YOUR-USERNAME/vibeguard
    rev: v0.1.0
    hooks:
      - id: vibeguard
""")
    print("Then run: pre-commit install")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibeguard",
        description="Stop AI-generated code from shipping secrets and security holes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan for secrets (default: staged changes).")
    scan.add_argument("--staged", action="store_true", help="Scan staged changes (default).")
    scan.add_argument("--all", action="store_true", help="Scan all tracked files.")
    scan.add_argument("--base", metavar="REF",
                      help="Scan the diff against a git ref, e.g. origin/main (great for CI).")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--config", metavar="PATH", help="Path to .vibeguard.toml")
    scan.add_argument("--llm", action="store_true", help="Enable LLM diff review.")
    scan.add_argument("--no-llm", action="store_true", help="Disable LLM diff review.")
    scan.add_argument("paths", nargs="*", help="Limit the staged scan to these paths.")

    sub.add_parser("init", help="Write an example .vibeguard.toml and show pre-commit setup.")
    return parser


def main(argv: list[str] | None = None) -> int:
    original = list(argv) if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(original)
    if args.command == "init":
        return cmd_init(args)
    if args.command is None:  # bare `vibeguard` -> `vibeguard scan`
        args = build_parser().parse_args(["scan", *original])
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
