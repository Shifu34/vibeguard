"""Configuration loading and allowlist matching."""
import os

from vibeguard.cli import _is_allowed
from vibeguard.config import load_config


def test_load_config_defaults_when_file_missing(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.toml"))
    assert cfg.fail_on == "high"
    assert "tests/**" in cfg.allowlist
    assert cfg.llm.enabled is False
    assert cfg.llm.model == "gpt-4o-mini"


def test_load_config_custom_values(tmp_path):
    p = tmp_path / ".vibeguard.toml"
    p.write_text(
        'fail_on = "medium"\n'
        'allowlist = ["src/**", "*.log"]\n'
        "[llm]\n"
        'enabled = true\n'
        'model = "gpt-4o"\n'
        'base_url = "https://proxy.example.com/v1"\n'
    )
    cfg = load_config(str(p))
    assert cfg.fail_on == "medium"
    assert cfg.allowlist == ["src/**", "*.log"]
    assert cfg.llm.enabled is True
    assert cfg.llm.model == "gpt-4o"
    assert cfg.llm.base_url == "https://proxy.example.com/v1"


def test_load_config_invalid_fail_on_is_ignored(tmp_path):
    p = tmp_path / ".vibeguard.toml"
    p.write_text('fail_on = "critical"\n')
    assert load_config(str(p)).fail_on == "high"


def test_is_allowed_exact_and_glob():
    assert _is_allowed("notes.md", ["*.md"])
    assert _is_allowed("docs/guide.md", ["docs/**"])
    assert _is_allowed("tests/test_x.py", ["tests/**", "test_*.py"])
    assert not _is_allowed("src/app.py", ["*.md", "docs/**"])


def test_is_allowed_matches_basename():
    # "test_*.py" should match even when nested
    assert _is_allowed("a/b/test_stuff.py", ["test_*.py"])
    assert not _is_allowed("a/b/stuff_test.py", ["test_*.py"])


def test_load_config_from_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".vibeguard.toml").write_text('fail_on = "medium"\n')
    # load_config() with no path reads .vibeguard.toml from the cwd
    assert load_config().fail_on == "medium"
    assert os.path.basename(os.getcwd()) == tmp_path.name
