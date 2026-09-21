"""Diff parsing edge cases: renames, deletions, binary files, multi-hunk tracking."""
from vibeguard.scanners.secrets import scan_diff


def test_rename_attributes_findings_to_new_path():
    diff = (
        "diff --git a/old.py b/new.py\n"
        "similarity index 95%\n"
        "rename from old.py\n"
        "rename to new.py\n"
        "index 1234567..89abcde 100644\n"
        "--- a/old.py\n"
        "+++ b/new.py\n"
        "@@ -1 +1 @@\n"
        "-x = 1\n"
        "+y = 2\n"
        '+GH_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
    )
    findings = scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].file == "new.py"
    assert findings[0].line == 2
    assert findings[0].rule == "github-pat-classic"


def test_deleted_file_contributes_no_findings():
    diff = (
        "diff --git a/gone.py b/gone.py\n"
        "deleted file mode 100644\n"
        "index abc1234..0000000\n"
        "--- a/gone.py\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        '-SECRET="AKIAIOSFODNN7EXAMPLE"\n'
    )
    assert scan_diff(diff) == []


def test_binary_diff_is_skipped():
    diff = (
        "diff --git a/logo.png b/logo.png\n"
        "new file mode 100644\n"
        "index 0000000..abc1234\n"
        "Binary files /dev/null and b/logo.png differ\n"
    )
    assert scan_diff(diff) == []


def test_binary_marker_suppresses_later_plus_lines():
    # Defensive: even if something emitted "+" lines after the marker, skip them.
    diff = (
        "diff --git a/data.bin b/data.bin\n"
        "index 111..222 100644\n"
        "Binary files a/data.bin and b/data.bin differ\n"
        '+AKIAIOSFODNN7EXAMPLE\n'
    )
    assert scan_diff(diff) == []


def test_git_binary_patch_is_skipped():
    diff = (
        "diff --git a/data.bin b/data.bin\n"
        "index 111..222 100644\n"
        "GIT binary patch\n"
        "literal 3\n"
        "KcmZQzU|?y?\n"
        "\n"
        "literal 0\n"
        "HcmV?d00001\n"
        "\n"
    )
    assert scan_diff(diff) == []


def test_multi_hunk_line_numbers():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,4 @@\n"
        " a\n"
        '+b = "x"\n'
        " c\n"
        " d\n"
        "@@ -10,2 +11,3 @@\n"
        " e\n"
        '+f = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
        " g\n"
    )
    findings = scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].line == 12
    assert findings[0].file == "app.py"


def test_new_file_diff_scanned():
    diff = (
        "diff --git a/secret.py b/secret.py\n"
        "new file mode 100644\n"
        "index 0000000..abc1234\n"
        "--- /dev/null\n"
        "+++ b/secret.py\n"
        "@@ -0,0 +1 @@\n"
        '+API_KEY="AKIAIOSFODNN7EXAMPLE"\n'
    )
    findings = scan_diff(diff)
    assert any(f.rule == "aws-access-key" for f in findings)
    aws = [f for f in findings if f.rule == "aws-access-key"][0]
    assert aws.file == "secret.py"
    assert aws.line == 1


def test_empty_diff_has_no_findings():
    assert scan_diff("") == []
