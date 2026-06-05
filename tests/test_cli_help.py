"""CLI surface tests: --help and --version (criterion 2)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from omen.cli import build_parser


def _help_text() -> str:
    parser = build_parser()
    return parser.format_help()


def test_help_lists_required_flags():
    text = _help_text()
    for token in (
        "--contract",
        "--batch",
        "--input-type",
        "--check",
        "--rpc-url",
        "--format",
    ):
        assert token in text, f"--help missing {token}"


def test_help_lists_input_type_choices():
    text = _help_text()
    for choice in ("sol", "vyper", "bytecode", "address"):
        assert choice in text


def test_help_lists_check_choices():
    text = _help_text()
    for choice in ("prodigal", "suicidal", "greedy", "reentrancy", "all"):
        assert choice in text


def test_help_lists_format_choices():
    text = _help_text()
    assert "json" in text and "h1md" in text and "sarif" in text
    # text format (POST_V01 Rotation 2, R2.6) is a scan output choice too.
    assert "text" in text
    # gha format (POST_V01 R3.5): GitHub Actions workflow-command annotations.
    assert "gha" in text
    # junit format (POST_V01 R3.6): JUnit XML test-results report.
    assert "junit" in text
    # checkstyle format (POST_V01 R3.7): Checkstyle XML code-review annotations.
    assert "checkstyle" in text
    # sonarqube format (POST_V01 R3.8): SonarQube Generic Issue Import JSON.
    assert "sonarqube" in text
    # gitlab-sast format (POST_V01 R3.9): GitLab SAST Report v15 JSON.
    assert "gitlab-sast" in text
    # azure-devops format (POST_V01 R3.10): Azure DevOps pipeline annotations.
    assert "azure-devops" in text
    # teams-webhook format (POST_V01 R3.11): Microsoft Teams Incoming Webhook MessageCard.
    assert "teams-webhook" in text
    # opsgenie format (POST_V01 R3.12): Opsgenie Create Alert API JSON.
    assert "opsgenie" in text
    # victorops format (POST_V01 R3.13): VictorOps / Splunk On-Call REST endpoint JSON.
    assert "victorops" in text


def test_text_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format text is exercisable in CI.
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "text",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # text output is the compact terminal view, not JSON.
    assert not out.lstrip().startswith("{")
    assert out.startswith("omen ")
    assert "findings:" in out
    assert "suicidal" in out
    assert "HIGH" in out


def test_gha_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format gha is exercisable in CI.
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "gha",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # gha output is one workflow command per line (or a single ::notice when
    # there are no findings) — never JSON.
    assert not out.lstrip().startswith("{")
    for line in out.splitlines():
        assert line.startswith("::"), f"non-command line in gha output: {line!r}"


def test_junit_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format junit is exercisable in CI.
    from pathlib import Path
    from xml.etree import ElementTree as ET

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "junit",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # junit output is a well-formed JUnit XML testsuite, not JSON.
    assert not out.lstrip().startswith("{")
    assert out.lstrip().startswith("<?xml")
    root = ET.fromstring(out)
    assert root.tag == "testsuite"
    assert root.get("name") == "omen"
    # the suicidal bytecode finding becomes one failing testcase.
    cases = root.findall("testcase")
    assert len(cases) == 1
    assert "suicidal" in cases[0].get("name")
    assert cases[0].find("failure") is not None


def test_checkstyle_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format checkstyle is exercisable
    # in CI on a fresh checkout.
    from pathlib import Path
    from xml.etree import ElementTree as ET

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "checkstyle",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # checkstyle output is a Checkstyle XML document, not JSON.
    assert not out.lstrip().startswith("{")
    assert out.lstrip().startswith("<?xml")
    root = ET.fromstring(out)
    assert root.tag == "checkstyle"
    # the suicidal bytecode finding becomes one <error> grouped under one <file>
    files = root.findall("file")
    assert len(files) == 1
    errors = files[0].findall("error")
    assert len(errors) == 1
    # high omen severity -> Checkstyle "error" level
    assert errors[0].get("severity") == "error"
    # original severity preserved verbatim
    assert errors[0].get("omen-severity") == "high"


def test_sonarqube_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format sonarqube is exercisable
    # in CI on a fresh checkout. The SonarQube generic issue schema requires
    # primaryLocation.filePath on every issue, which a bytecode finding (no
    # source mapping) cannot supply, so the bytecode suicidal finding is
    # skipped and the document is the well-formed empty-issues form — the
    # honest "this format cannot represent that finding" failure mode, and
    # the behaviour the unit tests pin.
    import json as _json
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "sonarqube",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # sonarqube output is a JSON document with an "issues" array.
    assert out.lstrip().startswith("{")
    data = _json.loads(out)
    assert "issues" in data
    assert isinstance(data["issues"], list)
    # Bytecode findings are skipped (no filePath), so the document is empty.
    assert data["issues"] == []


def test_gitlab_sast_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format gitlab-sast is exercisable
    # in CI on a fresh checkout. The GitLab SAST schema requires
    # location.file on every vulnerability, which a bytecode finding (no
    # source mapping) cannot supply, so the bytecode suicidal finding is
    # skipped and the document is the well-formed empty-vulnerabilities form
    # — the honest "this format cannot represent that finding" failure
    # mode, and the behaviour the unit tests pin.
    import json as _json
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "gitlab-sast",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # gitlab-sast output is a JSON document with the GitLab SAST shape.
    assert out.lstrip().startswith("{")
    data = _json.loads(out)
    assert "version" in data and data["version"].startswith("15.")
    assert data["scan"]["type"] == "sast"
    assert "vulnerabilities" in data
    assert isinstance(data["vulnerabilities"], list)
    # Bytecode findings are skipped (no file), so the vulnerabilities list
    # is empty — the rest of the envelope still emits.
    assert data["vulnerabilities"] == []


def test_azure_devops_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format azure-devops is exercisable
    # in CI on a fresh checkout. Bytecode findings have no source mapping, so
    # the command is emitted without sourcepath/linenumber but still appears
    # in the pipeline log (a fail-open posture parallel to gha's bytecode
    # behaviour).
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "azure-devops",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    # azure-devops output is one logging command per line (or a single
    # ##[debug] when there are no findings) — never JSON.
    assert not out.lstrip().startswith("{")
    for line in out.splitlines():
        assert line.startswith("##vso[task.logissue ") or line.startswith("##[debug]"), (
            f"non-command line in azure-devops output: {line!r}"
        )
    assert "code=suicidal" in out


def test_teams_webhook_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format teams-webhook is exercisable
    # in CI on a fresh checkout. The output must be a single valid JSON
    # MessageCard payload Teams' Incoming Webhook can ingest as-is.
    from pathlib import Path
    import json as _json

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "teams-webhook",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    data = _json.loads(out)
    assert data["@type"] == "MessageCard"
    assert data["@context"] == "https://schema.org/extensions"
    assert data["title"] == "omen security scan"
    assert "themeColor" in data
    assert isinstance(data["sections"], list)


def test_opsgenie_format_scan_runs_end_to_end():
    # Bytecode mode needs no compiler, so --format opsgenie is exercisable in
    # CI on a fresh checkout. The output must be a single valid JSON Opsgenie
    # Create Alert API payload.
    from pathlib import Path
    import json as _json

    fixtures = Path(__file__).parent / "fixtures"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            str(fixtures / "compiled.bin"),
            "--input-type",
            "bytecode",
            "--check",
            "suicidal",
            "--format",
            "opsgenie",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    data = _json.loads(out)
    assert "message" in data
    assert "alias" in data
    assert "description" in data
    assert "priority" in data
    assert isinstance(data["tags"], list)
    assert isinstance(data["details"], dict)


def test_cli_help_runs_as_subprocess():
    # The installed entry point must print usage and exit 0.
    proc = subprocess.run(
        [sys.executable, "-m", "omen.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "--contract" in proc.stdout


def test_address_mode_requires_rpc_url():
    # argparse error path -> exit code 2.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "omen.cli",
            "--contract",
            "0x" + "00" * 20,
            "--input-type",
            "address",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "rpc-url" in (proc.stderr.lower())
