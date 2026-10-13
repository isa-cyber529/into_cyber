import json
import subprocess
import sys
from pathlib import Path

from into_cyber.security_checker import scan_directory


def test_scan_directory_reports_common_issues(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        """import os\nimport random\n\nAPI_KEY = 'sk_live_example'\nDEBUG = True\nURL = 'http://example.com'\nTOKEN = os.getenv('TOKEN')\nweak = random.random()\n""",
        encoding="utf-8",
    )

    findings = scan_directory(tmp_path)

    assert {finding["rule"] for finding in findings} == {
        "hardcoded_secret",
        "debug_enabled",
        "insecure_http_url",
        "weak_random",
    }
    assert all(finding["path"] == str(source) for finding in findings)


def test_scan_directory_ignores_binary_and_empty_files(tmp_path: Path) -> None:
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "empty.txt").write_text("", encoding="utf-8")

    assert scan_directory(tmp_path) == []


def test_cli_writes_json_report(tmp_path: Path) -> None:
    source = tmp_path / "config.json"
    source.write_text('{"password": "secret-value"}', encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "into_cyber.security_checker", str(tmp_path), "--json"],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report[0]["rule"] == "hardcoded_secret"
    assert report[0]["path"] == str(source)
