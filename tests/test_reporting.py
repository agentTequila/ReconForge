"""Reporting tests: all four formats, no network."""

from reconforge.core.engine import ScanResult
from reconforge.core.target import Target
from reconforge.reporting import (
    write_all,
    write_html,
    write_json,
    write_markdown,
    write_summary,
)


def make_result() -> ScanResult:
    result = ScanResult(
        target=Target("domain", "example.com"),
        profile="passive",
        started_at="2026-10-11T00:00:00+00:00",
        finished_at="2026-10-11T00:01:00+00:00",
    )
    from reconforge.core.context import ModuleResult

    result.modules["domain.dns"] = ModuleResult(
        module_id="domain.dns", status="ok",
        data={"A": ["1.2.3.4"]}, findings=["No DMARC record found"], duration_s=0.5,
    )
    result.modules["domain.shodan"] = ModuleResult(
        module_id="domain.shodan", status="skipped",
        error="missing API key(s): SHODAN_API_KEY",
    )
    result.findings = ["[domain.dns] No DMARC record found"]
    return result


def test_write_json_roundtrip(tmp_path):
    path = write_json(make_result(), tmp_path)
    import json

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["target"]["value"] == "example.com"
    assert payload["stats"]["ok"] == 1
    assert payload["stats"]["skipped"] == 1


def test_write_markdown(tmp_path):
    path = write_markdown(make_result(), tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "# ReconForge Report" in text
    assert "No DMARC record found" in text
    assert "domain.shodan" in text


def test_write_html_escapes(tmp_path):
    result = make_result()
    result.findings.append("<script>alert(1)</script>")
    path = write_html(result, tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_write_summary(tmp_path):
    path = write_summary(make_result(), tmp_path)
    text = path.read_text(encoding="utf-8")
    assert "example.com" in text
    assert "ok=1" in text


def test_write_all(tmp_path):
    files = write_all(make_result(), tmp_path)
    names = {f.name for f in files}
    assert names == {"full_results.json", "REPORT.md", "report.html", "summary.txt"}
