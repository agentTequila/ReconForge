"""Report writers: JSON (canonical), Markdown, HTML, summary text."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from reconforge.core.engine import ScanResult


def output_directory(base: Path | None, result: ScanResult) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in result.target.value)
    stamp = (result.started_at or "scan")[:19].replace(":", "").replace("-", "").replace("T", "_")
    directory = (base or Path("reconforge_output")) / f"{result.target.kind}_{safe}_{stamp}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_json(result: ScanResult, directory: Path) -> Path:
    path = directory / "full_results.json"
    path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return path


def _module_rows(result: ScanResult) -> list[dict[str, Any]]:
    rows = []
    for mid, mod in sorted(result.modules.items()):
        rows.append({
            "id": mid,
            "status": mod.status,
            "duration": f"{mod.duration_s:.1f}s",
            "error": mod.error or "",
            "findings": mod.findings,
        })
    return rows


def write_markdown(result: ScanResult, directory: Path) -> Path:
    lines = [
        f"# ReconForge Report - {result.target.value}",
        "",
        f"- **Target type:** {result.target.kind}",
        f"- **Profile:** {result.profile}",
        f"- **Started:** {result.started_at}",
        f"- **Finished:** {result.finished_at}",
        f"- **Modules:** {len(result.modules)} total, {result.ok_count} ok, "
        f"{result.skipped_count} skipped, {result.error_count} errors",
        "",
        "## Key Findings",
        "",
    ]
    if result.findings:
        lines += [f"- {f}" for f in result.findings]
    else:
        lines.append("_No notable findings._")

    if result.ai:
        lines += ["", "## AI Insights", ""]
        for title, body in result.ai.items():
            lines += [f"### {title}", "", str(body), ""]

    lines += ["", "## Module Results", ""]
    for row in _module_rows(result):
        lines += [f"### {row['id']}", "",
                  f"`{row['status']}` ({row['duration']})"]
        if row["error"]:
            lines += ["", f"> {row['error']}"]
        if row["findings"]:
            lines += ["", * [f"- {f}" for f in row["findings"]]]
        lines += [""]
    path = directory / "REPORT.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


_CSS = """
body{font-family:'Segoe UI',system-ui,sans-serif;margin:0;background:#0d1117;color:#e6edf3}
.wrap{max-width:960px;margin:0 auto;padding:32px}
h1{border-bottom:2px solid #30363d;padding-bottom:12px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;margin:2px}
.ok{background:#1a7f37}.skipped{background:#9e6a03}.error{background:#cf222e}
.timeout{background:#cf222e}.section{background:#161b22;border:1px solid #30363d;
border-radius:8px;margin:12px 0;overflow:hidden}
.section summary{padding:12px 16px;cursor:pointer;font-weight:600}
.section .body{padding:0 16px 16px}
.findings li{margin:6px 0}
code{background:#21262d;padding:2px 6px;border-radius:4px}
.meta{color:#8b949e}
table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid #30363d;padding:6px 8px;text-align:left}
footer{margin-top:32px;color:#8b949e;font-size:12px;border-top:1px solid #30363d;padding-top:12px}
"""


def write_html(result: ScanResult, directory: Path) -> Path:
    esc = html.escape
    findings_html = (
        "<ul class='findings'>" + "".join(f"<li>{esc(f)}</li>" for f in result.findings)
        + "</ul>" if result.findings else "<p class='meta'>No notable findings.</p>"
    )
    sections = []
    for row in _module_rows(result):
        badge = f"<span class='badge {row['status']}'>{row['status']}</span>"
        inner = [f"<p class='meta'>{esc(row['duration'])}</p>"]
        if row["error"]:
            inner.append(f"<p><code>{esc(row['error'])}</code></p>")
        if row["findings"]:
            inner.append("<ul>" + "".join(
                f"<li>{esc(f)}</li>" for f in row["findings"]) + "</ul>")
        data = result.modules[row["id"]].data
        if data is not None:
            pretty = esc(json.dumps(data, indent=2, ensure_ascii=False, default=str)[:8000])
            inner.append(f"<pre><code>{pretty}</code></pre>")
        sections.append(
            f"<details class='section'><summary>{esc(row['id'])} {badge}</summary>"
            f"<div class='body'>{''.join(inner)}</div></details>"
        )
    ai_html = ""
    if result.ai:
        ai_html = "<h2>AI Insights</h2>" + "".join(
            f"<details class='section'><summary>{esc(k)}</summary>"
            f"<div class='body'><pre>{esc(str(v))}</pre></div></details>"
            for k, v in result.ai.items()
        )
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>ReconForge - {esc(result.target.value)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>ReconForge Report</h1>
<p class="meta">Target <code>{esc(result.target.value)}</code> ({esc(result.target.kind)})
&middot; profile <code>{esc(result.profile)}</code><br>
Started {esc(result.started_at)} &middot; finished {esc(result.finished_at)}<br>
{result.ok_count} ok &middot; {result.skipped_count} skipped &middot;
{result.error_count} errors &middot; {len(result.findings)} findings</p>
<h2>Key Findings</h2>{findings_html}
{ai_html}
<h2>Module Results</h2>{''.join(sections)}
<footer>Generated by ReconForge - passive/active reconnaissance for authorized testing only.</footer>
</div></body></html>"""
    path = directory / "report.html"
    path.write_text(doc, encoding="utf-8")
    return path


def write_summary(result: ScanResult, directory: Path) -> Path:
    finding_lines = [f"  - {f}" for f in result.findings] or ["  (none)"]
    lines = [
        f"ReconForge summary for {result.target.value} ({result.target.kind})",
        f"profile={result.profile} modules={len(result.modules)} "
        f"ok={result.ok_count} skipped={result.skipped_count} errors={result.error_count}",
        "",
        "Findings:",
        *finding_lines,
        "",
        "Modules:",
        *[f"  [{m.status:>7}] {mid} ({m.duration_s:.1f}s)"
          for mid, m in sorted(result.modules.items())],
    ]
    path = directory / "summary.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_all(result: ScanResult, directory: Path,
              formats: tuple[str, ...] = ("json", "md", "html", "txt")) -> list[Path]:
    written = []
    if "json" in formats:
        written.append(write_json(result, directory))
    if "md" in formats:
        written.append(write_markdown(result, directory))
    if "html" in formats:
        written.append(write_html(result, directory))
    if "txt" in formats:
        written.append(write_summary(result, directory))
    return written
