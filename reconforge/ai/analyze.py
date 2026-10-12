"""AI analysis over scan results: summarize, correlate, ask, suggest."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from reconforge.ai.providers import ProviderSpec, complete
from reconforge.core.context import ScanContext
from reconforge.core.engine import ScanResult

SYSTEM = (
    "You are ReconForge AI, an OSINT analyst assistant. You receive the structured "
    "results of a reconnaissance scan. Be concise, prioritize by risk, and only "
    "state what the data supports. Never invent findings. Remind the user that "
    "findings must only be used for authorized testing."
)

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE = re.compile(r"\+\d{7,15}")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact(text: str) -> str:
    def hide(match: re.Match) -> str:
        return hashlib.sha256(match.group(0).encode()).hexdigest()[:10] + "@redacted"

    text = _EMAIL.sub(hide, text)
    text = _PHONE.sub(lambda m: hashlib.sha256(m.group().encode()).hexdigest()[:10] + ":redacted", text)
    text = _IPV4.sub(lambda m: hashlib.sha256(m.group().encode()).hexdigest()[:10] + ".redacted", text)
    return text


def scan_digest(result: ScanResult, redact_pii: bool = False) -> str:
    payload = result.to_dict()
    text = json.dumps(payload, indent=1, ensure_ascii=False, default=str)
    if len(text) > 60_000:
        slim = {
            "target": payload["target"],
            "profile": payload["profile"],
            "stats": payload["stats"],
            "findings": payload["findings"],
            "modules": {
                k: {"status": v["status"], "data": v["data"], "findings": v["findings"]}
                for k, v in payload["modules"].items()
                if v["status"] == "ok"
            },
        }
        text = json.dumps(slim, indent=1, ensure_ascii=False, default=str)
        if len(text) > 60_000:
            text = text[:60_000] + "\n...[truncated]"
    return redact(text) if redact_pii else text


def _run(spec: ProviderSpec, ctx: ScanContext, task: str, result: ScanResult,
         redact_pii: bool) -> str:
    user = f"TASK: {task}\n\nSCAN RESULTS JSON:\n{scan_digest(result, redact_pii)}"
    return complete(spec, SYSTEM, user, ctx)


def summarize(spec: ProviderSpec, ctx: ScanContext, result: ScanResult,
              redact_pii: bool = False) -> str:
    return _run(
        spec, ctx,
        "Write an executive summary of this scan: what was checked, the most "
        "important observations, and a 1-10 exposure score with justification.",
        result, redact_pii,
    )


def correlate(spec: ProviderSpec, ctx: ScanContext, result: ScanResult,
              redact_pii: bool = False) -> str:
    return _run(
        spec, ctx,
        "Correlate findings ACROSS modules into prioritized risks. For each risk: "
        "severity (Critical/High/Medium/Low), the modules involved, why it matters, "
        "and a concrete remediation. Format as a numbered list.",
        result, redact_pii,
    )


def ask(spec: ProviderSpec, ctx: ScanContext, result: ScanResult, question: str,
        redact_pii: bool = False) -> str:
    user = (
        f"QUESTION: {question}\n\nSCAN RESULTS JSON:\n"
        f"{scan_digest(result, redact_pii)}\n\nAnswer the question using only this data."
    )
    return complete(spec, SYSTEM, user, ctx)


def suggest(spec: ProviderSpec, ctx: ScanContext, result: ScanResult,
            redact_pii: bool = False) -> str:
    return _run(
        spec, ctx,
        "Suggest the next 5 investigation steps (modules, dorks, manual lookups) "
        "based on what this scan found. One line each, most valuable first.",
        result, redact_pii,
    )


def run_ai(actions: dict[str, Any], spec: ProviderSpec, ctx: ScanContext,
           result: ScanResult) -> dict[str, str]:
    """Run the enabled AI actions; returns {title: text} for the report."""
    out: dict[str, str] = {}
    redact_pii = bool(ctx.redact)
    if actions.get("summarize"):
        out["Executive Summary"] = summarize(spec, ctx, result, redact_pii)
    if actions.get("correlate"):
        out["Risk Correlation"] = correlate(spec, ctx, result, redact_pii)
    if actions.get("suggest"):
        out["Next Steps"] = suggest(spec, ctx, result, redact_pii)
    return out
