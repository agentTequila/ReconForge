"""AI helper tests (pure functions, no network)."""

from reconforge.ai.analyze import redact, scan_digest
from reconforge.core.engine import ScanResult
from reconforge.core.target import Target


def test_redact_email_phone_ip():
    text = "user@example.com +441234567890 8.8.8.8"
    out = redact(text)
    assert "user@example.com" not in out
    assert "+441234567890" not in out
    assert "8.8.8.8" not in out
    assert "@redacted" in out


def test_scan_digest_without_redact_keeps_data():
    result = ScanResult(target=Target("email", "a@b.com"), profile="passive")
    digest = scan_digest(result, redact_pii=False)
    assert "a@b.com" in digest


def test_scan_digest_with_redact_hides_email():
    result = ScanResult(target=Target("email", "a@b.com"), profile="passive")
    digest = scan_digest(result, redact_pii=True)
    assert "a@b.com" not in digest


def test_scan_digest_truncates_huge_payload():
    result = ScanResult(target=Target("domain", "big.com"), profile="passive")
    from reconforge.core.context import ModuleResult

    result.modules["domain.big"] = ModuleResult(
        module_id="domain.big", status="ok",
        data={"blob": "x" * 200_000},
    )
    digest = scan_digest(result)
    assert len(digest) < 70_000
    assert "truncated" in digest


def test_provider_specs_shape():
    from reconforge.ai.providers import PROVIDERS

    assert {"openai", "anthropic", "gemini", "groq", "mistral", "openrouter",
            "ollama"} == set(PROVIDERS)
    assert PROVIDERS["ollama"].key_name is None
