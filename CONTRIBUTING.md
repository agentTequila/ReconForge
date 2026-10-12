# Contributing to ReconForge

Thanks for helping make OSINT tooling better for everyone.

## Ground rules

- Contribution targets **authorized, defensive, and educational** use only.
  PRs whose primary purpose is bypassing security controls, unauthorized
  access, or evasion will be declined.
- Never submit real API keys, scan artifacts containing personal data, or
  results from scanning targets you were not authorized to test.
- All new code is MIT-licensed under the same terms as the project.

## Adding a platform (no code)

Edit `reconforge/data/platforms.json`:

```json
{
  "name": "Example",
  "category": "social",
  "url": "https://example.com/{username}",
  "not_found_codes": [404]
}
```

- `url` must be HTTPS and contain `{username}`.
- Use `not_found_codes` for hard 404s, `not_found_marker` for soft-404 body
  text, and `body_marker` when the page only proves existence if a string is
  present.
- Run `pytest tests/test_platforms.py` before opening the PR.

## Adding a recon module (code)

```python
# reconforge/modules/<pack>/...
from reconforge.core.registry import register_module
from reconforge.core.target import Target
from reconforge.core.context import ScanContext

@register_module(
    id="domain.example",                # <target-kind>.<name>
    target_kinds=["domain"],            # or several kinds
    profile="passive",                  # "active" for intrusive modules
    requires_keys=[],                   # e.g. ["SHODAN_API_KEY"]
    description="One-line capability summary",
)
def run(target: Target, ctx: ScanContext):
    resp = ctx.http("GET", f"https://{target.value}/")   # rate-limited + cached
    findings = []
    if resp.status_code != 200:
        findings.append("site did not answer on HTTPS")
    return {"status_code": resp.status_code}, findings    # (data, findings)
```

Rules:

- **Never raise past your module** — the engine catches exceptions, but clean
  handling produces better `data`.
- Use `ctx.http()` (UA, proxy support, cache, rate limiting) instead of bare
  `requests`.
- Declare `requires_keys`; the engine skips the module when keys are absent.
- Import your module in the pack's `__init__.py` so it registers.
- Add/extend tests where practical; no live-network tests in the default suite
  (mark them `@pytest.mark.network`).

## Dev setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
```

## Pull requests

1. Fork and branch from `main`.
2. Keep PRs focused — one feature/fix per PR.
3. Describe *what* changed and *why*; link issues.
4. Ensure `pytest` and `ruff check .` pass.
5. Update README/docs if you change user-facing behavior.

## Reporting bugs

Open an issue with: OS, Python version, command run, expected vs actual,
and the module id if relevant. **Redact targets and keys.**
