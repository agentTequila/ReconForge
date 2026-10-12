# ReconForge — Design Spec

Date: 2026-10-11
Status: Approved (design), pending spec review
Repo target: public GitHub repository `ReconForge`

## 1. Purpose

ReconForge is a cross-platform OSINT reconnaissance toolkit for the cybersecurity
community. It refactors the existing monolithic `osint_recon.py` (1,299 lines) into a
modular core with two frontends: a `click`+`rich` CLI (Linux default) and a
CustomTkinter GUI (Windows default). Both frontends run on both OSes and share one
core.

Audience: penetration testers, red teamers, incident responders, threat analysts,
privacy researchers, and students.

## 2. Goals

- One shared engine; two frontends (CLI + GUI).
- Broader coverage than the original tool: 6 target types, 60+ platforms, BYOK AI.
- Safe by default: passive-only scans unless active mode is explicitly requested.
- Extensible: new recon modules register themselves with one decorator.
- Publishable: clean public repo — no secrets, no scan artifacts.

Non-goals (YAGNI): no crawling/spidering, no exploitation, no authentication
brute-force, no malware/Exploit-DB integration, no packaging of native installers
beyond documented PyInstaller command.

## 3. Architecture

```
reconforge/
├── core/
│   ├── engine.py          # orchestrator: builds module list, runs with timeouts
│   ├── target.py          # Target type: kind, value, normalization/validation
│   ├── registry.py        # @register_module decorator + module metadata
│   ├── context.py         # ScanContext: config, http session, cache, rate limiter, event bus
│   ├── config.py          # loads reconforge.toml + env vars; key management
│   ├── cache.py           # file-based response cache with TTL
│   ├── ratelimit.py       # token-bucket limiter, retry with backoff
│   └── events.py          # event bus: progress/log/finding events -> CLI or GUI
├── modules/
│   ├── domain/            # whois, dns, subdomains, ssl, tech, headers, robots,
│   │                      # wayback, dorks, ports, dirs, http_methods, emails_on_domain
│   ├── email/             # breach, reputation, verification (MX), smtp_verify,
│   │                      # gravatar, pattern_generator, social
│   ├── phone/             # format/carrier (key-less + optional API), osint links
│   ├── person/            # social, public_records, breaches, professional
│   ├── username/          # platform_checks (60+), name_to_usernames
│   ├── ip/                # rdap, geo_asn, rdns, shodan, reverse_dns_links
│   └── publicdata/        # aggregator of people-search / leak-index URL generators
├── integrations/          # shodan, virustotal, hibp, hunter, emailrep, numverify
├── ai/
│   ├── providers.py       # OpenAI, Anthropic, Gemini, Groq, Mistral, OpenRouter, Ollama
│   └── analyze.py         # summarize, correlate, ask, suggest_next_steps
├── reporting/
│   ├── json_report.py     # machine-readable full results
│   ├── markdown_report.py # GitHub-friendly report
│   ├── html_report.py     # self-contained single-file HTML
│   └── summary.py         # terminal/GUI summary tables
├── cli.py                 # entrypoint: reconforge
├── gui.py                 # entrypoint: reconforge-gui
└── data/                  # wordlists: subdomains, dirs, platforms (json)
```

### 3.1 Module contract

Every recon module is a function registered with metadata:

```python
@register_module(
    id="domain.subdomains",
    target_kinds=["domain"],
    profile="passive",          # "passive" | "active"
    requires_keys=[],           # e.g. ["shodan"]
    description="Enumerate subdomains via crt.sh + wordlist DNS probes",
)
def run(target: Target, ctx: ScanContext) -> ModuleResult: ...
```

`ModuleResult` fields: `module_id`, `status` (ok | skipped | error | timeout),
`data` (JSON-serializable), `findings` (list[str], the "interesting" items),
`error` (str | None), `duration_s` (float).

Rules:
- A module must never raise past its own boundary; failures become `status=error`.
- The engine enforces a per-module timeout (default 60 s active, 120 s network-heavy).
- Modules declare `requires_keys`; engine marks them `skipped` with reason when keys
  are absent. Missing keys never abort a scan.
- Bare `except:` clauses are forbidden (ruff rule); exceptions carry context.

### 3.2 ScanContext

Provides to every module: configured `requests.Session` (UA, proxy, retries),
`ctx.cache`, `ctx.limiter`, `ctx.emit(event)` for progress/findings, `ctx.keys`
(read-only mapping), `ctx.options` (profile, redact flag, etc.).

### 3.3 Event bus

Core emits events; frontends subscribe. Event types: `scan_started`,
`module_started`, `module_finished`, `log` (level, message),
`finding` (text), `scan_finished`. CLI renders with rich; GUI appends to log pane
and progress bar. This keeps core 100% UI-free.

## 4. Target types

| Kind    | Validation/normalization | Default modules |
|---------|--------------------------|-----------------|
| domain  | strip scheme/www, lowercase | passive domain set; active set with `--active` |
| email   | RFC-ish regex; split local/domain; domain part also scanned | email set + domain passive |
| phone   | E.164 normalize (keep leading +) | phone set (mostly URL generators + optional API) |
| person  | free-text name | person set (URL generators, breach links) |
| username| alphanumeric + `._-`; no spaces | username platform checks (60+) |
| ip      | IPv4/IPv6 parse | ip set (RDAP, geo/ASN, rDNS, Shodan) |

Auto-detection: `reconforge scan <value>` infers kind (email regex → email;
IP parse → ip; contains spaces → person; known TLD/hostname → domain; else prompt
in GUI / error in CLI with `--type` hint).

## 5. Profiles and safety rails

- `passive` (default): DNS/WHOIS/HTTP-GET/API lookups only. No connection attempts
  to target services beyond normal HTTP(S) requests to the web server itself.
- `active` (opt-in: `--active` CLI / toggle + confirmation dialog GUI): port scan,
  directory bruteforce, HTTP OPTIONS, SMTP verification.
- Active scans print/show an authorization notice and require confirmation
  (`--yes` to skip prompt for automation).
- Rate limiting: polite defaults (wordlist probes ≤ 30 concurrent, ≤ 5 rps per host).
- All output folders: `reconforge_output/<target>_<timestamp>/`; git-ignored.

## 6. BYOK AI

Provider abstraction `AIProvider` with `complete(system, user) -> str`:

| Provider   | Env var              | Notes |
|------------|----------------------|-------|
| openai     | OPENAI_API_KEY       | gpt-4o-mini default |
| anthropic  | ANTHROPIC_API_KEY    | claude default |
| gemini     | GEMINI_API_KEY       | |
| groq       | GROQ_API_KEY         | fast/free tier |
| mistral    | MISTRAL_API_KEY      | |
| openrouter | OPENROUTER_API_KEY   | many models |
| ollama     | (none)               | local http://localhost:11434, air-gapped |

Config: single **`.apikeys` file**, generated automatically on first run (template
with commented placeholders + "DO NOT COMMIT" header), populated by the user.

Key handling design:
- Format: plain `KEY=value` lines (same names as current `.env`:
  `SHODAN_API_KEY=`, `VIRUSTOTAL_API_KEY=`, ...), one file for all providers.
- Location precedence (first match wins):
  1. Environment variable (CI/scripts override)
  2. `.apikeys` in the current working directory (generated on first run)
  3. `~/.config/reconforge/.apikeys` (optional global copy; `%APPDATA%` on Windows)
- Hidden + protected: on Windows the file's Hidden attribute is set at creation; on
  Linux/macOS permissions are `0600`.
- Safety: `.apikeys` is in `.gitignore`; if it exists inside a git working tree and
  is not ignored, the tool prints a one-time warning. Key values are never logged,
  never sent to AI providers, never included in reports.
- `reconforge keys list|set|remove` edits this file from the CLI; the GUI has a
  provider/key form with a "Save to .apikeys" button and an "Open file" button.

Features (all opt-in, `--ai [--provider X]` or GUI toggle):
1. `summarize` — executive summary of scan results in plain English.
2. `correlate` — cross-module risk correlation with severity ranking.
3. `ask "<question>"` — NL Q&A scoped to `full_results.json`.
4. `suggest` — next-step modules/dorks/queries based on findings.

Rules:
- Only scan JSON is sent; never keys, never `.env`.
- `--redact` strips emails/phones/IPs from prompts (hashes them) before sending.
- If provider unreachable → module `status=error`, scan still completes.
- AI section is appended to reports only when enabled.

## 7. Frontends

### 7.1 CLI (`reconforge`) — click + rich

```
reconforge scan <target> [--type KIND] [--profile passive|active] [--active]
                        [--modules id,id] [--exclude id] [--output DIR]
                        [--format json,md,html] [--ai] [--provider P] [--redact]
                        [--proxy socks5h://127.0.0.1:9050] [--no-cache] [-y]
reconforge platforms [target]     # table of all sources for a target kind
reconforge keys [set|list|remove] # API key management
reconforge modules                # list registered modules w/ profiles + key needs
reconforge ai ask "..." --scan DIR
reconforge --version
```

Output: rich panels per module, progress bars, final summary table, findings list.

`--active` is shorthand for `--profile active` (they are the same option; if both
are given, `--active` wins).

### 7.2 GUI (`reconforge-gui`) — CustomTkinter

Layout:
- Top bar: target entry + type auto-detect, profile selector (Passive/Active),
  Scan button, dark/light toggle.
- Left: module checklist grouped by category with key-status icons.
- Center tabs: **Log** (live events), **Results** (per-module tree/table),
  **Platforms** (source list with open-links), **Report** (preview + export buttons).
- Bottom: status bar (progress %, module counter), AI panel (provider dropdown,
  key field, enable toggle, ask box).
- Active-scan confirmation dialog with authorization notice.
- Threading: scans run on a worker thread; events marshalled to UI thread via queue.

## 8. Reporting

- `full_results.json` — everything, stable schema (frontends consume it for reopen).
- `REPORT.md` — GitHub-friendly: summary, findings, per-module sections, AI insights.
- `report.html` — self-contained (inline CSS), collapsible sections, no JS deps.
- `summary.txt` — short console-friendly digest.
- Schema version field (`schema_version: 1`) for forward compatibility.

## 9. Popular platforms kept + expanded

Kept from original: Google, LinkedIn, Facebook, X/Twitter, Instagram, GitHub,
Reddit, Medium, YouTube, Truecaller, WhitePages, Spokeo, Pipl, TruePeopleSearch,
FastPeopleSearch, DeHashed, IntelligenceX, LeakCheck, Wayback, crt.sh, Shodan,
VirusTotal, HIBP, Hunter, EmailRep, FullContact, NumVerify, PhoneInfoga, Sync.me,
NumLookup, AngelList, Crunchbase.

Added: Telegram, TikTok, Twitch, Steam, Pinterest, Keybase, Pastebin, ProtonMail
lookup, gravatar, HaveIBeenPwned password-range (k-anonymity, no key), Sherlock-style
username checks (~60 sites with per-site detection logic: status code + body marker),
AbuseIPDB links, urlscan.io, SecurityTrails links (key-less UI links), BuiltWith
links, dirtiest-cowboy dorks pack.

Data files: `data/platforms.json` (name, url template, category, check mode:
`url_gen` | `http_check`, detection markers). Community can PR new entries without
touching code.

## 10. Refinements over existing code

- Replace god class with independent modules; no shared mutable `self.target`
  swapping (the email module currently mutates `self.target` mid-scan — fixed by
  passing explicit targets).
- Typed results; consistent logging; timeouts everywhere.
- `.apikeys` handling (see §6): single hidden/protected key file, generated on
  first run, env-var override; legacy `.env` still read as a last-resort fallback
  for back-compat with the old tool.
- Existing API integrations (Shodan, VT, Hunter, HIBP, EmailRep, NumVerify) moved to
  `integrations/` with unit-testable clients.

## 11. Testing & quality

- pytest: unit tests for target parsing, registry, engine (fake modules),
  reporting, config, cache, ratelimit, AI provider param building (mocked HTTP),
  platform checks (responses-mocked).
- `ruff` lint + format; type hints throughout (no strict mypy gate in v1).
- No live-network tests in default `pytest` run; marked `@pytest.mark.network`.

## 12. Repo & publishing

Files pushed to public repo:
- `reconforge/` (package), `tests/`, `pyproject.toml`, `README.md`, `LICENSE` (MIT),
  `.gitignore`, `docs/superpowers/specs/…design.md`, `CHANGELOG.md`,
  `CONTRIBUTING.md` (module/PR guide), `reconforge.toml.example`,
  `.github/workflows/ci.yml` (ruff + offline pytest — makes the README CI badge real).

Never pushed: `.apikeys`, `.env` (live keys), `reconforge_output/`,
`__pycache__/`, `.venv/`, scan artifacts. `.gitignore` committed first.

README contents: name/tagline, badges (license, python version, CI),
feature table, architecture diagram (ascii), install (pip/pipx), quickstart CLI +
GUI, AI BYOK setup, key configuration, screenshots section, ethical
use & legal notice, contributing, license.

Publishing steps: `gh repo create ReconForge --public`, single initial commit of
allow-listed files, verify tree contains no secrets (`git status`/grep for key
values) before push.

Note: author must rotate Shodan/VirusTotal/Hunter keys found in the old `.env`
because they were exposed locally; keys are never copied into the repo.

## 13. Packaging

- `pyproject.toml` with `[project.scripts] reconforge = "reconforge.cli:main"` and
  `reconforge-gui = "reconforge.gui:main"`.
- Extras: `reconforge[ai]` (no extra deps — plain HTTP via requests), core deps:
  requests, dnspython, python-whois, shodan, rich, click, customtkinter.
- Optional documented PyInstaller command for a Windows one-file GUI exe.

## 14. Success criteria

- `reconforge scan example.com` produces JSON+MD+HTML in output dir, exit 0.
- Same target via GUI produces identical JSON results.
- Passive scan needs zero API keys; configured keys unlock extra modules.
- `pytest` passes offline; `ruff check` clean.
- Public repo contains no secrets (grep-verified).
