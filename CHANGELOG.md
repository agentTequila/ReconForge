# Changelog

All notable changes to ReconForge are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-10-11

Initial public release.

### Added
- Modular core engine: module registry, per-module timeouts, failure isolation,
  response cache, token-bucket rate limiting, event bus.
- 40 built-in modules across 6 target types:
  domain (17), email (8), phone (4), person (6), username (2), ip (6).
- Passive/active scan profiles with authorization confirmation for active scans.
- CLI (`reconforge`) with startup banner (version, API key count, capabilities),
  rich tables, and commands: `scan`, `modules`, `platforms`, `keys`, `ai ask`.
- GUI (`reconforge-gui`) built on CustomTkinter: live log, module checklist,
  results inspector, platforms browser, AI panel, report actions, radar icon.
- 64+ platform dataset (`data/platforms.json`) with per-site detection logic,
  community-editable without code changes.
- BYOK AI analysis: OpenAI, Anthropic, Gemini, Groq, Mistral, OpenRouter,
  and local Ollama — summarize, correlate, ask, suggest; optional PII redaction.
- Hidden `.apikeys` file (generated on first run; Hidden attribute on Windows,
  `0600` on POSIX) with env-var override and legacy `.env` fallback.
- Reports: `full_results.json` (schema v1), `REPORT.md`, `report.html`,
  `summary.txt`.
- Proxy support (`--proxy socks5h://127.0.0.1:9050`), response cache,
  HTTPS everywhere in generated links.
- Offline pytest suite (52 tests) + ruff lint config + CI workflow.
- Portable Windows executables: PyInstaller specs (`packaging/`), one-command
  build (`tools/build_exe.ps1`), SHA256 checksums, published on GitHub Releases.

### Fixed

- Windows application icon (Explorer, taskbar, Alt+Tab) now renders the dark
  brand design at every size — the ICO uses all-PNG entries because Pillow's
  BMP frames lost the background in shell views.
