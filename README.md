# ReconForge

<p align="center">
  <img src="assets/icon.png" width="120" alt="ReconForge icon">
</p>

<p align="center">
  <b>OSINT reconnaissance, forged into one toolkit.</b><br>
  44 modules · 64+ platforms · 6 target types · rich CLI + GUI · bring-your-own-key AI
</p>

<p align="center">
  <a href="https://github.com/agentTequila/ReconForge/actions"><img src="https://github.com/agentTequila/ReconForge/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Cross-platform">
</p>

---

> ⚠️ **Authorized testing only.** ReconForge collects publicly available
> information. Active modules (ports, directories, SMTP probes) send traffic to
> the target and may only be used on assets you own or are explicitly authorized
> to test. See [Ethics & legal](#ethics--legal).

## Why ReconForge?

- **One engine, two frontends.** `reconforge` is the CLI: Linux-first, rich
  tables, a real startup banner. `reconforge-gui` is the Windows-first
  CustomTkinter app. Both run on Windows, Linux, and macOS and share the same
  scan logic, so a target comes back the same either way.
- **Passive profile out of the box.** Active modules (ports, directories, SMTP)
  stay behind an explicit flag and a confirmation prompt.
- **It shows its work.** A progress bar and flavor text ("sifting through
  certificate ashes...") stream in both frontends while modules run.
- **No keys needed to start.** Every key-less module runs with zero setup. Add
  API keys when you have them to run more, and point the AI features at your
  own key (BYOK) or a local [Ollama](https://ollama.com) model if you'd rather
  nothing left your machine.
- **A new capability is one file with one decorator.** See
  [CONTRIBUTING.md](CONTRIBUTING.md).

## Coverage

| Target type | What you get |
|-------------|--------------|
| **Domain** | WHOIS, DNS, subdomains (crt.sh + wordlist + HackerTarget), TLS certs, tech fingerprint, security headers, robots.txt, Wayback history, Google dorks, urlscan.io, Shodan & VirusTotal (key), port scan / directory discovery / HTTP methods (active) |
| **Email** | HIBP breach history (key), EmailRep reputation (key), MX checks, Gravatar profiles, naming-pattern analysis, social/breach search links, SMTP mailbox verify (active) |
| **Phone** | Region/carrier/line-type parsing, NumVerify lookup (key), caller-lookup & social URLs |
| **Person** | Social search (15 platforms), people-search engines, professional/academic networks, breach indexes, username-variant generator |
| **Username** | Live account checks across **64+ platforms** (GitHub, X, TikTok, Steam, Reddit, …) with per-site detection logic |
| **IP** | RDAP (org, abuse contact), geo/ASN, BGP announcements, reverse DNS, Shodan & VirusTotal (key), nmap service/version detection (active, needs `nmap`), threat-intel links |

Every module that can't run automatically still emits **ready-to-open OSINT
links** so no investigation path is a dead end.

## Install

```bash
git clone https://github.com/agentTequila/ReconForge.git
cd ReconForge
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

## Quickstart

```bash
reconforge                       # banner: version, API keys, capabilities
reconforge scan example.com      # passive domain scan -> JSON/MD/HTML/txt reports
reconforge scan user@example.com
reconforge scan "+441234567890"
reconforge scan "Jane Doe"       # person OSINT link pack
reconforge scan octocat --type username   # 64+ platform account sweep
reconforge scan 8.8.8.8          # IP: RDAP, geo, rDNS, intel links

reconforge --help                # all options
reconforge modules               # list every module, profile, key requirement
reconforge platforms             # every platform/source ReconForge touches
```

**GUI (Windows-first):**

```bash
reconforge-gui
```

Pick a target, choose Passive or Active, hit Scan. The log streams while it
runs, each module's raw JSON is readable as it lands, and reports are written
automatically (open them from the Report tab). AI insights run from the bottom
bar. Window icon comes from the bundled `assets/icon.ico`.

**Active scans** (ports, directories, SMTP) need explicit consent:

```bash
reconforge scan example.com --active        # prompts for YES
reconforge scan example.com --active -y     # scripted/CI use
```

## API keys (`.apikeys`)

On first run ReconForge generates a hidden `.apikeys` template in your working
directory (Hidden attribute on Windows, `0600` on Linux/macOS). Fill in what
you have. Empty keys simply skip those modules:

```bash
reconforge keys list                       # what's configured
reconforge keys set SHODAN_API_KEY abc...  # saved into .apikeys
```

In the GUI, use the toolbar button to open the **API keys** dialog. Every
service and AI key is listed with a `?` link to the provider's key page, and
saved keys are masked. Changes apply to the next scan without restarting.

Precedence: **environment variable → `./.apikeys` → global
`~/.config/reconforge/.apikeys`** (`%APPDATA%\reconforge\.apikeys` on Windows).
`.apikeys` is git-ignored, and ReconForge warns if it ever sits inside a git
repo without being ignored. **Never commit your keys.**

Supported keys: Shodan, VirusTotal, Hunter.io, Have I Been Pwned, EmailRep,
NumVerify, plus the AI keys below.

## AI (bring your own key)

AI features are **off unless you configure a provider**. Only scan results are
sent (never your keys), and `--redact` hashes emails/phones/IPs first.

| Provider | Key | Local? |
|----------|-----|--------|
| OpenAI / Anthropic / Gemini / Groq / Mistral / OpenRouter | per-provider key | no |
| **Ollama** | none | ✅ fully local, air-gap friendly |

```bash
reconforge keys set OPENAI_API_KEY sk-...
reconforge scan example.com --ai                    # summary + risk correlation + next steps
reconforge scan example.com --ai --provider ollama  # local model, zero data leaves your box
reconforge ai "what's the biggest risk here?" --scan reconforge_output/domain_example.com_...
```

In the GUI: choose a provider, paste the key, hit **Save key**, tick **AI
insights**, scan. The *Ask* box answers questions about the last scan.

## Output

Every scan writes `reconforge_output/<target>_<timestamp>/`:

- `full_results.json` — canonical machine-readable results (schema v1)
- `REPORT.md` — GitHub-friendly report with findings + AI insights
- `report.html` — self-contained dark-theme report, safe to share
- `summary.txt` — short digest

## Downloads (Windows)

Portable builds ship on the
[Releases](https://github.com/agentTequila/ReconForge/releases) page:

| Asset | What it is |
|-------|------------|
| `ReconForge-v*-win64.exe` | GUI: download and double-click, no installer |
| `reconforge-cli-v*-win64.exe` | the full CLI in one file |
| `SHA256SUMS.txt` | verify your download (`Get-FileHash -Algorithm SHA256`) |

Portable means no installer: `.apikeys` and `reconforge_output\` are created
**next to the exe** (it runs fine from a USB stick). Windows SmartScreen may
flag unsigned executables. That's normal for open-source builds; verify the
SHA-256 against `SHA256SUMS.txt` and run it yourself.

Prefer building from source? It's one command:

```powershell
powershell -ExecutionPolicy Bypass -File tools/build_exe.ps1
```

## Architecture

```
reconforge/
├── core/          # engine, module registry, .apikeys config, cache, rate-limit
├── modules/       # domain · email · phone · person · username · ip · publicdata
├── integrations/  # Shodan, VirusTotal, HIBP, Hunter, EmailRep, NumVerify
├── ai/            # BYOK providers + summarize/correlate/ask/suggest
├── reporting/     # JSON, Markdown, HTML, summary writers
├── cli.py         # click + rich frontend
├── gui.py         # CustomTkinter frontend
└── data/          # platforms.json - community-editable coverage list
```

Modules register with a decorator and return `(data, findings)`. The engine
enforces per-module timeouts, isolates failures, skips missing-key modules, and
emits events the CLI/GUI render. The core never imports UI code.

## Development

```bash
pip install -e ".[dev]"
pytest          # offline test suite
ruff check .    # lint
```

New platform to add? Append an entry to `reconforge/data/platforms.json`
(no code required). New module? See [CONTRIBUTING.md](CONTRIBUTING.md).

## Ethics & legal

ReconForge is intended for **authorized security testing, incident response,
defensive research, and education**. You are responsible for complying with all
applicable laws and terms of service of third-party sources. Passive modules
query public data; active modules interact with live systems. Obtain written
permission before scanning assets you do not own.

## License

[MIT](LICENSE). Contributions welcome.
