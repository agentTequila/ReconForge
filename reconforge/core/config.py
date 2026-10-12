"""Configuration and API key handling.

Single hidden ``.apikeys`` file (generated on first run), environment override,
legacy ``.env`` fallback. Key values are never logged.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

API_KEY_NAMES = (
    "SHODAN_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "HUNTER_API_KEY",
    "HIBP_API_KEY",
    "EMAILREP_API_KEY",
    "NUMVERIFY_API_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "OPENROUTER_API_KEY",
)

KEY_FILE_NAME = ".apikeys"

_TEMPLATE = """\
# ReconForge API keys - generated on first run
# DO NOT COMMIT THIS FILE to version control.
# Fill in whichever keys you have; modules without keys are skipped, never fatal.
# Format: KEY=value  (one per line, '#' starts a comment)
#
# Get keys:
#   SHODAN_API_KEY       https://account.shodan.io/
#   VIRUSTOTAL_API_KEY   https://www.virustotal.com/gui/my-apikey
#   HUNTER_API_KEY       https://hunter.io/api-keys
#   HIBP_API_KEY         https://haveibeenpwned.com/API/Key
#   EMAILREP_API_KEY     https://emailrep.io/
#   NUMVERIFY_API_KEY    https://numverify.com/
#
# AI (bring your own key) - only needed for `--ai` features:
#   OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / GROQ_API_KEY
#   MISTRAL_API_KEY / OPENROUTER_API_KEY
#   Ollama needs no key (local http://localhost:11434).

SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
HUNTER_API_KEY=
HIBP_API_KEY=
EMAILREP_API_KEY=
NUMVERIFY_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GEMINI_API_KEY=
GROQ_API_KEY=
MISTRAL_API_KEY=
OPENROUTER_API_KEY=
"""


def global_key_file() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "reconforge" / KEY_FILE_NAME


def _parse_key_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip().upper()
            value = value.strip().strip('"').strip("'")
            if key in API_KEY_NAMES and value:
                values[key] = value
    except OSError:
        pass
    return values


def _set_hidden(path: Path, enabled: bool) -> None:
    """Hide/unhide the key file as far as the OS allows.

    Note: some Windows security setups deny truncating ('w') hidden files, so
    writes go through _write_key_file which clears the attribute first.
    """
    try:
        if os.name == "nt":
            import ctypes

            FILE_ATTRIBUTE_HIDDEN = 0x02
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
            if attrs != -1:
                new = (attrs | FILE_ATTRIBUTE_HIDDEN) if enabled else (
                    attrs & ~FILE_ATTRIBUTE_HIDDEN
                )
                if new != attrs:
                    ctypes.windll.kernel32.SetFileAttributesW(str(path), new)  # type: ignore[attr-defined]
        elif enabled:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def _write_key_file(path: Path, text: str) -> None:
    """Write key-file content: unhide (Windows 'w' can fail on hidden files),
    write, re-apply protection."""
    _set_hidden(path, False)
    try:
        path.write_text(text, encoding="utf-8")
    finally:
        _set_hidden(path, True)


def ensure_key_file(directory: Path | None = None) -> Path:
    """Return the project key file, creating the template on first run."""
    directory = directory or Path.cwd()
    key_file = directory / KEY_FILE_NAME
    if not key_file.exists():
        _write_key_file(key_file, _TEMPLATE)
    return key_file


def load_keys(directory: Path | None = None) -> dict[str, str]:
    """Load API keys. Precedence: env var > ./.apikeys > global .apikeys > .env.

    Always returns a full mapping of every known key name ('' = not set).
    """
    directory = directory or Path.cwd()
    keys: dict[str, str] = {name: "" for name in API_KEY_NAMES}

    env_file = directory / ".env"
    if env_file.exists():
        keys.update({k: v for k, v in _parse_key_file(env_file).items()})

    global_file = global_key_file()
    if global_file.exists():
        keys.update(_parse_key_file(global_file))

    project_file = directory / KEY_FILE_NAME
    if project_file.exists():
        keys.update(_parse_key_file(project_file))
    else:
        project_file = ensure_key_file(directory)

    for name in API_KEY_NAMES:
        env_val = os.environ.get(name, "").strip()
        if env_val:
            keys[name] = env_val

    _warn_if_unignored(project_file, directory)
    return keys


def _warn_if_unignored(key_file: Path, directory: Path) -> None:
    """One-time warning if the key file sits in a git repo without being ignored."""
    if not any((p / ".git").exists() for p in [directory, *directory.parents]):
        return
    gitignore = directory / ".gitignore"
    ignored = False
    if gitignore.exists():
        patterns = gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
        ignored = any(
            p.strip() in (KEY_FILE_NAME, "/" + KEY_FILE_NAME, f"*{KEY_FILE_NAME}")
            for p in patterns
            if p.strip() and not p.strip().startswith("#")
        )
    if not ignored:
        print(
            f"[reconforge] WARNING: {key_file.name} is inside a git working tree and "
            f"not listed in .gitignore - add '{KEY_FILE_NAME}' before committing.",
            file=sys.stderr,
        )


def key_count(keys: dict[str, str]) -> int:
    return sum(1 for v in keys.values() if v)


def save_keys(updates: dict[str, str], directory: Path | None = None) -> Path:
    """Merge updates into the project .apikeys file (value empty string removes)."""
    key_file = ensure_key_file(directory)
    directory = directory or Path.cwd()
    existing: dict[str, str] = {}
    keep_lines: list[str] = []
    for line in key_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _, v = stripped.partition("=")
            existing[k.strip().upper()] = v.strip()
            keep_lines.append((k.strip().upper(), line))
        else:
            keep_lines.append((None, line))

    merged = {**existing, **{k.upper(): v for k, v in updates.items()}}
    out_lines = []
    seen = set()
    for key, line in keep_lines:
        if key is None:
            out_lines.append(line)
            continue
        seen.add(key)
        out_lines.append(f"{key}={merged.get(key, '')}")
    for key, value in merged.items():
        if key not in seen:
            out_lines.append(f"{key}={value}")
    _write_key_file(key_file, "\n".join(out_lines) + "\n")
    return key_file


def provider_display_name(key_name: str) -> str:
    return key_name.removesuffix("_API_KEY").replace("_", " ").title()
