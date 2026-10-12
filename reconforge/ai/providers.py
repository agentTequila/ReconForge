"""Bring-your-own-key AI providers (OpenAI, Anthropic, Gemini, Groq,
Mistral, OpenRouter, Ollama-local). Plain requests, no SDK dependencies."""

from __future__ import annotations

from dataclasses import dataclass

import requests

from reconforge.core.context import ScanContext


class AIError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    key_name: str | None  # None = local, no key needed
    base_url: str
    default_model: str
    style: str  # openai | anthropic | gemini
    label: str


PROVIDERS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec("openai", "OPENAI_API_KEY", "https://api.openai.com/v1",
                           "gpt-4o-mini", "openai", "OpenAI"),
    "anthropic": ProviderSpec("anthropic", "ANTHROPIC_API_KEY",
                              "https://api.anthropic.com/v1",
                              "claude-3-5-haiku-latest", "anthropic", "Anthropic"),
    "gemini": ProviderSpec("gemini", "GEMINI_API_KEY",
                           "https://generativelanguage.googleapis.com/v1beta",
                           "gemini-2.0-flash", "gemini", "Google Gemini"),
    "groq": ProviderSpec("groq", "GROQ_API_KEY", "https://api.groq.com/openai/v1",
                         "llama-3.3-70b-versatile", "openai", "Groq"),
    "mistral": ProviderSpec("mistral", "MISTRAL_API_KEY", "https://api.mistral.ai/v1",
                            "mistral-small-latest", "openai", "Mistral"),
    "openrouter": ProviderSpec("openrouter", "OPENROUTER_API_KEY",
                               "https://openrouter.ai/api/v1",
                               "openai/gpt-4o-mini", "openai", "OpenRouter"),
    "ollama": ProviderSpec("ollama", None, "http://localhost:11434/v1",
                           "llama3.2", "openai", "Ollama (local)"),
}


def resolve_provider(name: str | None, ctx: ScanContext) -> ProviderSpec:
    """Pick a provider: explicit name > first with a key > ollama if reachable."""
    if name:
        if name not in PROVIDERS:
            raise AIError(f"unknown provider: {name} (choose from {', '.join(PROVIDERS)})")
        spec = PROVIDERS[name]
        if spec.key_name and not ctx.has_key(spec.key_name):
            raise AIError(f"missing key for {spec.name}: set {spec.key_name} in .apikeys")
        return spec
    for spec in PROVIDERS.values():
        if spec.key_name and ctx.has_key(spec.key_name):
            return spec
    raise AIError(
        "no AI key configured - run `reconforge keys set openai <key>` "
        "or use --provider ollama with a local Ollama server"
    )


def complete(spec: ProviderSpec, system: str, user: str, ctx: ScanContext,
             timeout: int = 120) -> str:
    ctx.log(f"AI request -> {spec.label} ({spec.default_model})", "info")
    try:
        if spec.style == "openai":
            return _openai_style(spec, system, user, ctx, timeout)
        if spec.style == "anthropic":
            return _anthropic_style(spec, system, user, ctx, timeout)
        return _gemini_style(spec, system, user, ctx, timeout)
    except requests.RequestException as exc:
        raise AIError(f"{spec.label} request failed: {exc}") from exc


def _openai_style(spec: ProviderSpec, system: str, user: str, ctx: ScanContext,
                  timeout: int) -> str:
    headers = {}
    if spec.key_name:
        headers["Authorization"] = f"Bearer {ctx.keys[spec.key_name]}"
    resp = ctx.session.post(
        f"{spec.base_url}/chat/completions",
        headers=headers,
        json={
            "model": spec.default_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        },
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise AIError(f"{spec.label} HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()["choices"][0]["message"]["content"]


def _anthropic_style(spec: ProviderSpec, system: str, user: str, ctx: ScanContext,
                     timeout: int) -> str:
    resp = ctx.session.post(
        f"{spec.base_url}/messages",
        headers={
            "x-api-key": ctx.keys[spec.key_name],
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": spec.default_model,
            "max_tokens": 2048,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise AIError(f"{spec.label} HTTP {resp.status_code}: {resp.text[:200]}")
    blocks = resp.json().get("content", [])
    return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")


def _gemini_style(spec: ProviderSpec, system: str, user: str, ctx: ScanContext,
                  timeout: int) -> str:
    resp = ctx.session.post(
        f"{spec.base_url}/models/{spec.default_model}:generateContent",
        params={"key": ctx.keys[spec.key_name]},
        json={
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.2},
        },
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise AIError(f"{spec.label} HTTP {resp.status_code}: {resp.text[:200]}")
    candidates = resp.json().get("candidates", [])
    if not candidates:
        raise AIError(f"{spec.label} returned no candidates")
    parts = candidates[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts)
