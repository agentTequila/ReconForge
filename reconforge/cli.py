"""ReconForge command-line interface (click + rich).

Run ``reconforge`` with no arguments for the banner and help.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from reconforge import __version__
from reconforge.core import config, registry
from reconforge.core.verbose import flavor_for

console = Console()

TARGET_HELP = "Domain, email, phone number, person name, username, or IP address."


def _stdout_handles_blocks() -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "█╗╔╝═".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def _figlet(text: str) -> str:
    fonts = ("ansi_shadow", "slant", "standard") if _stdout_handles_blocks() else (
        "slant", "standard"
    )
    try:
        from pyfiglet import Figlet

        for font in fonts:
            try:
                return Figlet(font=font).renderText(text)
            except Exception:
                continue
    except Exception:
        pass
    return text + "\n"


def show_banner(keys: dict[str, str] | None = None) -> None:
    """Startup banner: name, version, API key count, capabilities."""
    keys = config.load_keys() if keys is None else keys
    registry.load_builtin_modules()
    modules = registry.all_modules()
    passive = sum(1 for m in modules if m.profile == "passive")
    active = sum(1 for m in modules if m.profile == "active")
    configured = config.key_count(keys)
    total_keys = len(config.API_KEY_NAMES)
    ai_ready = any(
        keys.get(k)
        for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                  "GROQ_API_KEY", "MISTRAL_API_KEY", "OPENROUTER_API_KEY")
    )

    wordmark = _figlet("ReconForge").rstrip()
    if any(len(line) > console.width - 1 for line in wordmark.splitlines()):
        wordmark = (_figlet("Recon").rstrip() + "\n" + _figlet("Forge").rstrip())
    console.print(Text(wordmark, style="bold cyan"))
    stats = Table.grid(padding=(0, 2))
    stats.add_row("v" + __version__, "OSINT Reconnaissance Toolkit",
                  style="dim")
    stats.add_row(
        f"[green]API keys[/green] {configured}/{total_keys}",
        f"[green]Modules[/green] {len(modules)} ({passive} passive / {active} active)",
        "[green]Targets[/green] 6",
    )
    stats.add_row(
        "[green]Platforms[/green] 64+",
        f"[green]AI[/green] {'ready' if ai_ready else 'byo-key (see keys)'}",
        "[dim]github.com/ReconForge/ReconForge[/dim]",
    )
    console.print(stats)
    if configured == 0:
        console.print(
            "[yellow]![/yellow] no API keys configured - key-less modules only. "
            "Add keys in .apikeys (auto-generated) then re-run.",
        )
    console.print()


def _confirm_active(yes: bool) -> None:
    if yes:
        return
    console.print(Panel.fit(
        "[bold yellow]ACTIVE SCAN[/bold yellow]\n"
        "Active modules send traffic directly to the target (ports, directories,\n"
        "SMTP). Only run this against assets you are [bold]authorized[/bold] to test.",
        border_style="yellow",
    ))
    if not sys.stdin.isatty():
        raise click.ClickException(
            "active profile needs confirmation: pass --yes in non-interactive mode"
        )
    answer = console.input("Type [bold]YES[/bold] to proceed: ").strip()
    if answer != "YES":
        raise click.Abort()


def _print_results(result, files: list[Path]) -> None:
    table = Table(title="Module results", show_lines=False)
    table.add_column("Module", style="cyan")
    table.add_column("Status")
    table.add_column("Time", justify="right")
    table.add_column("Detail", overflow="fold")
    status_style = {"ok": "green", "skipped": "yellow", "error": "red", "timeout": "red"}
    for mid, mod in sorted(result.modules.items()):
        if mod.status == "ok":
            detail = mod.error or f"{len(mod.findings)} finding(s)"
        else:
            detail = mod.error or ""
        table.add_row(
            mid,
            f"[{status_style.get(mod.status, 'white')}]{mod.status}[/]",
            f"{mod.duration_s:.1f}s",
            detail,
        )
    console.print(table)
    if result.findings:
        lines = "\n".join(f"• {f}" for f in result.findings[:30])
        console.print(Panel(lines, title=f"Key findings ({len(result.findings)})",
                            border_style="magenta"))
    if files:
        console.print("[green]+[/green] reports written:")
        for path in files:
            console.print(f"    {path}")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="reconforge")
@click.option("--no-banner", is_flag=True, help="Skip the startup banner.")
@click.pass_context
def main(ctx: click.Context, no_banner: bool) -> None:
    """ReconForge - cross-platform OSINT reconnaissance toolkit."""
    ctx.ensure_object(dict)
    ctx.obj["no_banner"] = no_banner
    if not no_banner and ctx.invoked_subcommand != "keys":
        show_banner()


@main.command()
@click.argument("target")
@click.option("--type", "target_type", type=click.Choice(
    ["domain", "email", "phone", "person", "username", "ip"]),
    help="Force target type (auto-detected by default).")
@click.option("--profile", type=click.Choice(["passive", "active"]),
    default="passive", show_default=True, help="Scan profile.")
@click.option("--active", is_flag=True, help="Shorthand for --profile active.")
@click.option("--modules", "include", help="Comma-separated module ids to run.")
@click.option("--exclude", help="Comma-separated module ids to skip.")
@click.option("--output", type=click.Path(file_okay=False, path_type=Path),
    default=None, help="Output directory root.")
@click.option("--format", "fmt", default="json,md,html,txt", show_default=True,
    help="Report formats: json,md,html,txt.")
@click.option("--ai", "ai_enabled", is_flag=True, help="Run BYOK AI analysis.")
@click.option("--provider", type=click.Choice(list(
    ["openai", "anthropic", "gemini", "groq", "mistral", "openrouter", "ollama"])),
    help="AI provider for --ai (default: first key found).")
@click.option("--redact", is_flag=True, help="Redact PII before sending to AI.")
@click.option("--proxy", help="Proxy for all requests, e.g. socks5h://127.0.0.1:9050.")
@click.option("--no-cache", is_flag=True, help="Disable the response cache.")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompts.")
@click.pass_context
def scan(ctx: click.Context, target: str, target_type: str | None, profile: str,
         active: bool, include: str | None, exclude: str | None,
         output: Path | None, fmt: str, ai_enabled: bool, provider: str | None,
         redact: bool, proxy: str | None, no_cache: bool, yes: bool) -> None:
    """Scan TARGET (domain, email, phone, person, username, or IP)."""
    from reconforge.core import engine
    from reconforge.core.cache import ResponseCache
    from reconforge.core.context import ScanContext
    from reconforge.core.events import EventBus
    from reconforge.core.target import parse_target
    from reconforge.reporting import output_directory, write_all

    if active:
        profile = "active"
    if profile == "active":
        _confirm_active(yes)

    keys = config.load_keys()
    try:
        parsed = parse_target(target, target_type)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if config.key_count(keys) == 0 and not ctx.obj.get("warned_keys"):
        console.print(
            "[yellow]![/yellow] .apikeys has no keys yet - continuing with "
            "key-less modules only."
        )

    events = EventBus()
    progress = Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=28, complete_style="green", finished_style="green"),
        TextColumn("[cyan]{task.completed}/{task.total}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    task_id: int | None = None
    buffer: list[str] = []

    def _flush() -> None:
        """Emit every buffered module line at once, above the live bar."""
        if not buffer:
            return
        progress.console.print("\n".join(buffer))
        buffer.clear()

    def _listener(event):  # noqa: ANN001
        nonlocal task_id
        if event.type == "scan_started":
            total = int(event.data.get("total_modules") or 0)
            task_id = progress.add_task(flavor_for("scan.start"), total=total)
        elif event.type == "module_started":
            if task_id is not None:
                progress.update(task_id, description=flavor_for(event.data["module_id"]))
        elif event.type == "module_finished":
            status = event.data["status"]
            style = {"ok": "green", "skipped": "yellow"}.get(status, "red")
            mark = {"ok": "+", "skipped": "~"}.get(status, "x")
            extra = (f" [red]{event.data['error']}[/red]"
                     if event.data.get("error") else "")
            buffer.append(
                f"  {event.data['module_id']:<28} [{style}]{mark} {status:<7}"
                f"[/{style}] {event.data['duration_s']:5.1f}s "
                f"[dim]{event.data.get('findings', 0)} finding(s)[/dim]{extra}"
            )
            if task_id is not None:
                progress.advance(task_id)
        elif event.type == "finding":
            buffer.append(f"    [green]>[/green] {event.data['message']}")
        elif event.type == "log":
            style = {"info": "dim", "success": "green", "warn": "yellow"}.get(
                event.data.get("level"), "dim")
            buffer.append(f"    [{style}]{event.data['message']}[/]")

    events.subscribe(_listener)

    cache_dir = Path.home() / ".cache" / "reconforge"
    scan_ctx = ScanContext(
        keys=keys,
        events=events,
        cache=ResponseCache(cache_dir, enabled=not no_cache),
        proxy=proxy,
        redact=redact,
        yes=yes,
    )
    progress.start()
    try:
        result = engine.run_scan(
            parsed,
            scan_ctx,
            profile=profile,
            include_ids=include.split(",") if include else None,
            exclude_ids=exclude.split(",") if exclude else None,
        )
    finally:
        _flush()
        progress.stop()

    if ai_enabled:
        _run_ai(result, scan_ctx, provider, redact)

    directory = output_directory(output, result)
    formats = tuple(f.strip() for f in fmt.split(",") if f.strip())
    files = write_all(result, directory, formats)
    _print_results(result, files)


def _run_ai(result, scan_ctx, provider: str | None, redact: bool) -> None:
    from reconforge.ai import analyze
    from reconforge.ai.providers import AIError, resolve_provider

    try:
        spec = resolve_provider(provider, scan_ctx)
        scan_ctx.redact = redact
        insights = analyze.run_ai(
            {"summarize": True, "correlate": True, "suggest": True},
            spec, scan_ctx, result,
        )
        result.ai = insights
        for title, body in insights.items():
            console.print(Panel(body, title=f"[bold]AI: {title}[/]",
                                border_style="blue"))
    except AIError as exc:
        console.print(f"[yellow]AI skipped:[/] {exc}")


@main.command()
@click.option("--kind", type=click.Choice(
    ["domain", "email", "phone", "person", "username", "ip"]),
    help="Show modules for one target kind.")
def modules(kind: str | None) -> None:
    """List all registered recon modules."""
    registry.load_builtin_modules()
    table = Table(title="ReconForge modules")
    table.add_column("ID", style="cyan")
    table.add_column("Targets")
    table.add_column("Profile")
    table.add_column("Keys")
    table.add_column("Description", overflow="fold")
    for meta in registry.get_modules(target_kind=kind):
        table.add_row(
            meta.id,
            ",".join(meta.target_kinds),
            f"[green]{meta.profile}[/]" if meta.profile == "passive"
            else f"[yellow]{meta.profile}[/]",
            ", ".join(k.removesuffix("_API_KEY") for k in meta.requires_keys) or "-",
            meta.description,
        )
    console.print(table)


@main.command()
@click.argument("action", type=click.Choice(["list", "set", "remove"]), required=False)
@click.argument("name", required=False)
@click.argument("value", required=False)
def keys(action: str | None, name: str | None, value: str | None) -> None:
    """Manage API keys in the hidden .apikeys file.

    \b
    reconforge keys list
    reconforge keys set SHODAN_API_KEY <key>
    reconforge keys remove SHODAN_API_KEY
    """
    if action is None or action == "list":
        current = config.load_keys()
        table = Table(title=f"API keys ({config.key_count(current)}/"
                            f"{len(config.API_KEY_NAMES)} configured)")
        table.add_column("Key")
        table.add_column("Status")
        for key_name in config.API_KEY_NAMES:
            status = "[green]configured[/]" if current.get(key_name) else "not set"
            table.add_row(key_name, status)
        console.print(table)
        console.print(f"[dim]file: {Path.cwd() / config.KEY_FILE_NAME}[/]")
        return
    if not name:
        raise click.ClickException("usage: reconforge keys set <KEY_NAME> <value>")
    key_name = name.upper()
    if key_name not in config.API_KEY_NAMES:
        raise click.ClickException(
            f"unknown key {key_name}; valid: {', '.join(config.API_KEY_NAMES)}"
        )
    if action == "set":
        if not value:
            raise click.ClickException("missing value")
        config.save_keys({key_name: value})
        console.print(f"[green]+[/green] {key_name} saved to "
                      f"{config.KEY_FILE_NAME} (hidden)")
    else:
        config.save_keys({key_name: ""})
        console.print(f"[yellow]-[/yellow] {key_name} removed")


@main.command()
@click.argument("target", required=False)
@click.option("--kind", type=click.Choice(
    ["domain", "email", "phone", "person", "username", "ip"]),
    help="Filter modules by target kind.")
def platforms(target: str | None, kind: str | None) -> None:
    """Show every OSINT platform/source ReconForge uses."""
    registry.load_builtin_modules()
    from reconforge.modules.username import load_platforms

    if target or kind:
        table = Table(title="Modules for this target")
        table.add_column("ID", style="cyan")
        table.add_column("Profile")
        table.add_column("Description", overflow="fold")
        for meta in registry.get_modules(target_kind=kind):
            table.add_row(meta.id, meta.profile, meta.description)
        console.print(table)
        return

    console.print(Panel.fit(
        "[bold]64+ platforms[/bold] across username checks, social search, "
        "people-search, breach indexes, threat intel and public records.",
        title="Coverage", border_style="cyan"))
    data = Table(title="Username check platforms")
    data.add_column("Platform", style="cyan")
    data.add_column("Category")
    data.add_column("URL template", overflow="fold")
    for p in load_platforms():
        data.add_row(p["name"], p["category"], p["url"])
    console.print(data)
    console.print("[dim]Plus per-target link modules: `reconforge modules`[/]")


@main.command()
@click.argument("question")
@click.option("--scan", "scan_dir", type=click.Path(exists=True, file_okay=False,
    path_type=Path), required=True, help="Directory containing full_results.json.")
@click.option("--provider", type=click.Choice(
    ["openai", "anthropic", "gemini", "groq", "mistral", "openrouter", "ollama"]))
@click.option("--redact", is_flag=True, help="Redact PII before sending to AI.")
def ai(question: str, scan_dir: Path, provider: str | None, redact: bool) -> None:
    """Ask a natural-language question about a previous scan."""
    from reconforge.ai import analyze
    from reconforge.ai.providers import AIError, resolve_provider
    from reconforge.core.context import ScanContext
    from reconforge.core.engine import ScanResult
    from reconforge.core.target import Target

    results_file = scan_dir / "full_results.json"
    if not results_file.exists():
        raise click.ClickException(f"{results_file} not found")
    payload = json.loads(results_file.read_text(encoding="utf-8"))
    target_data = payload.get("target", {})
    result = ScanResult(
        target=Target(target_data.get("kind", "domain"),
                      target_data.get("value", ""), target_data.get("meta", {})),
        profile=payload.get("profile", "passive"),
        started_at=payload.get("started_at", ""),
        finished_at=payload.get("finished_at", ""),
    )
    from reconforge.core.context import ModuleResult
    for mid, mod in payload.get("modules", {}).items():
        result.modules[mid] = ModuleResult(
            module_id=mid, status=mod.get("status", "ok"), data=mod.get("data"),
            findings=mod.get("findings", []), error=mod.get("error"),
            duration_s=mod.get("duration_s", 0),
        )
    result.findings = payload.get("findings", [])

    scan_ctx = ScanContext(keys=config.load_keys(), redact=redact)
    try:
        spec = resolve_provider(provider, scan_ctx)
        answer = analyze.ask(spec, scan_ctx, result, question, redact)
    except AIError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(Panel(answer, title=f"AI answer: {question}", border_style="blue"))


if __name__ == "__main__":
    main()
