"""Scan orchestrator: selects modules, enforces timeouts, collects results."""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from reconforge.core import registry
from reconforge.core.context import ModuleResult, ScanContext
from reconforge.core.target import Target

SCHEMA_VERSION = 1


@dataclass
class ScanResult:
    target: Target
    profile: str
    started_at: str = ""
    finished_at: str = ""
    modules: dict[str, ModuleResult] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    ai: dict[str, Any] | None = None

    @property
    def ok_count(self) -> int:
        return sum(1 for m in self.modules.values() if m.status == "ok")

    @property
    def error_count(self) -> int:
        return sum(1 for m in self.modules.values() if m.status in ("error", "timeout"))

    @property
    def skipped_count(self) -> int:
        return sum(1 for m in self.modules.values() if m.status == "skipped")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "reconforge",
            "target": {"kind": self.target.kind, "value": self.target.value,
                       "meta": self.target.meta},
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stats": {
                "total": len(self.modules),
                "ok": self.ok_count,
                "skipped": self.skipped_count,
                "errors": self.error_count,
                "findings": len(self.findings),
            },
            "findings": self.findings,
            "modules": {k: v.to_dict() for k, v in self.modules.items()},
            "ai": self.ai,
        }


def run_scan(
    target: Target,
    ctx: ScanContext,
    profile: str = "passive",
    include_ids: list[str] | None = None,
    exclude_ids: list[str] | None = None,
) -> ScanResult:
    """Run all matching modules sequentially with per-module timeout."""
    if profile not in registry.PROFILES:
        raise ValueError(f"unknown profile: {profile}")

    registry.load_builtin_modules()
    modules = registry.get_modules(target_kind=target.kind, profile=profile)
    if include_ids is not None:
        modules = registry.get_modules(ids=include_ids)
        modules = [m for m in modules if target.kind in m.target_kinds]
    if exclude_ids:
        modules = [m for m in modules if m.id not in set(exclude_ids)]

    result = ScanResult(
        target=target,
        profile=profile,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    ctx.emit("scan_started", target=str(target), profile=profile,
             total_modules=len(modules))

    for meta in modules:
        ctx.emit("module_started", module_id=meta.id, description=meta.description)

        missing = [k for k in meta.requires_keys if not ctx.has_key(k)]
        if missing:
            module_result = ModuleResult(
                module_id=meta.id,
                status="skipped",
                error=f"missing API key(s): {', '.join(missing)}",
            )
        else:
            module_result = _run_single(meta, target, ctx)

        result.modules[meta.id] = module_result
        for finding in module_result.findings:
            result.findings.append(f"[{meta.id}] {finding}")
            ctx.emit("finding", message=finding, module_id=meta.id)
        ctx.emit(
            "module_finished",
            module_id=meta.id,
            status=module_result.status,
            duration_s=module_result.duration_s,
            error=module_result.error,
            findings=len(module_result.findings),
        )

    result.finished_at = datetime.now(timezone.utc).isoformat()
    ctx.emit(
        "scan_finished",
        target=str(target),
        ok=result.ok_count,
        skipped=result.skipped_count,
        errors=result.error_count,
        findings=len(result.findings),
    )
    return result


def _run_single(meta: registry.ModuleMeta, target: Target, ctx: ScanContext) -> ModuleResult:
    start = time.monotonic()
    timeout = ctx.module_timeout
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(meta.func, target, ctx)
        try:
            data, findings = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            # don't block on a hung module - abandon the thread (its own I/O
            # timeouts bound its lifetime)
            pool.shutdown(wait=False, cancel_futures=True)
            return ModuleResult(
                module_id=meta.id, status="timeout",
                error=f"timed out after {timeout}s",
                duration_s=time.monotonic() - start,
            )
        module_result = ModuleResult(
            module_id=meta.id,
            status="ok",
            data=data,
            findings=list(findings or []),
        )
    except _Skipped as exc:
        module_result = ModuleResult(module_id=meta.id, status="skipped", error=str(exc))
    except Exception as exc:  # module boundary: never let one failure kill the scan
        module_result = ModuleResult(
            module_id=meta.id, status="error", error=f"{type(exc).__name__}: {exc}"
        )
    else:
        pool.shutdown(wait=False)
    module_result.duration_s = time.monotonic() - start
    return module_result


class _Skipped(Exception):
    """Modules raise this for 'nothing to do' (e.g. no key)."""


def skip(reason: str):
    raise _Skipped(reason)
