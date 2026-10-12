"""Module registry: recon modules self-register via @register_module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

PROFILES = ("passive", "active")


@dataclass(frozen=True)
class ModuleMeta:
    id: str
    target_kinds: tuple[str, ...]
    profile: str
    description: str
    requires_keys: tuple[str, ...] = ()
    func: Callable = field(compare=False, repr=False, default=None)


_REGISTRY: dict[str, ModuleMeta] = {}


def register_module(
    id: str,
    target_kinds: list[str],
    profile: str = "passive",
    description: str = "",
    requires_keys: list[str] | None = None,
):
    """Register a recon module.

    The decorated function must have signature ``(target, ctx) -> ModuleResult``
    and must not raise past its own boundary.
    """
    if profile not in PROFILES:
        raise ValueError(f"module {id}: profile must be one of {PROFILES}")

    def decorator(func):
        if id in _REGISTRY:
            raise ValueError(f"duplicate module id: {id}")
        _REGISTRY[id] = ModuleMeta(
            id=id,
            target_kinds=tuple(target_kinds),
            profile=profile,
            description=description,
            requires_keys=tuple(requires_keys or ()),
            func=func,
        )
        return func

    return decorator


def get_modules(
    target_kind: str | None = None,
    profile: str | None = None,
    ids: list[str] | None = None,
) -> list[ModuleMeta]:
    modules = list(_REGISTRY.values())
    if target_kind:
        modules = [m for m in modules if target_kind in m.target_kinds]
    if profile:
        modules = [m for m in modules if m.profile == profile]
    if ids is not None:
        wanted = set(ids)
        unknown = wanted - set(_REGISTRY)
        if unknown:
            raise KeyError(f"unknown module ids: {', '.join(sorted(unknown))}")
        modules = [m for m in modules if m.id in wanted]
    return sorted(modules, key=lambda m: m.id)


def all_modules() -> list[ModuleMeta]:
    return sorted(_REGISTRY.values(), key=lambda m: m.id)


def load_builtin_modules() -> None:
    """Import built-in module packs so they register themselves."""
    from reconforge.modules import (  # noqa: F401
        domain,
        email,
        ip,
        person,
        phone,
        publicdata,
        username,
    )
