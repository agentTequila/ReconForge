"""Registry tests."""

import pytest

from reconforge.core import registry


def test_builtin_modules_load():
    registry.load_builtin_modules()
    modules = registry.all_modules()
    assert len(modules) >= 35
    kinds = {k for m in modules for k in m.target_kinds}
    assert kinds == {"domain", "email", "phone", "person", "username", "ip"}
    profiles = {m.profile for m in modules}
    assert profiles == {"passive", "active"}


def test_filter_by_kind_and_profile():
    registry.load_builtin_modules()
    active_domain = registry.get_modules(target_kind="domain", profile="active")
    assert active_domain
    assert all("domain" in m.target_kinds and m.profile == "active"
               for m in active_domain)


def test_unknown_id_raises():
    registry.load_builtin_modules()
    with pytest.raises(KeyError):
        registry.get_modules(ids=["nope.not_a_module"])


def test_duplicate_id_rejected():
    registry.load_builtin_modules()
    with pytest.raises(ValueError):
        registry.register_module(
            id="domain.whois", target_kinds=["domain"], description="dup"
        )(lambda t, c: ({}, []))


def test_invalid_profile_rejected():
    with pytest.raises(ValueError):
        registry.register_module(
            id="test.bad", target_kinds=["domain"], profile="loud"
        )(lambda t, c: ({}, []))
