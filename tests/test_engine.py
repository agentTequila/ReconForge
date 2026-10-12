"""Engine tests with fake modules (no network)."""

from reconforge.core import engine, registry
from reconforge.core.context import ScanContext
from reconforge.core.target import Target

FAKE_KIND = "person"


def _register_fake(mid: str, func):
    if mid in registry._REGISTRY:
        del registry._REGISTRY[mid]
    registry.register_module(
        id=mid, target_kinds=[FAKE_KIND], profile="passive", description="fake",
        requires_keys=getattr(func, "requires_keys", []),
    )(func)


def _ctx(keys=None, timeout=10):
    return ScanContext(keys=keys or {}, module_timeout=timeout)


def test_run_scan_ok_module():
    def ok_module(target, ctx):
        return {"greet": f"hi {target.value}"}, ["a finding"]

    _register_fake("fake.ok", ok_module)
    result = engine.run_scan(
        Target(FAKE_KIND, "Jane Doe"), _ctx(), include_ids=["fake.ok"]
    )
    mod = result.modules["fake.ok"]
    assert mod.status == "ok"
    assert mod.data == {"greet": "hi Jane Doe"}
    assert result.findings == ["[fake.ok] a finding"]


def test_run_scan_contains_module_exception():
    def boom(target, ctx):
        raise RuntimeError("kaput")

    _register_fake("fake.boom", boom)
    result = engine.run_scan(
        Target(FAKE_KIND, "Jane Doe"), _ctx(), include_ids=["fake.boom"]
    )
    mod = result.modules["fake.boom"]
    assert mod.status == "error"
    assert "kaput" in mod.error
    assert result.error_count == 1


def test_run_scan_skips_missing_key():
    def keyed(target, ctx):
        return {}, []

    keyed.requires_keys = ["NOT_A_REAL_KEY"]  # type: ignore[attr-defined]
    _register_fake("fake.keyed", keyed)
    result = engine.run_scan(
        Target(FAKE_KIND, "Jane Doe"), _ctx(), include_ids=["fake.keyed"]
    )
    mod = result.modules["fake.keyed"]
    assert mod.status == "skipped"
    assert "NOT_A_REAL_KEY" in mod.error


def test_run_scan_times_out():
    import time

    def slow(target, ctx):
        time.sleep(5)
        return {}, []

    _register_fake("fake.slow", slow)
    result = engine.run_scan(
        Target(FAKE_KIND, "Jane Doe"), _ctx(timeout=1), include_ids=["fake.slow"]
    )
    assert result.modules["fake.slow"].status == "timeout"


def test_events_emitted():
    from reconforge.core.events import EventBus

    seen = []

    def ok_module(target, ctx):
        return {}, []

    _register_fake("fake.events", ok_module)
    events = EventBus()
    events.subscribe(lambda e: seen.append(e.type))
    ctx = _ctx()
    ctx.events = events
    engine.run_scan(Target(FAKE_KIND, "Jane Doe"), ctx, include_ids=["fake.events"])
    assert "scan_started" in seen
    assert "module_started" in seen
    assert "module_finished" in seen
    assert "scan_finished" in seen


def test_exclude_ids():
    def ok_module(target, ctx):
        return {}, []

    _register_fake("fake.excluded", ok_module)
    result = engine.run_scan(
        Target(FAKE_KIND, "Jane Doe"), _ctx(),
        include_ids=["fake.excluded"], exclude_ids=["fake.excluded"],
    )
    assert "fake.excluded" not in result.modules
