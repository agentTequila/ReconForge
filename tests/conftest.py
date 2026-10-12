"""Shared test fixtures: isolate key files and API-key env vars."""

import pytest

from reconforge.core import config


@pytest.fixture(autouse=True)
def isolate_key_files(tmp_path, monkeypatch):
    # point the global key file at a nonexistent path (name keeps 'reconforge'
    # for tests that assert on the location) so host config never leaks in
    monkeypatch.setattr(
        config, "global_key_file", lambda: tmp_path / "reconforge" / ".apikeys"
    )
    for name in config.API_KEY_NAMES:
        monkeypatch.delenv(name, raising=False)
