"""Config / .apikeys handling tests."""

import os

from reconforge.core import config


def test_first_run_creates_template(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    keys = config.load_keys()
    key_file = tmp_path / ".apikeys"
    assert key_file.exists()
    assert "DO NOT COMMIT" in key_file.read_text(encoding="utf-8")
    assert keys == {name: "" for name in config.API_KEY_NAMES} or all(
        v == "" for v in keys.values()
    )


def test_file_keys_loaded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".apikeys").write_text(
        "SHODAN_API_KEY=abc123\n# comment\nGARBAGE_KEY=nope\n", encoding="utf-8"
    )
    keys = config.load_keys()
    assert keys["SHODAN_API_KEY"] == "abc123"
    assert "GARBAGE_KEY" not in keys


def test_env_overrides_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".apikeys").write_text("SHODAN_API_KEY=fromfile\n", encoding="utf-8")
    monkeypatch.setenv("SHODAN_API_KEY", "fromenv")
    keys = config.load_keys()
    assert keys["SHODAN_API_KEY"] == "fromenv"
    monkeypatch.delenv("SHODAN_API_KEY")


def test_legacy_env_fallback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("HUNTER_API_KEY=legacy1\n", encoding="utf-8")
    keys = config.load_keys()
    assert keys["HUNTER_API_KEY"] == "legacy1"


def test_save_keys_merges(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.ensure_key_file(tmp_path)
    config.save_keys({"SHODAN_API_KEY": "s1"}, directory=tmp_path)
    config.save_keys({"OPENAI_API_KEY": "o1"}, directory=tmp_path)
    keys = config.load_keys()
    assert keys["SHODAN_API_KEY"] == "s1"
    assert keys["OPENAI_API_KEY"] == "o1"
    config.save_keys({"SHODAN_API_KEY": ""}, directory=tmp_path)
    assert config.load_keys()["SHODAN_API_KEY"] == ""


def test_key_count():
    assert config.key_count({"A": "", "B": "x", "C": "y"}) == 2


def test_global_key_file_location():
    path = config.global_key_file()
    assert path.name == ".apikeys"
    assert "reconforge" in str(path)


def test_permissions_on_posix(tmp_path, monkeypatch):
    if os.name == "nt":
        import pytest

        pytest.skip("POSIX-only")
    path = config.ensure_key_file(tmp_path)
    assert oct(path.stat().st_mode)[-3:] == "600"
