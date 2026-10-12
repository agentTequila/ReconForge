"""Tests for key-file fallback when the working directory is read-only."""

from reconforge.core import config


def _project_read_only(tmp_path, monkeypatch):
    """Simulate an unwritable project dir while the global dir stays writable."""
    real_write = config._write_key_file
    project_file = tmp_path / config.KEY_FILE_NAME

    def selective(path, text):
        if path == project_file:
            raise OSError("read-only directory")
        real_write(path, text)

    monkeypatch.setattr(config, "_write_key_file", selective)


def test_ensure_key_file_falls_back_to_global(tmp_path, monkeypatch):
    _project_read_only(tmp_path, monkeypatch)

    result = config.ensure_key_file(tmp_path)

    assert result == config.global_key_file()
    assert result.exists()
    assert result.read_text(encoding="utf-8").startswith("# ReconForge")


def test_save_keys_targets_global_when_project_read_only(tmp_path, monkeypatch):
    _project_read_only(tmp_path, monkeypatch)

    saved = config.save_keys({"SHODAN_API_KEY": "x"}, directory=tmp_path)

    assert saved == config.global_key_file()
    assert "SHODAN_API_KEY=x" in saved.read_text(encoding="utf-8")
    # the read-only project location was never created
    assert not (tmp_path / config.KEY_FILE_NAME).exists()


def test_writable_project_dir_still_used(tmp_path, monkeypatch):
    result = config.ensure_key_file(tmp_path)

    assert result == tmp_path / config.KEY_FILE_NAME
    assert result.exists()
