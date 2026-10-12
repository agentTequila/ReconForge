# -*- mode: python ; coding: utf-8 -*-
"""ReconForge CLI - one-file console build.

Prefer:  powershell -File tools/build_exe.ps1
Manual:  python -m PyInstaller --noconfirm packaging/reconforge-cli.spec
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPEC).parent.parent

datas, binaries, hiddenimports = [], [], []

# banner fonts (pyfiglet) + TLS roots (certifi)
for pkg in ("pyfiglet", "certifi"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# package data: platform list
for f in (ROOT / "reconforge" / "data").rglob("*"):
    if f.is_file():
        datas.append((str(f), "reconforge/data"))

# in-function imports PyInstaller's static analysis can miss
hiddenimports += ["phonenumbers", "whois", "dns.resolver", "dns.message"]

a = Analysis(
    [str(ROOT / "cli_entry.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["customtkinter"],  # GUI-only dependency
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="reconforge-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "assets" / "icon.ico"),
    version=str(ROOT / "packaging" / "file_version_info_cli.txt"),
)
