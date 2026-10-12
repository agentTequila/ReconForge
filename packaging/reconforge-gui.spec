# -*- mode: python ; coding: utf-8 -*-
"""ReconForge GUI - one-file windowed build.

Prefer:  powershell -File tools/build_exe.ps1
Manual:  python -m PyInstaller --noconfirm packaging/reconforge-gui.spec
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPEC).parent.parent

datas, binaries, hiddenimports = [], [], []

# theme files (customtkinter), image support (PIL), banner fonts (pyfiglet),
# TLS roots (certifi)
for pkg in ("customtkinter", "darkdetect", "PIL", "pyfiglet", "certifi"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# package data: platform list + window icon (see reconforge/gui.py ASSETS)
for f in (ROOT / "reconforge" / "data").rglob("*"):
    if f.is_file():
        datas.append((str(f), "reconforge/data"))
datas.append((str(ROOT / "assets" / "icon.ico"), "reconforge/assets"))

# in-function imports PyInstaller's static analysis can miss
hiddenimports += ["phonenumbers", "whois", "dns.resolver", "dns.message"]

a = Analysis(
    [str(ROOT / "gui_entry.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ReconForge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "assets" / "icon.ico"),
    version=str(ROOT / "packaging" / "file_version_info.txt"),
)
