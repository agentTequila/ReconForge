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
datas.append((str(ROOT / "assets" / "icon.png"), "reconforge/assets"))

# in-function imports PyInstaller's static analysis can miss
hiddenimports += ["phonenumbers", "whois", "dns.resolver", "dns.message"]

# whois reads its public-suffix list at runtime; bundle it or the module fails
# inside a frozen build with a FileNotFoundError.
try:
    import whois

    _whois_root = Path(whois.__file__).resolve().parent
    for _f in _whois_root.rglob("*"):
        if _f.is_file() and _f.suffix != ".py" and "__pycache__" not in _f.parts:
            datas.append(
                (str(_f), str(Path("whois") / _f.relative_to(_whois_root).parent))
            )
except ImportError:
    pass

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
