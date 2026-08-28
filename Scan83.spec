# -*- mode: python ; coding: utf-8 -*-

import os
import shutil


a = Analysis(
    ['ignition83_scan.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Scan83',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Scan83',
)

for filename in ('ignition83_rules.csv', 'README.txt'):
    source = os.path.join(SPECPATH, filename)
    destination = os.path.join(DISTPATH, 'Scan83', filename)
    shutil.copy2(source, destination)
