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
    a.binaries,
    a.datas,
    [],
    name='Scan83',
    icon=os.path.join(SPECPATH, 'Scan83.ico'),
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

for filename in ('ignition83_rules.csv', 'README.md', 'LICENSE', 'Scan83.ico'):
    source = os.path.join(SPECPATH, filename)
    destination = os.path.join(DISTPATH, filename)
    shutil.copy2(source, destination)

console_scripts_source = os.path.join(SPECPATH, 'console-scripts')
console_scripts_destination = os.path.join(DISTPATH, 'console-scripts')
shutil.copytree(console_scripts_source, console_scripts_destination, dirs_exist_ok=True)
