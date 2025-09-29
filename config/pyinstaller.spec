# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for packaging vane_project_full/vanity.py
# Generated/maintained by assistant: simplified and correct.
block_cipher = None

a = Analysis(
    ['vanity.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('regexes.json', '.'), 
        ('chains/*.py', 'chains')
    ],
    hiddenimports=['mnemonic','nacl','eth_account','web3','tonsdk','base58','Crypto','cryptography'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='vanity',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='vanity_dist'
)
