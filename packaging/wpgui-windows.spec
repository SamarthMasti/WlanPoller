# wpgui-windows.spec
from pathlib import Path
from PyInstaller.utils.hooks import collect_all
#from PyInstaller.utils.crypto import PyiBlockCipher
import netmiko
#import PySide6

#block_cipher = None

try:
    import pyi_crypto
    block_cipher = pyi_crypto.PyiBlockCipher(key='1gN6H9IaifI1NiK')
except Exception as exc:
    print("Warning: pyi_crypto not available; building without block cipher. Reason:", exc)
    block_cipher = None


# Collect everything Netmiko needs (best practice)
netmiko_datas, netmiko_binaries, netmiko_hidden = collect_all('netmiko')

# ✅ DEFINE datas OUTSIDE Analysis
datas = [
    ('..\\assets\\ciscologo.ico', 'assets'),
] + netmiko_datas

datas = netmiko_datas

a = Analysis(
    ['..\\WlanPollerGUI.py'],              # positional first
    ['.'],                        # pathex (positional form)
    binaries=netmiko_binaries,
    datas=datas,
    hiddenimports=netmiko_hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='WlanPollerGui',
    debug=False,
    strip=False,
    upx=True,
    console=True,
    exclude_binaries=False,
)
