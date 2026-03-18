CISCO WLAN POLLER/PARSER (New App)

Files:
- WlanPollerGUI.py (Frontend - PySide6)
- PollerEngine.py (Backend - Netmiko SSH + filtering + logging)
- ApFlashVulnerableChecker.py (Parser - adapts ApLogParser_detectionv5 logic)

Install:
  pip install PySide6 netmiko openpyxl

Run:
  python WlanPollerGUI.py

Notes:
- config: confd/config.ini (supports legacy 'key: value' and converts to INI)
- logs: data/YYYY/MM/DD/

AP Image Download: Say for AP2802/3802/4802
archive download /no-reload tftp://192.168.0.47/ap3g3-k9w8-tar.17_15_5_36.tar


Cpython for encoding Backend logic to C binary:
pip install cython
python cpy-setup.py build_ext --inplace

Final Build with Logo:
pyinstaller --clean --noconfirm --windowed --onefile --icon=assets/ciscologo.ico --add-data "assets;assets" WlanPollerGUI.py



