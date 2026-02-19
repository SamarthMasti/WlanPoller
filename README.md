# Cisco WLAN Poller GUI

Enterprise-grade GUI tool for polling Cisco WLCs and Access Points using SSH automation.

## Features

- WLC Only Polling
- AP Only Polling
- WLC & AP Combined Mode
- Multi-threaded AP SSH execution
- Flash Vulnerability Checker
- Regex-based Log Parser
- Excel Export (AP + Vulnerable Reports)
- Clean PySide6 GUI

## Technologies Used

- Python 3.12
- PySide6
- Netmiko
- ThreadPoolExecutor
- OpenPyXL

## How to Run

```bash
pip install -r requirements.txt
python WlanPollerGUI.py
