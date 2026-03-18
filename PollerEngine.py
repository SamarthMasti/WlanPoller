# ==========================================================
# Author: Prashanth Baragur Hanuman
# File  : PollerEngine.py
# ==========================================================

import os
import re
import time
import math
import socket
import configparser
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple
import threading
print(">>> LOADED PollerEngine FROM:", __file__)
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler




import sys
from pathlib import Path
import time


def get_app_base_dir():
    """
    Returns base directory where:
    - WlanPollerGUI.app lives (macOS)
    - WlanPollerGUI.exe lives (Windows)
    - script folder when running source
    """

    if getattr(sys, "frozen", False):

        exe = Path(sys.executable).resolve()

        # macOS .app bundle
        if exe.parent.name == "MacOS" and exe.parent.parent.name == "Contents":
            return exe.parents[3]

        return exe.parent

    return Path(__file__).resolve().parent

BASE_DIR = get_app_base_dir()

CONFD = BASE_DIR / "confd"
DATA_ROOT = BASE_DIR / "data"

CONFD.mkdir(parents=True, exist_ok=True)
DATA_ROOT.mkdir(parents=True, exist_ok=True)
QCA_PREFIXES = (

    # ---------------- Wi-Fi 6 (802.11ax) ----------------
    "9117",
    "9124",
    "9130",

    # ---------------- Wi-Fi 6E (6 GHz) ----------------
    "9136",
    "9162",
    "9163",
    "9164",
    "9166",
    "9167",

    # ---------------- Wi-Fi 7 (802.11be) ----------------
    "9171",
    "9172",
    "9174",
    "9176",
    "9178",
    "9179",
)

def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def today_data_dir() -> str:
    now = datetime.now()
    path = DATA_ROOT / f"{now.year:04d}" / f"{now.month:02d}" / f"{now.day:02d}"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)

def _safe_write_append(path, text: str):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "a", encoding="utf-8", errors="ignore") as f:
        f.write(text)

def _safe_filename(name: str) -> str:
    if not name:
        return "UNKNOWN"

    # Replace anything not alphanumeric, dash, underscore or dot
    safe = re.sub(r'[^\w\-.]', "_", name)

    safe = safe.strip().rstrip(".")
    return safe[:120] or "UNKNOWN"


def _is_ipv4(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except Exception:
        return False
def ssh_port_open(ip, port=22, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))
        sock.close()

        return result == 0
    except Exception:
        return False

@dataclass
class ApRow:
    ip: str
    model: str
    name: str
    site_tag: str = ""

import base64

ENC_PREFIX = "ENC::"
_XOR_KEY = "WlanPollerKey"   # simple internal key


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_value(val: str) -> str:
    if not val:
        return val

    raw = val.encode()
    key = _XOR_KEY.encode()

    xored = _xor_bytes(raw, key)
    encoded = base64.b64encode(xored).decode()

    return ENC_PREFIX + encoded


def decrypt_value(val: str) -> str:
    if not val or not val.startswith(ENC_PREFIX):
        return val

    try:
        raw = val[len(ENC_PREFIX):]
        decoded = base64.b64decode(raw.encode())

        key = _XOR_KEY.encode()
        original = _xor_bytes(decoded, key)

        return original.decode()
    except Exception:
        return val
class IniStore:
    """
    Backward compatible config loader.

    Supports:
      1) INI sections: [WLC], [AP], [FTP]
      2) Legacy 'key: value' flat file (auto-converted)
    """
    def __init__(self, path: str):
        self.path = path
        self.cfg = configparser.ConfigParser(interpolation=None)

        if os.path.exists(path):
            try:
                self.cfg.read(path, encoding="utf-8")
            except configparser.MissingSectionHeaderError:
                self._convert_legacy_to_ini()
        self._ensure_defaults()
        # ---- MIGRATION FIX ----
        migrated = False
        if self.cfg.has_option("WLC", "WlcIpaddr"):
            val = self.cfg.get("WLC", "WlcIpaddr")
            self.cfg.set("WLC", "wlc_ip", val)
            self.cfg.remove_option("WLC", "WlcIpaddr")
            self.save()
            migrated = True
        if self.cfg.has_option("WLC", "wlcipaddr"):
            val = self.cfg.get("WLC", "wlcipaddr")
            self.cfg.set("WLC", "wlc_ip", val)
            self.cfg.remove_option("WLC", "wlcipaddr")
            self.save()
            migrated = True
        if migrated:
            self.save()

    def _convert_legacy_to_ini(self):
        legacy: Dict[str, str] = {}
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                elif "=" in line:
                    k, v = line.split("=", 1)
                else:
                    continue
                legacy[k.strip()] = v.strip()

        self.cfg["WLC"] = {
            "WlcIpaddr": legacy.get("WlcIpaddr", ""),
            "wlc_user": legacy.get("wlc_user", ""),
            "wlc_pasw": legacy.get("wlc_pasw", legacy.get("wlc_pasw:", "")),
        }
        self.cfg["AP"] = {
            "ap_user": legacy.get("ap_user", ""),
            "ap_pasw": legacy.get("ap_pasw", ""),
            "ap_enable": legacy.get("ap_enable", ""),
        }
        self.cfg["FTP"] = {
            "ftp_addr": legacy.get("ftp_addr", ""),
            "ftp_path": legacy.get("ftp_path", ""),
            "ftp_user": legacy.get("ftp_user", ""),
            "ftp_pasw": legacy.get("ftp_pasw", ""),
            "scp_port": legacy.get("scp_port", "22"),
        }
        self.save()

    def _ensure_defaults(self):
        changed = False
        for sec in ["WLC", "AP", "FTP"]:
            if sec not in self.cfg:
                self.cfg[sec] = {}
                changed = True
        if "scp_port" not in self.cfg["FTP"]:
            self.cfg["FTP"]["scp_port"] = "22"
            changed = True
        if changed:
            self.save()

    def save(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            self.cfg.write(f)

    def get(self, sec: str, key: str, default: str = "") -> str:
        val = self.cfg.get(sec, key, fallback=default)

        if "pasw" in key.lower() or "password" in key.lower() or "enable" in key.lower():
            return decrypt_value(val)

        return val

    def set(self, sec: str, key: str, val: str):
        if sec not in self.cfg:
            self.cfg[sec] = {}

        if "pasw" in key.lower() or "password" in key.lower() or "enable" in key.lower():
            if isinstance(val, str) and not val.startswith(ENC_PREFIX):
                val = encrypt_value(val)

        self.cfg[sec][key] = val

    def bulk_set(self, sec: str, mapping: Dict[str, str]):
        if sec not in self.cfg:
            self.cfg[sec] = {}

        for k, v in mapping.items():

            if "pasw" in k.lower() or "password" in k.lower() or "enable" in k.lower():
                if isinstance(v, str) and not v.startswith(ENC_PREFIX):
                    v = encrypt_value(v)

            self.cfg[sec][k] = v


class WlcParse:
    @staticmethod
    def wlc_hostname_from_uptime(output: str) -> str:
        for line in output.splitlines():
            if " uptime is " in line:
                return line.split()[0].strip()
        return "eWLC-9800"

    @staticmethod
    def parse_ap_summary(output: str) -> List[ApRow]:
        rows: List[ApRow] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            if line.lower().startswith("number of aps"):
                continue
            if set(line.strip()) <= set("-"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = ""
            for tok in parts:
                if _is_ipv4(tok):
                    ip = tok
                    break
            if not ip:
                continue
            name = parts[0]
            model = parts[2] if len(parts) >= 3 else "UNKNOWN"
            rows.append(ApRow(ip=ip, model=model, name=name))
        return rows

    @staticmethod
    def parse_total_ap_cnt_from_tag_summary(output: str) -> Optional[int]:
        for line in output.splitlines():
            if line.lower().startswith("number of aps"):
                m = re.search(r"(\d+)", line)
                if m:
                    return int(m.group(1))
        return None

    @staticmethod
    def parse_ap_names_from_tag_summary(output: str, site_tag: str) -> List[str]:
        names: List[str] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            if line.lower().startswith("number of aps"):
                continue
            if set(line.strip()) <= set("-"):
                continue
            if site_tag not in line:
                continue
            parts = line.split()
            if parts:
                names.append(parts[0])
        seen = set()
        out = []
        for n in names:
            if n not in seen:
                out.append(n)
                seen.add(n)
        return out


def compute_max_workers(ap_filtered_cnt: int) -> int:
    if ap_filtered_cnt <= 0:
        return 1
    if ap_filtered_cnt < 50:
        return max(1, ap_filtered_cnt)
    if ap_filtered_cnt < 100:
        return max(1, math.ceil(ap_filtered_cnt / 2))
    if ap_filtered_cnt < 500:
        return max(1, math.ceil(ap_filtered_cnt / 4))
    return max(1, math.ceil(ap_filtered_cnt / 10))


class PollerEngine:
    def __init__(
        self,
        log_cb: Optional[Callable[[str], None]] = None,
        progress_cb: Optional[Callable[[int], None]] = None,
        ap_update_cb: Optional[Callable[[int, str, str, str, str], None]] = None,
    ):
        CONFD.mkdir(parents=True, exist_ok=True)
        # ---------------- DATE + RUN BASED DATA DIRECTORY ----------------
        now = datetime.now()

        year = f"{now.year:04d}"
        month = f"{now.month:02d}"
        day = f"{now.day:02d}"
        base_path = DATA_ROOT / year / month / day
        base_path.mkdir(parents=True, exist_ok=True)
        existing_runs = [
            d for d in os.listdir(base_path)
            if os.path.isdir(os.path.join(base_path, d)) and d.startswith("RUN")
        ]

        run_numbers = []
        for d in existing_runs:
            try:
                run_numbers.append(int(d.replace("RUN", "")))
            except:
                pass

        next_run = max(run_numbers) + 1 if run_numbers else 1

        self.run_id = f"RUN{next_run}"
        self.run_id = f"RUN{next_run}"

        run_path = base_path / self.run_id
        run_path.mkdir(parents=True, exist_ok=True)

        self.data_dir = str(run_path)
        # ------------------------------------------------------------------
        self.ini = IniStore(str(CONFD / "config.ini"))
        self.log_cb = log_cb
        self.progress_cb = progress_cb
        self.ap_update_cb = ap_update_cb
        self._log(f"[ENGINE] Using data directory: {self.data_dir}")
        self.success = 0
        self.failed = 0
        # Cooperative shutdown
        self._shutdown_event = threading.Event()
        # Executor reference (will be set when run_ap_poller creates it)
        self.executor = None
        # track sessions/sockets if we want to forcibly close them on shutdown
        self._open_sessions = []
        self.operation = "WLC & AP"
        self.workflow = ""
        print("DEBUG DATA DIR:", self.data_dir)
        print("DEBUG BASE DIR:", BASE_DIR)
    def _log(self, msg: str):
        if self.log_cb:
            self.log_cb(msg)
        else:
            print(msg)

    def _progress(self, pct: int):
        if self.progress_cb:
            self.progress_cb(pct)

    def shutdown(self):
        try:
            # request cooperative stop
            try:
                self._shutdown_event.set()
            except Exception:
                pass

            # If we have an executor reference, ask it to stop accepting new tasks
            if getattr(self, "executor", None) is not None:
                try:
                    self.executor.shutdown(wait=False)
                except Exception:
                    pass

            # Close tracked sessions (netmiko/paramiko/ssh)
            for s in getattr(self, "_open_sessions", []) or []:
                try:
                    # netmiko supports disconnect(); paramiko sockets support close()
                    try:
                        s.disconnect()
                    except Exception:
                        try:
                            s.close()
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    def _wlc_connect(self):
        wlc_ip = self.ini.get("WLC", "wlc_ip")

        if not wlc_ip:
            raise ValueError("Missing WLC IP in config.ini ([WLC] wlc_ip)")

        self._log(f"[WLC] Checking SSH port on {wlc_ip}...")
        if not ssh_port_open(wlc_ip):
            raise RuntimeError(f"WLC {wlc_ip} unreachable on port 22")

        dev = {
            "device_type": "cisco_ios",
            "host": wlc_ip,
            "username": self.ini.get("WLC", "wlc_user"),
            "password": self.ini.get("WLC", "wlc_pasw"),
            "timeout": 60,
            "conn_timeout": 30,
            "banner_timeout": 30,
            "auth_timeout": 30,
        }

        # ✅ Clean single message
        self._log(f"[WLC] Connecting to {wlc_ip} ...")

        conn = None
        try:
            for _ in range(3):  # retry silently
                try:
                    conn = ConnectHandler(**dev)
                    break
                except Exception:
                    time.sleep(3)

            if conn is None:
                raise RuntimeError(f"WLC {wlc_ip} connection failed after retries")

            conn.send_command("term len 0")
            return conn

        except Exception as e:
            self._log(f"[WLC] Connection failed to {wlc_ip}: {e}")
            raise

    def run_wlc_cmds(self, wlc_cmds: List[str]) -> str:
        conn = self._wlc_connect()
        uptime_out = conn.send_command("show version | i uptime is", read_timeout=60)
        wlc_host = WlcParse.wlc_hostname_from_uptime(uptime_out)

        out_file = os.path.join(self.data_dir, f"{wlc_host}_outputs.txt")
        header = (
            f"<run timestamp='{datetime.now().isoformat()}' device='eWLC' hostname='{wlc_host}' "
            f"model='eWLC-9800' version='None'>\n"
        )
        _safe_write_append(out_file, header)

        total = len(wlc_cmds)
        for i, cmd in enumerate(wlc_cmds, 1):
            is_special, actual_cmd, needs_confirm, sleep_secs = self.SpecialCmdCheck(cmd)

            # --- Handle sleep ---
            if is_special and sleep_secs > 0:
                self._log(f"[SLEEP] Waiting {sleep_secs}s before next command...")
                _safe_write_append(out_file,
                                   f"\n<cmd string='sleep_{sleep_secs}'>\n\t[SLEEP] {sleep_secs} seconds delay\n")
                time.sleep(sleep_secs)
                pct = int((i / total) * 100)
                self._progress(pct)
                continue

            self._log(f"[WLC] Running: {actual_cmd}")
            _safe_write_append(out_file, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")

            # --- Handle confirm command ---
            if needs_confirm:
                conn.write_channel(actual_cmd + "\n")
                time.sleep(3)
                conn.write_channel("y\n")
                time.sleep(2)
                out = conn.read_channel()
            else:
                out = conn.send_command(actual_cmd, read_timeout=120)

            _safe_write_append(out_file, out + "\n")
            pct = int((i / total) * 100)
            self._progress(pct)
        conn.disconnect()
        self._log(f"[WLC] Done. Output: {out_file}")
        return out_file

    def fetch_full_ap_list(self) -> List[ApRow]:
        self._log("[WLC] fetch_full_ap_list() starting...")
        self._log(f"[MODE CHECK] operation={self.operation} workflow={self.workflow}")
        conn = self._wlc_connect()
        out = conn.send_command("show ap summary", read_timeout=180)
        conn.disconnect()

        rows = WlcParse.parse_ap_summary(out)

        # QCA Filter for AP Flash Checker workflow
        if self.operation == "WLC & AP" and self.workflow == "AP Flash Checker":
            filtered = []
            for r in rows:
                model_upper = r.model.upper()
                if any(prefix in model_upper for prefix in QCA_PREFIXES):
                    filtered.append(r)
            rows = filtered

        all_path = os.path.join(CONFD, "ap_ip_list_all.txt")

        with open(all_path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(f"{r.ip} {r.model} {r.name}\n")

        with open(os.path.join(self.data_dir, "ap_ip_list_all.txt"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(f"{r.ip} {r.model} {r.name}\n")

        self._log(f"[WLC] Full AP list saved: {all_path} ({len(rows)} APs)")
        return rows
    def filter_by_site_tag(self, full_rows: List[ApRow], site_tag: str):
        self._log(f"[WLC] filter_by_site_tag('{site_tag}') starting...")
        conn = self._wlc_connect()
        tag_all = conn.send_command("show ap tag summary", read_timeout=180)
        total = WlcParse.parse_total_ap_cnt_from_tag_summary(tag_all) or len(full_rows)
        out = conn.send_command(f"show ap tag summary | inc {site_tag}", read_timeout=120)
        conn.disconnect()

        names = WlcParse.parse_ap_names_from_tag_summary(out, site_tag)
        if not names:
            if len(full_rows) == 0:
                raise ValueError("WLC has no APs (show ap summary returned 0 rows).")
            raise ValueError(f"'{site_tag}' Site Tag Name Does not exists")

        aplist_tag_path = os.path.join(self.data_dir, "aplist_tag.txt")
        _safe_write_append(aplist_tag_path, out + "\n")

        name_map = {r.name: r for r in full_rows}
        selected: List[ApRow] = []
        for n in names:
            if n in name_map:
                rr = name_map[n]
                rr.site_tag = site_tag
                selected.append(rr)

        return selected, total

    def filter_by_model_group(self, full_rows: List[ApRow], model_group_label: str) -> List[ApRow]:
        if model_group_label == "All AP Models":
            return full_rows
        nums = re.findall(r"\d{4}", model_group_label)
        if not nums:
            return full_rows
        def matches(model: str) -> bool:
            return any(n in model for n in nums)
        return [r for r in full_rows if matches(r.model)]

    def write_filtered_ap_list(self, rows: List[ApRow]) -> str:
        p = os.path.join(CONFD, "ap_ip_list.txt")
        with open(p, "w", encoding="utf-8") as f:
            for r in rows:
                if r.site_tag:
                    f.write(f"{r.ip} {r.model} {r.site_tag}\n")
                else:
                    f.write(f"{r.ip} {r.model}\n")
        with open(os.path.join(self.data_dir, "ap_ip_list.txt"), "w", encoding="utf-8") as f:
            for r in rows:
                if r.site_tag:
                    f.write(f"{r.ip} {r.model} {r.site_tag}\n")
                else:
                    f.write(f"{r.ip} {r.model}\n")
        return p

    # ADD THIS — new method, place it above _ap_connect_params()
    def _build_image_download_cmd(self) -> list:
        proto = self.ini.get("FTP", "ftp_proto", "TFTP")
        server = self.ini.get("FTP", "ftp_addr", "")
        path = self.ini.get("FTP", "ftp_path", "")  # e.g. /images/ap3g3-k9w8-tar.153-3.JK9.tar
        user = self.ini.get("FTP", "ftp_user", "")
        pasw = self.ini.get("FTP", "ftp_pasw", "")

        filename = path.split("/")[-1]  # just the tar filename for flash destination

        if proto == "SFTP":
            return [
                f"ip sftp username {user}",
                f"ip sftp password {pasw}",
                f"copy sftp://{server}/{path.lstrip('/')} flash:{filename}",
            ]
        else:  # TFTP
            return [
                f"copy tftp://{server}/{path.lstrip('/')} flash:{filename}",
            ]

    def _ap_connect_params(self, ip: str, model: str) -> Dict[str, str]:

        device_type = "cisco_ios"  # default

        model_upper = (model or "").upper()

        # Use XE ONLY for known models
        if any(prefix in model_upper for prefix in QCA_PREFIXES):
            device_type = "cisco_xe"

        return {
            "device_type": device_type,
            "host": ip,
            "username": self.ini.get("AP", "ap_user"),
            "password": self.ini.get("AP", "ap_pasw"),
            "secret": self.ini.get("AP", "ap_enable"),

            "timeout": 60,
            "conn_timeout": 30,
            "banner_timeout": 30,
            "auth_timeout": 30,
            "fast_cli": False,
        }
    @staticmethod
    def _ap_send_command(conn, cmd: str, read_timeout: int) -> str:
        try:
            return conn.send_command(cmd, read_timeout=read_timeout)
        except Exception as exc:
            if "Pattern not detected" in str(exc):
                return conn.send_command_timing(cmd, read_timeout=read_timeout)
            raise

    def run_command_interactive(self, conn, cmd, ftp_user=None, ftp_pass=None):
        is_image_download = "archive download-sw" in cmd.lower()
        conn.write_channel(cmd + "\n")

        buffer = ""
        start = time.time()

        while True:

            time.sleep(1)
            output = conn.read_channel()

            if output:
                buffer += output

                if is_image_download:

                    # Only show transfer progress symbols
                    progress_symbols = re.findall(r"[!.]+", output)

                    if progress_symbols:
                        self._log(progress_symbols[0])  # show !!!! or .... etc

                else:
                    # Normal commands show full output
                    self._log(output)
            # Username prompt
            buf = buffer.lower()

            if "username:" in buf and ftp_user:
                conn.write_channel(ftp_user + "\n")
                buffer = ""
                continue

            if "password:" in buf and ftp_pass:
                conn.write_channel(ftp_pass + "\n")
                buffer = ""
                continue
            # Confirmation prompts
            if "[confirm]" in buf:
                conn.write_channel("\n")
                buffer = ""
                continue

            if "(yes/no)" in buf:
                conn.write_channel("yes\n")
                buffer = ""
                continue

            # detect completion (prompt returned)
            buf = buffer.lower()

            # Detect archive/image completion
            # Detect archive/image completion OR failure
            if (
                    "archive done" in buf
                    or "archive download completed" in buf
                    or "image transfer complete" in buf
                    or "extracting images" in buf
                    or "error" in buf
                    or "failed" in buf
                    or "fail" in buf
                    or "no such file" in buf
                    or "permission denied" in buf
                    or "connection refused" in buf
                    or "timed out" in buf
                    or buffer.strip().endswith(conn.base_prompt)
            ):
                # Log the last meaningful line from the AP as the exit message
                exit_msg = ""
                for line in reversed(buffer.strip().splitlines()):
                    line = line.strip()
                    if line and not line.endswith("#") and not line.endswith(">"):
                        exit_msg = line
                        break
                self._log(f"[IMAGE DOWNLOAD] Result: {exit_msg}")
                break

            # safety timeout
            if time.time() - start > 3600:
                raise RuntimeError("Command timed out")

        return buffer

    def SpecialCmdCheck(self, cmd: str):
        """
        Checks for special command signatures.
        Returns: (is_special, actual_cmd, needs_confirm, sleep_secs)

        Signatures handled:
          1. sleep_N  → sleep for N seconds  e.g. sleep_5
          2. %cmd%    → send cmd + inject 'y' confirmation  e.g. %reload%
        """
        cmd = cmd.strip()

        # --- Signature 1: Sleep ---
        # e.g. sleep_5 → wait 5 seconds
        import re as _re
        m = _re.match(r'^(sleep|pause)[_(](\d+)\)?$', cmd, _re.IGNORECASE)
        if m:
            secs = int(m.group(2))
            if secs > 3600:
                self._log(
                    f"[SLEEP] *** Invalid sleep value: {secs}s. "
                    f"Maximum allowed is 3600s (1 hour). Command skipped."
                )
                return (True, None, False, 0)
            return (True, None, False, secs)
        # --- Signature 2: Confirm command ---
        # e.g. %reload% → send reload + inject y
        if cmd.startswith("%") and cmd.endswith("%") and len(cmd) > 4:
            actual = cmd[1:-1].strip()
            return (True, actual, True, 0)

        # --- Normal command ---
        return (False, cmd, False, 0)
    def _poll_one_ap(self, idx: int, ap: ApRow, device: str, cmds: List[str]):
        try:
            self._log(f"[AP] ({idx+1}) Connecting {ap.ip} ({ap.name}) ...")
            if not ssh_port_open(ap.ip, timeout=5):
                self._log(f"[AP] {ap.ip} SSH check slow, trying anyway...")
            params = self._ap_connect_params(ap.ip, ap.model)


            conn = None
            for _ in range(3):
                try:
                    conn = ConnectHandler(**params)
                    break
                except Exception:
                    time.sleep(3)

            if conn is None:
                return idx, ap.ip, ap.model, "Fail: Connection retries exhausted"
            self._open_sessions.append(conn)
            conn.enable()
            # Disable paging; some APs use non-standard "more" prompts.
            try:
                self._ap_send_command(conn, "terminal length 0", read_timeout=30)
            except Exception:
                try:
                    self._ap_send_command(conn, "term len 0", read_timeout=30)
                except Exception:
                    pass

            inv = self._ap_send_command(conn, "show inventory", read_timeout=120)
            sn_m = re.search(r"SN:\s*([A-Za-z0-9]+)", inv)
            sn = sn_m.group(1) if sn_m else "UNKNOWN"

            ver = self._ap_send_command(conn, "show version", read_timeout=120)
            img_m = re.search(r"AP Running Image\s*:\s*(.*)", ver)
            img = img_m.group(1).strip() if img_m else "UNKNOWN"
            # --- FIX: Update model from actual AP (authoritative source) ---
            model_match = re.search(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)", ver)
            if model_match:
                new_model = model_match.group(1)
                if new_model and new_model.upper() != "UNKNOWN":
                    ap.model = new_model

            fname = os.path.join(self.data_dir, f"{device}_{_safe_filename(ap.name)}.log")
            header = (
                f"<run timestamp='{datetime.now().isoformat()}' device='{device}' hostname='{ap.name}' "
                f"model='{ap.model}' version='{img}' Ip='{ap.ip}' SN='{sn}'>\n"
            )
            _safe_write_append(fname, header)

            for cmd in cmds:
                if self._shutdown_event.is_set():
                    return idx, ap.ip, ap.model, "Cancelled"

                is_special, actual_cmd, needs_confirm, sleep_secs = self.SpecialCmdCheck(cmd)

                # --- Handle sleep ---
                if is_special and sleep_secs > 0:
                    self._log(f"[SLEEP] Waiting {sleep_secs}s before next command...")
                    _safe_write_append(fname, f"\n<cmd string='sleep_{sleep_secs}'>\n\t[SLEEP] {sleep_secs} seconds delay\n")
                    time.sleep(sleep_secs)
                    continue

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd}")

                _safe_write_append(fname, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")

                cmd_lower = actual_cmd.lower()

                is_transfer_cmd = (
                        "sftp://" in cmd_lower

                        or "scp://" in cmd_lower
                )

                if is_transfer_cmd:
                    ftp_user = self.ini.get("FTP", "ftp_user", "")
                    ftp_pasw = self.ini.get("FTP", "ftp_pasw", "")
                    out = self.run_command_interactive(conn, actual_cmd, ftp_user=ftp_user, ftp_pass=ftp_pasw)
                    # Write the final AP output line to the log file
                    exit_msg = ""
                    for line in reversed(out.strip().splitlines()):
                        line = line.strip()
                        if line:
                            exit_msg = line
                            break
                    _safe_write_append(fname, f"\n[IMAGE DOWNLOAD] Result: {exit_msg}\n")

                elif needs_confirm:
                    conn.write_channel(actual_cmd + "\n")
                    time.sleep(3)
                    conn.write_channel("y\n")
                    time.sleep(2)
                    out = conn.read_channel()

                else:
                    # Use longer timeout for archive/image download commands
                    _timeout = 3600 if "archive download-sw" in cmd_lower else 180
                    out = self._ap_send_command(conn, actual_cmd,read_timeout=_timeout)

                _safe_write_append(fname, out + "\n")

            conn.disconnect()
            return idx, ap.ip, ap.model, "Success"
        except Exception as e:
            return idx, ap.ip, ap.model, f"Fail: {e}"

    def run_ap_poller(self, ap_rows, device, ap_cmds, ap_mode="AP Custom Cmd List"):
        # Option A: user types the full command manually in the AP cmd box.
        # GUI already prepends "ip sftp username/password" for SFTP before calling here.
        # So ap_cmds arrives complete — no override needed.
        # If Image Download mode, override commands
        if ap_mode == "AP Image Download" and not ap_cmds:
            ap_cmds = self._build_image_download_cmd()
        self._log(f"[AP] Mode={ap_mode} | Commands to run: {ap_cmds}")
        ap_cnt = len(ap_rows)
        workers = compute_max_workers(ap_cnt)
        self._log(f"ApFilteredCnt={ap_cnt} -> MAX_WORKERS={workers}")

        results = [("", "", "")] * ap_cnt
        self.success = 0
        self.failed = 0

        start = time.time()
        # create an executor and store reference so shutdown() can access it
        self.executor = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = []
            for i in range(ap_cnt):
                if self._shutdown_event.is_set():
                    self._log("[AP] shutdown requested before submitting all tasks")
                    break
                futures.append(self.executor.submit(self._poll_one_ap, i, ap_rows[i], device, ap_cmds))

            done = 0
            # As futures complete, handle results and check shutdown
            for fut in as_completed(futures):
                if self._shutdown_event.is_set():
                    self._log("[AP] shutdown requested during polling; stopping result handling.")
                    break
                try:
                    idx, ip, model, status = fut.result()
                except Exception as e:
                    self._log(f"[AP] task exception: {e}")

                    idx = None
                    try:
                        idx = futures.index(fut)
                    except Exception:
                        pass

                    done += 1
                    self.failed += 1
                    pct = int((done / ap_cnt) * 100) if ap_cnt else 100
                    self._progress(pct)

                    if idx is not None and self.ap_update_cb:
                        try:
                            ap_name = getattr(ap_rows[idx], "name", "")
                            self.ap_update_cb(idx, ap_rows[idx].ip, ap_rows[idx].model, "Failed", ap_name)
                        except Exception:
                            pass

                    continue

                results[idx] = (ip, model, status)
                done += 1
                pct = int((done / ap_cnt) * 100) if ap_cnt else 100
                self._progress(pct)

                if status.lower().startswith("success"):
                    self.success += 1
                else:
                    self.failed += 1

                # Look up AP name defensively
                ap_name = ""
                try:
                    if 0 <= idx < len(ap_rows):
                        ap_name = getattr(ap_rows[idx], "name", "") or ""
                except Exception:
                    ap_name = ""

                if self.ap_update_cb:
                    try:
                        # NEW: include ap_name as 5th argument
                        self.ap_update_cb(idx, ip, model, status, ap_name)
                    except Exception:
                        # ensure callbacks never kill the engine
                        pass

        finally:
            # ensure executor is shutdown
            try:
                if getattr(self, "executor", None) is not None:
                    try:
                        self.executor.shutdown(wait=False)
                    except Exception:
                        pass
                    self.executor = None
            except Exception:
                pass

        elapsed = int(time.time() - start)


        self._log(f"[AP] Done. Success={self.success} Fail={self.failed} Time={elapsed}s")
        return results
