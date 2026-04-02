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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    wlc_ip: str =""

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
        ap_update_cb: Optional[Callable[[int, str, str, str, str, str], None]] = None,
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
    def _process_single_wlc(self, section):
        try:
            self._log(f"[WLC] Connecting to {section}")

            conn = self._wlc_connect(section)

            out = conn.send_command("show ap summary", read_timeout=180)

            conn.disconnect()

            rows = WlcParse.parse_ap_summary(out)

            # attach WLC info
            for r in rows:
                r.wlc_ip = self.ini.get(section, "wlc_ip")

            self._log(f"[WLC] Completed {section} ({len(rows)} APs)")

            return rows

        except Exception as e:
            self._log(f"[WLC ERROR] {section}: {e}")
            return []
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

    def _wlc_connect(self, section: str = "WLC"):
        wlc_ip = self.ini.get(section, "wlc_ip")
        if not wlc_ip:
            raise ValueError(f"Missing WLC IP in config.ini ([{section}] wlc_ip)")
        self._log(f"[WLC] Checking SSH port on {wlc_ip} ({section})...")
        if not ssh_port_open(wlc_ip):
            raise RuntimeError(f"WLC {wlc_ip} ({section}) unreachable on port 22")
        dev = {
            "device_type": "cisco_ios",
            "host": wlc_ip,
            "username": self.ini.get(section, "wlc_user"),
            "password": self.ini.get(section, "wlc_pasw"),
            "timeout": 60,
            "conn_timeout": 30,
            "banner_timeout": 30,
            "auth_timeout": 30,
        }
        self._log(f"[WLC] Connecting to {wlc_ip} ({section}) ...")

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
        wlc_sections = self._get_wlc_sections()
        last_out_file = ""
        for section in wlc_sections:
            self._log(f"[WLC] ===== Starting section [{section}] =====")
            # Use per-WLC commands if stored, else fall back to shared commands
            # Per-WLC override > shared fallback
            cmds_section = f"{section}_CMDS"
            effective_cmds = wlc_cmds   # default: shared list
            if self.ini.cfg.has_section(cmds_section):
                raw = self.ini.cfg.get(cmds_section, "cmds", fallback="").strip()
                if raw:
                    effective_cmds = [c.strip() for c in raw.splitlines() if c.strip()]
                    self._log(f"[WLC] [{section}] using per-WLC override ({len(effective_cmds)} cmds)")
                else:
                    self._log(f"[WLC] [{section}] override empty — using shared cmd list ({len(effective_cmds)} cmds)")
            else:
                self._log(f"[WLC] [{section}] using shared cmd list ({len(effective_cmds)} cmds)")
            try:
                conn = self._wlc_connect(section)
                
                
                
                wlc_ip_val = self.ini.get(section, "wlc_ip")
                safe_ip = wlc_ip_val.replace(".", "_")

                # ✅ Define folder FIRST
                wlc_folder = os.path.join(self.data_dir, f"WLC_{safe_ip}")

                # ✅ Then create it
                os.makedirs(wlc_folder, exist_ok=True)

                # ✅ File name (constant)
                out_file = os.path.join(wlc_folder, "wlc_outputs.txt")

                # ✅ Header
                header = (
                    f"<run timestamp='{datetime.now().isoformat()}' "
                    f"device='eWLC' hostname='{wlc_ip_val}' "
                    f"model='eWLC-9800' version='None'>\n"
                )
                _safe_write_append(out_file, header)
                total = len(effective_cmds)
                for i, cmd in enumerate(effective_cmds, 1):
                    is_special, actual_cmd, needs_confirm, sleep_secs = self.SpecialCmdCheck(cmd)
                    if is_special and sleep_secs > 0:
                        self._log(f"[SLEEP] Waiting {sleep_secs}s before next command...")
                        elapsed = 0
                        heartbeat_interval = 30
                        while elapsed < sleep_secs:
                            chunk = min(heartbeat_interval, sleep_secs - elapsed)
                            time.sleep(chunk)
                            elapsed += chunk
                            if elapsed < sleep_secs:
                                self._log(f"[SLEEP] Still waiting... {elapsed}s / {sleep_secs}s")
                        continue
                    self._log(f"[WLC] Running: {actual_cmd}")
                    _safe_write_append(out_file, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")
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
                self._log(f"[WLC] Done [{section}]. Output: {out_file}")
                last_out_file = out_file
            except Exception as e:
                self._log(f"[WLC] [{section}] failed: {e}")
        return last_out_file
    def run_client_auth_workflow(self):

        delete_list = []

        wlc_sections = self._get_wlc_sections()

        for section in wlc_sections:

            self._log(f"[AUTH] ===== WLC: {section} =====")

            conn = self._wlc_connect(section)

            # ---------------- STEP 1 ----------------
            cmd1 = "show wireless client summary"
            self._log(f"[AUTH][CMD] {cmd1}")

            out1 = conn.send_command(cmd1)

            self._log(f"[AUTH][RAW F1]\n{out1}")

            f1 = self._extract_macs(out1)

            self._log(f"[AUTH] F1 MACs: {f1}")

            # ---------------- WAIT ----------------
            self._log("[AUTH] Waiting 15 minutes...")
            time.sleep(900)

            # ---------------- STEP 2 ----------------
            self._log(f"[AUTH][CMD] {cmd1}")

            out2 = conn.send_command(cmd1)

            self._log(f"[AUTH][RAW F2]\n{out2}")

            f2 = self._extract_macs(out2)

            self._log(f"[AUTH] F2 MACs: {f2}")

            # ---------------- INTERSECTION ----------------
            stuck = list(set(f1).intersection(set(f2)))

            self._log(f"[AUTH] Persistent clients: {stuck}")

            # ---------------- DETAIL CHECK ----------------
            for mac in stuck:

                cmd2 = f"show wireless client mac {mac} detail"
                self._log(f"[AUTH][CMD] {cmd2}")

                detail = conn.send_command(cmd2)

                self._log(f"[AUTH][DETAIL]\n{detail}")

                connected_for = self._extract_value(detail, "Connected For")
                entry_time = self._extract_value(detail, "Client Entry Create Time")

                self._log(f"[AUTH] {mac} → Connected: {connected_for}, Entry: {entry_time}")

                if "Policy Manager State: Authenticating" not in detail:
                    self._log(f"[AUTH][SKIP] {mac} not in Authenticating state")
                    continue

                if entry_time <= connected_for:
                    self._log(f"[AUTH][SKIP] {mac} timing condition failed")
                    continue

                self._log(f"[AUTH][MARKED] {mac} added to delete list")
                delete_list.append(mac)

            conn.disconnect()

        self._log(f"[AUTH] FINAL DELETE LIST: {delete_list}")

        return delete_list
    def _extract_macs(self, output):
        macs = []
        for line in output.splitlines():
            match = re.search(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", line, re.I)
            if match:
                macs.append(match.group(1))
        return macs


    def _extract_value(self, text, key):
        match = re.search(rf"{key}\s*:\s*(\d+)", text)
        return int(match.group(1)) if match else 0
    def deauth_clients(self, mac_list):

        for section in self._get_wlc_sections():

            conn = self._wlc_connect(section)

            for mac in mac_list:
                self._log(f"[AUTH] Deauth {mac}")
                conn.send_command(f"wireless client mac-address {mac} deauthenticate")

            conn.disconnect()
    def fetch_full_ap_list(self) -> List[ApRow]:
        self._log("[WLC] Parallel fetch_full_ap_list() starting...")

        wlc_sections = self._get_wlc_sections()
        all_rows: List[ApRow] = []
        seen_ips = set()

        max_threads = min(len(wlc_sections), 5)

        with ThreadPoolExecutor(max_workers=max_threads) as executor:

            futures = {
                executor.submit(self._process_single_wlc, sec): sec
                for sec in wlc_sections
            }

            for future in as_completed(futures):
                sec = futures[future]

                try:
                    rows = future.result()

                    for r in rows:
                        if r.ip not in seen_ips:
                            all_rows.append(r)
                            seen_ips.add(r.ip)

                    self._log(f"[WLC] [{sec}] merged {len(rows)} APs")

                except Exception as e:
                    self._log(f"[WLC ERROR] {sec}: {e}")

        self._log(f"[WLC] Total APs across all WLCs: {len(all_rows)}")
        # 🔥 QCA FILTER FOR FLASH CHECKER
        if self.operation == "WLC & AP" and self.workflow == "AP Flash Checker":
            self._log("[FILTER] Applying QCA model filter...")

            filtered = []
            for r in all_rows:
                model_upper = r.model.upper()
                if any(prefix in model_upper for prefix in QCA_PREFIXES):
                    filtered.append(r)
                else:
                    self._log(f"[FILTER REMOVED] {r.name} ({r.model})")

            all_rows = filtered

            self._log(f"[FILTER RESULT] {len(all_rows)} APs after filtering")
        return all_rows
    def filter_by_site_tag(self, full_rows: List[ApRow], site_tag: str):
        self._log(f"[WLC] filter_by_site_tag('{site_tag}') starting...")
        wlc_sections = self._get_wlc_sections()
        total = 0
        all_names = []

        for section in wlc_sections:
            try:
                conn = self._wlc_connect(section)
                tag_all = conn.send_command("show ap tag summary", read_timeout=180)
                total += WlcParse.parse_total_ap_cnt_from_tag_summary(tag_all) or 0
                out = conn.send_command(f"show ap tag summary | inc {site_tag}", read_timeout=120)
                conn.disconnect()
                aplist_tag_path = os.path.join(self.data_dir, "aplist_tag.txt")
                _safe_write_append(aplist_tag_path, out + "\n")
                names = WlcParse.parse_ap_names_from_tag_summary(out, site_tag)
                all_names.extend(names)
            except Exception as e:
                self._log(f"[WLC] [{section}] filter_by_site_tag failed: {e}")

        total = total or len(full_rows)

        if not all_names:
            if len(full_rows) == 0:
                raise ValueError("WLC has no APs (show ap summary returned 0 rows).")
            raise ValueError(f"'{site_tag}' Site Tag Name Does not exist")

        name_map = {r.name: r for r in full_rows}
        selected: List[ApRow] = []
        for n in all_names:
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
                    or "successful file transfer" in buf
                    or "archive download completed" in buf
                    or "image transfer complete" in buf
                    or "extracting images" in buf
                    or "bundle for transfer" in buf
                    or "bytes copied" in buf
                    or "transfer complete" in buf
                    or "upload complete" in buf
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
    def _get_tmp_usage_percent(self, output: str) -> int:
        for line in output.splitlines():
            if "/tmp" in line.lower():
                match = re.search(r"(\d+)%", line)
                if match:
                    return int(match.group(1))
        return 0
    def _poll_one_ap(self, idx: int, ap: ApRow, device: str, cmds: List[str]):
        try:
            self._log(f"[AP] ({idx+1}) Connecting {ap.ip} ({ap.name}) {ap.model} ...")
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
                return idx, ap.ip, ap.model, "Fail: Connection retries exhausted",ap.name,ap.wlc_ip
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
            pid_m = re.search(r"PID:\s*([A-Za-z0-9\-]+)", inv)
            actual_model = pid_m.group(1).strip() if pid_m else ap.model
            #print('DbgWpgui: Poll One AP : ',actual_model,pid_m.group(1))

            ver = self._ap_send_command(conn, "show version", read_timeout=120)
            img_m = re.search(r"AP Running Image\s*:\s*(.*)", ver)
            img = img_m.group(1).strip() if img_m else "UNKNOWN"
            # --- FIX: Update model from actual AP (authoritative source) ---
            model_match = re.search(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)", ver)
            if model_match:
                new_model = model_match.group(1)
                if new_model and new_model.upper() != "UNKNOWN":
                    ap.model = new_model

            if ap.wlc_ip:
                safe_ip = ap.wlc_ip.replace(".", "_")
                wlc_folder = os.path.join(self.data_dir, f"WLC_{safe_ip}")
                os.makedirs(wlc_folder, exist_ok=True)
            else:
                wlc_folder = self.data_dir
            fname = os.path.join(wlc_folder, f"{device}_{_safe_filename(ap.name)}.log")
            header = (
                f"<run timestamp='{datetime.now().isoformat()}' device='{device}' hostname='{ap.name}' "
                f"model='{ap.model}' version='{img}' Ip='{ap.ip}' SN='{sn}'>\n"
            )
            _safe_write_append(fname, header)
            tmp_usage = 0
            cleanup_done = False
            for cmd in cmds:
                if self._shutdown_event.is_set():
                        return idx, ap.ip, ap.model, "Cancelled", getattr(ap, "name", ""), getattr(ap, "wlc_ip", "")

                is_special, actual_cmd, needs_confirm, sleep_secs = self.SpecialCmdCheck(cmd)

                # --- Handle sleep ---
                if is_special and sleep_secs > 0:
                    self._log(f"[SLEEP] Waiting {sleep_secs}s before next command...")
                    elapsed = 0
                    heartbeat_interval = 30
                    while elapsed < sleep_secs:
                        chunk = min(heartbeat_interval, sleep_secs - elapsed)
                        time.sleep(chunk)
                        elapsed += chunk
                        if elapsed < sleep_secs:
                            self._log(f"[SLEEP] Still waiting... {elapsed}s / {sleep_secs}s")
                    continue

                cmd_lower = actual_cmd.lower()

                # ================================
                # 🔥 TMP DETECTION
                # ================================
                if "show filesystems" in cmd_lower:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd}")
                    _safe_write_append(fname, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")
                    output = self._ap_send_command(conn, actual_cmd, read_timeout=120)
                    tmp_usage = self._get_tmp_usage_percent(output)
                    self._log(f"[TMP] {ap.ip} → /tmp usage = {tmp_usage}%")
                    _safe_write_append(fname, output + "\n")
                    _safe_write_append(fname, f"[TMP] /tmp usage detected: {tmp_usage}%\n")
                    continue

                # ================================
                # 🔥 TMP CLEANUP (>60%)
                # ================================
                if "delete /force /recursive /tmp" in cmd_lower:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if tmp_usage > 60:
                        self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd}")
                        _safe_write_append(fname, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")
                        self._log(f"[TMP] {ap.ip} → /tmp is {tmp_usage}% — running cleanup")
                        try:
                            conn.send_command_timing(actual_cmd)
                            cleanup_done = True
                            self._log(f"[TMP] {ap.ip} → Cleanup complete")
                            _safe_write_append(fname, "[TMP] Cleanup executed successfully\n")
                        except Exception as e:
                            self._log(f"[TMP] {ap.ip} → Cleanup failed: {e}")
                            _safe_write_append(fname, f"[TMP] Cleanup failed: {e}\n")
                    else:
                        self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd} [SKIPPED — /tmp={tmp_usage}%]")
                        _safe_write_append(fname, f"\n[TMP] Cleanup skipped (/tmp={tmp_usage}%, threshold=60%)\n")
                    continue

                # ================================
                # 🔥 RELOAD (ONLY IF CLEANED)
                # ================================
                if "reload" in cmd_lower:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if True:
                        self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd}")
                        _safe_write_append(fname, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")
                        self._log(f"[TMP] {ap.ip} → Injecting reload (cleanup was done)")
                        try:
                            out = conn.send_command_timing(actual_cmd)
                            if "confirm" in out.lower():
                                conn.send_command_timing("\n")
                            self._log(f"[TMP] {ap.ip} → Reload initiated successfully")
                            _safe_write_append(fname, "[TMP] Reload initiated\n")
                        
                        except Exception:
                            self._log(f"[TMP] {ap.ip} → Connection closed after reload (expected)")
                            _safe_write_append(fname, "[TMP] Connection closed after reload (expected)\n")
                    else:
                        self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd} [SKIPPED — no cleanup was needed]")
                        _safe_write_append(fname, f"\n[TMP] Reload skipped (cleanup was not needed)\n")
                    break

                # ================================
                # 🔥 TRANSFER COMMANDS (upload/copy)
                # ================================
                is_transfer_cmd = (
                    "sftp://" in cmd_lower
                    or "scp://" in cmd_lower
                    or "copy syslogs" in cmd_lower
                    or "copy core:" in cmd_lower
                    or "copy crashinfo:" in cmd_lower
                    or "copy support-bundle" in cmd_lower
                )
                if is_transfer_cmd:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd}")
                    _safe_write_append(fname, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")
                    ftp_user = self.ini.get("FTP", "ftp_user", "")
                    ftp_pasw = self.ini.get("FTP", "ftp_pasw", "")
                    out = self.run_command_interactive(conn, actual_cmd, ftp_user=ftp_user, ftp_pass=ftp_pasw)
                    exit_msg = ""
                    for line in reversed(out.strip().splitlines()):
                        line = line.strip()
                        if line:
                            exit_msg = line
                            break
                    _safe_write_append(fname, f"\n[IMAGE DOWNLOAD] Result: {exit_msg}\n")
                    continue

                # ================================
                # 🔥 NORMAL COMMANDS
                # ================================
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._log(f"{timestamp} | {ap.ip:<15} | {ap.name:<15} | {actual_cmd}")

                _safe_write_append(fname, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")

                if needs_confirm:
                    conn.write_channel(actual_cmd + "\n")
                    time.sleep(3)
                    conn.write_channel("y\n")
                    time.sleep(2)
                    out = conn.read_channel()
                else:
                    out = self._ap_send_command(conn, actual_cmd, read_timeout=180)

                _safe_write_append(fname, out + "\n")

                

            conn.disconnect()

            return idx, ap.ip, actual_model, "Success", ap.name, ap.wlc_ip
        except Exception as e:
           return idx, ap.ip, ap.model, f"Failed: {str(e)}", getattr(ap, "name", ""), getattr(ap, "wlc_ip", "")
    def _get_wlc_sections_list(self) -> list:
        """Return all configured WLC sections regardless of operation mode."""
        sections = []
        for sec in self.ini.cfg.sections():
            if sec == "WLC" or (sec.startswith("WLC") and sec[3:].isdigit()):
                if self.ini.get(sec, "wlc_ip"):
                    sections.append(sec)
        return sorted(sections, key=lambda s: 0 if s == "WLC" else int(s[3:]))

    def _run_wlc_cmds_for_section(self, section: str, wlc_cmds: list) -> str:
        """Run WLC commands for a single named section. Same logic as run_wlc_cmds but single-section."""
        self._log(f"[WLC] ===== Starting section [{section}] =====")
        cmds_section = f"{section}_CMDS"
        effective_cmds = wlc_cmds
        if self.ini.cfg.has_section(cmds_section):
            raw = self.ini.cfg.get(cmds_section, "cmds", fallback="").strip()
            if raw:
                effective_cmds = [c.strip() for c in raw.splitlines() if c.strip()]
        try:
            conn = self._wlc_connect(section)
            wlc_ip_val = self.ini.get(section, "wlc_ip")
            safe_ip = wlc_ip_val.replace(".", "_")
            wlc_folder = os.path.join(self.data_dir, f"WLC_{safe_ip}")
            os.makedirs(wlc_folder, exist_ok=True)
            out_file = os.path.join(wlc_folder, "wlc_outputs.txt")
            header = (
                f"<run timestamp='{datetime.now().isoformat()}' "
                f"device='eWLC' hostname='{wlc_ip_val}'>\n"
            )
            _safe_write_append(out_file, header)
            total = len(effective_cmds)
            for i, cmd in enumerate(effective_cmds, 1):
                is_special, actual_cmd, needs_confirm, sleep_secs = self.SpecialCmdCheck(cmd)
                if is_special and sleep_secs > 0:
                    self._log(f"[SLEEP] Waiting {sleep_secs}s before next command...")
                    elapsed = 0
                    heartbeat_interval = 30
                    while elapsed < sleep_secs:
                        chunk = min(heartbeat_interval, sleep_secs - elapsed)
                        time.sleep(chunk)
                        elapsed += chunk
                        if elapsed < sleep_secs:
                            self._log(f"[SLEEP] Still waiting... {elapsed}s / {sleep_secs}s")
                    continue
                self._log(f"[WLC][{section}] Running: {actual_cmd}")
                _safe_write_append(out_file, f"\n<cmd string='{actual_cmd}'>\n\t{actual_cmd}\n")
                if needs_confirm:
                    conn.write_channel(actual_cmd + "\n")
                    time.sleep(3)
                    conn.write_channel("y\n")
                    time.sleep(2)
                    out = conn.read_channel()
                else:
                    out = conn.send_command(actual_cmd, read_timeout=120)
                _safe_write_append(out_file, out + "\n")
                self._progress(int((i / total) * 100))
            conn.disconnect()
            return out_file
        except Exception as e:
            self._log(f"[WLC] [{section}] failed: {e}")
            return ""

    def _fetch_ap_list_for_section(self, section: str) -> list:
        """Fetch AP list from a single WLC section."""
        try:
            rows = self._process_single_wlc(section)
            if self.workflow == "AP Flash Checker":
                filtered = []
                for r in rows:
                    model_upper = r.model.upper()
                    if any(prefix in model_upper for prefix in QCA_PREFIXES):
                        filtered.append(r)
                self._log(f"[FILTER] {section}: {len(filtered)}/{len(rows)} APs after QCA filter")
                return filtered
            return rows
        except Exception as e:
            self._log(f"[WLC] _fetch_ap_list_for_section [{section}] error: {e}")
            return []

    def _filter_by_site_tag_section(self, section: str, full_rows: list, site_tag: str):
        """Apply site tag filter for a single WLC section."""
        try:
            conn = self._wlc_connect(section)
            tag_all = conn.send_command("show ap tag summary", read_timeout=180)
            total = WlcParse.parse_total_ap_cnt_from_tag_summary(tag_all) or len(full_rows)
            out = conn.send_command(f"show ap tag summary | inc {site_tag}", read_timeout=120)
            conn.disconnect()
            names = WlcParse.parse_ap_names_from_tag_summary(out, site_tag)
            if not names:
                return [], total
            name_map = {r.name: r for r in full_rows}
            selected = []
            for n in names:
                if n in name_map:
                    r = name_map[n]
                    r.site_tag = site_tag
                    selected.append(r)
            return selected, total
        except Exception as e:
            self._log(f"[WLC] site tag filter [{section}] failed: {e}")
            return full_rows, len(full_rows)
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
                    idx, ip, model, status, ap_name, wlc = fut.result()
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
                            self.ap_update_cb(idx, ap_rows[idx].ip, ap_rows[idx].model, f"Failed: {str(e)}", ap_name, "")
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
                        self.ap_update_cb(idx, ip, model, status, ap_name,wlc)
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
        return self.success, self.failed  # return instead of only storing

    def _get_wlc_sections(self) -> list:
        """Returns all WLC sections from ini e.g. ['WLC', 'WLC2', 'WLC3']"""
        sections = []
        for sec in self.ini.cfg.sections():
            if sec == "WLC" or (sec.startswith("WLC") and sec[3:].isdigit()):
                if self.ini.get(sec, "wlc_ip"):  # only include if IP is set
                    sections.append(sec)

        

        # 🔒 Restrict to ONE WLC for WLC & AP
        
        def _sort_key(s):
            return 0 if s == "WLC" else int(s[3:])
        return sorted(sections, key=lambda s: 0 if s == "WLC" else int(s[3:]))
















