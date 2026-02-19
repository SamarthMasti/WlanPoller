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
from netmiko import ConnectHandler

CONFD = "confd"


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def today_data_dir() -> str:
    now = datetime.now()
    return ensure_dir(os.path.join("data", f"{now.year:04d}", f"{now.month:02d}", f"{now.day:02d}"))


def _safe_write_append(path: str, text: str):
    ensure_dir(os.path.dirname(path) or ".")
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


@dataclass
class ApRow:
    ip: str
    model: str
    name: str
    site_tag: str = ""


class IniStore:
    """
    Backward compatible config loader.

    Supports:
      1) INI sections: [WLC], [AP], [FTP]
      2) Legacy 'key: value' flat file (auto-converted)
    """
    def __init__(self, path: str):
        self.path = path
        self.cfg = configparser.ConfigParser()

        if os.path.exists(path):
            try:
                self.cfg.read(path, encoding="utf-8")
            except configparser.MissingSectionHeaderError:
                self._convert_legacy_to_ini()
        self._ensure_defaults()

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
        ensure_dir(os.path.dirname(self.path) or ".")
        with open(self.path, "w", encoding="utf-8") as f:
            self.cfg.write(f)

    def get(self, sec: str, key: str, default: str = "") -> str:
        return self.cfg.get(sec, key, fallback=default)

    def set(self, sec: str, key: str, val: str):
        if sec not in self.cfg:
            self.cfg[sec] = {}
        self.cfg[sec][key] = val

    def bulk_set(self, sec: str, mapping: Dict[str, str]):
        if sec not in self.cfg:
            self.cfg[sec] = {}
        for k, v in mapping.items():
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
        ap_update_cb: Optional[Callable[[int, str, str, str], None]] = None,
    ):
        ensure_dir(CONFD)
        self.data_dir = today_data_dir()
        self.ini = IniStore(os.path.join(CONFD, "config.ini"))
        self.log_cb = log_cb
        self.progress_cb = progress_cb
        self.ap_update_cb = ap_update_cb
        self.success = 0
        self.failed = 0
        # Cooperative shutdown
        self._shutdown_event = threading.Event()
        # Executor reference (will be set when run_ap_poller creates it)
        self.executor = None
        # track sessions/sockets if we want to forcibly close them on shutdown
        self._open_sessions = []
        self.operation = "WLC & AP"
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
        wlc_ip = self.ini.get("WLC", "WlcIpaddr")
        if not wlc_ip:
            raise ValueError("Missing WLC IP in confd/config.ini ([WLC] WlcIpaddr)")
        dev = {
            "device_type": "cisco_ios",
            "host": wlc_ip,
            "username": self.ini.get("WLC", "wlc_user"),
            "password": self.ini.get("WLC", "wlc_pasw"),
            # reduce connect timeout so we fail fast if unreachable
            "timeout": 20,
        }
        self._log(f"[WLC] Connecting to {wlc_ip} ...")
        try:
            conn = ConnectHandler(**dev)
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
            self._log(f"[WLC] Running: {cmd}")

            _safe_write_append(out_file, f"\n<cmd string='{cmd}'>\n\t{cmd}\n")
            out = conn.send_command(cmd, read_timeout=120)
            _safe_write_append(out_file, out + "\n")

            # ---- progress update ----
            pct = int((i / total) * 100)
            self._progress(pct)

        conn.disconnect()
        self._log(f"[WLC] Done. Output: {out_file}")
        return out_file

    def fetch_full_ap_list(self) -> List[ApRow]:
        self._log("[WLC] fetch_full_ap_list() starting...")
        conn = self._wlc_connect()
        out = conn.send_command("show ap summary", read_timeout=180)
        conn.disconnect()
        rows = WlcParse.parse_ap_summary(out)

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


    def _ap_connect_params(self, ip: str) -> Dict[str, str]:
        return {
            "device_type": "cisco_ios",
            "host": ip,
            "username": self.ini.get("AP", "ap_user"),
            "password": self.ini.get("AP", "ap_pasw"),
            "secret": self.ini.get("AP", "ap_enable"),
            # shorter timeout so stuck TCP connects do not block too long
            "timeout": 20,
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

    def _poll_one_ap(self, idx: int, ap: ApRow, device: str, cmds: List[str]):
        try:
            self._log(f"[AP] ({idx+1}) Connecting {ap.ip} ({ap.name}) ...")
            conn = ConnectHandler(**self._ap_connect_params(ap.ip))
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

            fname = os.path.join(self.data_dir, f"{device}_{_safe_filename(ap.name)}.log")
            header = (
                f"<run timestamp='{datetime.now().isoformat()}' device='{device}' hostname='{ap.name}' "
                f"model='{ap.model}' version='{img}' Ip='{ap.ip}' SN='{sn}'>\n"
            )
            _safe_write_append(fname, header)

            for cmd in cmds:
                _safe_write_append(fname, f"\n<cmd string='{cmd}'>\n\t{cmd}\n")
                out = self._ap_send_command(conn, cmd, read_timeout=180)
                _safe_write_append(fname, out + "\n")

            conn.disconnect()
            return idx, ap.ip, ap.model, "Success"
        except Exception as e:
            return idx, ap.ip, ap.model, f"Fail: {e}"

    def run_ap_poller(self, ap_rows: List[ApRow], device: str, ap_cmds: List[str]):
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
