# ==========================================================
# Author: Prashanth Baragur Hanuman
# File  : ApFlashVulnerableChecker.py
# ==========================================================

import os
import re
import string
from typing import Dict, List, Optional, Tuple
from datetime import datetime


def _read_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def ap_hostname_from_run_header(path: str) -> Optional[str]:
    for line in _read_lines(path):
        if line.startswith("<run ") and "hostname=" in line:
            m = re.search(r"hostname='([^']+)'", line)
            if m:
                return m.group(1)
    return None


def ap_model_from_log(path: str) -> Tuple[Optional[str], Optional[bool]]:
    for line in _read_lines(path):
        if "Cisco AP Software" not in line:
            continue
        parts = line.split(",")
        if len(parts) < 2:
            return None, None
        ap_model = parts[1].strip()
        FLASH_ALLOWED_MODELS = {"(ap1g6)", "(ap1g6a)", "(ap1g6b)"}
        return ap_model, ap_model in FLASH_ALLOWED_MODELS
    return None, None


def primary_version_check(path: str) -> Tuple[Optional[str], Optional[bool]]:
    primary_image = None
    for line in _read_lines(path):
        if "AP Running Image     :" in line:
            primary_image = line.split(":", 1)[1].strip()
            break
    if not primary_image:
        return None, None
    try:
        a, b, c, d = primary_image.split(".")
        c_i = int(c); d_i = int(d)
        buggy = True
        if a == "17" and b == "12" and c_i <= 3:
            buggy = False
        elif a == "17" and b == "12" and c == "4" and d_i >= 213:
            buggy = False
        elif a == "17" and b == "12" and c == "5" and d_i >= 209:
            buggy = False
        elif a == "17" and b == "12" and c == "6" and d_i >= 201:
            buggy = False
        elif a == "17" and b == "15" and c == "3" and d_i >= 212:
            buggy = False
        elif a == "17" and b == "15" and c == "4" and d_i >= 206:
            buggy = False
        elif a == "17" and b == "15" and c == "5":
            buggy = False
        elif a == "17" and b == "18" and c == "1" and d_i >= 203:
            buggy = False
        elif a == "17" and b == "18" and c == "2" and d_i >= 201:
            buggy = False
        elif a == "17" and int(b) <= 9:
            buggy = False
        return primary_image, buggy
    except Exception:
        return primary_image, None


def backup_version_check(path: str) -> Tuple[Optional[str], Optional[bool]]:
    backup_image = None
    for line in _read_lines(path):
        if "Backup Boot Image    :" in line:
            backup_image = line.split(":", 1)[1].strip()
            break
    if not backup_image:
        return None, False
    try:
        a, b, c, d = backup_image.split(".")
        c_i = int(c); d_i = int(d)
        buggy = True
        if a == "17" and b == "12" and c_i <= 3:
            buggy = False
        elif a == "17" and b == "12" and c == "4" and d_i >= 213:
            buggy = False
        elif a == "17" and b == "12" and c == "5" and d_i >= 209:
            buggy = False
        elif a == "17" and b == "12" and c == "6" and d_i >= 201:
            buggy = False
        elif a == "17" and b == "15" and c == "3" and d_i >= 212:
            buggy = False
        elif a == "17" and b == "15" and c == "4" and d_i >= 206:
            buggy = False
        elif a == "17" and b == "15" and c == "5":
            buggy = False
        elif a == "17" and b == "18" and c == "1" and d_i >= 203:
            buggy = False
        elif a == "17" and b == "18" and c == "2" and d_i >= 201:
            buggy = False
        elif a == "17" and b == "9" and c == "7":
            buggy = False
        return backup_image, buggy
    except Exception:
        return backup_image, None


def cnssdaemon_log_present(path: str) -> bool:
    for line in _read_lines(path):
        if "cnssdaemon.log" in line and "root" in line:
            return True
    return False


def current_boot_partition(path: str) -> Tuple[Optional[str], Optional[bool]]:
    for line in _read_lines(path):
        if "BOOT path-list:" in line:
            part = line.split(":", 1)[1].strip()
            return part, (part == "part1")
    return None, None


def image_integrity_failed(path: str) -> Optional[bool]:
    try:
        lines = _read_lines(path)
        idx = None
        for i, line in enumerate(lines):
            if "show image integrity" in line:
                idx = i
                break
        if idx is None:
            return None
        next_25 = [l for l in lines[idx+1:idx+1+25] if l.strip()]
        if len(next_25) < 9:
            return None
        part1_bin = next_25[2].split(":")[1].strip()
        part1_ramfs = next_25[3].split(":")[1].strip()
        part1_ioxtar = next_25[4].split(":")[1].strip()
        part2_bin = next_25[6].split(":")[1].strip()
        part2_ramfs = next_25[7].split(":")[1].strip()
        part2_ioxtar = next_25[8].split(":")[1].strip()
        ok = all(x == "Good" for x in [part1_bin, part1_ramfs, part1_ioxtar, part2_bin, part2_ramfs, part2_ioxtar])
        return not ok
    except Exception:
        return None


def part2_mem_available_mb(path: str) -> Tuple[Optional[float], Optional[bool]]:
    target = "/dev/ubivol/part2"
    for line in _read_lines(path):
        if target not in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            return None, None
        mem_str = parts[3].strip()
        if not mem_str:
            return None, None
        suffix = mem_str[-1].lower()
        number_part = mem_str.rstrip(string.ascii_letters)
        try:
            value = float(number_part)
        except ValueError:
            return None, None
        if suffix == "g":
            mb = value * 1024.0
        elif suffix == "k":
            mb = value / 1024.0
        elif suffix == "m":
            mb = value
        else:
            mb = value
        return mb, not (mb > 80.0)
    return None, None


def analyze_logs(log_dir: str):

    recovery_option_image_partition_swap = []
    recovery_option_devshell = []
    recovery_option_simple_archive_download = []
    recovery_option_image_integrity_check_failed = []
    recovery_option_partition_safe_but_clean_up_reccomended = []

    status_rows: List[Dict[str, str]] = []

    for fn in os.listdir(log_dir):
        fp = os.path.join(log_dir, fn)
        if not os.path.isfile(fp):
            continue

        if not fn.lower().endswith(".log"):
            continue

        ap_name = ap_hostname_from_run_header(fp) or fn
        ap_model_sig, ap_model_check = ap_model_from_log(fp)
        ap_ip = ap_ip_from_run_header(fp)

        if ap_model_sig is None:
            ap_model_sig = "UNKNOWN"

        cnss = cnssdaemon_log_present(fp)
        primary_image, prim_buggy = primary_version_check(fp)
        backup_image, back_buggy = backup_version_check(fp)
        part, part1 = current_boot_partition(fp)
        integ_fail = image_integrity_failed(fp)
        mem_mb, mem_low = part2_mem_available_mb(fp)

        # ------------------------------
        # Build Status Table Row
        # ------------------------------
        status_rows.append({
            "AP Name": ap_name,
            "Model": ap_model_sig or "",
            "Primary Image": primary_image or "",
            "Primary Buggy": str(prim_buggy),
            "Backup Image": backup_image or "",
            "Backup Buggy": str(back_buggy),
            "Boot Partition": part or "",
            "Image Integrity Failed": str(integ_fail),
            "Part2 Free MB": f"{mem_mb:.2f}" if mem_mb is not None else "",
            "Low Memory": str(mem_low)
        })

        # ------------------------------
        # Recovery Logic (UNCHANGED)
        # ------------------------------

        if integ_fail is True:
            recovery_option_image_integrity_check_failed.append((ap_name, ap_model_sig,ap_ip))
            continue

        if mem_mb is not None and mem_mb < 20.0:
            recovery_option_devshell.append((ap_name, ap_model_sig,ap_ip))
            continue

        if ap_model_check:
            if cnss:
                if prim_buggy:
                    if part1:
                        if mem_low:
                            recovery_option_image_partition_swap.append((ap_name, ap_model_sig,ap_ip))
                    else:
                        if mem_low and mem_mb and mem_mb < 20.0:
                            recovery_option_partition_safe_but_clean_up_reccomended.append((ap_name, ap_model_sig,ap_ip))
                else:
                    if back_buggy:
                        recovery_option_simple_archive_download.append((ap_name, ap_model_sig,ap_ip))
            else:
                if back_buggy:
                    recovery_option_simple_archive_download.append((ap_name, ap_model_sig,ap_ip))

    # ---------------------------------------------------
    # Write Status Check Summary File
    # ---------------------------------------------------
    # ---------------------------------------------------
    # Write Status Check Summary File (FULL TABLE + RECOVERY)
    # ---------------------------------------------------

    if status_rows:

        folder_name = os.path.basename(log_dir)
        output_file = os.path.join(
            log_dir,
            f"Status_check_results_{folder_name}.log"
        )

        with open(output_file, "a", encoding="utf-8") as f:

            f.write("\n=========== AP FLASH CHECK STATUS SUMMARY ===========\n\n")

            # Define headers in correct order
            headers = [
                "AP Name",
                "Model",
                "Primary Image",
                "Primary Buggy",
                "Backup Image",
                "Backup Buggy",
                "Boot Partition",
                "Image Integrity Failed",
                "Part2 Free MB",
                "Low Memory"
            ]

            # Column width (increase for cleaner spacing)
            col_width = 22

            # Print header row
            for h in headers:
                f.write(h.ljust(col_width))
            f.write("\n")

            # Print separator line
            f.write("-" * (col_width * len(headers)))
            f.write("\n")

            # Print each AP row
            for row in status_rows:
                for h in headers:
                    value = str(row.get(h, ""))
                    f.write(value.ljust(col_width))
                f.write("\n")

            # Add Recovery Section
            f.write("\n\n=========== RECOVERY SUMMARY ===========\n\n")

            def write_recovery(title, items):
                if items:
                    f.write(title + "\n")
                    for name, model, ip in items:
                        f.write(f"  - {name} ({model}) [{ip}]\n")
                    f.write("\n")

            write_recovery("Recover with image partition swap", recovery_option_image_partition_swap)
            write_recovery("Recover with devshell", recovery_option_devshell)
            write_recovery("Safe state but buggy backup image", recovery_option_simple_archive_download)
            write_recovery("Image integrity failed", recovery_option_image_integrity_check_failed)
            write_recovery("Partition safe but low flash", recovery_option_partition_safe_but_clean_up_reccomended)

    # ---------------------------------------------------
    # Build GUI Vulnerable Table (unchanged)
    # ---------------------------------------------------

    vulnerable_rows: List[Dict[str, str]] = []

    def add_rows(items, recovery):
        for name, model, ip in items:
            vulnerable_rows.append({
                "ap_name": name,
                "ap_model": model or "",
                "ap_ip": ip or "",
                "recovery": recovery
            })

    add_rows(recovery_option_image_partition_swap, "Recover with image partition swap")
    add_rows(recovery_option_devshell, "Recover with devshell")
    add_rows(recovery_option_simple_archive_download, "Safe state but AP has buggy image in the backup partition")
    add_rows(recovery_option_image_integrity_check_failed, "Image integrity check has failed for these APs")
    add_rows(recovery_option_partition_safe_but_clean_up_reccomended, "Partition is safe but the flash storage is low")
    print("DEBUG: analyze_logs running on:", log_dir)

    # ---------------- BUILD SUMMARY TEXT ----------------

    summary_lines = []
    summary_lines.append("========== AP FLASH CHECK STATUS SUMMARY ==========")
    summary_lines.append("")

    for ap_name, ap_model,ap_ip in recovery_option_image_partition_swap:
        summary_lines.append(f"{ap_name} ({ap_model}) [{ap_ip}]-> IMAGE PARTITION SWAP")

    for ap_name, ap_model, ap_ip in recovery_option_devshell:
        summary_lines.append(f"{ap_name} ({ap_model}) [{ap_ip}] -> DEV SHELL RECOVERY")

    for ap_name, ap_model, ap_ip in recovery_option_simple_archive_download:
        summary_lines.append(f"{ap_name} ({ap_model}) [{ap_ip}] -> SIMPLE ARCHIVE DOWNLOAD")
    for ap_name, ap_model, ap_ip in recovery_option_image_integrity_check_failed:
        summary_lines.append(
            f"{ap_name} ({ap_model}) [{ap_ip}] -> IMAGE INTEGRITY FAILED"
        )

    summary_text = "\n".join(summary_lines)

    summary_filename = os.path.join(
        log_dir,
        f"Status_check_results_{datetime.now().day}.log"
    )




    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = (
        "\n"
        "============================================================\n"
        f"Flash Checker Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "------------------------------------------------------------\n"
    )

    with open(summary_filename, "a", encoding="utf-8") as f:
        f.write(header)
        f.write(summary_text)
    print("DEBUG summary_filename:", summary_filename)

    return vulnerable_rows, summary_filename
def ap_ip_from_run_header(fp: str) -> str:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # First try header style
        m = re.search(r"[Ii]p='([^']+)'", content)
        if m:
            return m.group(1)

        # Then try GOT IP[10.x.x.x] format
        m = re.search(r"GOT IP\[(.*?)\]", content)
        if m:
            return m.group(1)

        return ""
    except Exception:
        return ""



