import psutil
import time
import os
import csv
from datetime import datetime

# Configuration

scan_interval = 5                       # seconds between scans
csv_file = "suspicious_processes.csv"   # CSV file to append findings


# Helper functions

def timestamp():
    # Return readable timestamp string.
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_csv_header(path):
    # Create CSV and write header if it doesn't exist
    if not os.path.exists(path):
        try:
            with open(path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",    # when we observed it
                    "pid",
                    "process_name",
                    "username",
                    "exe_path"
                    "cmdline",
                    "cpu_percent",
                    "memory_mb",
                    "reasons"       # semi-colon seperated textual reasons
                ])
        except Exception as e:
            print(f"Could not create CSV file {path}: {e}")

def append_to_csv(path, row):
    # Append one row (list) to CSV safely
    try:
        with open(path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(row)
    except Exception as e:
        print(f"Failed to write to CSV {path}: {e}")


# Suspicion rules

suspisious_names = {"cmd.exe", "powershell.exe", "sh", "bash"}
cpu_threshold = 30.0    # percent
suspicious_path_keywords = ["downloads", "temp"]

def get_cmdline_text(proc):
    # Return a safe string representation of the process command line.
    try:
        cmd = proc.cmdline()
        if isinstance(cmd, list):
            return " ".join(cmd)
        return str(cmd)
    except Exception:
        return ""
    
def get_exe_path(proc):
    # Return executable path or empty string if unavailable.
    try:
        return proc.exe()
    except Exception:
        return ""
    
def is_suspicious(proc):
    reasons = []

    # 1. suspicious name
    try:
        name = proc.name().lower()
        if name in suspisious_names:
            reasons.append("shell-like name")
    except Exception:
        name = "<unknown>"

    # 2. high CPU
    try:
        cpu = proc.cpu_percent(interval=0)
        if cpu > cpu_threshold:
            reasons.append(f"high CPU {cpu:.1f}%")
    except Exception:
        cpu = None

    # 3. running from downloads/temp
    exe = get_exe_path(proc).lower()
    for keyword in suspicious_path_keywords:
        if keyword in exe:
            reasons.append(f"exe path contains '{keyword}'")
            break

    return reasons


# Main loop
def main():
    print("Simple process monitor (CSV logging). Press Ctrl+C to stop.")
    print(f"Logging suspicious findings to: {csv_file}")

    # Prepare CSV header if needed
    ensure_csv_header(csv_file)

    # Warm up cpu counters for all processes (psutil quirk)
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=0)
        except Exception:
            pass
            
    try:
        while True:
            scan_time = timestamp()
            print(f"\n--- Scan at {scan_time} ---")

            for proc in psutil.process_iter():
                try:
                    reasons = is_suspicious(proc)
                    if not reasons:
                        continue

                    # Gather info for display and CSV
                    pid = proc.pid

                    try:
                        pname = proc.name()
                    except Exception:
                        pname = ""

                    try:
                        user = proc.username()
                    except Exception:
                        user = ""
                    
                    exe = get_exe_path(proc)
                    cmd = get_cmdline_text(proc)

                    try:
                        mem = proc.memory_info().rss / (1024 * 1024)    # MB
                    except Exception:
                        mem = ""

                    try:
                        cpu = proc.cpu_percent(interval=0)
                    except Exception:
                        cpu = ""

                    # Show on screen
                    print(f"[!] PID {pid} | {pname} | user: {user}")
                    print(f"    exe: {exe}")
                    print(f"    cmd: {cmd}")
                    print(f"    cpu: {cpu}")
                    print(f"    reasons: {', '.join(reasons)}")

                    # Prepare CSV row (reasons joined by semicolon for single cell)
                    csv_row = [
                        scan_time,
                        pid,
                        pname,
                        user,
                        exe,
                        cmd,
                        cpu,
                        f"{mem:.1f}" if isinstance(mem, float) else mem,
                        "; ".join(reasons)
                    ]

                    append_to_csv(csv_file, csv_row)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # process disappeared or cannot be read; skip
                    continue

            time.sleep(scan_interval)
    except KeyboardInterrupt:
        print("\nStopping monitor (user requested).")

if __name__ == "__main__":
    main()    