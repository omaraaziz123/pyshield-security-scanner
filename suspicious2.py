import psutil
import subprocess
import os
import glob
import winreg
from datetime import datetime
from tqdm import tqdm
import tkinter as tk
from tkinter import scrolledtext

suspicious_keywords = ["temp", "appdata", "roaming", "unknown", "malware", "virus"]
trusted_names = [
    "avg", "avast", "nvt", "osarmor", "msedge", "onedrive", "defender", "windows defender",
    "wsc_proxy", "avsEngSrv", "avswiagent", "avfwServ", "glasswire", "prtg", "spyshelter"
]

def is_signed(exe_path):
    try:
        result = subprocess.run(['sigcheck.exe', '-nobanner', '-q', exe_path],
                                capture_output=True, text=True)
        return 'Verified' in result.stdout or 'Signed' in result.stdout
    except:
        return False

def get_suspicious_processes():
    results = []
    procs = list(psutil.process_iter(['pid', 'name', 'memory_percent', 'exe']))
    for proc in tqdm(procs, desc="🔍 Scanning processes"):
        try:
            name = proc.info['name'].lower()
            path = (proc.info['exe'] or "").lower()
            mem = proc.info['memory_percent']
            is_trusted = any(t in name for t in trusted_names)
            is_malicious = any(k in path for k in suspicious_keywords) or mem > 5
            if is_malicious and not is_trusted and not is_signed(path):
                results.append(f"Suspicious process:\n{proc.info['pid']} - {name} - {mem:.2f}% - {path}")
        except:
            continue
    return results

def get_suspicious_network_connections():
    results = []
    conns = list(psutil.net_connections(kind='inet'))
    for conn in tqdm(conns, desc="🌐 Scanning network"):
        try:
            raddr = conn.raddr
            pid = conn.pid
            if raddr and conn.status == 'ESTABLISHED' and pid:
                ip = raddr.ip
                if ip.startswith("127.") or ip.startswith("192.168."):
                    continue
                proc = psutil.Process(pid)
                name = proc.name().lower()
                path = proc.exe() if proc.exe() else "N/A"
                if not any(t in name for t in trusted_names):
                    results.append(f"External connection:\n{pid} - {name} - {ip}:{raddr.port} - {path}")
        except:
            continue
    return results

def scan_temp_files():
    results = []
    temp_dirs = [os.getenv("TEMP"), os.getenv("APPDATA"), os.getenv("LOCALAPPDATA")]
    for folder in temp_dirs:
        if not folder:
            continue
        files = glob.glob(os.path.join(folder, "**", "*.exe"), recursive=True)
        for file_path in tqdm(files, desc="📁 Scanning temp files"):
            try:
                if not is_signed(file_path):
                    results.append(f"Unsigned temp file:\n{file_path}")
            except:
                continue
    return results

def scan_startup_entries():
    entries = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    for hive, path in keys:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in tqdm(range(winreg.QueryInfoKey(key)[1]), desc="🪪 Registry startup"):
                    name, val, _ = winreg.EnumValue(key, i)
                    exe_path = val.strip('"')
                    if os.path.exists(exe_path) and not is_signed(exe_path):
                        entries.append(f"Startup registry entry:\n{name} - {exe_path}")
        except:
            continue
    startup_dirs = [
        os.path.join(os.getenv("ProgramData"), r"Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        os.path.join(os.getenv("APPDATA"), r"Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    ]
    for folder in startup_dirs:
        if not folder:
            continue
        files = glob.glob(os.path.join(folder, "*.exe"))
        for file_path in tqdm(files, desc="🗂️ Startup folders"):
            if not is_signed(file_path):
                entries.append(f"Startup folder file:\n{file_path}")
    return entries

def show_results(results):
    root = tk.Tk()
    root.title("Security Scan Result")
    root.geometry("780x600")
    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
    text_area.pack(fill=tk.BOTH, expand=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if results:
        text_area.insert(tk.END, f"⚠ Suspicious items: {len(results)}\nScan time: {timestamp}\n\n" + "\n\n".join(results))
    else:
        text_area.insert(tk.END, f"✅ Scan completed: {timestamp}\n\nNo suspicious activity detected.")
    root.mainloop()

def run_scan_with_progress():
    steps = 4
    overall = tqdm(total=steps, desc="🔄 Overall Scan Progress", position=0)

    results = []
    overall.set_description("🔍 Scanning processes")
    results += get_suspicious_processes()
    overall.update(1)

    overall.set_description("🌐 Scanning network")
    results += get_suspicious_network_connections()
    overall.update(1)

    overall.set_description("📁 Scanning temp files")
    results += scan_temp_files()
    overall.update(1)

    overall.set_description("🪪 Scanning startup entries")
    results += scan_startup_entries()
    overall.update(1)

    overall.set_description("✅ Scan complete")
    show_results(results)

if __name__ == "__main__":
    run_scan_with_progress()
