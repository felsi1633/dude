#!/usr/bin/env python3
"""
dude.py — HTB scan helper

Usage examples (quick reference):

# 1️⃣ Basic scan (top 1000 TCP ports, includes -sC and -sV automatically)
python3 dude.py -t 10.10.11.93

# 2️⃣ Scan all ports
python3 dude.py -t 10.10.11.93 --all

# 3️⃣ Use a custom gobuster wordlist
python3 dude.py -t 10.10.11.93 --gobuster-wordlist /path/to/wordlist.txt

# Notes:
# - If port 80 is open and the server redirects (e.g., to http://nanocorp.htb/),
#   the script automatically adds "10.10.x.x  nanocorp.htb" to /etc/hosts.
# - Gobuster runs automatically when port 80 is open.
# - -sC and -sV are included in every nmap scan by default.
# - For authorized penetration testing (HTB or lab only).
"""

import argparse
import subprocess
import requests
from urllib.parse import urlparse
import re
import sys
import shutil
import socket
import os

def run_command(cmd):
    """Run a command, print it and show stdout/stderr."""
    print(f"[*] running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return result.stdout
    except Exception as e:
        print(f"[!] Error running command: {e}", file=sys.stderr)
        return ""

def detect_and_append_hostname(ip):
    """
    Perform a GET to http://<ip> (no redirects followed).
    If Location header has a hostname, add it to /etc/hosts via sudo tee.
    Returns (hostname_or_None, info_string).
    """
    url = f"http://{ip}"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
    except Exception as e:
        return None, f"no-hostname; info=http-error: {e}"

    loc = resp.headers.get("Location")
    if not loc:
        return None, f"no-redirect; status={getattr(resp, 'status_code', 'n/a')}"

    parsed = urlparse(loc)
    hostname = parsed.hostname
    if hostname and re.match(r"^[a-zA-Z0-9.-]+$", hostname):
        line = f"{ip}  {hostname}"
        try:
            # Avoid duplicate entry
            try:
                with open("/etc/hosts", "r", encoding="utf-8", errors="ignore") as f:
                    if line in f.read():
                        return hostname, f"already-present; loc={loc}; status={resp.status_code}"
            except Exception:
                pass

            echo_cmd = f'echo "{line}" | sudo tee -a /etc/hosts'
            print(f"[*] Appending to /etc/hosts: {line} (may prompt for sudo password)")
            subprocess.run(echo_cmd, shell=True)
            return hostname, f"appended; loc={loc}; status={resp.status_code}"
        except Exception as e:
            return None, f"append-failed: {e}"
    else:
        return None, f"no-hostname-in-location; loc={loc}; status={resp.status_code}"

def run_gobuster_dir(host, wordlist):
    """Run gobuster dir if installed and wordlist exists."""
    gob = shutil.which("gobuster")
    if not gob:
        print("[*] gobuster not installed or not in PATH; skipping gobuster dir.")
        return
    if not wordlist or not os.path.isfile(wordlist):
        print(f"[*] Wordlist {wordlist} not found; skipping gobuster.")
        return

    url = f"http://{host}/"
    cmd = [
        gob, "dir",
        "-u", url,
        "-w", wordlist,
        "-t", "50",
        "-x", "php,asp,aspx,html,txt"
    ]
    print(f"[*] Running gobuster: {' '.join(cmd)}")
    run_command(cmd)

def build_nmap_cmd(ip, scan_all):
    """Build the nmap command list."""
    nmap_bin = shutil.which("nmap") or "/usr/bin/nmap"
    if scan_all:
        return [nmap_bin, "-n", "-T4", "-sT", "-Pn", "-p-", "-sC", "-sV", ip]
    else:
        return [nmap_bin, "-n", "-T4", "-sT", "-Pn", "--top-ports", "1000", "-sC", "-sV", ip]

def parse_args():
    p = argparse.ArgumentParser(description="dude.py — HTB scan helper")
    p.add_argument("-t", "--target", required=True, help="Target IP")
    p.add_argument("--all", action="store_true", help="Scan all ports (-p-)")
    p.add_argument("--gobuster-wordlist", help="Custom gobuster wordlist path")
    return p.parse_args()

def main():
    args = parse_args()
    ip = args.target
    wordlist = args.gobuster_wordlist or "/usr/share/wordlists/dirb/common.txt"

    print(f"[*] Checking HTTP redirection for hostname on {ip} ...")
    hostname, info = detect_and_append_hostname(ip)
    print(f"[*] HTTP check result: {info}")

    # Check if port 80 is open
    try:
        sock = socket.create_connection((ip, 80), timeout=2)
        sock.close()
        port80_open = True
    except Exception:
        port80_open = False

    if port80_open:
        print(f"[*] Port 80 open on {ip}; running gobuster against {hostname or ip}")
        run_gobuster_dir(hostname or ip, wordlist)
    else:
        print("[*] Port 80 closed; skipping gobuster.")

    # Run nmap
    print("[*] Starting nmap scan...")
    cmd = build_nmap_cmd(ip, args.all)
    run_command(cmd)

if __name__ == "__main__":
    main()
