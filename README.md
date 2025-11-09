# dude — HTB / lab auto-recon helper

`dude` is a small, practical reconnaissance helper designed for Hack The Box / lab environments.  
It automates quick HTTP checks, optional directory enumeration with `gobuster`, and an optimized `nmap` scan (with `-sV -sC`) so you can get useful findings fast.

> ⚠️ **Important:** This tool is intended for authorized lab and penetration testing practice only (HTB, TryHackMe, permitted engagements). Do **not** run it against systems you do not own or have permission to test.

---

## Features

- Fast nmap scan with sensible defaults (`-n -T4 -Pn`, default `--top-ports 1000`).
- Always runs `-sV` (service/version detection) and `-sC` (default NSE scripts) to gather useful service info.
- Detects HTTP redirects from `http://<ip>` and automatically appends `<ip>  <hostname>` to `/etc/hosts` (via `sudo tee -a`) if a redirect hostname is found.
- If port 80 is open, optionally runs `gobuster` directory enumeration.
- Accepts a custom `gobuster` wordlist via `--gobuster-wordlist`.
- Graceful fallbacks if tools (`gobuster`, etc.) are missing.

---

## Usage

# Basic usage (default: top 1000 popular ports, -sV -sC always enabled):
python3 dude.py -t 10.10.11.93

# Scan all ports (equivalent to -p -):
python3 dude.py -t 10.10.11.93 --all

# Use a custom gobuster wordlist:
python3 dude.py -t 10.10.11.93 --gobuster-wordlist /path/to/wordlist.txt
