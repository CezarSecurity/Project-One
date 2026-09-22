# Project One — Multi-Service Honeypot

A honeypot that simulates an SSH server and a router admin login page, captures attacker behavior, and maps it to MITRE ATT&CK techniques. Built from scratch in Python to learn how honeypots, protocol emulation, and basic intrusion detection actually work.

## What It Does

- Simulates an SSH server (fake shell, ~10 commands, session logging)
- Simulates an HTTP router admin login page (TP-Link Archer C7)
- Captures every connection, login attempt, and command typed
- Stores events as both JSON Lines (raw audit log) and SQLite (queryable)
- Detects brute force, recon, and credential-access patterns
- Maps detections to MITRE ATT&CK technique IDs

## Architecture

Attackers connect over SSH (port 2222) or HTTP (port 8080). Both honeypot services write every event through a shared storage module into a JSON Lines log and a SQLite database. A separate detection script reads the database afterward and flags suspicious patterns, mapped to MITRE ATT&CK technique IDs.

```
SSH client (2222)
      |
      v
ssh_honeypot.py -----+
                      |
Browser (8080)        |
      |                |
      v                v
http_honeypot.py --> storage.py
                      |
        +-------------+-------------+
        |                           |
        v                           v
  logs/events.jsonl           logs/events.db
                                     |
                                     v
                               detect.py
                                     |
                                     v
                         MITRE ATT&CK alerts
```

## Quick Start

```bash
git clone <your-repo-url>
cd "Project One"
python3 -m venv .venv
source .venv/bin/activate
pip install asyncssh aiohttp
ssh-keygen -t ed25519 -f ssh_host_key -N ""
python ssh_honeypot.py     # in one terminal
python http_honeypot.py    # in another
```

SSH honeypot: `ssh -p 2222 <any-username>@127.0.0.1` (any password is accepted)
HTTP honeypot: open `http://127.0.0.1:8080`

Both are bound to `127.0.0.1` only, not exposed to the network.

## Services

| Service | Port | Protocol | Notes |
|---|---|---|---|
| SSH | 2222 | asyncssh | Fake shell, always accepts login, logs credentials + commands |
| HTTP | 8080 | aiohttp | Fake TP-Link router login page, always rejects, logs credentials |

## MITRE ATT&CK Coverage

| Technique | Name | Detection Logic |
|---|---|---|
| T1110 | Brute Force | 5+ login attempts from one IP against one service within 60 seconds |
| T1082 | System Information Discovery | 2+ of: `whoami`, `uname -a`, `id`, `ps aux` run in a session |
| T1552.001 | Unsecured Credentials: Credentials In Files | `cat /etc/passwd` run in a session |

## Detection Example

Run `python detect.py` after capturing some traffic:

```
[T1110 Brute Force] 127.0.0.1: 5 attempts in 0.01s on port 2222
[T1110 Brute Force] 127.0.0.1: 5 attempts in 0.01s on port 8080
[T1082 System Information Discovery] 127.0.0.1: whoami, uname -a, id
[T1552.001 Unsecured Credentials: Credentials In Files] 127.0.0.1
```

## Attack Testing

The honeypot was tested against itself using standard offensive tools, purely on localhost.

**Hydra (brute force, both services):** 15 credential pairs tried against SSH, 15 against the HTTP login form, all captured and correctly flagged as T1110.

**nmap (service fingerprinting):**

```
PORT     STATE SERVICE VERSION
2222/tcp open  ssh     AsyncSSH sshd 2.24.0 (protocol 2.0)
8080/tcp open  http    aiohttp 3.14.3 (Python 3.14)
```

nmap correctly identified both services as non-standard (AsyncSSH and aiohttp rather than OpenSSH/nginx), since the underlying libraries announce themselves honestly in their protocol banners. The HTTP `Server` header was overridden to `nginx` to reduce this fingerprint. The fake page content itself (`TP-Link Archer C7 - Login`) was successfully extracted by nmap's `http-title` script, confirming the deception layer works even where the transport layer doesn't fully hide the stack.

## Known Limitations

- Python 3.14 on macOS raises a non-fatal `SO_KEEPALIVE` socket error on every new connection (both asyncssh and aiohttp). Connections and logging still work correctly; this appears to be an upstream compatibility issue with a very recent Python release.
- The fake shell supports a fixed set of commands; anything else returns `command not found`, there's no real filesystem behind it.
- Detection thresholds (5 attempts / 60s) were tuned for quick manual testing, not production traffic.

## Tech Stack

Python 3.14, asyncio, asyncssh, aiohttp, SQLite

## License

MIT
