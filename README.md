## 🐧 linrecon — Linux Recon & Security Inventory

**linrecon** is a Linux reconnaissance, inventory, and security assessment script designed for security audits, incident response, and post-compromise analysis.

It collects system, network, user, service, and security posture data, correlates it with lightweight heuristics, and produces clean, evidence-backed reports in both TXT and HTML formats.

## ✨ Key Features

🔍 Comprehensive Linux reconnaissance

📊 Automated security findings with severity levels

🧾 HTML & TXT reports with indexed evidence

⚙️ Non-intrusive & read-only data collection

🧠 Practical heuristics (no guessing, evidence-based)

📦 Automatic report packaging (ZIP / TAR.GZ)

## 🧠 What linrecon Collects

🖥️ System & Hardware

OS release, kernel, uptime

CPU, memory, disks, mounts

Virtualization/container detection

BIOS & DMI info (when available)

🌐 Networking

Interfaces, routes, rules

Listening TCP/UDP ports

DNS configuration

NetworkManager / Netplan / ifcfg (where applicable)

👥 Users & Access

Users, groups, sudoers

Login history (last, who)

SSH configuration & effective settings

⚙️ Services & Jobs

systemd services, timers, failed units

Cron jobs (system & user)

🔐 Security Posture

SSH hardening checks

Firewall status (ufw / firewalld / nftables / iptables)

SELinux / AppArmor status

SUID binaries

World-writable directories

🧰 Living off the Land (LotL)

Detection of common dual-use tools:

nc, socat, nmap, gcc, python, curl, wget, etc.

📦 Software Inventory

Installed packages (apt / yum / dnf)

Pending updates (heuristic-based)

Snap, Flatpak, Pip (if present)

🚨 Automated Findings Engine

linrecon includes built-in heuristics that generate findings with:
**
🔴 HIGH

🟠 MEDIUM

🟢 OK

🔵 INFO**

Each finding:

Is evidence-backed

Links directly to the relevant report section

Avoids assumptions when data is incomplete

Example findings:

SSH PasswordAuthentication enabled

Root SSH login allowed

SSH exposed on all interfaces

Firewall inactive or unclear

Pending system updates

Presence of SUID binaries

LotL tools detected

## 📄 Output Structure
```
linrecon_<host>_<timestamp>/
├── report.txt        # Full textual report
├── report.html       # Interactive HTML report
├── errors.txt        # Non-fatal command errors
└── data/
    ├── 00_os_release.txt
    ├── 44_listening_tcp_udp.txt
    ├── 88_sshd_effective.txt
    ├── 140_lotl_inventory.txt
    └── ...
```

## 📦 Automatically packaged as:

.zip (preferred)

.tar.gz (fallback)

## 🚀 Usage

```
chmod +x linrecon.sh
./linrecon.sh
```

**Optional output directory:**

```
./linrecon.sh /path/to/output_dir
```

## 🔑 Privileges

Automatically re-executes with sudo if not run as root

Preserves original user ownership and permissions

## 🛡️ Design Principles

✅ Read-only, safe by default

❌ No exploitation

❌ No network scanning

❌ No configuration changes

📎 Evidence-first reporting

📖 Audit-friendly output

🧪 Intended Use Cases

🔐 Security assessments

🚑 Incident response

🧰 Blue team investigations

🕵️ Post-exploitation enumeration

📋 Compliance & hardening reviews

## 📌 Versioning

Current version: 1.0.5

See script header for full changelog.

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing and system auditing**.

Run it **only on systems you own** or where you have **explicit permission** to perform an assessment.
