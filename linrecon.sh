#!/usr/bin/env bash
# ============================================================
# linrecon - Linux Recon & Security Inventory
#
# Version: 1.0.5
# Author: Nesphaar
#
# Changelog:
# 1.0.5
# - Add New Findings and Heuristics
#
# 1.0.4
# - Add section 13x - Environment & Permissions (Hardening)
# - Add section 14x - Living off the Land (LotL) / Post-Exploitation tools
# - Add CSS to Findings HTML
#
# 1.0.3
# - Add "Automated Findings" section to HTML (severity + evidence links)
# - Add optional sshd effective config capture via "sshd -T" when available
#
# 1.0.2
# - Add "Execution Summary" block at the top of the HTML report (timing, error count, archive)
# - Move packaging step before HTML generation so the archive path is included in the summary
#
# 1.0.1
# - Translated all script comments to English (no functional changes)
#
# 1.0.0
# - First stable release for Security Assessment usage
# - Auto-elevation using sudo if not executed as root
# - Preserve original executing user and restore ownership/perms at the end
# - Visible progress percentage (single-line overwrite)
# - Generates report.txt + report.html + data/*.txt evidence per section
# - Logs command failures (non-zero RC) to errors.txt without aborting
# - Automatic packaging: zip (preferred) or tar.gz (fallback)
# ============================================================

set -Eeuo pipefail
shopt -s nullglob

VERSION="1.0.5"
PROG="linrecon"

# ------------------------------------------------------------
# Original user detection (before sudo)
# - If launched via sudo, SUDO_USER is the real user
# - Otherwise, current user is the original user
# ------------------------------------------------------------
ORIG_USER="${SUDO_USER:-$(id -un)}"
ORIG_GROUP="$(id -gn "$ORIG_USER" 2>/dev/null || echo "$ORIG_USER")"

# ------------------------------------------------------------
# Auto-elevation with sudo
# - Re-exec the script with sudo if not running as root
# - Preserve original user/group so we can restore ownership later
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "[INFO] Superuser privileges are required for a full assessment."
  echo "[INFO] Requesting sudo..."
  export ORIG_USER ORIG_GROUP
  exec sudo -E bash "$0" "$@"
fi

TS="$(date +%Y%m%d_%H%M%S)"
HOST="$(hostname -f 2>/dev/null || hostname)"
OUTDIR="${1:-./${PROG}_${HOST}_${TS}}"
DATADIR="$OUTDIR/data"
HTML="$OUTDIR/report.html"
TXT="$OUTDIR/report.txt"
ERRORS="$OUTDIR/errors.txt"

# ------------------------------------------------------------
# Execution timing (used for HTML summary)
# ------------------------------------------------------------
START_EPOCH="$(date +%s)"
START_HUMAN="$(date +%F' '%T)"

# Secure default permissions for created artifacts
umask 077
mkdir -p "$DATADIR"

# ------------------------------------------------------------
# Progress (single-line overwrite)
# IMPORTANT: TOTAL_STEPS must match the number of progress() calls
# ------------------------------------------------------------
TOTAL_STEPS=16
CURRENT_STEP=0

progress(){
  local msg="$1"
  CURRENT_STEP=$((CURRENT_STEP + 1))
  local percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  printf "\r[%3s%%] %s" "$percent" "$msg" >&2
}

progress_done(){
  printf "\n" >&2
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

safe_cat(){
  local p="$1"
  if [ -r "$p" ]; then
    cat "$p"
  else
    echo "NOACCESS: $p"
  fi
}

# Log only to report.txt to avoid breaking the progress line
log(){ echo "[$(date +%F' '%T)] $*" >> "$TXT"; }

# Run a command, capture stdout/stderr into data/<name>.txt
# If the command exits non-zero, record it in errors.txt (but continue)
run(){
  local name="$1"; shift
  local f="$DATADIR/${name}.txt"
  local rc=0
  local cmdline=""
  if [ "$#" -gt 0 ]; then cmdline="$(printf "%q " "$@")"; fi
  {
    echo "### $name"
    if [ -n "$cmdline" ]; then echo "\$ $cmdline"; fi
    echo
    "$@" 2>&1 || rc=$?
    echo
  } > "$f"
  if [ "$rc" -ne 0 ]; then
    echo "[$(date +%F' '%T)] ERROR ($rc) in $name: $cmdline" >> "$ERRORS"
  fi
}

# Run a bash snippet, capture output into data/<name>.txt
# If it exits non-zero, record it in errors.txt (but continue)
run_shell(){
  local name="$1"; shift
  local snippet="$1"
  local f="$DATADIR/${name}.txt"
  local rc=0
  export -f safe_cat
  {
    echo "### $name"
    echo "\$ bash -lc (snippet)"
    echo
    bash -lc "$snippet" 2>&1 || rc=$?
    echo
  } > "$f"
  if [ "$rc" -ne 0 ]; then
    echo "[$(date +%F' '%T)] ERROR ($rc) in $name (snippet)" >> "$ERRORS"
  fi
}

# ------------------------------------------------------------
# OS / package manager detection
# ------------------------------------------------------------
detect_os(){
  OS_ID="unknown"
  OS_NAME="unknown"
  OS_VER="unknown"
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_NAME="${NAME:-unknown}"
    OS_VER="${VERSION_ID:-unknown}"
  fi

  FAMILY="unknown"
  PKG="unknown"
  if cmd_exists apt-get; then
    FAMILY="debian"
    PKG="apt"
  elif cmd_exists dnf; then
    FAMILY="rhel"
    PKG="dnf"
  elif cmd_exists yum; then
    FAMILY="rhel"
    PKG="yum"
  fi
}

detect_os

# ------------------------------------------------------------
# report.txt and errors.txt headers
# ------------------------------------------------------------
echo "==== $PROG report ($TS) ====" > "$TXT"
echo "Version: $VERSION" >> "$TXT"
echo "Host: $HOST" >> "$TXT"
echo "OS: $OS_NAME ($OS_ID) $OS_VER" >> "$TXT"
echo "Family: $FAMILY  PackageMgr: $PKG" >> "$TXT"
echo "User (orig): $ORIG_USER  Group (orig): $ORIG_GROUP" >> "$TXT"
echo "User (effective): $(id -un 2>/dev/null || true)  UID: $(id -u 2>/dev/null || true)" >> "$TXT"
echo "Out: $OUTDIR" >> "$TXT"
echo >> "$TXT"

echo "==== $PROG errors ($TS) ====" > "$ERRORS"
echo "Version: $VERSION" >> "$ERRORS"
echo "Host: $HOST" >> "$ERRORS"
echo >> "$ERRORS"

# ------------------------------------------------------------
# 0x - Base system
# ------------------------------------------------------------
progress "Collecting base system info"
log "Collecting base system info..."

run_shell "00_os_release" 'safe_cat /etc/os-release'
run "01_uname" uname -a
run "02_uptime" uptime
run_shell "03_date_locale" 'date; echo; locale 2>/dev/null || true'
if cmd_exists lsb_release; then run "04_lsb_release" lsb_release -a; fi
if cmd_exists hostnamectl; then run "05_hostnamectl" hostnamectl; fi
if cmd_exists timedatectl; then run "06_timedatectl" timedatectl; fi

# ------------------------------------------------------------
# 1x - Hardware and storage
# ------------------------------------------------------------
progress "Collecting hardware and storage info"
log "Collecting hardware and storage info..."

run_shell "10_cpu" 'lscpu 2>/dev/null || safe_cat /proc/cpuinfo'
run_shell "11_mem" 'free -h 2>/dev/null || safe_cat /proc/meminfo'
run_shell "12_load" 'cat /proc/loadavg 2>/dev/null || true'
if cmd_exists lsblk; then run "13_lsblk" lsblk -a -o NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINTS,MODEL,SERIAL,ROTA; fi
if cmd_exists blkid; then run "14_blkid" blkid; fi
run "15_df" df -hT
run "16_mount" mount
run_shell "17_fstab" 'safe_cat /etc/fstab'
if cmd_exists lspci; then run "18_lspci" lspci -nn; fi
if cmd_exists lsusb; then run "19_lsusb" lsusb; fi

if cmd_exists dmidecode; then
  run "20_dmidecode" dmidecode -t system -t baseboard -t bios -t chassis
else
  run_shell "20_dmidecode" 'echo "TIP: install dmidecode for DMI inventory (serial/model/BIOS)."'
fi

# ------------------------------------------------------------
# 3x - Kernel and tuning
# ------------------------------------------------------------
progress "Collecting kernel/modules/sysctl"
log "Collecting kernel/modules/sysctl..."

run_shell "30_kernel_cmdline" 'safe_cat /proc/cmdline'
if cmd_exists sysctl; then run "31_sysctl_all" sysctl -a; fi
if cmd_exists lsmod; then run "32_lsmod" lsmod; fi
if cmd_exists modinfo; then run_shell "33_modinfo_netfilter" 'modinfo nf_tables 2>/dev/null || true; modinfo ip_tables 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 4x - Networking
# ------------------------------------------------------------
progress "Collecting network/DNS/ports"
log "Collecting network/DNS/ports..."

if cmd_exists ip; then
  run "40_ip_addr" ip -details addr
  run "41_ip_link" ip -details link
  run "42_ip_route" ip -details route
  run "43_ip_rule" ip rule show
fi

if cmd_exists ss; then
  run "44_listening_tcp_udp" ss -tulpen
else
  run_shell "44_listening_tcp_udp" 'netstat -tulpen 2>/dev/null || true'
fi

run_shell "45_resolv_conf" 'safe_cat /etc/resolv.conf'
run_shell "46_hosts" 'safe_cat /etc/hosts'
if cmd_exists resolvectl; then run "47_resolvectl" resolvectl status; fi
if cmd_exists nmcli; then run_shell "48_nmcli" 'nmcli -f all general,device,connection show 2>/dev/null || true'; fi

if [ -d /etc/netplan ]; then
  run_shell "49_netplan" 'ls -la /etc/netplan 2>/dev/null || true; echo; for f in /etc/netplan/*.yaml; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done'
fi

if [ -d /etc/sysconfig/network-scripts ]; then
  run_shell "49_ifcfg" 'ls -la /etc/sysconfig/network-scripts 2>/dev/null || true; echo; for f in /etc/sysconfig/network-scripts/ifcfg-*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done'
fi

# ------------------------------------------------------------
# 6x - Users and access
# ------------------------------------------------------------
progress "Collecting users/groups/sudo"
log "Collecting users/groups/sudo..."

run_shell "60_passwd" 'safe_cat /etc/passwd'
run_shell "61_group" 'safe_cat /etc/group'
run_shell "62_shadow_hint" 'if [ -r /etc/shadow ]; then echo "OK: /etc/shadow is readable (root)"; else echo "NOACCESS: /etc/shadow (non-root)"; fi'
run_shell "63_sudoers" 'safe_cat /etc/sudoers; echo; if [ -d /etc/sudoers.d ]; then ls -la /etc/sudoers.d; echo; for f in /etc/sudoers.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done; fi'
if cmd_exists last; then run "64_last" last -a -n 50; fi
if cmd_exists lastlog; then run_shell "65_lastlog" 'lastlog 2>/dev/null || true'; fi
if cmd_exists who; then run "66_who" who -a; fi

# ------------------------------------------------------------
# 7x - Services and jobs
# ------------------------------------------------------------
progress "Collecting services/timers/cron"
log "Collecting services/timers/cron..."

if cmd_exists systemctl; then
  run "70_systemd_units" systemctl list-units --all --no-pager
  run "71_systemd_services" systemctl list-unit-files --type=service --no-pager
  run "72_systemd_timers" systemctl list-timers --all --no-pager
  run "73_failed_units" systemctl --failed --no-pager
fi

run_shell "74_crontab_system" 'ls -la /etc/cron* 2>/dev/null || true; echo; for d in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do [ -d "$d" ] && echo "== $d ==" && ls -la "$d" && echo; done'
if cmd_exists crontab; then run_shell "75_crontab_user" 'crontab -l 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 8x - Security (SSH, firewall, MAC)
# ------------------------------------------------------------
progress "Collecting security (SSH/firewall/MAC)"
log "Collecting security (SSH/firewall/MAC)..."

run_shell "80_sshd_config" 'safe_cat /etc/ssh/sshd_config; echo; if [ -d /etc/ssh/sshd_config.d ]; then ls -la /etc/ssh/sshd_config.d; echo; for f in /etc/ssh/sshd_config.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done; fi'

# Optional: capture effective sshd config (best for automated findings)
if cmd_exists sshd; then
  run_shell "88_sshd_effective" 'sshd -T 2>/dev/null || true'
fi

if cmd_exists ssh-keygen; then run_shell "81_ssh_hostkeys_fpr" 'for k in /etc/ssh/ssh_host_*_key.pub; do [ -e "$k" ] && echo "$k" && ssh-keygen -lf "$k" && echo; done'; fi

if cmd_exists ufw; then run_shell "82_ufw" 'ufw status verbose 2>&1 || true'; fi
if cmd_exists firewall-cmd; then run_shell "83_firewalld" 'firewall-cmd --state 2>/dev/null || true; echo; firewall-cmd --list-all 2>/dev/null || true; echo; firewall-cmd --list-all-zones 2>/dev/null || true'; fi
if cmd_exists nft; then run_shell "84_nft" 'nft list ruleset 2>&1 || true'; fi
if cmd_exists iptables; then run_shell "85_iptables" 'iptables -S 2>&1 || true; echo; iptables -L -n -v 2>&1 || true'; fi

if cmd_exists getenforce; then run_shell "86_selinux" 'getenforce; echo; sestatus 2>/dev/null || true'; fi
if cmd_exists aa-status; then run_shell "87_apparmor" 'aa-status 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 9x - Logs (when readable)
# ------------------------------------------------------------
progress "Collecting authentication logs"
log "Collecting authentication logs..."

if [ -r /var/log/auth.log ]; then run_shell "90_auth_log_tail" 'tail -n 200 /var/log/auth.log'; fi
if [ -r /var/log/secure ]; then run_shell "90_secure_log_tail" 'tail -n 200 /var/log/secure'; fi
if cmd_exists journalctl; then run_shell "91_journal_ssh" 'journalctl -n 300 --no-pager -u ssh 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 10x - Software inventory
# ------------------------------------------------------------
progress "Collecting software/repos/updates"
log "Collecting software/repos/updates..."

if [ "$PKG" = "apt" ]; then
  run_shell "100_apt_sources" 'ls -la /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true; echo; safe_cat /etc/apt/sources.list; echo; for f in /etc/apt/sources.list.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done'
  run_shell "101_pkgs_dpkg" 'dpkg-query -W -f="${binary:Package}\t${Version}\t${Architecture}\n" 2>/dev/null | sort'
  run_shell "102_apt_policy" 'apt-cache policy 2>/dev/null || true'
  run_shell "103_updates_sim" 'apt-get -s update 2>/dev/null || true; echo; apt-get -s upgrade 2>/dev/null || true'
elif [ "$PKG" = "dnf" ]; then
  run_shell "100_repos_dnf" 'dnf -q repolist all 2>/dev/null || true; echo; dnf config-manager --dump 2>/dev/null || true'
  run_shell "101_pkgs_rpm" 'rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort'
  run_shell "103_updates" 'dnf -q check-update 2>/dev/null || true'
elif [ "$PKG" = "yum" ]; then
  run_shell "100_repos_yum" 'yum repolist all 2>/dev/null || true'
  run_shell "101_pkgs_rpm" 'rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort'
  run_shell "103_updates" 'yum check-update 2>/dev/null || true'
else
  run_shell "100_pkgmgr" 'echo "No supported package manager detected (apt/dnf/yum)"'
fi

if cmd_exists snap; then run_shell "110_snap_list" 'snap list 2>/dev/null || true'; fi
if cmd_exists flatpak; then run_shell "111_flatpak_list" 'flatpak list 2>/dev/null || true'; fi
if cmd_exists pip; then run_shell "112_pip_freeze" 'pip freeze 2>/dev/null || true'; fi
if cmd_exists pip3; then run_shell "112_pip3_freeze" 'pip3 freeze 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 12x - Runtime state
# ------------------------------------------------------------
progress "Collecting runtime (processes/dmesg)"
log "Collecting runtime (processes/dmesg)..."

run_shell "120_ps" 'ps auxfww 2>/dev/null || ps -ef 2>/dev/null || true'
if cmd_exists top; then run_shell "121_top" 'top -b -n 1 2>/dev/null || true'; fi
if cmd_exists dmesg; then run_shell "122_dmesg_tail" 'dmesg -T 2>/dev/null | tail -n 200 || dmesg 2>/dev/null | tail -n 200 || true'; fi

# ------------------------------------------------------------
# 13x - Environment & Permissions (Hardening)
# ------------------------------------------------------------
progress "Checking virtualization & SUID"
log "Checking environment and permissions..."

# Detect virtualization or containerization
if cmd_exists systemd-detect-virt; then
  run "130_virt_type" systemd-detect-virt
else
  run_shell "130_virt_type" 'grep -iq docker /proc/1/cgroup && echo "docker" || echo "unknown/bare-metal"'
fi

# Find top SUID binaries (limited to 20 to keep report clean)
run_shell "131_suid_bins" 'find /usr/bin /usr/sbin -xdev -type f -perm -4000 2>/dev/null | head -n 20'

# Find world-writable directories (potential for persistence/temp storage)
run_shell "132_world_writable_dirs" 'find /tmp /var/tmp /dev/shm -xdev -type d -perm -0002 2>/dev/null'

# ------------------------------------------------------------
# 14x - Living off the Land (LotL) / Post-Exploitation tools
# ------------------------------------------------------------
progress "Identifying LotL binaries"
log "Checking for dual-use tools..."

lotl_tools=("nc" "netcat" "nmap" "socat" "python" "python3" "perl" "ruby" "gcc" "g++" "curl" "wget" "tcpdump" "wireshark" "tshark")
LOTL_OUT="$DATADIR/140_lotl_inventory.txt"
{
  echo "### 140_lotl_inventory"
  echo "# Common tools often used for pivoting or exfiltration"
  echo
  for tool in "${lotl_tools[@]}"; do
    if cmd_exists "$tool"; then
      echo "[FOUND] $tool: $(command -v "$tool")"
    fi
  done
} > "$LOTL_OUT"

# ------------------------------------------------------------
# Final packaging (zip preferred, tar.gz fallback)
# NOTE: kept before HTML generation so the archive path is included in the HTML summary
# ------------------------------------------------------------
progress "Packaging results (zip or tar.gz)"
log "Packaging results..."

PARENT_DIR="$(cd "$(dirname "$OUTDIR")" && pwd)"
BASE_DIR="$(basename "$OUTDIR")"

ARCHIVE_ZIP="${PARENT_DIR}/${BASE_DIR}.zip"
ARCHIVE_TGZ="${PARENT_DIR}/${BASE_DIR}.tar.gz"

rm -f "$ARCHIVE_ZIP" "$ARCHIVE_TGZ" 2>/dev/null || true

ARCHIVE_FINAL=""
if cmd_exists zip; then
  run_shell "200_archive_zip" "cd \"${PARENT_DIR}\" && zip -r -q \"${ARCHIVE_ZIP}\" \"${BASE_DIR}\" && echo \"OK: ${ARCHIVE_ZIP}\""
  ARCHIVE_FINAL="$ARCHIVE_ZIP"
elif cmd_exists tar; then
  run_shell "200_archive_tgz" "cd \"${PARENT_DIR}\" && tar -czf \"${ARCHIVE_TGZ}\" \"${BASE_DIR}\" && echo \"OK: ${ARCHIVE_TGZ}\""
  ARCHIVE_FINAL="$ARCHIVE_TGZ"
else
  run_shell "200_archive_none" 'echo "WARNING: zip and tar not found. No archive generated."'
fi

# ------------------------------------------------------------
# Compute summary stats for the HTML header
# - Duration includes collection + packaging (up to HTML generation)
# ------------------------------------------------------------
END_EPOCH="$(date +%s)"
END_HUMAN="$(date +%F' '%T)"
DURATION_SEC="$((END_EPOCH - START_EPOCH))"

ERR_COUNT="0"
if [ -f "$ERRORS" ]; then
  ERR_COUNT="$(grep -c "ERROR (" "$ERRORS" 2>/dev/null || echo 0)"
fi

# ------------------------------------------------------------
# Automated Findings (simple, evidence-based heuristics)
# - No guesses: if we cannot determine, mark as UNKNOWN
# - Evidence links point to sections in the HTML
# ------------------------------------------------------------
FINDINGS_HTML=""

# Update this function to handle colors via CSS classes
add_finding(){
  local sev="$1"
  local title="$2"
  local detail="$3"
  local evidence="$4"
  # Clean concatenation
  FINDINGS_HTML+="<tr><td><b class='sev-${sev}'>${sev}</b></td><td>${title}</td><td>${detail}</td><td>${evidence}</td></tr>"
# FINDINGS_HTML+="${FINDINGS_HTML}<tr><td><b>${sev}</b></td><td>${title}</td><td>${detail}</td><td>${evidence}</td></tr>"
}

# Determine SSH effective config via sshd -T if available
SSH_EFF_FILE="$DATADIR/88_sshd_effective.txt"
SSH_PASSAUTH="UNKNOWN"
SSH_ROOTLOGIN="UNKNOWN"

if [ -s "$SSH_EFF_FILE" ]; then
  SSH_PASSAUTH="$(awk '$1=="passwordauthentication"{print $2; exit}' "$SSH_EFF_FILE" 2>/dev/null || echo UNKNOWN)"
  SSH_ROOTLOGIN="$(awk '$1=="permitrootlogin"{print $2; exit}' "$SSH_EFF_FILE" 2>/dev/null || echo UNKNOWN)"
fi

# SSH PasswordAuthentication
if [ "$SSH_PASSAUTH" = "yes" ]; then
  add_finding "HIGH" "SSH PasswordAuthentication enabled" "Consider disabling password logins and enforce key-based auth." "<a href=\"#88_sshd_effective\">evidence</a>"
elif [ "$SSH_PASSAUTH" = "no" ]; then
  add_finding "OK" "SSH PasswordAuthentication disabled" "Key-based auth likely enforced (good)." "<a href=\"#88_sshd_effective\">evidence</a>"
else
  add_finding "INFO" "SSH PasswordAuthentication unknown" "Could not determine effective SSH setting (sshd -T missing or unavailable)." "<a href=\"#80_sshd_config\">evidence</a>"
fi

# SSH PermitRootLogin
if [ "$SSH_ROOTLOGIN" = "yes" ]; then
  add_finding "HIGH" "SSH PermitRootLogin enabled" "Direct root SSH login is risky. Use sudo with named accounts." "<a href=\"#88_sshd_effective\">evidence</a>"
elif [ "$SSH_ROOTLOGIN" = "no" ]; then
  add_finding "OK" "SSH PermitRootLogin disabled" "Direct root SSH login not allowed (good)." "<a href=\"#88_sshd_effective\">evidence</a>"
elif [ "$SSH_ROOTLOGIN" = "prohibit-password" ] || [ "$SSH_ROOTLOGIN" = "without-password" ]; then
  add_finding "MEDIUM" "SSH PermitRootLogin allows keys" "Root login allowed via keys. Consider disabling entirely unless justified." "<a href=\"#88_sshd_effective\">evidence</a>"
else
  add_finding "INFO" "SSH PermitRootLogin unknown" "Could not determine effective SSH setting." "<a href=\"#80_sshd_config\">evidence</a>"
fi

# SSH exposure (0.0.0.0 or ::) on port 22
SS_FILE="$DATADIR/44_listening_tcp_udp.txt"
if [ -s "$SS_FILE" ]; then
  if grep -Eq 'LISTEN.+(0\.0\.0\.0:22|\[::\]:22|:::22)' "$SS_FILE"; then
    add_finding "MEDIUM" "SSH is listening on all interfaces (port 22)" "If external access is not required, bind to management network or restrict via firewall." "<a href=\"#44_listening_tcp_udp\">evidence</a>"
  else
    add_finding "INFO" "SSH exposure not clearly broad" "No direct match for 0.0.0.0:22 or ::22 in listener list." "<a href=\"#44_listening_tcp_udp\">evidence</a>"
  fi
else
  add_finding "INFO" "Listening ports unknown" "Could not parse listening ports output." "<a href=\"#44_listening_tcp_udp\">evidence</a>"
fi

# Firewall status (ufw or firewalld primary checks)
UFW_FILE="$DATADIR/82_ufw.txt"
FWD_FILE="$DATADIR/83_firewalld.txt"

FW_ACTIVE="UNKNOWN"
FW_EVID="#"

if [ -s "$UFW_FILE" ] && grep -qi 'Status:\s*active' "$UFW_FILE"; then
  FW_ACTIVE="yes"
  FW_EVID="<a href=\"#82_ufw\">evidence</a>"
elif [ -s "$UFW_FILE" ] && grep -qi 'Status:\s*inactive' "$UFW_FILE"; then
  FW_ACTIVE="no"
  FW_EVID="<a href=\"#82_ufw\">evidence</a>"
elif [ -s "$FWD_FILE" ] && head -n 3 "$FWD_FILE" | grep -qi 'running'; then
  FW_ACTIVE="yes"
  FW_EVID="<a href=\"#83_firewalld\">evidence</a>"
fi

if [ "$FW_ACTIVE" = "yes" ]; then
  add_finding "OK" "Firewall appears active" "A host firewall is enabled (good baseline)." "$FW_EVID"
elif [ "$FW_ACTIVE" = "no" ]; then
  add_finding "MEDIUM" "Firewall appears inactive" "Consider enabling a host firewall (ufw/firewalld/nftables) with least privilege rules." "$FW_EVID"
else
  add_finding "INFO" "Firewall status unclear" "No clear indication from ufw/firewalld outputs." "<a href=\"#82_ufw\">ufw</a> | <a href=\"#83_firewalld\">firewalld</a> | <a href=\"#84_nft\">nft</a> | <a href=\"#85_iptables\">iptables</a>"
fi

# SELinux / AppArmor status
SEL_FILE="$DATADIR/86_selinux.txt"
AA_FILE="$DATADIR/87_apparmor.txt"

if [ -s "$SEL_FILE" ]; then
  if head -n 1 "$SEL_FILE" | grep -qi 'Enforcing'; then
    add_finding "OK" "SELinux Enforcing" "SELinux is enforcing (good baseline for RHEL-like systems)." "<a href=\"#86_selinux\">evidence</a>"
  elif head -n 1 "$SEL_FILE" | grep -qi 'Permissive'; then
    add_finding "MEDIUM" "SELinux Permissive" "SELinux is permissive. Consider enforcing if feasible." "<a href=\"#86_selinux\">evidence</a>"
  else
    add_finding "MEDIUM" "SELinux not enforcing" "SELinux may be disabled or not enforcing." "<a href=\"#86_selinux\">evidence</a>"
  fi
else
  add_finding "INFO" "SELinux status not available" "SELinux tools not detected or not applicable." "<a href=\"#86_selinux\">evidence</a>"
fi

if [ -s "$AA_FILE" ]; then
  if grep -qi 'profiles are in enforce mode' "$AA_FILE"; then
    add_finding "OK" "AppArmor enforcing profiles" "AppArmor profiles are enforcing (good baseline for Debian/Ubuntu)." "<a href=\"#87_apparmor\">evidence</a>"
  else
    add_finding "MEDIUM" "AppArmor not clearly enforcing" "AppArmor output does not confirm enforce mode." "<a href=\"#87_apparmor\">evidence</a>"
  fi
else
  add_finding "INFO" "AppArmor status not available" "AppArmor tools not detected or not applicable." "<a href=\"#87_apparmor\">evidence</a>"
fi

# Pending updates heuristic
UPD_SEV="INFO"
UPD_TITLE="Updates status unclear"
UPD_DETAIL="Could not determine pending updates from collected outputs."
UPD_EVID=""

if [ "$PKG" = "apt" ]; then
  UPD_FILE="$DATADIR/103_updates_sim.txt"
  if [ -s "$UPD_FILE" ]; then
    line="$(grep -E '^[0-9]+ upgraded,' "$UPD_FILE" | tail -n 1 || true)"
    if [ -n "${line:-}" ]; then
      upgraded="$(echo "$line" | awk '{print $1}' 2>/dev/null || echo 0)"
      if [ "${upgraded:-0}" != "0" ]; then
        UPD_SEV="MEDIUM"
        UPD_TITLE="Pending package upgrades detected (apt simulation)"
        UPD_DETAIL="Simulated upgrade indicates packages to upgrade. Review patching policy and apply updates."
        UPD_EVID="<a href=\"#103_updates_sim\">evidence</a>"
      else
        UPD_SEV="OK"
        UPD_TITLE="No pending upgrades detected (apt simulation)"
        UPD_DETAIL="Simulated upgrade shows 0 upgraded."
        UPD_EVID="<a href=\"#103_updates_sim\">evidence</a>"
      fi
    else
      UPD_SEV="INFO"
      UPD_TITLE="Pending upgrades not clearly parsed (apt simulation)"
      UPD_DETAIL="Could not parse the typical 'X upgraded' line."
      UPD_EVID="<a href=\"#103_updates_sim\">evidence</a>"
    fi
  fi
elif [ "$PKG" = "dnf" ] || [ "$PKG" = "yum" ]; then
  UPD_FILE="$DATADIR/103_updates.txt"
  if [ -s "$UPD_FILE" ]; then
    if grep -Eqi '(^| )Obsoleting Packages|(^| )Security:|^[A-Za-z0-9_.+-]+[[:space:]]+[0-9]' "$UPD_FILE"; then
      UPD_SEV="MEDIUM"
      UPD_TITLE="Pending package updates detected"
      UPD_DETAIL="Package manager output indicates available updates. Review and patch per policy."
      UPD_EVID="<a href=\"#103_updates\">evidence</a>"
    else
      UPD_SEV="OK"
      UPD_TITLE="No pending updates clearly detected"
      UPD_DETAIL="No obvious update candidates found in output (heuristic)."
      UPD_EVID="<a href=\"#103_updates\">evidence</a>"
    fi
  fi
fi

# --- New Findings Heuristics ---

# SUID Logic
SUID_FILE="$DATADIR/131_suid_bins.txt"
if [ -s "$SUID_FILE" ]; then
  SUID_COUNT=$(wc -l < "$SUID_FILE")
  add_finding "MEDIUM" "SUID binaries detected" "Found ${SUID_COUNT} SUID binaries. Review for potential privilege escalation via GTFOBins." "<a href='#131_suid_bins'>evidence</a>"
fi

# LotL / Dual-use tools Logic
LOTL_FILE="$DATADIR/140_lotl_inventory.txt"
if grep -qiE "gcc|g\+\+|nc|socat|nmap" "$LOTL_FILE" 2>/dev/null; then
  add_finding "INFO" "Post-exploitation tools found" "Compilers or networking tools (nc/socat) are present. Useful for attackers to build or pivot." "<a href='#140_lotl_inventory'>evidence</a>"
fi

# World-Writable Check
WW_FILE="$DATADIR/132_world_writable_dirs.txt"
if [ -s "$WW_FILE" ]; then
  add_finding "INFO" "World-writable directories" "Common writable paths found. Ensure no sensitive data is stored here." "<a href='#132_world_writable_dirs'>evidence</a>"
fi

add_finding "$UPD_SEV" "$UPD_TITLE" "$UPD_DETAIL" "$UPD_EVID"

# ------------------------------------------------------------
# HTML report generation
# ------------------------------------------------------------
progress "Generating HTML report"
log "Generating HTML report..."

html_escape(){
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

{
  echo "<!doctype html>"
  echo "<html><head><meta charset=\"utf-8\">"
  echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
  echo "<title>${PROG} report - ${HOST} - ${TS}</title>"
# echo "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}h1{margin:0 0 8px 0}h2{margin-top:22px}pre{white-space:pre-wrap;background:#f6f8fa;border:1px solid #d0d7de;padding:12px;border-radius:8px}code{background:#f6f8fa;padding:2px 6px;border-radius:6px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d0d7de;padding:8px;text-align:left}th{background:#f6f8fa}</style>"
  echo "<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}
  h1{margin:0 0 8px 0}
  h2{margin-top:22px}
  pre{white-space:pre-wrap;background:#f6f8fa;border:1px solid #d0d7de;padding:12px;border-radius:8px}
  code{background:#f6f8fa;padding:2px 6px;border-radius:6px}
  table{border-collapse:collapse;width:100%}
  th,td{border:1px solid #d0d7de;padding:8px;text-align:left}
  th{background:#f6f8fa}
  /* Severity Colors */
  .sev-HIGH{background:#ffebe9;color:#cf222e;padding:2px 6px;border-radius:4px}
  .sev-MEDIUM{background:#fff8c5;color:#9a6700;padding:2px 6px;border-radius:4px}
  .sev-OK{background:#dafbe1;color:#1a7f37;padding:2px 6px;border-radius:4px}
  .sev-INFO{background:#ddf4ff;color:#0969da;padding:2px 6px;border-radius:4px}
  </style>"
  echo "</head><body>"
  echo "<h1>${PROG} - Inventory & Audit</h1>"

  echo "<h2>Execution Summary</h2>"
  echo "<pre>"
  echo "Tool: ${PROG} v${VERSION}"
  echo "Host: ${HOST}"
  echo "OS: ${OS_NAME} (${OS_ID}) ${OS_VER}"
  echo "Family: ${FAMILY} | Package manager: ${PKG}"
  echo "Original user: ${ORIG_USER}"
  echo "Effective user: $(id -un) (UID $(id -u))"
  echo "Start: ${START_HUMAN}"
  echo "End: ${END_HUMAN}"
  echo "Duration (sec): ${DURATION_SEC}"
  echo "Errors (count): ${ERR_COUNT}"
  echo "Output dir: ${OUTDIR}"
  echo "Archive: ${ARCHIVE_FINAL:-N/A}"
  echo "</pre>"

  echo "<h2>Automated Findings</h2>"
  echo "<table>"
  echo "<tr><th>Severity</th><th>Finding</th><th>Details</th><th>Evidence</th></tr>"
  if [ -n "$FINDINGS_HTML" ]; then
    echo "$FINDINGS_HTML"
  else
    echo "<tr><td><b>INFO</b></td><td>No findings generated</td><td>Heuristics did not produce output.</td><td>-</td></tr>"
  fi
  echo "</table>"

  echo "<p><b>Version:</b> ${VERSION}<br><b>Host:</b> ${HOST}<br><b>Timestamp:</b> ${TS}<br><b>OS:</b> ${OS_NAME} (${OS_ID}) ${OS_VER}<br><b>Family:</b> ${FAMILY} - <b>PkgMgr:</b> ${PKG}<br><b>Original user:</b> ${ORIG_USER}<br><b>Output:</b> ${OUTDIR}</p>"

  echo "<h2>Index</h2><ul>"
  for f in "$DATADIR"/*.txt; do
    b="$(basename "$f" .txt)"
    echo "<li><a href=\"#${b}\">${b}</a></li>"
  done
  echo "<li><a href=\"#errors\">errors.txt</a></li>"
  echo "</ul>"

  echo "<h2 id=\"errors\">errors.txt</h2>"
  echo "<pre>"
  html_escape < "$ERRORS"
  echo "</pre>"

  for f in "$DATADIR"/*.txt; do
    b="$(basename "$f" .txt)"
    echo "<h2 id=\"${b}\">${b}</h2>"
    echo "<pre>"
    html_escape < "$f"
    echo "</pre>"
  done

  echo "<hr><p>Generated by ${PROG} v${VERSION}.</p>"
  echo "</body></html>"
} > "$HTML"

# ------------------------------------------------------------
# Post-run: restore ownership/perms to the original user
# ------------------------------------------------------------
progress "Restoring ownership/perms to original user"
log "Restoring ownership/perms..."

if [ -n "${ORIG_USER:-}" ] && [ "$ORIG_USER" != "root" ]; then
  chown -R "$ORIG_USER:$ORIG_GROUP" "$OUTDIR" 2>/dev/null || true
  chmod -R u+rwX,go-rwx "$OUTDIR" 2>/dev/null || true

  if [ -n "${ARCHIVE_FINAL:-}" ] && [ -e "$ARCHIVE_FINAL" ]; then
    chown "$ORIG_USER:$ORIG_GROUP" "$ARCHIVE_FINAL" 2>/dev/null || true
    chmod u+rw,go-rwx "$ARCHIVE_FINAL" 2>/dev/null || true
  fi
fi

progress "Finished"
progress_done

echo "OK: $OUTDIR"
if [ -n "${ARCHIVE_FINAL:-}" ]; then echo "ARCHIVE: $ARCHIVE_FINAL"; fi
if [ -s "$ERRORS" ]; then echo "ERRORS: $ERRORS"; fi
