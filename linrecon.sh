#!/usr/bin/env bash
# ============================================================
# linrecon - Linux Recon & Security Inventory
#
# Version: 1.0.0
#
# Changelog:
# 1.0.0
# - Primera version estable para Assessment de Seguridad
# - Auto-elevacion con sudo si no se ejecuta como root
# - Preserva usuario original y reasigna ownership/permisos al final
# - Progreso visible (porcentaje) que se pisa en la consola
# - Genera report.txt + report.html + data/*.txt por seccion
# - Registra errores por comando (RC != 0) en errors.txt
# - Empaquetado automatico: zip (si existe) o tar.gz (fallback)
# ============================================================

set -Eeuo pipefail
shopt -s nullglob

VERSION="1.0.0"
PROG="linrecon"

# ------------------------------------------------------------
# Usuario original (antes de sudo)
# ------------------------------------------------------------
ORIG_USER="${SUDO_USER:-$(id -un)}"
ORIG_GROUP="$(id -gn "$ORIG_USER" 2>/dev/null || echo "$ORIG_USER")"

# ------------------------------------------------------------
# Auto-elevacion con sudo
# - Preserva ORIG_USER/ORIG_GROUP para usar al final
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
echo "[INFO] Se requieren privilegios de superusuario para el relevamiento completo."
echo "[INFO] Solicitando sudo..."
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

umask 077
mkdir -p "$DATADIR"

# ------------------------------------------------------------
# Progreso (se pisa)
# TOTAL_STEPS debe coincidir con cantidad de progress()
# ------------------------------------------------------------
TOTAL_STEPS=14
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

# log(): solo al TXT para no interferir con progress
log(){ echo "[$(date +%F' '%T)] $*" >> "$TXT"; }

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
echo "[$(date +%F' '%T)] ERROR ($rc) en $name: $cmdline" >> "$ERRORS"
fi
}

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
echo "[$(date +%F' '%T)] ERROR ($rc) en $name (snippet)" >> "$ERRORS"
fi
}

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
# Cabecera report.txt + errors.txt
# ------------------------------------------------------------
echo "==== $PROG report ($TS) ====" > "$TXT"
echo "Version: $VERSION" >> "$TXT"
echo "Host: $HOST" >> "$TXT"
echo "OS: $OS_NAME ($OS_ID) $OS_VER" >> "$TXT"
echo "Family: $FAMILY PackageMgr: $PKG" >> "$TXT"
echo "User (orig): $ORIG_USER Group (orig): $ORIG_GROUP" >> "$TXT"
echo "User (effective): $(id -un 2>/dev/null || true) UID: $(id -u 2>/dev/null || true)" >> "$TXT"
echo "Out: $OUTDIR" >> "$TXT"
echo >> "$TXT"

echo "==== $PROG errors ($TS) ====" > "$ERRORS"
echo "Version: $VERSION" >> "$ERRORS"
echo "Host: $HOST" >> "$ERRORS"
echo >> "$ERRORS"

# ------------------------------------------------------------
# 0x - Sistema base
# ------------------------------------------------------------
progress "Relevando sistema base"
log "Relevando sistema base..."

run_shell "00_os_release" 'safe_cat /etc/os-release'
run "01_uname" uname -a
run "02_uptime" uptime
run_shell "03_date_locale" 'date; echo; locale 2>/dev/null || true'
if cmd_exists lsb_release; then run "04_lsb_release" lsb_release -a; fi
if cmd_exists hostnamectl; then run "05_hostnamectl" hostnamectl; fi
if cmd_exists timedatectl; then run "06_timedatectl" timedatectl; fi

# ------------------------------------------------------------
# 1x - Hardware y almacenamiento
# ------------------------------------------------------------
progress "Relevando hardware y almacenamiento"
log "Hardware y recursos..."

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
run_shell "20_dmidecode" 'echo "TIP: instalar dmidecode para inventario DMI (serial/model/BIOS)."'
fi

# ------------------------------------------------------------
# 3x - Kernel y tuning
# ------------------------------------------------------------
progress "Relevando kernel, modulos y sysctl"
log "Kernel, modulos, sysctl..."

run_shell "30_kernel_cmdline" 'safe_cat /proc/cmdline'
if cmd_exists sysctl; then run "31_sysctl_all" sysctl -a; fi
if cmd_exists lsmod; then run "32_lsmod" lsmod; fi
if cmd_exists modinfo; then run_shell "33_modinfo_netfilter" 'modinfo nf_tables 2>/dev/null || true; modinfo ip_tables 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 4x - Red
# ------------------------------------------------------------
progress "Relevando red, DNS y puertos"
log "Red, interfaces, rutas, DNS..."

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
# 6x - Usuarios y accesos
# ------------------------------------------------------------
progress "Relevando usuarios, grupos y sudo"
log "Usuarios, grupos, sudo, logins..."

run_shell "60_passwd" 'safe_cat /etc/passwd'
run_shell "61_group" 'safe_cat /etc/group'
run_shell "62_shadow_hint" 'if [ -r /etc/shadow ]; then echo "OK: /etc/shadow es legible"; else echo "NOACCESS: /etc/shadow"; fi'
run_shell "63_sudoers" 'safe_cat /etc/sudoers; echo; if [ -d /etc/sudoers.d ]; then ls -la /etc/sudoers.d; echo; for f in /etc/sudoers.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done; fi'
if cmd_exists last; then run "64_last" last -a -n 50; fi
if cmd_exists lastlog; then run_shell "65_lastlog" 'lastlog 2>/dev/null || true'; fi
if cmd_exists who; then run "66_who" who -a; fi

# ------------------------------------------------------------
# 7x - Servicios y jobs
# ------------------------------------------------------------
progress "Relevando servicios, timers y cron"
log "Servicios, timers, jobs..."

if cmd_exists systemctl; then
run "70_systemd_units" systemctl list-units --all --no-pager
run "71_systemd_services" systemctl list-unit-files --type=service --no-pager
run "72_systemd_timers" systemctl list-timers --all --no-pager
run "73_failed_units" systemctl --failed --no-pager
fi

run_shell "74_crontab_system" 'ls -la /etc/cron* 2>/dev/null || true; echo; for d in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do [ -d "$d" ] && echo "== $d ==" && ls -la "$d" && echo; done'
if cmd_exists crontab; then run_shell "75_crontab_user" 'crontab -l 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 8x - Seguridad (SSH, firewall, MAC)
# ------------------------------------------------------------
progress "Relevando seguridad (SSH, firewall, MAC)"
log "Seguridad: SSH, firewall, SELinux/AppArmor..."

run_shell "80_sshd_config" 'safe_cat /etc/ssh/sshd_config; echo; if [ -d /etc/ssh/sshd_config.d ]; then ls -la /etc/ssh/sshd_config.d; echo; for f in /etc/ssh/sshd_config.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done; fi'
if cmd_exists ssh-keygen; then run_shell "81_ssh_hostkeys_fpr" 'for k in /etc/ssh/ssh_host_*_key.pub; do [ -e "$k" ] && echo "$k" && ssh-keygen -lf "$k" && echo; done'; fi

if cmd_exists ufw; then run_shell "82_ufw" 'ufw status verbose 2>&1 || true'; fi
if cmd_exists firewall-cmd; then run_shell "83_firewalld" 'firewall-cmd --state 2>/dev/null || true; echo; firewall-cmd --list-all 2>/dev/null || true; echo; firewall-cmd --list-all-zones 2>/dev/null || true'; fi
if cmd_exists nft; then run_shell "84_nft" 'nft list ruleset 2>&1 || true'; fi
if cmd_exists iptables; then run_shell "85_iptables" 'iptables -S 2>&1 || true; echo; iptables -L -n -v 2>&1 || true'; fi

if cmd_exists getenforce; then run_shell "86_selinux" 'getenforce; echo; sestatus 2>/dev/null || true'; fi
if cmd_exists aa-status; then run_shell "87_apparmor" 'aa-status 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 9x - Logs (si accesibles)
# ------------------------------------------------------------
progress "Relevando logs de autenticacion"
log "Logs de autenticacion..."

if [ -r /var/log/auth.log ]; then run_shell "90_auth_log_tail" 'tail -n 200 /var/log/auth.log'; fi
if [ -r /var/log/secure ]; then run_shell "90_secure_log_tail" 'tail -n 200 /var/log/secure'; fi
if cmd_exists journalctl; then run_shell "91_journal_ssh" 'journalctl -n 300 --no-pager -u ssh 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 10x - Inventario de software
# ------------------------------------------------------------
progress "Relevando software, repos y updates"
log "Inventario de software..."

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
run_shell "100_pkgmgr" 'echo "No se detecto apt/dnf/yum"'
fi

if cmd_exists snap; then run_shell "110_snap_list" 'snap list 2>/dev/null || true'; fi
if cmd_exists flatpak; then run_shell "111_flatpak_list" 'flatpak list 2>/dev/null || true'; fi
if cmd_exists pip; then run_shell "112_pip_freeze" 'pip freeze 2>/dev/null || true'; fi
if cmd_exists pip3; then run_shell "112_pip3_freeze" 'pip3 freeze 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 12x - Runtime
# ------------------------------------------------------------
progress "Relevando runtime (procesos y dmesg)"
log "Procesos y estado runtime..."

run_shell "120_ps" 'ps auxfww 2>/dev/null || ps -ef 2>/dev/null || true'
if cmd_exists top; then run_shell "121_top" 'top -b -n 1 2>/dev/null || true'; fi
if cmd_exists dmesg; then run_shell "122_dmesg_tail" 'dmesg -T 2>/dev/null | tail -n 200 || dmesg 2>/dev/null | tail -n 200 || true'; fi

# ------------------------------------------------------------
# HTML
# ------------------------------------------------------------
progress "Generando reporte HTML"
log "Armando HTML..."

html_escape(){
sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

{
echo "<!doctype html>"
echo "<html><head><meta charset=\"utf-8\">"
echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
echo "<title>${PROG} report - ${HOST} - ${TS}</title>"
echo "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}h1{margin:0 0 8px 0}h2{margin-top:22px}pre{white-space:pre-wrap;background:#f6f8fa;border:1px solid #d0d7de;padding:12px;border-radius:8px}code{background:#f6f8fa;padding:2px 6px;border-radius:6px}</style>"
echo "</head><body>"
echo "<h1>${PROG} - Inventory & Audit</h1>"
echo "<p><b>Version:</b> ${VERSION}<br><b>Host:</b> ${HOST}<br><b>Timestamp:</b> ${TS}<br><b>OS:</b> ${OS_NAME} (${OS_ID}) ${OS_VER}<br><b>Family:</b> ${FAMILY} - <b>PkgMgr:</b> ${PKG}<br><b>Original user:</b> ${ORIG_USER}<br><b>Output:</b> ${OUTDIR}</p>"
echo "<h2>Indice</h2><ul>"
for f in "$DATADIR"/*.txt; do
b="$(basename "$f" .txt)"
echo "<li><a href=\"#${b}\">${b}</a></li>"
done
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
echo "<hr><p>Generado por ${PROG} v${VERSION}.</p>"
echo "</body></html>"
} > "$HTML"

# ------------------------------------------------------------
# Empaquetado final (zip preferido, tar.gz fallback)
# ------------------------------------------------------------
progress "Empaquetando resultados (zip o tar.gz)"
log "Comprimiendo salida..."

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
run_shell "200_archive_none" 'echo "WARNING: no se encontro zip ni tar. No se genero archivo comprimido."'
fi

# ------------------------------------------------------------
# Post: devolver ownership/permisos al usuario original
# ------------------------------------------------------------
progress "Aplicando ownership/permisos al usuario original"
log "Ajustando ownership/permisos para $ORIG_USER:$ORIG_GROUP..."

if [ -n "${ORIG_USER:-}" ] && [ "$ORIG_USER" != "root" ]; then
chown -R "$ORIG_USER:$ORIG_GROUP" "$OUTDIR" 2>/dev/null || true
chmod -R u+rwX,go-rwx "$OUTDIR" 2>/dev/null || true
if [ -n "${ARCHIVE_FINAL:-}" ] && [ -e "$ARCHIVE_FINAL" ]; then
chown "$ORIG_USER:$ORIG_GROUP" "$ARCHIVE_FINAL" 2>/dev/null || true
chmod u+rw,go-rwx "$ARCHIVE_FINAL" 2>/dev/null || true
fi
fi

progress "Finalizado"
progress_done

echo "OK: $OUTDIR"
if [ -n "${ARCHIVE_FINAL:-}" ]; then echo "ARCHIVE: $ARCHIVE_FINAL"; fi
if [ -s "$ERRORS" ]; then echo "ERRORS: $ERRORS"; fi
