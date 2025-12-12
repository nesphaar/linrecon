#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s nullglob

# ------------------------------------------------------------
# linrecon - Relevamiento estilo Belarc/WinAudit para Linux
# - Compatible: Debian/Ubuntu (apt) y RHEL/Fedora (dnf/yum)
# - Output: TXT + HTML + evidencias por seccion (data/*.txt)
# - Read-only: no modifica configuracion, solo consulta
# - Recomendado: correr como root para mayor cobertura
# ------------------------------------------------------------

# Nombre del programa (para nombres de carpetas y titulos)
PROG="linrecon"

# Timestamp para versionar reportes
TS="$(date +%Y%m%d_%H%M%S)"

# FQDN si existe, si no el hostname corto
HOST="$(hostname -f 2>/dev/null || hostname)"

# Directorio salida: si pasan arg1 se usa, sino uno default con host y timestamp
OUTDIR="${1:-./${PROG}_${HOST}_${TS}}"

# Carpeta de evidencias por seccion
DATADIR="$OUTDIR/data"

# Archivos finales
HTML="$OUTDIR/report.html"
TXT="$OUTDIR/report.txt"

# Umask restrictivo: los reportes pueden contener info sensible
umask 077

# Crea estructura de salida
mkdir -p "$DATADIR"

# Flag simple: estamos corriendo como root o no
is_root=0
if [ "${EUID:-$(id -u)}" -eq 0 ]; then is_root=1; fi

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

# log(): escribe en pantalla y agrega al TXT principal
log(){ echo "[$(date +%F' '%T)] $*" | tee -a "$TXT" >/dev/null; }

# cmd_exists(): chequea si un comando existe
cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

# safe_cat(): cat si es legible, si no deja evidencia de NOACCESS
safe_cat(){
local p="$1"
if [ -r "$p" ]; then
cat "$p"
else
echo "NOACCESS: $p"
fi
}

# run(): ejecuta un comando "simple" (sin subshell complejo) y vuelca salida a data/<name>.txt
# - Captura stdout+stderr
# - No corta el script si falla (|| true)
run(){
local name="$1"; shift
local f="$DATADIR/${name}.txt"
local cmdline=""
if [ "$#" -gt 0 ]; then
cmdline="$(printf "%q " "$@")"
fi
{
echo "### $name"
if [ -n "$cmdline" ]; then echo "\$ $cmdline"; fi
echo
"$@" 2>&1 || true
echo
} > "$f"
}

# run_shell(): ejecuta un snippet en bash -lc para comandos compuestos (for/if/pipes)
# Importante: exporta safe_cat para que el snippet pueda usarlo
run_shell(){
local name="$1"; shift
local snippet="$1"
local f="$DATADIR/${name}.txt"
export -f safe_cat
{
echo "### $name"
echo "\$ bash -lc (snippet)"
echo
bash -lc "$snippet" 2>&1 || true
echo
} > "$f"
}

# detect_os(): identifica familia (debian/rhel) y package manager (apt/dnf/yum)
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

# Ejecuta deteccion de OS al inicio
detect_os

# ------------------------------------------------------------
# Cabecera del reporte TXT principal
# ------------------------------------------------------------

echo "==== $PROG report ($TS) ====" > "$TXT"
echo "Host: $HOST" >> "$TXT"
echo "OS: $OS_NAME ($OS_ID) $OS_VER" >> "$TXT"
echo "Family: $FAMILY PackageMgr: $PKG" >> "$TXT"
echo "User: $(id -un 2>/dev/null || true) UID: $(id -u 2>/dev/null || true) Root: $is_root" >> "$TXT"
echo "Out: $OUTDIR" >> "$TXT"
echo >> "$TXT"

# ------------------------------------------------------------
# 0x - Sistema base
# ------------------------------------------------------------

log "Relevando sistema base..."

# Identidad del OS
run_shell "00_os_release" 'safe_cat /etc/os-release'

# Kernel + arquitectura
run "01_uname" uname -a

# Uptime y load basico
run "02_uptime" uptime

# Fecha y locale (util para interpretar logs)
run_shell "03_date_locale" 'date; echo; locale 2>/dev/null || true'

# Extras si existen
if cmd_exists lsb_release; then run "04_lsb_release" lsb_release -a; fi
if cmd_exists hostnamectl; then run "05_hostnamectl" hostnamectl; fi
if cmd_exists timedatectl; then run "06_timedatectl" timedatectl; fi

# ------------------------------------------------------------
# 1x - Hardware y almacenamiento
# ------------------------------------------------------------

log "Hardware y recursos..."

# CPU: preferir lscpu, fallback a /proc/cpuinfo
run_shell "10_cpu" 'lscpu 2>/dev/null || safe_cat /proc/cpuinfo'

# Memoria: preferir free, fallback a /proc/meminfo
run_shell "11_mem" 'free -h 2>/dev/null || safe_cat /proc/meminfo'

# Loadavg crudo
run_shell "12_load" 'cat /proc/loadavg 2>/dev/null || true'

# Discos y particiones detallados
if cmd_exists lsblk; then run "13_lsblk" lsblk -a -o NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINTS,MODEL,SERIAL,ROTA; fi

# Identificadores de volumen
if cmd_exists blkid; then run "14_blkid" blkid; fi

# Filesystems montados
run "15_df" df -hT
run "16_mount" mount

# Persistencia de mounts
run_shell "17_fstab" 'safe_cat /etc/fstab'

# Inventario PCI/USB si estan disponibles
if cmd_exists lspci; then run "18_lspci" lspci -nn; fi
if cmd_exists lsusb; then run "19_lsusb" lsusb; fi

# DMI (modelo/serial/BIOS) requiere root y dmidecode
if [ "$is_root" -eq 1 ] && cmd_exists dmidecode; then
run "20_dmidecode" dmidecode -t system -t baseboard -t bios -t chassis
else
run_shell "20_dmidecode" 'echo "TIP: ejecutar como root e instalar dmidecode para inventario DMI (serial/model/BIOS)."'
fi

# ------------------------------------------------------------
# 3x - Kernel y tuning
# ------------------------------------------------------------

log "Kernel, modulos, sysctl..."

# Cmdline del kernel
run_shell "30_kernel_cmdline" 'safe_cat /proc/cmdline'

# sysctl completo (puede ser grande)
if cmd_exists sysctl; then run "31_sysctl_all" sysctl -a; fi

# Modulos cargados
if cmd_exists lsmod; then run "32_lsmod" lsmod; fi

# Info de modulos netfilter (si existen)
if cmd_exists modinfo; then run_shell "33_modinfo_netfilter" 'modinfo nf_tables 2>/dev/null || true; modinfo ip_tables 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 4x - Red
# ------------------------------------------------------------

log "Red, interfaces, rutas, DNS..."

# Estado de interfaces y direccionamiento
if cmd_exists ip; then
run "40_ip_addr" ip -details addr
run "41_ip_link" ip -details link
run "42_ip_route" ip -details route
run "43_ip_rule" ip rule show
fi

# Puertos en escucha (ss preferido)
if cmd_exists ss; then
run "44_listening_tcp_udp" ss -tulpen
else
run_shell "44_listening_tcp_udp" 'netstat -tulpen 2>/dev/null || true'
fi

# DNS y hosts locales
run_shell "45_resolv_conf" 'safe_cat /etc/resolv.conf'
run_shell "46_hosts" 'safe_cat /etc/hosts'

# systemd-resolved (si aplica)
if cmd_exists resolvectl; then run "47_resolvectl" resolvectl status; fi

# NetworkManager (si aplica)
if cmd_exists nmcli; then run_shell "48_nmcli" 'nmcli -f all general,device,connection show 2>/dev/null || true'; fi

# Netplan (Ubuntu moderno)
if [ -d /etc/netplan ]; then
run_shell "49_netplan" 'ls -la /etc/netplan 2>/dev/null || true; echo; for f in /etc/netplan/*.yaml; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done'
fi

# Scripts ifcfg (RHEL/CentOS legacy)
if [ -d /etc/sysconfig/network-scripts ]; then
run_shell "49_ifcfg" 'ls -la /etc/sysconfig/network-scripts 2>/dev/null || true; echo; for f in /etc/sysconfig/network-scripts/ifcfg-*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done'
fi

# ------------------------------------------------------------
# 6x - Usuarios y accesos
# ------------------------------------------------------------

log "Usuarios, grupos, sudo, logins..."

# Usuarios/grupos
run_shell "60_passwd" 'safe_cat /etc/passwd'
run_shell "61_group" 'safe_cat /etc/group'

# Shadow suele requerir root
run_shell "62_shadow_hint" 'if [ -r /etc/shadow ]; then echo "OK: /etc/shadow es legible (root)"; else echo "NOACCESS: /etc/shadow (normal)"; fi'

# sudoers y includes
run_shell "63_sudoers" 'safe_cat /etc/sudoers; echo; if [ -d /etc/sudoers.d ]; then ls -la /etc/sudoers.d; echo; for f in /etc/sudoers.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done; fi'

# Ultimos logins
if cmd_exists last; then run "64_last" last -a -n 50; fi
if cmd_exists lastlog; then run_shell "65_lastlog" 'lastlog 2>/dev/null || true'; fi
if cmd_exists who; then run "66_who" who -a; fi

# ------------------------------------------------------------
# 7x - Servicios y jobs
# ------------------------------------------------------------

log "Servicios, timers, jobs..."

# systemd: unidades, unit-files, timers, fallidas
if cmd_exists systemctl; then
run "70_systemd_units" systemctl list-units --all --no-pager
run "71_systemd_services" systemctl list-unit-files --type=service --no-pager
run "72_systemd_timers" systemctl list-timers --all --no-pager
run "73_failed_units" systemctl --failed --no-pager
fi

# Cron del sistema
run_shell "74_crontab_system" 'ls -la /etc/cron* 2>/dev/null || true; echo; for d in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do [ -d "$d" ] && echo "== $d ==" && ls -la "$d" && echo; done'

# Crontab del usuario que corre el script (si existe)
if cmd_exists crontab; then run_shell "75_crontab_user" 'crontab -l 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 8x - Seguridad (SSH, firewall, MAC)
# ------------------------------------------------------------

log "Seguridad: SSH, firewall, SELinux/AppArmor..."

# SSH daemon config + includes
run_shell "80_sshd_config" 'safe_cat /etc/ssh/sshd_config; echo; if [ -d /etc/ssh/sshd_config.d ]; then ls -la /etc/ssh/sshd_config.d; echo; for f in /etc/ssh/sshd_config.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done; fi'

# Fingerprints de host keys
if cmd_exists ssh-keygen; then run_shell "81_ssh_hostkeys_fpr" 'for k in /etc/ssh/ssh_host_*_key.pub; do [ -e "$k" ] && echo "$k" && ssh-keygen -lf "$k" && echo; done'; fi

# Firewall UFW (Ubuntu)
if cmd_exists ufw; then run_shell "82_ufw" 'ufw status verbose 2>&1 || true'; fi

# Firewalld (RHEL/Fedora)
if cmd_exists firewall-cmd; then run_shell "83_firewalld" 'firewall-cmd --state 2>/dev/null || true; echo; firewall-cmd --list-all 2>/dev/null || true; echo; firewall-cmd --list-all-zones 2>/dev/null || true'; fi

# nftables
if cmd_exists nft; then run_shell "84_nft" 'nft list ruleset 2>&1 || true'; fi

# iptables legacy
if cmd_exists iptables; then run_shell "85_iptables" 'iptables -S 2>&1 || true; echo; iptables -L -n -v 2>&1 || true'; fi

# SELinux status
if cmd_exists getenforce; then run_shell "86_selinux" 'getenforce; echo; sestatus 2>/dev/null || true'; fi

# AppArmor status
if cmd_exists aa-status; then run_shell "87_apparmor" 'aa-status 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 9x - Logs (si accesibles)
# ------------------------------------------------------------

log "Logs de autenticacion (si accesible)..."

# Debian/Ubuntu
if [ -r /var/log/auth.log ]; then run_shell "90_auth_log_tail" 'tail -n 200 /var/log/auth.log'; fi

# RHEL/Fedora
if [ -r /var/log/secure ]; then run_shell "90_secure_log_tail" 'tail -n 200 /var/log/secure'; fi

# Journal - unidad ssh
if cmd_exists journalctl; then run_shell "91_journal_ssh" 'journalctl -n 300 --no-pager -u ssh 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 10x - Inventario de software
# ------------------------------------------------------------

log "Inventario de software..."

# Debian/Ubuntu (APT)
if [ "$PKG" = "apt" ]; then
run_shell "100_apt_sources" 'ls -la /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true; echo; safe_cat /etc/apt/sources.list; echo; for f in /etc/apt/sources.list.d/*; do [ -e "$f" ] && echo "----- $f -----" && cat "$f" && echo; done'
run_shell "101_pkgs_dpkg" 'dpkg-query -W -f="${binary:Package}\t${Version}\t${Architecture}\n" 2>/dev/null | sort'
run_shell "102_apt_policy" 'apt-cache policy 2>/dev/null || true'
run_shell "103_updates_sim" 'apt-get -s update 2>/dev/null || true; echo; apt-get -s upgrade 2>/dev/null || true'
# RHEL/Fedora (DNF)
elif [ "$PKG" = "dnf" ]; then
run_shell "100_repos_dnf" 'dnf -q repolist all 2>/dev/null || true; echo; dnf config-manager --dump 2>/dev/null || true'
run_shell "101_pkgs_rpm" 'rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort'
run_shell "103_updates" 'dnf -q check-update 2>/dev/null || true'
# RHEL/CentOS legacy (YUM)
elif [ "$PKG" = "yum" ]; then
run_shell "100_repos_yum" 'yum repolist all 2>/dev/null || true'
run_shell "101_pkgs_rpm" 'rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort'
run_shell "103_updates" 'yum check-update 2>/dev/null || true'
else
run_shell "100_pkgmgr" 'echo "No se detecto apt/dnf/yum"'
fi

# Inventario adicional
if cmd_exists snap; then run_shell "110_snap_list" 'snap list 2>/dev/null || true'; fi
if cmd_exists flatpak; then run_shell "111_flatpak_list" 'flatpak list 2>/dev/null || true'; fi
if cmd_exists pip; then run_shell "112_pip_freeze" 'pip freeze 2>/dev/null || true'; fi
if cmd_exists pip3; then run_shell "112_pip3_freeze" 'pip3 freeze 2>/dev/null || true'; fi

# ------------------------------------------------------------
# 12x - Runtime (procesos, top, kernel ring buffer)
# ------------------------------------------------------------

log "Procesos y estado runtime..."

# Procesos en ejecucion
run_shell "120_ps" 'ps auxfww 2>/dev/null || ps -ef 2>/dev/null || true'

# Foto de consumo (1 iteracion)
if cmd_exists top; then run_shell "121_top" 'top -b -n 1 2>/dev/null || true'; fi

# Ultimos eventos del kernel
if cmd_exists dmesg; then run_shell "122_dmesg_tail" 'dmesg -T 2>/dev/null | tail -n 200 || dmesg 2>/dev/null | tail -n 200 || true'; fi

# ------------------------------------------------------------
# HTML
# ------------------------------------------------------------

log "Armando HTML..."

# html_escape(): escapa &,<,> para que el contenido no rompa el HTML
html_escape(){
sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# Genera un HTML navegable con indice y cada evidencia embebida en <pre>
{
echo "<!doctype html>"
echo "<html><head><meta charset=\"utf-8\">"
echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
echo "<title>${PROG} report - ${HOST} - ${TS}</title>"
echo "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}h1{margin:0 0 8px 0}h2{margin-top:22px}pre{white-space:pre-wrap;background:#f6f8fa;border:1px solid #d0d7de;padding:12px;border-radius:8px}code{background:#f6f8fa;padding:2px 6px;border-radius:6px}</style>"
echo "</head><body>"
echo "<h1>${PROG} - Inventory & Audit</h1>"
echo "<p><b>Host:</b> ${HOST}<br><b>Timestamp:</b> ${TS}<br><b>OS:</b> ${OS_NAME} (${OS_ID}) ${OS_VER}<br><b>Family:</b> ${FAMILY} - <b>PkgMgr:</b> ${PKG}<br><b>Root:</b> ${is_root}<br><b>Output:</b> ${OUTDIR}</p>"
echo "<h2>Indice</h2><ul>"
for f in "$DATADIR"/*.txt; do
b="$(basename "$f" .txt)"
echo "<li><a href=\"#${b}\">${b}</a></li>"
done
echo "</ul>"
for f in "$DATADIR"/*.txt; do
b="$(basename "$f" .txt)"
echo "<h2 id=\"${b}\">${b}</h2>"
echo "<pre>"
html_escape < "$f"
echo "</pre>"
done
echo "<hr><p>Generado por ${PROG}.</p>"
echo "</body></html>"
} > "$HTML"

# ------------------------------------------------------------
# Cierre
# ------------------------------------------------------------

log "Listo. Reporte TXT: $TXT"
log "Listo. Reporte HTML: $HTML"
log "Evidencias: $DATADIR"
echo
echo "OK: $OUTDIR"
