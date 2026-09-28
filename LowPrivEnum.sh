#!/usr/bin/env bash
#
# linpriv.sh — Question-driven Linux privilege escalation enumeration
#
# Structure: 1) Your Position  2) Understand the Machine  3) Privilege Boundaries
# Each item is a plain-English question with the answer only (commands hidden).
# RED  = potential vulnerability / worth exploiting
# YELLOW = worth a manual look, not confirmed dangerous
# Everything else = informational, plain output.
#
# Usage: chmod +x linpriv.sh && ./linpriv.sh | tee out.txt
#
set +e

# ---- colors -----------------------------------------------------------
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

red()    { echo -e "${RED}[!] $*${NC}"; }
yellow() { echo -e "${YELLOW}[?] $*${NC}"; }
plain()  { echo "$*"; }

banner() { echo; echo -e "${BOLD}${CYAN}== $* ==${NC}"; }

# q "Question text"  then feed answer lines via the color helpers above
q() { echo; echo -e "${BOLD}Q: $1${NC}"; }

hr() { echo "-------------------------------------------------------------"; }

echo -e "${BOLD}linpriv.sh${NC} — run as $(whoami) (uid=$(id -u)) on $(hostname) — $(date)"

# =========================================================================
# 1. YOUR CURRENT POSITION
# =========================================================================
banner "1. YOUR CURRENT POSITION"

q "Who am I, and what UID do I have?"
me="$(id 2>/dev/null)"
plain "$me"
echo "$me" | grep -q "uid=0(" && red "Running as root already — no privesc needed."

q "What groups am I in? Any of them privileged?"
groups_out="$(id -Gn 2>/dev/null)"
plain "$groups_out"
for g in docker lxd disk adm shadow video root sudo wheel; do
    echo "$groups_out" | grep -qw "$g" && red "Member of '$g' — this group can often be abused for privesc (check GTFOBins / group-specific tricks)."
done

q "What privileges do I already have via sudo (no password needed)?"
sudo_out="$(sudo -n -l 2>&1)"
if echo "$sudo_out" | grep -qi "may run\|NOPASSWD"; then
    red "Passwordless sudo rights found:"
    echo "$sudo_out" | sed 's/^/    /'
elif echo "$sudo_out" | grep -qi "password"; then
    plain "Sudo requires a password — nothing usable without credentials."
else
    plain "$sudo_out"
fi

q "Do I have any special Linux capabilities on my own shell/process?"
own_caps="$(getpcaps $$ 2>&1)"
plain "$own_caps"

# =========================================================================
# 2. UNDERSTAND THE MACHINE
# =========================================================================
banner "2. UNDERSTAND THE MACHINE"

q "What OS distribution is this?"
plain "$(cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION)=' | sed 's/"//g')"

q "What kernel and version?"
kernel="$(uname -r 2>/dev/null)"
plain "$(uname -a 2>/dev/null)"
yellow "Kernel $kernel — cross-check against known local-root CVEs (Dirty Pipe, Dirty COW, PwnKit, etc.) manually."

q "What architecture?"
plain "$(uname -m 2>/dev/null)"

q "What applications/packages are installed that stand out?"
if command -v dpkg >/dev/null 2>&1; then
    apps="$(dpkg -l 2>/dev/null | awk '/^ii/{print $2, $3}' | grep -Ei 'mysql|postgres|ftp|tftp|nfs|docker|jenkins|tomcat|apache|nginx|redis|mongo|samba|snmp')"
elif command -v rpm >/dev/null 2>&1; then
    apps="$(rpm -qa 2>/dev/null | grep -Ei 'mysql|postgres|ftp|tftp|nfs|docker|jenkins|tomcat|apache|nginx|redis|mongo|samba|snmp')"
fi
if [ -n "$apps" ]; then
    yellow "Notable installed software (check versions for known exploits):"
    echo "$apps" | sed 's/^/    /'
else
    plain "No notable enumerable services/packages found (or package manager not available)."
fi

q "What services are running?"
svc="$( (systemctl list-units --type=service --state=running 2>/dev/null | grep '\.service' | awk '{print $1}') || service --status-all 2>/dev/null)"
plain "$svc" | head -n 30

q "What network interfaces exist?"
plain "$( (ip -brief addr 2>/dev/null) || (ifconfig 2>/dev/null) )"

q "What ports are listening, and are any only reachable locally?"
ports="$( (ss -tulpn 2>/dev/null) || (netstat -tulpn 2>/dev/null) )"
plain "$ports"
echo "$ports" | grep -q "127.0.0.1" && yellow "Some services only listen on localhost — now reachable since you're a local user. Investigate what they are."

q "Is this a VM, container, or bare metal?"
if [ -f /.dockerenv ]; then
    red "Running inside a Docker container (/.dockerenv present) — look for container escape paths (privileged mode, mounted docker.sock, capabilities)."
elif grep -qa docker /proc/1/cgroup 2>/dev/null; then
    red "cgroup indicates this is a container."
elif command -v systemd-detect-virt >/dev/null 2>&1; then
    virt="$(systemd-detect-virt 2>/dev/null)"
    plain "systemd-detect-virt reports: $virt"
else
    plain "No strong container indicators found — likely a VM or bare metal."
fi

q "What users exist on this system?"
plain "$(cut -d: -f1,3,6 /etc/passwd 2>/dev/null | (column -t -s: 2>/dev/null || cat))"
uid0="$(awk -F: '($3 == 0){print $1}' /etc/passwd 2>/dev/null)"
uid0_count="$(echo "$uid0" | grep -c .)"
if [ "$uid0_count" -gt 1 ]; then
    red "Multiple UID 0 (root-equivalent) accounts found: $(echo "$uid0" | tr '\n' ' ')"
fi

# =========================================================================
# 3. PRIVILEGE BOUNDARIES
# =========================================================================
banner "3. PRIVILEGE BOUNDARIES"

q "Are there SUID binaries I can abuse?"
suid="$(find / -xdev -perm -4000 -type f 2>/dev/null)"
common_suid="passwd|su$|sudo|mount|umount|ping|su |newgrp|gpasswd|chsh|chfn|chage|pkexec"
odd_suid="$(echo "$suid" | grep -vE "$common_suid")"
if [ -n "$odd_suid" ]; then
    red "Non-standard SUID binaries (check each against GTFOBins):"
    echo "$odd_suid" | sed 's/^/    /'
fi
if [ -n "$suid" ]; then
    plain "All SUID binaries found:"
    echo "$suid" | sed 's/^/    /'
fi

q "Are there SGID binaries I can abuse?"
sgid="$(find / -xdev -perm -2000 -type f 2>/dev/null)"
[ -n "$sgid" ] && { yellow "SGID binaries found — check against GTFOBins:"; echo "$sgid" | sed 's/^/    /'; }

q "Do any binaries have dangerous Linux capabilities set?"
caps="$(getcap -r / 2>/dev/null)"
if [ -n "$caps" ]; then
    red "Binaries with capabilities set (cap_setuid/cap_dac_override/etc. are especially dangerous):"
    echo "$caps" | sed 's/^/    /'
else
    plain "No capabilities found."
fi

q "What can I run as another user via sudo?"
sudo_l="$(sudo -l 2>&1)"
if echo "$sudo_l" | grep -qi "may run"; then
    red "Sudo rules found — verify each against GTFOBins:"
    echo "$sudo_l" | sed 's/^/    /'
else
    plain "$sudo_l"
fi

q "Are there world-writable files owned by root, or in system paths?"
ww_files="$(find / -xdev -type f -perm -0002 2>/dev/null | grep -vE '^/proc|^/sys' | head -n 30)"
[ -n "$ww_files" ] && { yellow "World-writable files (first 30):"; echo "$ww_files" | sed 's/^/    /'; }

q "Are there world-writable directories in system paths?"
ww_dirs="$(find / -xdev -type d -perm -0002 2>/dev/null | grep -vE '^/proc|^/sys|^/tmp$|^/var/tmp$|^/dev/shm$' | head -n 30)"
[ -n "$ww_dirs" ] && { yellow "World-writable directories (excluding standard tmp dirs, first 30):"; echo "$ww_dirs" | sed 's/^/    /'; }

q "Are there cron jobs I can hijack (writable scripts run by root)?"
cron_all="$(cat /etc/crontab 2>/dev/null; ls /etc/cron.d/ 2>/dev/null)"
plain "$cron_all"
cron_writable="$(find /etc/cron* -writable -type f 2>/dev/null)"
[ -n "$cron_writable" ] && red "Writable cron files — likely root code execution: $cron_writable"

q "Are there services (systemd units) with writable exec paths?"
svc_writable="$(find /etc/systemd/system /lib/systemd/system -writable -type f 2>/dev/null)"
[ -n "$svc_writable" ] && red "Writable systemd unit files — can redefine what root executes: $svc_writable"

q "Is my PATH hijackable — any writable directory in it, or does it contain '.'?"
path_writable=""
IFS=':' read -ra pdirs <<< "$PATH"
for d in "${pdirs[@]}"; do
    [ -w "$d" ] 2>/dev/null && path_writable="$path_writable $d"
done
plain "PATH=$PATH"
[ -n "$path_writable" ] && red "Writable directories in PATH — a root process using default PATH could execute your planted binary:$path_writable"
echo "$PATH" | grep -q "^\.:\|:\.:\|:\.$" && red "PATH contains '.' — dangerous, can lead to arbitrary code execution."

q "Are there credentials or secrets lying around in plaintext?"
sshkeys="$(find / -xdev \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" \) 2>/dev/null)"
[ -n "$sshkeys" ] && { red "Readable private SSH keys found:"; echo "$sshkeys" | sed 's/^/    /'; }

pw_files="$(find / -xdev -iname '*password*' -type f 2>/dev/null | head -n 20)"
[ -n "$pw_files" ] && { yellow "Files with 'password' in the name (first 20):"; echo "$pw_files" | sed 's/^/    /'; }

pw_grep="$(grep -rEi 'password\s*=|passwd\s*=|api[_-]?key\s*=' /etc /opt /var/www /home 2>/dev/null | grep -v Binary | head -n 20)"
[ -n "$pw_grep" ] && { red "Plaintext credential-looking strings in config files (first 20):"; echo "$pw_grep" | sed 's/^/    /'; }

hist="$(cat ~/.bash_history 2>/dev/null | grep -Ei 'pass|passwd|secret|key' | head -n 10)"
[ -n "$hist" ] && { yellow "Shell history references credentials — review manually:"; echo "$hist" | sed 's/^/    /'; }

q "Is /etc/passwd or /etc/shadow writable by me?"
[ -w /etc/passwd ] && red "/etc/passwd is writable — you can add a root-equivalent user directly."
[ -w /etc/shadow ] && red "/etc/shadow is writable — you can overwrite the root password hash directly."

q "Is there other sensitive information exposed (backup files, .git, config dumps)?"
sensitive="$(find / -xdev \( -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~" \) -type f 2>/dev/null | grep -vE '^/proc|^/sys' | head -n 20)"
[ -n "$sensitive" ] && { yellow "Backup/old files that may contain leftover sensitive data:"; echo "$sensitive" | sed 's/^/    /'; }

gitdirs="$(find / -xdev -name ".git" -type d 2>/dev/null | grep -vE '^/proc|^/sys' | head -n 10)"
[ -n "$gitdirs" ] && { yellow ".git directories found — history may contain committed secrets:"; echo "$gitdirs" | sed 's/^/    /'; }

q "Are there known kernel/software vulnerabilities worth checking?"
yellow "Manually cross-reference the kernel version ($kernel) and any installed software versions above against public CVE databases (e.g. searchsploit, exploit-db) — not auto-checked here to avoid false positives."

hr
echo -e "${BOLD}Done.${NC} ${RED}Red${NC} = investigate first (likely exploitable). ${YELLOW}Yellow${NC} = worth a manual look."
echo "Always confirm SUID/sudo findings against https://gtfobins.github.io before acting."
