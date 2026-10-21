#!/usr/bin/env bash
# ==============================================================================
# DFIR Triage & Rootkit Hunter — Enterprise-Grade, Evidence-First Edition
# ==============================================================================
# Purpose:
#   Capture a defensible, high-value snapshot of a potentially compromised Linux
#   host while preserving chain-of-custody and forensic integrity.
#
# Design goals:
#   - Transparent, verifiable, attributable execution.
#   - Prefer trusted, external binaries when present.
#   - Record evidence and metadata in a format suitable for later review.
#   - Fail safely without hiding the fact that the tool ran.
#   - Keep the investigation robust even in partially compromised environments.
#
# Usage:
#   sudo ./dfir_triage.sh [--trusted-dir /mnt/ir-tools] [--scan-root /]
#                         [--workspace-root /tmp] [--dry-run] [--no-install]
# ==============================================================================

set -Eeuo pipefail
umask 077

SCRIPT_NAME="$(basename "$0")"
VERSION="3.0.0"

DRY_RUN=0
NO_INSTALL=0
TRUSTED_DIR="/mnt/ir-tools"
SCAN_ROOT="/"
WORKSPACE_ROOT="${TMPDIR:-/tmp}"
LOG_FILE_OVERRIDE=""
EXTRA_SCAN_DIRS=(
  "/tmp"
  "/dev/shm"
  "/var/tmp"
  "/home"
  "/var/www"
  "/srv"
  "/opt"
)

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -h, --help              Show this help message
  --trusted-dir DIR       Directory containing trusted scanner binaries
  --scan-root DIR         Root path to scan for persistence and keys (default: /)
  --workspace-root DIR    Temp directory for evidence workspace (default: ${TMPDIR:-/tmp})
  --dry-run               Explain actions without executing live checks
  --no-install            Never install packages; only use trusted binaries or existing tools
  --log-file FILE         Explicit log file path for the evidence log
EOF
}

while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --trusted-dir)
      [ $# -ge 2 ] || { echo "[-] Missing value for --trusted-dir" >&2; exit 2; }
      TRUSTED_DIR="$2"
      shift 2
      ;;
    --scan-root)
      [ $# -ge 2 ] || { echo "[-] Missing value for --scan-root" >&2; exit 2; }
      SCAN_ROOT="$2"
      shift 2
      ;;
    --workspace-root)
      [ $# -ge 2 ] || { echo "[-] Missing value for --workspace-root" >&2; exit 2; }
      WORKSPACE_ROOT="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --no-install)
      NO_INSTALL=1
      shift
      ;;
    --log-file)
      [ $# -ge 2 ] || { echo "[-] Missing value for --log-file" >&2; exit 2; }
      LOG_FILE_OVERRIDE="$2"
      shift 2
      ;;
    *)
      echo "[-] Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  echo "[-] This script must be run as root in live mode." >&2
  echo "    Use --dry-run for safe validation without executing live host checks." >&2
  exit 1
fi

log() {
  printf '%s | %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE"
}

warn() {
  log "[!] $*"
}

record_hash() {
  local file_path="$1"
  [ -n "$file_path" ] || return 0
  [ -f "$file_path" ] || return 0
  sha256sum "$file_path" | tee -a "$LOG_FILE" >> "$MANIFEST_FILE"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

cleanup() {
  local rc=$?
  if [ -n "${LOG_FILE:-}" ] && [ -f "$LOG_FILE" ]; then
    chattr -a "$LOG_FILE" 2>/dev/null || true
  fi
  if [ "$rc" -ne 0 ] && [ "$DRY_RUN" -eq 1 ]; then
    log "[!] Dry-run finished with exit code $rc. No live host changes were made."
  fi
}
trap cleanup EXIT

mkdir -p "$WORKSPACE_ROOT" || { echo "[-] Failed to create workspace root: $WORKSPACE_ROOT" >&2; exit 1; }

WORKSPACE="$(mktemp -d "${WORKSPACE_ROOT%/}/.triage-XXXXXXXX")" || {
  echo "[-] Failed to create evidence workspace under $WORKSPACE_ROOT" >&2
  exit 1
}

HOSTNAME_SAFE="$(hostname 2>/dev/null || echo "unknown-host")"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_FILE_OVERRIDE:-$WORKSPACE/audit_${TIMESTAMP}.log}"
MANIFEST_FILE="$WORKSPACE/manifest_${TIMESTAMP}.sha256"
PACKAGE_FILE="$WORKSPACE.tar.gz"
PACKAGE_HASH_FILE="$PACKAGE_FILE.sha256"

: > "$LOG_FILE"
chattr +a "$LOG_FILE" 2>/dev/null || log "[!] Warning: chattr +a unsupported on this filesystem; log is not append-only protected."

log "[*] DFIR Triage & Rootkit Hunter v${VERSION}"
log "[*] Started by $(logname 2>/dev/null || whoami) on $HOSTNAME_SAFE"
log "[*] Workspace: $WORKSPACE"
log "[*] Scan root: $SCAN_ROOT"
log "[*] Trusted binary directory: $TRUSTED_DIR"
log "[*] Chain-of-custody: investigator + hostname + UTC timestamp recorded above."

collect_snapshot() {
  local label="$1"
  local target="$2"
  [ -n "$target" ] || return 0
  if [ -d "$target" ] || [ -f "$target" ]; then
    log "[*] Collecting $label: $target"
    if [ "$DRY_RUN" -eq 0 ]; then
      cp -a "$target" "$WORKSPACE/" 2>/dev/null || warn "Unable to copy $label: $target"
    else
      log "[DRY-RUN] Would copy $label: $target"
    fi
  fi
}

# -----------------------------------------------------------------------------
# 1. Baseline host intelligence
# -----------------------------------------------------------------------------
log "[*] PHASE 0: Host Baseline & Environment"

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would record host baseline information: uname, os-release, uptime, mount, users, and time sync."
else
  for cmd in uname cat /etc/os-release /proc/version uptime df -h mount ps -eo pid,ppid,uid,comm,cmd --forest who id lastlog; do
    if have_cmd "${cmd%% *}" || [ "$cmd" = "cat" ] || [ "$cmd" = "uname" ] || [ "$cmd" = "id" ] || [ "$cmd" = "who" ] || [ "$cmd" = "lastlog" ] || [ "$cmd" = "ps" ] || [ "$cmd" = "df" ] || [ "$cmd" = "mount" ]; then
      :
    fi
  done

  log "[+] Kernel and OS"
  uname -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/os-release ] && cat /etc/os-release 2>/dev/null | tee -a "$LOG_FILE" || true
  [ -f /proc/version ] && cat /proc/version 2>/dev/null | tee -a "$LOG_FILE" || true

  log "[+] System uptime, disk, and mounts"
  uptime 2>&1 | tee -a "$LOG_FILE" || true
  df -h 2>&1 | tee -a "$LOG_FILE" || true
  mount 2>&1 | tee -a "$LOG_FILE" || true
  if have_cmd lsblk; then lsblk -f 2>&1 | tee -a "$LOG_FILE" || true; fi

  log "[+] Users and privilege context"
  id 2>&1 | tee -a "$LOG_FILE" || true
  who -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/passwd ] && awk -F: '{print $1":"$3":"$4":"$6":"$7}' /etc/passwd 2>/dev/null | tee -a "$LOG_FILE" || true
  [ -f /etc/shadow ] && ls -l /etc/shadow 2>/dev/null | tee -a "$LOG_FILE" || true
  if have_cmd sudo; then sudo -l 2>&1 | tee -a "$LOG_FILE" || true; fi
fi

# -----------------------------------------------------------------------------
# 2. Runtime anomaly detection
# -----------------------------------------------------------------------------
log "[*] PHASE 1: Runtime Anomaly Analysis"

log "[+] Scanning for processes executing from deleted, unlinked, or suspicious binaries..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /proc/*/exe and /proc/*/cmdline for deleted or suspicious execution links."
else
  find /proc -maxdepth 1 -mindepth 1 -type d -regex '/proc/[0-9]+' -exec sh -c 'for d do p="${d#/proc/}"; target=$(readlink "$d/exe" 2>/dev/null || true); [ -n "$target" ] || continue; case "$target" in *" (deleted)"*) printf "%s %s\n" "$p" "$target";; esac; done' sh {} + 2>/dev/null | tee -a "$LOG_FILE" || true

  log "[+] Detailed process list (including command lines and ancestors)"
  ps -eo pid,ppid,uid,comm,args --forest 2>/dev/null | tee -a "$LOG_FILE" || true
fi

log "[+] Cross-referencing /proc, ps, and /proc/*/status for hidden process indicators..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare kernel-visible PIDs against userland process listings and status data."
else
  KERNEL_PIDS="$(find /proc -maxdepth 1 -mindepth 1 -type d -regex '/proc/[0-9]+' 2>/dev/null | sed 's|/proc/||' | sort -n || true)"
  USERLAND_PIDS="$(ps -eo pid= 2>/dev/null | awk '{print $1}' | sort -n || true)"
  if [ -n "$KERNEL_PIDS" ] && [ -n "$USERLAND_PIDS" ]; then
    HIDDEN_PIDS="$(comm -23 <(printf '%s\n' "$KERNEL_PIDS") <(printf '%s\n' "$USERLAND_PIDS") || true)"
  else
    HIDDEN_PIDS=""
  fi
  if [ -n "$HIDDEN_PIDS" ]; then
    log "[!] ALERT: PIDs visible in /proc but missing from ps: $HIDDEN_PIDS"
  else
    log "[+] No discrepancy between /proc and ps."
  fi

  log "[+] Process status summary"
  for p in /proc/[0-9]*; do
    [ -r "$p/status" ] || continue
    grep -E 'Name:|State:|PPid:|Uid:|Gid:|VmSize:|Threads:' "$p/status" 2>/dev/null | head -n 10 | tee -a "$LOG_FILE" || true
  done
fi

log "[+] Cross-referencing /proc/modules against lsmod for hidden kernel modules..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare Linux module lists provided by kernel and userspace."
else
  if have_cmd lsmod; then
    LSMOD_MODS="$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort || true)"
  else
    LSMOD_MODS=""
  fi
  PROC_MODS="$(awk '{print $1}' /proc/modules 2>/dev/null | sort || true)"
  if [ -n "$PROC_MODS" ] && [ -n "$LSMOD_MODS" ]; then
    HIDDEN_MODS="$(comm -23 <(printf '%s\n' "$PROC_MODS") <(printf '%s\n' "$LSMOD_MODS") || true)"
  else
    HIDDEN_MODS=""
  fi
  if [ -n "$HIDDEN_MODS" ]; then
    log "[!] ALERT: Modules visible in /proc/modules but hidden from lsmod: $HIDDEN_MODS"
  else
    log "[+] No discrepancy between /proc/modules and lsmod."
  fi
fi

log "[+] Checking for LD_PRELOAD and preload poisoning..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /etc/profile, /etc/profile.d, /etc/environment, shell rc files, and /etc/ld.so.preload."
else
  for candidate in /etc/profile /etc/profile.d /etc/environment /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile; do
    [ -e "$candidate" ] || continue
    grep -RIn "LD_PRELOAD\|LD_LIBRARY_PATH\|PRELOAD" "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/ld.so.preload ]; then
    log "[!] ALERT: /etc/ld.so.preload exists. Contents:"
    cat /etc/ld.so.preload 2>/dev/null | tee -a "$LOG_FILE" || true
  else
    log "[+] No /etc/ld.so.preload file detected."
  fi
fi

log "[+] Checking listening sockets and network metadata..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would enumerate listening sockets, routes, netstat data, and open ports."
else
  if have_cmd ss; then
    ss -tulpn 2>/dev/null | tee -a "$LOG_FILE" || true
  elif have_cmd netstat; then
    netstat -tulpn 2>/dev/null | tee -a "$LOG_FILE" || true
  else
    log "[!] No socket-listing tool found in PATH."
  fi
  if have_cmd ip; then
    ip addr show 2>/dev/null | tee -a "$LOG_FILE" || true
    ip route show 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
  if have_cmd route; then route -n 2>/dev/null | tee -a "$LOG_FILE" || true; fi
  if [ -f /proc/net/tcp ] || [ -f /proc/net/tcp6 ]; then
    cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
fi

# -----------------------------------------------------------------------------
# 3. Persistence mechanism audit
# -----------------------------------------------------------------------------
log "[*] PHASE 2: Persistence Artifact Audit"

log "[+] Auditing SSH authorized_keys and known SSH config vectors..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would search for authorized_keys, known_hosts, sshd_config, and likely persistence vectors."
else
  find "$SCAN_ROOT" -xdev -type f \( -name 'authorized_keys' -o -name 'known_hosts' -o -name 'sshd_config' -o -name 'config' \) 2>/dev/null | while IFS= read -r entry; do
    log "[*] Investigating $entry"
    grep -HnE 'ssh-rsa|ssh-ed25519|ecdsa-sha2|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysFile|Match ' "$entry" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

log "[+] Auditing cron and scheduled task persistence..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect cron directories, crontabs, systemd units, init scripts, and rc scripts for recent modifications."
else
  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/init.d /etc/rc.local /etc/rc.d; do
    [ -e "$dir" ] || continue
    find "$dir" -xdev -type f -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/rc.local ]; then
    log "[+] /etc/rc.local contents:"
    cat /etc/rc.local 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
fi

log "[+] Auditing startup and autostart directories..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect ~/.config/autostart, /etc/profile.d, /etc/xdg/autostart, and /etc/rc*.d."
else
  for dir in /etc/profile.d /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart /etc/rc*.d /etc/init.d; do
    [ -e "$dir" ] || continue
    find "$dir" -maxdepth 2 -type f 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

log "[+] Checking shell profiles and startup scripts for malicious command injection..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect shell startup files and common persistence locations."
else
  for candidate in /etc/profile /etc/bash.bashrc /etc/profile.d/* /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.profile; do
    [ -f "$candidate" ] || continue
    log "[*] $candidate"
    sed -n '1,200p' "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

log "[+] Auditing suspicious user and system binaries in writable locations..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would search writable directories for executable files that were modified recently."
else
  for dir in /tmp /var/tmp /dev/shm /opt /srv /home /var/www /usr/local/bin /usr/local/sbin /tmp/.*/; do
    [ -d "$dir" ] || continue
    find "$dir" -xdev -type f -perm /022 -o -type f -perm /002 2>/dev/null | head -n 200 | tee -a "$LOG_FILE" || true
  done
fi

# -----------------------------------------------------------------------------
# 4. Fileless / suspicious artifact detection
# -----------------------------------------------------------------------------
log "[*] PHASE 3: Suspicious File & Memory Artifact Search"

log "[+] Looking for recently modified binaries and scripts in common persistence locations..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would search /tmp, /dev/shm, /var/tmp, /opt, /srv, /home, and /var/www for recent executable artifacts."
else
  find /tmp /dev/shm /var/tmp /opt /srv /home /var/www -xdev -type f \( -iname '*.sh' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.php' -o -iname '*.bin' -o -perm -u+x \) -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
fi

log "[+] Scanning for suspicious names and hidden directories..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would scan root file system for hidden directories and suspicious names."
else
  find "$SCAN_ROOT" -xdev \( -name '.*' -o -name '.*.*' -o -name '*tmp*' -o -name '*bak*' -o -name '*evil*' -o -name '*.so' \) 2>/dev/null | head -n 300 | tee -a "$LOG_FILE" || true
fi

# -----------------------------------------------------------------------------
# 5. Trusted binary selection and scanner execution
# -----------------------------------------------------------------------------
log "[*] PHASE 4: Signature-Based Scanning"
log "[!] A ring-0 compromised host cannot fully trust PATH-resolved scanner binaries."
log "    This script prefers known-good tools from $TRUSTED_DIR when present."
log "    It will fall back to package-manager installation only if allowed."

CLAM_BINARY=""
RK_BINARY=""
CHK_BINARY=""

if [ -x "$TRUSTED_DIR/clamscan" ] && [ -x "$TRUSTED_DIR/rkhunter" ] && [ -x "$TRUSTED_DIR/chkrootkit" ]; then
  CLAM_BINARY="$TRUSTED_DIR/clamscan"
  RK_BINARY="$TRUSTED_DIR/rkhunter"
  CHK_BINARY="$TRUSTED_DIR/chkrootkit"
  log "[+] Using externally supplied trusted binaries from $TRUSTED_DIR."
else
  log "[!] No complete set of trusted binaries found at $TRUSTED_DIR."
  if [ "$NO_INSTALL" -eq 1 ]; then
    log "[!] --no-install is set; installation is skipped."
  else
    if have_cmd apt-get; then
      log "[+] Attempting fallback installation via apt-get."
      DEBIAN_FRONTEND=noninteractive apt-get update -yq >/dev/null 2>&1 || warn "apt-get update failed."
      DEBIAN_FRONTEND=noninteractive apt-get install -yq clamav rkhunter chkrootkit >/dev/null 2>&1 || warn "apt-get install failed."
      if have_cmd clamscan; then CLAM_BINARY="$(command -v clamscan)"; fi
      if have_cmd rkhunter; then RK_BINARY="$(command -v rkhunter)"; fi
      if have_cmd chkrootkit; then CHK_BINARY="$(command -v chkrootkit)"; fi
      if have_cmd freshclam; then
        systemctl stop clamav-freshclam >/dev/null 2>&1 || true
        freshclam --quiet >/dev/null 2>&1 || true
        systemctl start clamav-freshclam >/dev/null 2>&1 || true
      fi
      if have_cmd rkhunter; then
        rkhunter --update --quiet >/dev/null 2>&1 || true
        rkhunter --propupd --quiet >/dev/null 2>&1 || true
      fi
    else
      warn "No supported package manager found; scanner installation is skipped."
    fi
  fi
fi

log "[+] Recording SHA-256 of the exact scanner binaries used:"
for b in "$RK_BINARY" "$CHK_BINARY" "$CLAM_BINARY"; do
  [ -n "$b" ] && [ -x "$b" ] && record_hash "$b"
done

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would run: chkrootkit -q"
  log "[DRY-RUN] Would run: rkhunter --check --skip-keypress --report-warnings-only"
  log "[DRY-RUN] Would run: clamscan --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www /srv /opt"
else
  if [ -n "$CHK_BINARY" ] && [ -x "$CHK_BINARY" ]; then
    log "[+] Running chkrootkit (real name, no obfuscation)..."
    "$CHK_BINARY" -q >> "$LOG_FILE" 2>&1 || warn "chkrootkit returned a non-zero exit code."
  else
    warn "chkrootkit not available; skipping."
  fi

  if [ -n "$RK_BINARY" ] && [ -x "$RK_BINARY" ]; then
    log "[+] Running rkhunter..."
    "$RK_BINARY" --check --skip-keypress --report-warnings-only >> "$LOG_FILE" 2>&1 || warn "rkhunter returned a non-zero exit code."
  else
    warn "rkhunter not available; skipping."
  fi

  if [ -n "$CLAM_BINARY" ] && [ -x "$CLAM_BINARY" ]; then
    log "[+] Running ClamAV against common persistence and user-space directories..."
    "$CLAM_BINARY" --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www /srv /opt >> "$LOG_FILE" 2>&1 || warn "ClamAV returned a non-zero exit code."
  else
    warn "clamscan not available; skipping."
  fi
fi

# -----------------------------------------------------------------------------
# 6. Capture critical forensic artifacts
# -----------------------------------------------------------------------------
log "[*] PHASE 5: Evidence Collection"

collect_snapshot "hosts file" "/etc/hosts"
collect_snapshot "resolv.conf" "/etc/resolv.conf"
collect_snapshot "sudoers" "/etc/sudoers"
collect_snapshot "sudoers.d" "/etc/sudoers.d"
collect_snapshot "cron hourly" "/etc/cron.hourly"
collect_snapshot "cron daily" "/etc/cron.daily"
collect_snapshot "cron weekly" "/etc/cron.weekly"
collect_snapshot "cron monthly" "/etc/cron.monthly"
collect_snapshot "systemd unit dir" "/etc/systemd/system"
collect_snapshot "init.d" "/etc/init.d"
collect_snapshot "profile.d" "/etc/profile.d"
collect_snapshot "rc.local" "/etc/rc.local"

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would gather forensic copies of high-value persistence and config artifacts."
fi

# -----------------------------------------------------------------------------
# 7. Final packaging and chain-of-custody integrity
# -----------------------------------------------------------------------------
log "[*] SCANS COMPLETE."
if [ -f "$LOG_FILE" ]; then
  chattr -a "$LOG_FILE" 2>/dev/null || true
fi

if [ -f "$LOG_FILE" ]; then
  sha256sum "$LOG_FILE" >> "$MANIFEST_FILE"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would create archive: $PACKAGE_FILE"
  log "[DRY-RUN] Would hash archive and write $PACKAGE_HASH_FILE"
  log "[+] Evidence manifest path: $MANIFEST_FILE"
  log "[+] Log file path: $LOG_FILE"
  log "[+] Dry run complete. No live evidence artifact was packaged."
  exit 0
fi

if ! tar -czf "$PACKAGE_FILE" -C "$(dirname "$WORKSPACE")" "$(basename "$WORKSPACE")"; then
  log "[!] Failed to create final evidence archive: $PACKAGE_FILE"
  exit 1
fi

sha256sum "$PACKAGE_FILE" > "$PACKAGE_HASH_FILE"

log "[+] Evidence package: $PACKAGE_FILE"
log "[+] Package hash: $(cat "$PACKAGE_HASH_FILE")"
log "[+] Binary/log manifest: $MANIFEST_FILE"
log "[-] Transfer the tarball and the .sha256 file together and verify the hash on the receiving end before treating it as evidence."

exit 0
