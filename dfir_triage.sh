#!/usr/bin/env bash
# ==============================================================================
# DFIR Triage & Rootkit Hunter — Forensics Suite Edition
# ==============================================================================
# Purpose:
#   Collect a high-value, evidence-first snapshot for a potentially compromised
#   Linux host while preserving chain-of-custody and making findings auditable.
#
# Features:
#   - Transparent forensic workflow with explicit logging
#   - Hidden process / module detection
#   - LD_PRELOAD, cron, systemd, startup, SSH persistence checks
#   - Fileless artifact detection and writable executable review
#   - Optional trusted scanner selection from /mnt/ir-tools
#   - Final evidence packaging with SHA-256 integrity manifest
#   - Investigator summary report for triage handoff
# ==============================================================================

set -Eeuo pipefail
umask 077

SCRIPT_NAME="$(basename "$0")"
VERSION="3.1.0"

DRY_RUN=0
NO_INSTALL=0
TRUSTED_DIR="/mnt/ir-tools"
SCAN_ROOT="/"
WORKSPACE_ROOT="${TMPDIR:-/tmp}"
LOG_FILE_OVERRIDE=""

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
  echo "    Use --dry-run for safe validation without changing the host." >&2
  exit 1
fi

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

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

add_summary() {
  printf '%s\n' "$*" >> "$SUMMARY_FILE"
}

copy_artifact() {
  local label="$1"
  local src="$2"
  local dst_dir="$3"

  [ -n "$src" ] || return 0
  if [ -e "$src" ]; then
    mkdir -p "$dst_dir"
    local b="$(basename "$src")"
    if [ -d "$src" ]; then
      cp -a "$src" "$dst_dir/" 2>/dev/null || warn "Unable to copy directory $src"
    else
      cp -a "$src" "$dst_dir/$b" 2>/dev/null || warn "Unable to copy file $src"
    fi
    log "[*] Captured $label: $src"
  fi
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
  echo "[-] Failed to create evidence workspace" >&2
  exit 1
}

HOSTNAME_SAFE="$(hostname 2>/dev/null || echo "unknown-host")"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_FILE_OVERRIDE:-$WORKSPACE/audit_${TIMESTAMP}.log}"
MANIFEST_FILE="$WORKSPACE/manifest_${TIMESTAMP}.sha256"
SUMMARY_FILE="$WORKSPACE/summary_${TIMESTAMP}.txt"
ARTIFACT_DIR="$WORKSPACE/artifacts"
PACKAGE_FILE="$WORKSPACE.tar.gz"
PACKAGE_HASH_FILE="$PACKAGE_FILE.sha256"

: > "$LOG_FILE"
: > "$SUMMARY_FILE"
mkdir -p "$ARTIFACT_DIR"

chattr +a "$LOG_FILE" 2>/dev/null || log "[!] Warning: chattr +a unsupported on this filesystem; log is not append-only protected."

log "[*] DFIR Triage & Rootkit Hunter v${VERSION}"
log "[*] Started by $(logname 2>/dev/null || whoami) on $HOSTNAME_SAFE"
log "[*] Workspace: $WORKSPACE"
log "[*] Scan root: $SCAN_ROOT"
log "[*] Trusted binary directory: $TRUSTED_DIR"
log "[*] Chain-of-custody: investigator + hostname + UTC timestamp recorded above."

add_summary "DFIR Triage Summary"
add_summary "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
add_summary "Host: $HOSTNAME_SAFE"
add_summary "Investigator: $(logname 2>/dev/null || whoami)"
add_summary "Workspace: $WORKSPACE"
add_summary "============================"

# -----------------------------------------------------------------------------
# Baseline host intelligence
# -----------------------------------------------------------------------------
log "[*] PHASE 0: Host Baseline"

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would collect uname, os-release, uptime, mounts, users, and system details."
else
  log "[+] Kernel and OS information"
  uname -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/os-release ] && cat /etc/os-release 2>/dev/null | tee -a "$LOG_FILE" || true
  [ -f /proc/version ] && cat /proc/version 2>/dev/null | tee -a "$LOG_FILE" || true

  log "[+] Uptime, filesystems, and mounts"
  uptime 2>&1 | tee -a "$LOG_FILE" || true
  df -h 2>&1 | tee -a "$LOG_FILE" || true
  mount 2>&1 | tee -a "$LOG_FILE" || true
  if have_cmd lsblk; then lsblk -f 2>&1 | tee -a "$LOG_FILE" || true; fi

  log "[+] User and privilege context"
  id 2>&1 | tee -a "$LOG_FILE" || true
  who -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/passwd ] && awk -F: '{print $1":"$3":"$4":"$6":"$7}' /etc/passwd 2>/dev/null | tee -a "$LOG_FILE" || true
  if have_cmd lastlog; then lastlog 2>/dev/null | tee -a "$LOG_FILE" || true; fi
fi

# -----------------------------------------------------------------------------
# Runtime anomaly detection
# -----------------------------------------------------------------------------
log "[*] PHASE 1: Runtime Anomaly Analysis"

log "[+] Scanning for processes executing from deleted or unlinked binaries..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /proc/*/exe for deleted entries."
else
  find /proc -maxdepth 1 -mindepth 1 -type d -regex '/proc/[0-9]+' -exec sh -c 'for d do target=$(readlink "$d/exe" 2>/dev/null || true); [ -n "$target" ] || continue; case "$target" in *" (deleted)") printf "%s %s\n" "${d#/proc/}" "$target";; esac; done' sh {} + 2>/dev/null | tee -a "$LOG_FILE" || true
fi

log "[+] Cross-referencing /proc against ps for hidden processes..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare kernel-visible PIDs and userland process lists."
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
    add_summary "ALERT: Hidden process indicator detected: $HIDDEN_PIDS"
  else
    log "[+] No discrepancy between /proc and ps."
    add_summary "No hidden process discrepancy between /proc and ps."
  fi
fi

log "[+] Cross-referencing /proc/modules against lsmod..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare /proc/modules and lsmod outputs."
else
  PROC_MODS="$(awk '{print $1}' /proc/modules 2>/dev/null | sort || true)"
  if have_cmd lsmod; then
    LSMOD_MODS="$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort || true)"
  else
    LSMOD_MODS=""
  fi
  if [ -n "$PROC_MODS" ] && [ -n "$LSMOD_MODS" ]; then
    HIDDEN_MODS="$(comm -23 <(printf '%s\n' "$PROC_MODS") <(printf '%s\n' "$LSMOD_MODS") || true)"
  else
    HIDDEN_MODS=""
  fi
  if [ -n "$HIDDEN_MODS" ]; then
    log "[!] ALERT: Hidden kernel modules detected: $HIDDEN_MODS"
    add_summary "ALERT: Hidden kernel module indicator detected: $HIDDEN_MODS"
  else
    log "[+] No discrepancy between /proc/modules and lsmod."
    add_summary "No hidden module discrepancy between /proc/modules and lsmod."
  fi
fi

log "[+] Checking for LD_PRELOAD / ld.so.preload poisoning..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect shell rc files and /etc/ld.so.preload."
else
  for candidate in /etc/profile /etc/profile.d /etc/environment /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile; do
    [ -e "$candidate" ] || continue
    grep -RIn "LD_PRELOAD\|LD_LIBRARY_PATH\|PRELOAD" "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/ld.so.preload ]; then
    log "[!] ALERT: /etc/ld.so.preload exists. Contents:"
    cat /etc/ld.so.preload 2>/dev/null | tee -a "$LOG_FILE" || true
    add_summary "ALERT: /etc/ld.so.preload exists."
  else
    log "[+] No /etc/ld.so.preload file detected."
  fi
fi

log "[+] Checking listening sockets and network metadata..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would list listening sockets and routing details."
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
  if [ -f /proc/net/tcp ] || [ -f /proc/net/tcp6 ]; then
    cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
fi

# -----------------------------------------------------------------------------
# Persistence mechanism audit
# -----------------------------------------------------------------------------
log "[*] PHASE 2: Persistence Artifact Audit"

log "[+] Auditing SSH persistence and configuration files..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect authorized_keys, known_hosts, sshd_config, and SSH config files."
else
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    log "[*] $path"
    grep -HnE 'ssh-rsa|ssh-ed25519|ecdsa-sha2|PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|AuthorizedKeysFile|Match ' "$path" 2>/dev/null | tee -a "$LOG_FILE" || true
  done < <(find "$SCAN_ROOT" -xdev -type f \( -name 'authorized_keys' -o -name 'known_hosts' -o -name 'sshd_config' -o -name 'config' \) 2>/dev/null)
fi

log "[+] Checking cron, systemd, and rc scripts modified recently..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect cron and systemd directories for recent modifications."
else
  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/init.d /etc/rc.d; do
    [ -e "$dir" ] || continue
    find "$dir" -xdev -type f -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/rc.local ]; then
    log "[+] /etc/rc.local contents:"
    cat /etc/rc.local 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
fi

log "[+] Auditing startup and auto-run directories..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /etc/profile.d, ~/.config/autostart, /etc/xdg/autostart, and rc.d directories."
else
  for dir in /etc/profile.d /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart /etc/rc*.d /etc/init.d; do
    [ -e "$dir" ] || continue
    find "$dir" -maxdepth 2 -type f 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

log "[+] Auditing shell profile persistence and injection points..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would review shell startup files /etc/profile and ~/.bashrc family."
else
  for candidate in /etc/profile /etc/bash.bashrc /etc/profile.d/* /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile /home/*/.profile; do
    [ -f "$candidate" ] || continue
    log "[*] $candidate"
    sed -n '1,220p' "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

# -----------------------------------------------------------------------------
# Suspicious file / artifact search
# -----------------------------------------------------------------------------
log "[*] PHASE 3: File & Artifact Search"

log "[+] Searching for suspicious recent executables and scripts..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would examine temp, service, app, and home directories for recent executable artifacts."
else
  find /tmp /dev/shm /var/tmp /opt /srv /home /var/www /usr/local/bin /usr/local/sbin -xdev -type f \( -perm -u+x -o -iname '*.sh' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.php' -o -iname '*.bin' \) -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
fi

log "[+] Looking for hidden directories and suspicious naming conventions..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would scan the filesystem for hidden or suspicious file names."
else
  find "$SCAN_ROOT" -xdev \( -name '.*' -o -name '*tmp*' -o -name '*bak*' -o -name '*evil*' -o -name '*.so' \) 2>/dev/null | head -n 400 | tee -a "$LOG_FILE" || true
fi

log "[+] Reviewing writable executable binaries and scripts..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would locate writable executables in common directories."
else
  for dir in /tmp /var/tmp /dev/shm /opt /srv /home /var/www /usr/local/bin /usr/local/sbin; do
    [ -d "$dir" ] || continue
    find "$dir" -xdev -type f \( -perm -o+w -o -perm -g+w \) -perm /111 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

# -----------------------------------------------------------------------------
# Capture forensic copies of key files
# -----------------------------------------------------------------------------
log "[*] PHASE 4: Evidence Collection"

for artifact in \
  /etc/hosts \
  /etc/resolv.conf \
  /etc/sudoers \
  /etc/sudoers.d \
  /etc/cron.d \
  /etc/cron.daily \
  /etc/cron.hourly \
  /etc/cron.weekly \
  /etc/cron.monthly \
  /etc/systemd/system \
  /etc/profile.d \
  /etc/init.d \
  /etc/rc.local \
  /etc/ssh/sshd_config \
  /etc/ssh/ssh_config \
  /etc/passwd \
  /etc/shadow; do
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[DRY-RUN] Would capture forensic artifact: $artifact"
  else
    copy_artifact "$(basename "$artifact" 2>/dev/null || echo "$artifact")" "$artifact" "$ARTIFACT_DIR"
  fi
done

# -----------------------------------------------------------------------------
# Scanner selection and execution
# -----------------------------------------------------------------------------
log "[*] PHASE 5: Signature-Based Scanning"
log "[!] Host package managers and PATH-resolved binaries are lower assurance in a potentially compromised environment."
log "    This script prefers known-good tools from $TRUSTED_DIR when available."

CLAM_BINARY=""
RK_BINARY=""
CHK_BINARY=""

if [ -x "$TRUSTED_DIR/clamscan" ] && [ -x "$TRUSTED_DIR/rkhunter" ] && [ -x "$TRUSTED_DIR/chkrootkit" ]; then
  CLAM_BINARY="$TRUSTED_DIR/clamscan"
  RK_BINARY="$TRUSTED_DIR/rkhunter"
  CHK_BINARY="$TRUSTED_DIR/chkrootkit"
  log "[+] Using externally supplied trusted binaries from $TRUSTED_DIR."
else
  log "[!] No complete trusted scanner set detected at $TRUSTED_DIR."
  if [ "$NO_INSTALL" -eq 1 ]; then
    log "[!] --no-install set; scanner installation is skipped."
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

log "[+] Recording SHA-256 of scanner binaries used:"
for b in "$RK_BINARY" "$CHK_BINARY" "$CLAM_BINARY"; do
  [ -n "$b" ] && [ -x "$b" ] && record_hash "$b"
done

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would run chkrootkit -q"
  log "[DRY-RUN] Would run rkhunter --check --skip-keypress --report-warnings-only"
  log "[DRY-RUN] Would scan common directories with clamscan --infected --recursive --max-filesize=50M"
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
    log "[+] Running ClamAV against common living-off-the-land directories..."
    "$CLAM_BINARY" --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www /srv /opt >> "$LOG_FILE" 2>&1 || warn "ClamAV returned a non-zero exit code."
  else
    warn "clamscan not available; skipping."
  fi
fi

# -----------------------------------------------------------------------------
# Summary report generation
# -----------------------------------------------------------------------------
log "[*] PHASE 6: Summary Report"
add_summary "============================"
add_summary "Findings summary"
add_summary "- Scanner binaries used:"
for b in "$RK_BINARY" "$CHK_BINARY" "$CLAM_BINARY"; do
  if [ -n "$b" ] && [ -x "$b" ]; then
    add_summary "  * $b"
  fi
done
add_summary "- Log file: $LOG_FILE"
add_summary "- Manifest: $MANIFEST_FILE"
add_summary "- Artifacts directory: $ARTIFACT_DIR"
add_summary "=== End of report ==="

# -----------------------------------------------------------------------------
# Final integrity packaging
# -----------------------------------------------------------------------------
log "[*] SCANS COMPLETE."
if [ -f "$LOG_FILE" ]; then
  chattr -a "$LOG_FILE" 2>/dev/null || true
fi

if [ -f "$LOG_FILE" ]; then
  sha256sum "$LOG_FILE" >> "$MANIFEST_FILE"
fi

if [ -f "$SUMMARY_FILE" ]; then
  sha256sum "$SUMMARY_FILE" >> "$MANIFEST_FILE"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would create final archive: $PACKAGE_FILE"
  log "[DRY-RUN] Would hash archive and write $PACKAGE_HASH_FILE"
  log "[+] Summary file: $SUMMARY_FILE"
  log "[+] Evidence manifest: $MANIFEST_FILE"
  log "[+] Dry-run complete. No live evidence archive was produced."
  exit 0
fi

if ! tar -czf "$PACKAGE_FILE" -C "$(dirname "$WORKSPACE")" "$(basename "$WORKSPACE")"; then
  log "[!] Failed to create final evidence archive."
  exit 1
fi
sha256sum "$PACKAGE_FILE" > "$PACKAGE_HASH_FILE"

log "[+] Evidence package: $PACKAGE_FILE"
log "[+] Package hash: $(cat "$PACKAGE_HASH_FILE")"
log "[+] Binary/log manifest: $MANIFEST_FILE"
log "[+] Summary report: $SUMMARY_FILE"
log "[-] Transfer the tarball and .sha256 together and verify hash on the receiving end before treating the archive as evidence."

exit 0
