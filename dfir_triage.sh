#!/usr/bin/env bash
# ==============================================================================
# DFIR Triage & Rootkit Hunter — Hardened, Chain-of-Custody Edition v2
# ==============================================================================
# Purpose:
#   Collect a fast, defensible snapshot of a potentially compromised Linux host.
#   Evidence is prioritized over stealth: the tool is intentionally explicit,
#   attributable, and verifiable rather than trying to hide itself.
#
# Security model:
#   - Run as root from a trusted environment whenever possible.
#   - Prefer trusted binaries from /mnt/ir-tools when present.
#   - Log everything with UTC timestamps.
#   - Record SHA-256 hashes for all binaries and resulting evidence.
#   - Keep the log append-only where supported.
#
# Usage:
#   sudo ./dfir_triage.sh [--trusted-dir /mnt/ir-tools] [--scan-root /] [--workspace-root /tmp] [--dry-run]
# ==============================================================================

set -Eeuo pipefail
umask 077

SCRIPT_NAME="$(basename "$0")"
VERSION="2.1.0"

DRY_RUN=0
TRUSTED_DIR="/mnt/ir-tools"
WORKSPACE_ROOT="${TMPDIR:-/tmp}"
SCAN_ROOT="/"
LOG_FILE_OVERRIDE=""

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -h, --help              Show this help message
  --trusted-dir DIR       Directory containing trusted scanner binaries
  --scan-root DIR         Root path to scan for persistence and keys (default: /)
  --workspace-root DIR    Temp directory for evidence workspace (default: ${TMPDIR:-/tmp})
  --dry-run               Explain actions without executing destructive or privileged checks
  --log-file FILE         Optional explicit log path
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
  echo "    Use --dry-run for a safe local validation run." >&2
  exit 1
fi

log() {
  printf '%s | %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE"
}

record_hash() {
  local file_path="$1"
  [ -n "$file_path" ] || return 0
  [ -f "$file_path" ] || return 0
  sha256sum "$file_path" | tee -a "$LOG_FILE" >> "$MANIFEST_FILE"
}

run_logged_command() {
  local description="$1"
  shift

  log "[*] $description"

  if [ "$DRY_RUN" -eq 1 ]; then
    log "[DRY-RUN] Would execute: $*"
    return 0
  fi

  if "$@" >> "$LOG_FILE" 2>&1; then
    return 0
  fi

  local rc=$?
  log "[!] Command failed with exit code $rc: $*"
  return "$rc"
}

ensure_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "[!] Required command not found: $cmd"
    return 1
  fi
  return 0
}

safe_append_file() {
  local source="$1"
  local target="$2"
  [ -f "$source" ] || return 0
  cat "$source" >> "$target"
}

cleanup() {
  local rc=$?
  if [ -f "$LOG_FILE" ]; then
    chattr -a "$LOG_FILE" 2>/dev/null || true
  fi
  if [ "$rc" -ne 0 ] && [ "$DRY_RUN" -eq 1 ]; then
    log "[!] Dry-run finished with exit code $rc. No live host changes were made."
  fi
}
trap cleanup EXIT

mkdir -p "$WORKSPACE_ROOT" || { echo "[-] Failed to create workspace root: $WORKSPACE_ROOT" >&2; exit 1; }

WORKSPACE="$(mktemp -d "${WORKSPACE_ROOT%/}/.triage-XXXXXXXX")" || {
  echo "[-] Failed to create evidence workspace." >&2
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
log "[*] Chain-of-custody: investigator + hostname + UTC timestamp are recorded above."

log "[*] PHASE 1: Runtime Anomaly Analysis"

log "[+] Scanning for processes executing from deleted or unlinked binaries..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /proc/*/exe for 'deleted' entries."
else
  find /proc -maxdepth 1 -mindepth 1 -type d -regex '/proc/[0-9]+' -exec ls -al {}/exe \; 2>/dev/null | grep -i 'deleted' | tee -a "$LOG_FILE" || true
fi

log "[+] Cross-referencing /proc vs ps for hidden processes..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare kernel-visible PIDs to ps output."
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
fi

log "[+] Cross-referencing /proc/modules vs lsmod for hidden kernel modules..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare /proc/modules to lsmod output."
else
  if command -v lsmod >/dev/null 2>&1; then
    LSMOD_MODS="$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort || true)"
  else
    LSMOD_MODS=""
    log "[!] lsmod not available; cannot compare against /proc/modules."
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

log "[+] Checking for LD_PRELOAD / ld.so.preload usage..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /etc/profile, /etc/profile.d, /etc/environment, ~/.bashrc, ~/.bash_profile, and /etc/ld.so.preload."
else
  for candidate in /etc/profile /etc/profile.d /etc/environment /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile; do
    [ -e "$candidate" ] || continue
    grep -RIn "LD_PRELOAD" "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/ld.so.preload ]; then
    log "[!] ALERT: /etc/ld.so.preload exists. Contents:"
    cat /etc/ld.so.preload | tee -a "$LOG_FILE"
  else
    log "[+] No /etc/ld.so.preload file detected."
  fi
fi

log "[+] Checking listening sockets..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would run ss -tulpn or netstat fallback."
else
  if command -v ss >/dev/null 2>&1; then
    ss -tulpn 2>/dev/null | tee -a "$LOG_FILE" || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn 2>/dev/null | tee -a "$LOG_FILE" || true
  else
    log "[!] No socket-listing tool found in PATH."
  fi
fi

log "[*] PHASE 2: Persistence Artifact Audit"

log "[+] Auditing SSH authorized_keys..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would search for authorized_keys files in /etc, /root, /home, /srv, /opt, and /var/www."
else
  for dir in /etc /root /home /srv /opt /var/www; do
    [ -d "$dir" ] || continue
    find "$dir" -xdev -type f -name 'authorized_keys' -print0 2>/dev/null | \
      while IFS= read -r -d '' keyfile; do
        grep -HnE 'ssh-rsa|ssh-ed25519|ecdsa-sha2' "$keyfile" 2>/dev/null | tee -a "$LOG_FILE" || true
      done
  done
fi

log "[+] Checking cron/systemd artifacts modified in the last 7 days..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect cron and systemd configuration directories for files modified in the last 7 days."
else
  find \
    /etc /var/spool/cron /var/spool/cron/crontabs /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
    -xdev -type f \( -name 'cron*' -o -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.target' \) \
    -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
fi

log "[*] PHASE 3: Signature-Based Scanning"
log "[!] Host package managers and PATH-resolved binaries are lower assurance in a potentially compromised environment."
log "    This script prefers statically-linked or externally supplied tools from $TRUSTED_DIR when available."
log "    If not available, it may install scanners from the OS package manager as a fallback."

CLAM_BINARY=""
RK_BINARY=""
CHK_BINARY=""

if [ -x "$TRUSTED_DIR/clamscan" ] && [ -x "$TRUSTED_DIR/rkhunter" ] && [ -x "$TRUSTED_DIR/chkrootkit" ]; then
  CLAM_BINARY="$TRUSTED_DIR/clamscan"
  RK_BINARY="$TRUSTED_DIR/rkhunter"
  CHK_BINARY="$TRUSTED_DIR/chkrootkit"
  log "[+] Using externally supplied trusted binaries from $TRUSTED_DIR."
else
  log "[!] No trusted external binaries detected at $TRUSTED_DIR. Falling back to host package manager when possible."
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[DRY-RUN] Would verify package manager and install clamav, rkhunter, chkrootkit only if available."
  else
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -yq >/dev/null 2>&1 || log "[!] apt-get update failed."
      DEBIAN_FRONTEND=noninteractive apt-get install -yq clamav rkhunter chkrootkit >/dev/null 2>&1 || log "[!] apt-get install of scanners failed."
      if command -v clamscan >/dev/null 2>&1; then CLAM_BINARY="$(command -v clamscan)"; fi
      if command -v rkhunter >/dev/null 2>&1; then RK_BINARY="$(command -v rkhunter)"; fi
      if command -v chkrootkit >/dev/null 2>&1; then CHK_BINARY="$(command -v chkrootkit)"; fi
      if command -v freshclam >/dev/null 2>&1; then
        systemctl stop clamav-freshclam >/dev/null 2>&1 || true
        freshclam --quiet >/dev/null 2>&1 || true
        systemctl start clamav-freshclam >/dev/null 2>&1 || true
      fi
      if command -v rkhunter >/dev/null 2>&1; then
        rkhunter --update --quiet >/dev/null 2>&1 || true
        rkhunter --propupd --quiet >/dev/null 2>&1 || true
      fi
    else
      log "[!] No supported package manager (apt-get) present; scanner installation is skipped."
    fi
  fi
fi

log "[+] Recording SHA-256 of scanner binaries used:"
for binary in "$RK_BINARY" "$CHK_BINARY" "$CLAM_BINARY"; do
  [ -n "$binary" ] || continue
  [ -x "$binary" ] || continue
  record_hash "$binary"
done

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would run: chkrootkit -q"
  log "[DRY-RUN] Would run: rkhunter --check --skip-keypress --report-warnings-only"
  log "[DRY-RUN] Would run: clamscan --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www"
else
  if [ -n "$CHK_BINARY" ] && [ -x "$CHK_BINARY" ]; then
    log "[+] Running chkrootkit (real binary name, no obfuscation)..."
    "$CHK_BINARY" -q >> "$LOG_FILE" 2>&1 || log "[!] chkrootkit returned a non-zero exit code."
  else
    log "[!] chkrootkit not available; skipping."
  fi

  if [ -n "$RK_BINARY" ] && [ -x "$RK_BINARY" ]; then
    log "[+] Running rkhunter..."
    "$RK_BINARY" --check --skip-keypress --report-warnings-only >> "$LOG_FILE" 2>&1 || log "[!] rkhunter returned a non-zero exit code."
  else
    log "[!] rkhunter not available; skipping."
  fi

  if [ -n "$CLAM_BINARY" ] && [ -x "$CLAM_BINARY" ]; then
    log "[+] Running ClamAV against common living-off-the-land directories..."
    "$CLAM_BINARY" --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www >> "$LOG_FILE" 2>&1 || log "[!] ClamAV returned a non-zero exit code."
  else
    log "[!] clamscan not available; skipping."
  fi
fi

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
  LOG_FILE_PATH="$LOG_FILE"
  log "[+] Evidence manifest: $MANIFEST_FILE"
  log "[+] Log file: $LOG_FILE"
  log "[+] Dry run complete; no live evidence was packaged."
  exit 0
fi

tar -czf "$PACKAGE_FILE" -C "$(dirname "$WORKSPACE")" "$(basename "$WORKSPACE")" || {
  log "[!] Failed to create final archive: $PACKAGE_FILE"
  exit 1
}
sha256sum "$PACKAGE_FILE" > "$PACKAGE_HASH_FILE"

log "[+] Evidence package: $PACKAGE_FILE"
log "[+] Package hash: $(cat "$PACKAGE_HASH_FILE")"
log "[+] Binary/log manifest: $MANIFEST_FILE"
log "[-] Transfer the tarball AND its .sha256 together, and verify the hash on the receiving end before treating the archive as evidence."

exit 0
