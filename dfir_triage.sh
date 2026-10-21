#!/usr/bin/env bash
# ============================================================================== 
# DFIR Triage & Rootkit Hunter — Advanced Forensics Suite v5
# ============================================================================== 
# Purpose:
#   Build a high-value, evidence-first Linux forensic snapshot suitable for
#   incident response, red-team review, and system-level threat hunting.
#
# Security model:
#   - Transparent, attributable execution.
#   - Prefer trusted binaries from external media when available.
#   - Preserve chain-of-custody and verifiable integrity.
#   - Collect evidence without randomization or stealth behavior.
# ============================================================================== 

set -Eeuo pipefail
umask 077

SCRIPT_NAME="$(basename "$0")"
VERSION="5.0.0"

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
  echo "    Use --dry-run for safe validation without altering the host." >&2
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

append_summary() {
  printf '%s\n' "$*" >> "$SUMMARY_FILE"
}

copy_artifact() {
  local label="$1"
  local src="$2"
  local dst_dir="$3"

  [ -n "$src" ] || return 0
  if [ -e "$src" ]; then
    mkdir -p "$dst_dir"
    local base="$(basename "$src")"
    if [ -d "$src" ]; then
      cp -a "$src" "$dst_dir/" 2>/dev/null || warn "Unable to copy directory: $src"
    else
      cp -a "$src" "$dst_dir/$base" 2>/dev/null || warn "Unable to copy file: $src"
    fi
    log "[*] Captured $label: $src"
  fi
}

capture_process_artifacts() {
  local pid="$1"
  local proc_dir="/proc/$pid"
  local out_dir="$ARTIFACT_DIR/processes/$pid"

  [ -d "$proc_dir" ] || return 0
  mkdir -p "$out_dir"

  if [ -r "$proc_dir/status" ]; then cp -a "$proc_dir/status" "$out_dir/status" 2>/dev/null || true; fi
  if [ -r "$proc_dir/cmdline" ]; then cp -a "$proc_dir/cmdline" "$out_dir/cmdline" 2>/dev/null || true; fi
  if [ -r "$proc_dir/environ" ]; then cp -a "$proc_dir/environ" "$out_dir/environ" 2>/dev/null || true; fi
  if [ -r "$proc_dir/mountinfo" ]; then cp -a "$proc_dir/mountinfo" "$out_dir/mountinfo" 2>/dev/null || true; fi
  if [ -r "$proc_dir/maps" ]; then cp -a "$proc_dir/maps" "$out_dir/maps" 2>/dev/null || true; fi
  if [ -r "$proc_dir/exe" ]; then
    cp -a "$proc_dir/exe" "$out_dir/exe" 2>/dev/null || true
  fi
  if [ -r "$proc_dir/fd" ]; then
    cp -a "$proc_dir/fd" "$out_dir/fd" 2>/dev/null || true
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
  echo "[-] Failed to create evidence workspace." >&2
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
mkdir -p "$ARTIFACT_DIR/processes"
chattr +a "$LOG_FILE" 2>/dev/null || log "[!] Warning: chattr +a unsupported on this filesystem; log is not append-only protected."

log "[*] DFIR Triage & Rootkit Hunter v${VERSION}"
log "[*] Started by $(logname 2>/dev/null || whoami) on $HOSTNAME_SAFE"
log "[*] Workspace: $WORKSPACE"
log "[*] Scan root: $SCAN_ROOT"
log "[*] Trusted binary directory: $TRUSTED_DIR"
log "[*] Chain-of-custody: investigator + hostname + UTC timestamp recorded above."

append_summary "DFIR Triage Summary"
append_summary "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
append_summary "Host: $HOSTNAME_SAFE"
append_summary "Investigator: $(logname 2>/dev/null || whoami)"
append_summary "Workspace: $WORKSPACE"
append_summary "============================"

# -----------------------------------------------------------------------------
# 0. Baseline system data
# -----------------------------------------------------------------------------
log "[*] PHASE 0: Host Baseline"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would capture uname, OS, uptime, mounts, and user context."
else
  log "[+] Kernel and OS"
  uname -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/os-release ] && cat /etc/os-release 2>/dev/null | tee -a "$LOG_FILE" || true
  [ -f /proc/version ] && cat /proc/version 2>/dev/null | tee -a "$LOG_FILE" || true

  log "[+] Uptime and storage"
  uptime 2>&1 | tee -a "$LOG_FILE" || true
  df -h 2>&1 | tee -a "$LOG_FILE" || true
  mount 2>&1 | tee -a "$LOG_FILE" || true
  if have_cmd lsblk; then lsblk -f 2>&1 | tee -a "$LOG_FILE" || true; fi

  log "[+] Users and privilege context"
  id 2>&1 | tee -a "$LOG_FILE" || true
  who -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/passwd ] && awk -F: '{print $1":"$3":"$4":"$6":"$7}' /etc/passwd 2>/dev/null | tee -a "$LOG_FILE" || true
  if have_cmd lastlog; then lastlog 2>/dev/null | tee -a "$LOG_FILE" || true; fi
fi

# -----------------------------------------------------------------------------
# 1. Process-level forensics
# -----------------------------------------------------------------------------
log "[*] PHASE 1: Process-Level Forensics"

log "[+] Capturing process metadata and suspicious process state..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would dump /proc process metadata, cmdline, environ, maps, stat, status, and executables."
else
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    pid="${proc#/proc/}"
    capture_process_artifacts "$pid"
  done

  log "[+] Full process table"
  ps -eo pid,ppid,uid,comm,args,etimes --forest 2>/dev/null | tee -a "$LOG_FILE" || true

  log "[+] Open files and network listeners"
  if have_cmd lsof; then
    lsof -nP 2>/dev/null | head -n 500 | tee -a "$LOG_FILE" || true
  else
    log "[!] lsof not installed; skipping open-file inventory."
  fi
fi

log "[+] Hidden process and process tree analysis..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare /proc and ps, and inspect suspicious process ancestry."
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
    append_summary "ALERT: Hidden process indicator detected: $HIDDEN_PIDS"
  else
    log "[+] No discrepancy between /proc and ps."
  fi

  log "[+] Process ancestry summary"
  ps -eo pid,ppid,uid,comm,args --forest 2>/dev/null | tee -a "$LOG_FILE" || true
fi

# -----------------------------------------------------------------------------
# 2. Runtime anomaly detection
# -----------------------------------------------------------------------------
log "[*] PHASE 2: Runtime Anomaly Analysis"

log "[+] Scanning for deleted or unlinked binary execution paths..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect /proc/*/exe for deleted entries."
else
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    target="$(readlink "$proc/exe" 2>/dev/null || true)"
    if [ -n "$target" ] && [[ "$target" == *" (deleted)"* ]]; then
      printf '%s %s\n' "${proc#/proc/}" "$target" | tee -a "$LOG_FILE"
    fi
  done
fi

log "[+] Hidden kernel modules and preload poisoning checks..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare /proc/modules with lsmod and inspect preload configuration."
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
    log "[!] ALERT: Modules visible in /proc/modules but hidden from lsmod: $HIDDEN_MODS"
    append_summary "ALERT: Hidden kernel module indicator detected: $HIDDEN_MODS"
  else
    log "[+] No discrepancy between /proc/modules and lsmod."
  fi

  for candidate in /etc/profile /etc/profile.d /etc/environment /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile; do
    [ -e "$candidate" ] || continue
    grep -RIn "LD_PRELOAD\|LD_LIBRARY_PATH\|PRELOAD" "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/ld.so.preload ]; then
    log "[!] ALERT: /etc/ld.so.preload exists; contents:"
    cat /etc/ld.so.preload 2>/dev/null | tee -a "$LOG_FILE" || true
    append_summary "ALERT: /etc/ld.so.preload exists."
  fi
fi

# -----------------------------------------------------------------------------
# 3. Persistence and artifact audit
# -----------------------------------------------------------------------------
log "[*] PHASE 3: Persistence Artifact Audit"

log "[+] SSH persistence checks..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect SSH key files and config."
else
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    log "[*] $candidate"
    grep -HnE 'ssh-rsa|ssh-ed25519|ecdsa-sha2|PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|AuthorizedKeysFile|Match ' "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done < <(find "$SCAN_ROOT" -xdev -type f \( -name 'authorized_keys' -o -name 'known_hosts' -o -name 'sshd_config' -o -name 'config' \) 2>/dev/null)
fi

log "[+] Cron, systemd, and startup persistence checks..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect cron/systemd/startup dirs for recent files."
else
  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/init.d /etc/rc.d; do
    [ -e "$dir" ] || continue
    find "$dir" -xdev -type f -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/rc.local ]; then
    log "[+] /etc/rc.local contents:"
    cat /etc/rc.local 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
  for dir in /etc/profile.d /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart /etc/rc*.d; do
    [ -e "$dir" ] || continue
    find "$dir" -maxdepth 2 -type f 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

# -----------------------------------------------------------------------------
# 4. Suspicious file and directory hunting
# -----------------------------------------------------------------------------
log "[*] PHASE 4: Suspicious File & Directory Hunt"

log "[+] Recent executable artifacts and scripts in ephemeral and user spaces..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would search temp, service, and user directories for suspicious recent scripts and binaries."
else
  find /tmp /dev/shm /var/tmp /opt /srv /home /var/www /usr/local/bin /usr/local/sbin -xdev -type f \( -perm -u+x -o -iname '*.sh' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.php' -o -iname '*.bin' \) -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
fi

log "[+] Writable executables in core directories..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would detect writable executable files in writable service locations."
else
  for dir in /tmp /var/tmp /dev/shm /opt /srv /home /var/www /usr/local/bin /usr/local/sbin; do
    [ -d "$dir" ] || continue
    find "$dir" -xdev -type f \( -perm -o+w -o -perm -g+w \) -perm /111 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

log "[+] Hidden or suspicious names..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would scan the filesystem for hidden or suspicious names."
else
  find "$SCAN_ROOT" -xdev \( -name '.*' -o -name '*tmp*' -o -name '*bak*' -o -name '*evil*' -o -name '*.so' \) 2>/dev/null | head -n 500 | tee -a "$LOG_FILE" || true
fi

# -----------------------------------------------------------------------------
# 5. Collector / artifact capture
# -----------------------------------------------------------------------------
log "[*] PHASE 5: Artifact Capture"
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
# 6. Scanner selection and integrity
# -----------------------------------------------------------------------------
log "[*] PHASE 6: Trusted Scanner Selection"
CLAM_BINARY=""
RK_BINARY=""
CHK_BINARY=""

if [ -x "$TRUSTED_DIR/clamscan" ] && [ -x "$TRUSTED_DIR/rkhunter" ] && [ -x "$TRUSTED_DIR/chkrootkit" ]; then
  CLAM_BINARY="$TRUSTED_DIR/clamscan"
  RK_BINARY="$TRUSTED_DIR/rkhunter"
  CHK_BINARY="$TRUSTED_DIR/chkrootkit"
  log "[+] Using externally supplied trusted binaries from $TRUSTED_DIR."
else
  log "[!] No complete trusted scanner set found at $TRUSTED_DIR."
  if [ "$NO_INSTALL" -eq 1 ]; then
    log "[!] --no-install set; scanner installation is skipped."
  else
    if have_cmd apt-get; then
      log "[+] Attempting fallback install via apt-get."
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
    log "[+] Running ClamAV against common living-off-the-land directories..."
    "$CLAM_BINARY" --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www /srv /opt >> "$LOG_FILE" 2>&1 || warn "ClamAV returned a non-zero exit code."
  else
    warn "clamscan not available; skipping."
  fi
fi

# -----------------------------------------------------------------------------
# 7. Summary and packaging
# -----------------------------------------------------------------------------
log "[*] PHASE 7: Summary & Finalization"
append_summary "============================"
append_summary "Findings summary"
append_summary "- Scanner binaries used:"
for b in "$RK_BINARY" "$CHK_BINARY" "$CLAM_BINARY"; do
  if [ -n "$b" ] && [ -x "$b" ]; then
    append_summary "  * $b"
  fi
done
append_summary "- Log file: $LOG_FILE"
append_summary "- Manifest: $MANIFEST_FILE"
append_summary "- Artifacts directory: $ARTIFACT_DIR"
append_summary "=== End of report ==="

if [ -f "$LOG_FILE" ]; then
  sha256sum "$LOG_FILE" >> "$MANIFEST_FILE"
fi
if [ -f "$SUMMARY_FILE" ]; then
  sha256sum "$SUMMARY_FILE" >> "$MANIFEST_FILE"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would create final evidence archive: $PACKAGE_FILE"
  log "[DRY-RUN] Would hash archive and write $PACKAGE_HASH_FILE"
  log "[+] Summary report: $SUMMARY_FILE"
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
log "[-] Transfer the tarball and .sha256 together and verify the hash on the receiving end before treating the archive as evidence."

exit 0
