#!/usr/bin/env bash
# ============================================================================== 
# DFIR Triage & Rootkit Hunter — Advanced Forensics Suite v6
# ============================================================================== 
# Purpose:
#   Perform a transparent, evidence-first Linux triage and rootkit audit with
#   broader behavior analysis, process artifacts, and investigator-ready output.
#
# Features:
#   - runtime anomaly detection
#   - hidden process / module checks
#   - persistence analysis (SSH, cron, systemd, RC)
#   - suspicious process classification
#   - optional memory snapshot capture when tools are available
#   - hash manifest and evidence packaging
#   - summary report + optional JSON report export
# ============================================================================== 

set -Eeuo pipefail
umask 077

SCRIPT_NAME="$(basename "$0")"
VERSION="6.0.0"

DRY_RUN=0
NO_INSTALL=0
JSON_REPORT=0
MEMORY_DUMP=0
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
  --json-report           Write a JSON report to the evidence workspace
  --memory-dump           Attempt optional process core dumps when gcore is available
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
    --json-report)
      JSON_REPORT=1
      shift
      ;;
    --memory-dump)
      MEMORY_DUMP=1
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

append_summary() {
  printf '%s\n' "$*" >> "$SUMMARY_FILE"
}

append_json() {
  printf '%s\n' "$*" >> "$JSON_REPORT_FILE"
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
  if [ -r "$proc_dir/stat" ]; then cp -a "$proc_dir/stat" "$out_dir/stat" 2>/dev/null || true; fi
  if [ -r "$proc_dir/exe" ]; then cp -a "$proc_dir/exe" "$out_dir/exe" 2>/dev/null || true; fi
  if [ -r "$proc_dir/fd" ]; then cp -a "$proc_dir/fd" "$out_dir/fd" 2>/dev/null || true; fi
}

attempt_memory_dump() {
  local pid="$1"
  local dump_dir="$ARTIFACT_DIR/memory"
  [ "$MEMORY_DUMP" -eq 1 ] || return 0
  [ -d "/proc/$pid" ] || return 0

  if have_cmd gcore; then
    mkdir -p "$dump_dir"
    gcore -o "$dump_dir/${pid}" "$pid" >/dev/null 2>&1 || true
  fi
}

is_suspicious_process() {
  local pid="$1"
  local exe_path="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  local cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"

  if [ -z "$exe_path" ]; then
    return 1
  fi

  case "$exe_path" in
    /tmp/*|/dev/shm/*|/var/tmp/*|/run/*|/home/*/.cache*|/home/*/.local/share*|/var/www/*|/srv/*|/opt/*)
      return 0
      ;;
  esac

  case "$cmdline" in
    *"base64 "*|*"curl "*|*"wget "*|*"nc "*|*"ncat "*|*"bash -c "*|*"python -c "*|*"perl -e "*|*"php -r "*)
      return 0
      ;;
  esac

  if [ -f "$exe_path" ]; then
    if [ -w "$exe_path" ] || [ -g "$exe_path" ]; then
      return 0
    fi
  fi

  return 1
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
JSON_REPORT_FILE="$WORKSPACE/report_${TIMESTAMP}.json"
ARTIFACT_DIR="$WORKSPACE/artifacts"
PACKAGE_FILE="$WORKSPACE.tar.gz"
PACKAGE_HASH_FILE="$PACKAGE_FILE.sha256"

: > "$LOG_FILE"
: > "$SUMMARY_FILE"
if [ "$JSON_REPORT" -eq 1 ]; then : > "$JSON_REPORT_FILE"; fi
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

if [ "$JSON_REPORT" -eq 1 ]; then
  append_json '{'
  append_json '  "timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",'
  append_json '  "host": "'"$HOSTNAME_SAFE"'",'
  append_json '  "investigator": "'"$(logname 2>/dev/null || whoami)"'",'
  append_json '  "workspace": "'"$WORKSPACE"'",'
  append_json '  "checks": {'
fi

# -----------------------------------------------------------------------------
# 0. Baseline data
# -----------------------------------------------------------------------------
log "[*] PHASE 0: Host Baseline"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would capture uname, OS details, package inventory, user context, and mounts."
else
  log "[+] Kernel and OS"
  uname -a 2>&1 | tee -a "$LOG_FILE" || true
  [ -f /etc/os-release ] && cat /etc/os-release 2>/dev/null | tee -a "$LOG_FILE" || true
  [ -f /proc/version ] && cat /proc/version 2>/dev/null | tee -a "$LOG_FILE" || true

  log "[+] Installed package inventory"
  if have_cmd dpkg; then dpkg -l 2>/dev/null | head -n 200 | tee -a "$LOG_FILE" || true; fi
  if have_cmd rpm; then rpm -qa 2>/dev/null | head -n 200 | tee -a "$LOG_FILE" || true; fi

  log "[+] Uptime, storage, and mounts"
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
# 1. Process-level forensic capture
# -----------------------------------------------------------------------------
log "[*] PHASE 1: Process-Level Forensics"

log "[+] Capturing /proc process metadata and suspicious process classification..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would capture per-process metadata and attempt optional memory dumps."
else
  suspicious_count=0
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    pid="${proc#/proc/}"
    capture_process_artifacts "$pid"
    if is_suspicious_process "$pid"; then
      suspicious_count=$((suspicious_count + 1))
      log "[!] Possibly suspicious process PID $pid"
      append_summary "Suspicious process PID $pid"
      if [ "$JSON_REPORT" -eq 1 ]; then
        append_json '    "suspicious_process_'"$pid"'": "'"$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")"'",'
      fi
      attempt_memory_dump "$pid"
    fi
  done
  log "[+] Suspicious process count: $suspicious_count"
  append_summary "Suspicious process count: $suspicious_count"
fi

log "[+] Full process table with ancestor context"
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would print the current process tree."
else
  ps -eo pid,ppid,uid,comm,args,etimes --forest 2>/dev/null | tee -a "$LOG_FILE" || true
fi

# -----------------------------------------------------------------------------
# 2. Runtime anomaly analysis
# -----------------------------------------------------------------------------
log "[*] PHASE 2: Runtime Anomaly Analysis"

log "[+] Hidden process detection via /proc vs ps..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare kernel-visible and userland-visible PIDs."
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
    append_summary "ALERT: Hidden process indicator: $HIDDEN_PIDS"
  else
    log "[+] No discrepancy between /proc and ps."
  fi
fi

log "[+] Hidden module and preload checks..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would compare /proc/modules with lsmod and inspect preload values."
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
    log "[!] ALERT: Kernel modules hidden from lsmod: $HIDDEN_MODS"
    append_summary "ALERT: Hidden kernel module indicator: $HIDDEN_MODS"
  fi

  for candidate in /etc/profile /etc/profile.d /etc/environment /root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile; do
    [ -e "$candidate" ] || continue
    grep -RIn "LD_PRELOAD\|LD_LIBRARY_PATH\|PRELOAD" "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done
  if [ -f /etc/ld.so.preload ]; then
    log "[!] ALERT: /etc/ld.so.preload exists. Contents:"
    cat /etc/ld.so.preload 2>/dev/null | tee -a "$LOG_FILE" || true
  fi
fi

# -----------------------------------------------------------------------------
# 3. Persistence analysis
# -----------------------------------------------------------------------------
log "[*] PHASE 3: Persistence Artifact Audit"

log "[+] SSH persistence checks..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would audit SSH keys and config files."
else
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    log "[*] $candidate"
    grep -HnE 'ssh-rsa|ssh-ed25519|ecdsa-sha2|PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|AuthorizedKeysFile|Match ' "$candidate" 2>/dev/null | tee -a "$LOG_FILE" || true
  done < <(find "$SCAN_ROOT" -xdev -type f \( -name 'authorized_keys' -o -name 'known_hosts' -o -name 'sshd_config' -o -name 'config' \) 2>/dev/null)
fi

log "[+] Cron, systemd, and startup checks..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would inspect cron/systemd/startup entries for modifications."
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
# 4. Suspicious file and executable hunt
# -----------------------------------------------------------------------------
log "[*] PHASE 4: Suspicious File Hunt"

log "[+] Recent executable artifacts and scripts in common writable spaces..."
if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would scan temp, service, and writable directories for recent executable artifacts."
else
  find /tmp /dev/shm /var/tmp /opt /srv /home /var/www /usr/local/bin /usr/local/sbin -xdev -type f \( -perm -u+x -o -iname '*.sh' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.php' -o -iname '*.bin' \) -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE" || true
  for dir in /tmp /var/tmp /dev/shm /opt /srv /home /var/www /usr/local/bin /usr/local/sbin; do
    [ -d "$dir" ] || continue
    find "$dir" -xdev -type f \( -perm -o+w -o -perm -g+w \) -perm /111 2>/dev/null | tee -a "$LOG_FILE" || true
  done
fi

# -----------------------------------------------------------------------------
# 5. Artifact capture
# -----------------------------------------------------------------------------
log "[*] PHASE 5: Artifact Collection"
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
# 6. Scanner and checks
# -----------------------------------------------------------------------------
log "[*] PHASE 6: Scanner Selection"
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
  log "[DRY-RUN] Would run chkrootkit, rkhunter, and clamscan."
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
    log "[+] Running ClamAV against common directories..."
    "$CLAM_BINARY" --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www /srv /opt >> "$LOG_FILE" 2>&1 || warn "ClamAV returned a non-zero exit code."
  else
    warn "clamscan not available; skipping."
  fi
fi

# -----------------------------------------------------------------------------
# 7. Finalize, hash, package report
# -----------------------------------------------------------------------------
log "[*] PHASE 7: Finalization"
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

if [ "$JSON_REPORT" -eq 1 ]; then
  append_json '  },'
  append_json '  "summary": "'"$(tr '\n' ' ' < "$SUMMARY_FILE" | sed 's/"/\\"/g')"'"'
  append_json '}'
fi

if [ "$DRY_RUN" -eq 1 ]; then
  log "[DRY-RUN] Would create final evidence archive: $PACKAGE_FILE"
  log "[DRY-RUN] Would hash the archive and write $PACKAGE_HASH_FILE"
  log "[+] Summary report: $SUMMARY_FILE"
  log "[+] Manifest: $MANIFEST_FILE"
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
if [ "$JSON_REPORT" -eq 1 ]; then
  log "[+] JSON report: $JSON_REPORT_FILE"
fi
log "[-] Transfer the tarball and .sha256 together and verify the hash on the receiving end before treating the archive as evidence."

exit 0
