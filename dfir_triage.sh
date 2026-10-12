#!/usr/bin/env bash
# ==============================================================================
# DFIR Triage & Rootkit Hunter — Hardened, Chain-of-Custody Edition
# ==============================================================================
# Design principle: this tool must be TRUSTED, not HIDDEN. Its value as
# evidence depends on being verifiable and attributable — so it deliberately
# avoids binary obfuscation, randomized process names, and anti-forensic
# tricks. What it does instead, for a host you can't fully trust:
#   - brings in known-good scanner binaries from read-only external media
#     rather than trusting the (possibly compromised) host's own copies
#   - hashes every binary it runs and every artifact it produces
#   - records investigator, host, and timestamp for chain of custody
#   - keeps the log append-only and tamper-evident, not tamper-proof-via-stealth
#
# Run as root, ideally booted/mounted from trusted external media.
# ==============================================================================

set -uo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "[-] This script must be run as root." >&2
  exit 1
fi

# ------------------------------------------------------------------------------
# 1. Workspace setup
# ------------------------------------------------------------------------------
# Unpredictable path name: this is about avoiding symlink pre-staging races
# against a known path, not about hiding the tool's presence.

WORKSPACE=$(mktemp -d /tmp/.triage-XXXXXXXX) || { echo "[-] Failed to create workspace" >&2; exit 1; }
HOSTNAME_SAFE=$(hostname 2>/dev/null || echo "unknown-host")
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_FILE="$WORKSPACE/audit_${TIMESTAMP}.log"
MANIFEST_FILE="$WORKSPACE/manifest_${TIMESTAMP}.sha256"

touch "$LOG_FILE"
chattr +a "$LOG_FILE" 2>/dev/null || echo "[!] Warning: chattr +a unsupported on this filesystem; log is NOT append-only-protected."

log() {
    echo -e "$(date -u '+%Y-%m-%dT%H:%M:%SZ') | $1" | tee -a "$LOG_FILE"
}

log "[*] DFIR Triage started by $(logname 2>/dev/null || whoami) on $HOSTNAME_SAFE"
log "[*] Workspace: $WORKSPACE"
log "[*] Investigator and timestamp above are the chain-of-custody record."

# ------------------------------------------------------------------------------
# 2. Runtime anomaly checks
# ------------------------------------------------------------------------------
log "[*] PHASE 1: Runtime Anomaly Analysis"

log "[+] Scanning for processes executing from deleted/unlinked binaries..."
find /proc -maxdepth 1 -regex '/proc/[0-9]+' -exec ls -al {}/exe \; 2>/dev/null | grep -i "deleted" | tee -a "$LOG_FILE"

log "[+] Cross-referencing kernel-visible PIDs against 'ps' output (hidden process check)..."
KERNEL_PIDS=$(find /proc -maxdepth 1 -type d -name '[0-9]*' 2>/dev/null | sed 's|/proc/||' | sort -n)
USERLAND_PIDS=$(ps -A -o pid= 2>/dev/null | awk '{print $1}' | sort -n)
HIDDEN_PIDS=$(comm -23 <(echo "$KERNEL_PIDS") <(echo "$USERLAND_PIDS"))
if [ -n "$HIDDEN_PIDS" ]; then
    log "[!] ALERT: PIDs visible in /proc but missing from 'ps': $HIDDEN_PIDS"
else
    log "[+] No discrepancy between /proc and ps."
fi

# NEW CHECK: the same unlinking trick used to hide processes is used to hide
# kernel modules. /proc/modules reads the kernel's module list directly;
# lsmod is a userland tool that some rootkits hook. A discrepancy here is a
# strong LKM-rootkit indicator, same logic as the PID check above.
log "[+] Cross-referencing /proc/modules against 'lsmod' (hidden kernel module check)..."
LSMOD_MODS=$(lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort)
PROC_MODS=$(awk '{print $1}' /proc/modules 2>/dev/null | sort)
HIDDEN_MODS=$(comm -23 <(echo "$PROC_MODS") <(echo "$LSMOD_MODS"))
if [ -n "$HIDDEN_MODS" ]; then
    log "[!] ALERT: Kernel modules in /proc/modules but hidden from lsmod: $HIDDEN_MODS"
else
    log "[+] No discrepancy between /proc/modules and lsmod."
fi

log "[+] Checking for LD_PRELOAD hooking..."
grep -rH "LD_PRELOAD" /etc/profile /etc/profile.d/ /etc/environment ~/.bashrc ~/.bash_profile 2>/dev/null | tee -a "$LOG_FILE"
if [ -f /etc/ld.so.preload ]; then
    log "[!] ALERT: /etc/ld.so.preload exists. Contents:"
    cat /etc/ld.so.preload | tee -a "$LOG_FILE"
fi

log "[+] Checking listening sockets..."
ss -tulpn 2>/dev/null | tee -a "$LOG_FILE"

# ------------------------------------------------------------------------------
# 3. Persistence mechanism audit
# ------------------------------------------------------------------------------
log "[*] PHASE 2: Persistence Artifact Audit"

log "[+] Auditing SSH authorized_keys..."
find / -xdev -name "authorized_keys" 2>/dev/null -exec grep -HnE "ssh-rsa|ssh-ed25519|ecdsa-sha2" {} \; | tee -a "$LOG_FILE"

log "[+] Checking cron/systemd units modified in the last 7 days..."
find /etc/cron* /var/spool/cron /etc/systemd/system -type f -mtime -7 -ls 2>/dev/null | tee -a "$LOG_FILE"

# ------------------------------------------------------------------------------
# 4. Signature-based scanning — trusted binaries, honest execution
# ------------------------------------------------------------------------------
log "[*] PHASE 3: Signature-Based Scanning"
log "[!] A Ring-0-compromised host's package manager and PATH-resolved"
log "    binaries can't be fully trusted. The legitimate mitigation is to"
log "    bring statically-linked, pre-hashed copies of these tools in on"
log "    read-only external media and run those under their real names —"
log "    not to rename or hide whatever runs. This script looks for such"
log "    binaries at /mnt/ir-tools/ first and falls back to the host's"
log "    package manager (lower assurance) only if they aren't present."

TRUSTED_DIR="/mnt/ir-tools"
if [ -x "$TRUSTED_DIR/clamscan" ] && [ -x "$TRUSTED_DIR/rkhunter" ] && [ -x "$TRUSTED_DIR/chkrootkit" ]; then
    CLAM_BINARY="$TRUSTED_DIR/clamscan"
    RK_BINARY="$TRUSTED_DIR/rkhunter"
    CHK_BINARY="$TRUSTED_DIR/chkrootkit"
    log "[+] Using externally supplied trusted binaries from $TRUSTED_DIR."
else
    log "[!] No trusted external binaries at $TRUSTED_DIR — falling back to host package manager."
    DEBIAN_FRONTEND=noninteractive apt-get update -yq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -yq clamav rkhunter chkrootkit >/dev/null 2>&1
    systemctl stop clamav-freshclam >/dev/null 2>&1 || true
    freshclam --quiet || true
    systemctl start clamav-freshclam >/dev/null 2>&1 || true
    rkhunter --update --quiet || true
    rkhunter --propupd --quiet || true
    RK_BINARY=$(command -v rkhunter)
    CHK_BINARY=$(command -v chkrootkit)
    CLAM_BINARY=$(command -v clamscan)
fi

log "[+] Recording SHA-256 of the exact scanner binaries used:"
for b in "$RK_BINARY" "$CHK_BINARY" "$CLAM_BINARY"; do
    [ -n "$b" ] && [ -x "$b" ] && sha256sum "$b" | tee -a "$LOG_FILE" >> "$MANIFEST_FILE"
done

log "[+] Running chkrootkit (real name, no obfuscation)..."
"$CHK_BINARY" -q >> "$LOG_FILE" 2>&1

log "[+] Running rkhunter..."
"$RK_BINARY" --check --skip-keypress --report-warnings-only >> "$LOG_FILE" 2>&1

log "[+] Running ClamAV against common living-off-the-land directories..."
"$CLAM_BINARY" --infected --recursive --max-filesize=50M /tmp /dev/shm /var/tmp /home /var/www >> "$LOG_FILE" 2>&1

# ------------------------------------------------------------------------------
# 5. Seal and package evidence
# ------------------------------------------------------------------------------
log "[*] SCANS COMPLETE."
chattr -a "$LOG_FILE" 2>/dev/null || true

# Hash the final log before packaging, so any later tampering is detectable.
sha256sum "$LOG_FILE" >> "$MANIFEST_FILE"

tar -czf "$WORKSPACE.tar.gz" -C /tmp "$(basename "$WORKSPACE")"
sha256sum "$WORKSPACE.tar.gz" > "$WORKSPACE.tar.gz.sha256"

log "[+] Evidence package: $WORKSPACE.tar.gz"
log "[+] Package hash: $(cat "$WORKSPACE.tar.gz.sha256")"
log "[+] Binary/log manifest: $MANIFEST_FILE"
log "[-] Transfer the tarball AND its .sha256 together, and verify the hash"
log "    on the receiving end before treating the archive as evidence."
