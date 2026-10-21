# 🛡️ DFIR Triage & Rootkit Hunter

A transparent, chain-of-custody-first Linux incident-response and forensic analysis script built for authorized use in hostile or partially compromised environments.

![license](https://img.shields.io/badge/license-MIT-blue.svg)
![bash](https://img.shields.io/badge/shell-bash-121011.svg)
![platform](https://img.shields.io/badge/platform-linux-informational.svg)

## What this tool does

This script is designed to give an investigator a fast, defensible snapshot of a potentially compromised Linux host without trying to hide itself. It emphasizes evidence preservation, clear attribution, and verifiable execution.

It checks for:

- hidden processes via /proc vs ps comparison
- hidden kernel modules via /proc/modules vs lsmod comparison
- LD_PRELOAD / ld.so.preload poisoning
- deleted or unlinked process execution paths
- SSH persistence and authorized_keys exposure
- cron, systemd, shell startup, and rc-script persistence
- suspicious startup / autostart entries
- recent malicious or unusual executables in temp and user spaces
- writable executable files in common persistence locations
- network listeners and socket inventory
- scanner integrity via SHA-256 hashing of all binaries used
- final evidence packaging with a hash-verified archive

## Why it looks this way

Most triage scripts either trust the host's own tools blindly or try to hide their activity. This one deliberately avoids both extremes:

- it does not conceal its execution
- it logs everything with UTC timestamps
- it prefers trusted external binaries when available
- it records hashes to preserve chain-of-custody
- it keeps logs append-only where the filesystem supports it

This makes the output more trustworthy as evidence and easier to defend in a forensic review.

## Features

| Area | Capability |
|---|---|
| Runtime anomaly detection | /proc vs ps hidden process checks |
| Kernel checks | /proc/modules vs lsmod module mismatch detection |
| Preload analysis | LD_PRELOAD and ld.so.preload inspection |
| Process forensics | suspicious deleted/unlinked command paths |
| Persistence audit | SSH, cron, systemd, rc.d, profile.d, autostart |
| File hunting | recent scripts/binaries in temp and writable directories |
| Network triage | socket and listener review |
| Evidence integrity | SHA-256 hashing of binary and log artifacts |
| Final packaging | compressed evidence bundle with .sha256 verification file |
| Reporting | investigator summary report generated alongside the evidence |

## Requirements

- Linux system
- root privileges
- bash
- coreutils
- procps
- iproute2
- optional: clamav, rkhunter, chkrootkit (installed automatically if permitted)

## Usage

Basic live run:

```bash
sudo ./dfir_triage.sh
```

Dry run (safe validation without executing active host checks):

```bash
sudo ./dfir_triage.sh --dry-run
```

Custom scanner directory and scan root:

```bash
sudo ./dfir_triage.sh --trusted-dir /mnt/ir-tools --scan-root /
```

Do not install scanners automatically:

```bash
sudo ./dfir_triage.sh --no-install
```

## Output

The script creates a randomly named workspace under the configured workspace root (`/tmp` by default):

- `audit_<timestamp>.log` — full runtime evidence log
- `manifest_<timestamp>.sha256` — SHA-256 entries for binaries and evidence files
- `summary_<timestamp>.txt` — investigator summary for quick triage handoff
- `artifacts/` — captured config and persistence-related files
- `<workspace>.tar.gz` + `.sha256` — final evidence package and verification hash

Verify the archive hash on the receiving end before treating it as evidence.

## Security and forensic notes

- The script intentionally avoids stealth or obfuscation.
- It favors transparent evidence generation over any anti-forensic trickery.
- It does not attempt to hide the script's existence or execution path.
- It prefers known-good external binaries when they are available.
- All high-value outputs are hashed and packaged with integrity metadata.

## Disclaimer

Built for authorized incident response, system administration, and security review on systems you own or are explicitly authorized to assess. This is a rapid triage and forensic aid, not a substitute for a complete, case-driven investigation by trained responders.

## License

MIT — see [LICENSE](LICENSE).
