# 🛡️ DFIR Triage & Rootkit Hunter

A transparent, chain-of-custody-first incident response script for Linux hosts.

![license](https://img.shields.io/badge/license-MIT-blue.svg)
![bash](https://img.shields.io/badge/shell-bash-121011.svg)
![platform](https://img.shields.io/badge/platform-linux-informational.svg)

## What it is

A single bash script an incident responder can run on a Linux host to collect a fast, defensible snapshot of potential compromise: hidden processes, hidden kernel modules, `LD_PRELOAD` hooking, suspicious listening sockets, SSH-key and cron/systemd persistence — plus orchestrated `chkrootkit`, `rkhunter`, and `ClamAV` scans. All of it wrapped in SHA-256 hashing and an append-only, timestamped log built for evidentiary integrity.

## Why it looks the way it does

Most triage scripts either trust the host's own binaries blindly, or swing the other way and try to hide themselves — which quietly destroys the one thing that makes evidence usable: a verifiable chain of custody. This script takes a third path: it brings in trusted, pre-hashed binaries from external media when available, and hashes everything it runs and everything it produces, instead of relying on obfuscation. Nothing here is renamed or disguised — a responder's findings are only as good as their ability to prove what actually ran.

## Features

| Check | What it catches |
|---|---|
| `/proc` vs `ps` diff | Hidden processes (PID unlinking) |
| `/proc/modules` vs `lsmod` diff | Hidden kernel modules (LKM rootkits) |
| `LD_PRELOAD` / `ld.so.preload` scan | Userland hooking |
| Deleted-binary execution scan | Fileless / in-memory malware |
| `authorized_keys` audit | SSH persistence |
| cron / systemd diff (7-day) | Scheduled-task persistence |
| chkrootkit + rkhunter + ClamAV | Signature-based detection |
| SHA-256 manifest | Chain-of-custody for every binary run and artifact produced |

## Usage

```bash
sudo ./dfir_triage.sh
```

Optional, for hosts you don't fully trust: mount statically-linked, pre-verified copies of `clamscan`, `rkhunter`, and `chkrootkit` at `/mnt/ir-tools/` before running. The script will use those instead of the host's own package manager.

## Output

Everything lands in a randomly-named workspace under `/tmp/`:

- `audit_<timestamp>.log` — the full triage log
- `manifest_<timestamp>.sha256` — hashes of every binary used and the final log
- `<workspace>.tar.gz` + `.sha256` — the packaged, hash-verified evidence bundle

Verify the archive hash on the receiving end before treating it as evidence.

## Requirements

- Root
- `bash`, `coreutils`, `procps`, `iproute2`
- `clamav`, `rkhunter`, `chkrootkit` (auto-installed via `apt` if `/mnt/ir-tools` isn't present)

## Disclaimer

Built for authorized incident response and system administration on systems you own or are authorized to assess. It's a fast triage aid, not a substitute for a full forensic investigation by trained personnel when the stakes are high.

## License

MIT — see [LICENSE](LICENSE).
