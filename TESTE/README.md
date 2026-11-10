# OBLIVION EDR — Adversary Emulation Test Suite

## Prerequisites

```bash
# Terminal 1 — start the EDR (requires root for eBPF)
cd /path/to/OBLIVION/GO
sudo ./oblivion 2>&1 | tee oblivion_alerts.log

# Terminal 2 — run the tests
cd /path/to/OBLIVION/GO/TESTE
sudo python3 edr_test_suite.py
```

## Rules covered

| Category | Rule IDs |
|---|---|
| Command & Control | `c2-shell-direct-socket`, `c2-netconn-exec-shell`, `c2-parent-server-spawn-shell`, `c2-shell-to-external-low-port` |
| Defense Evasion | `defense-ld-preload-write`, `defense-ld-preload-open`, `defense-tmp-exec-rename-to-sys`, `binary-self-deletion` (Go) |
| Execution LotL | `exec-from-tmp`, `exec-fileless-memfd`, `exec-from-dev-shm`, `exec-interpreter-script-from-tmp` |
| Persistence | `persist-cron-job-creation`, `persist-systemd-unit-drop`, `persist-ssh-authorized-key`, `persist-pam-config-write`, `persist-initd-script-drop`, `persist-etc-crontab-write` |
| Privilege Escalation | `privesc-suid-bit-set`, `privesc-unprivileged-userns`, `privesc-root-euid-transition`, `privesc-cap-sys-admin-acquired` |
| Credential Access | `cred-shadow-file-access`, `cred-pam-tampering`, `cred-ssh-private-key-read`, `cred-aws-credentials-access`, `cred-docker-config-access` |
| Container Escape | `container-docker-sock-access`, `container-docker-api-tcp`, `container-proc-kernel-write`, `container-cgroup-release-agent` |
| WebShells / RCE | `webshell-server-spawn-shell`, `webshell-server-spawn-recon`, `webshell-server-spawn-downloader`, `webshell-server-spawn-netcat` |
| Impact / Malware | `impact-crypto-stratum-ports`, `impact-crypto-xmrig-exec`, `impact-wiper-tmp-mass-unlink`, `ransomware-suspected` (Go) |
| Memory Exploitation | `rwx-anonymous-memory`, `ptrace-process-injection` (Go) |

## Notes

- Tests that require writing to `/etc/` will fail if not run as root — the kernel LSM hook fires regardless, so the EDR will still generate the alert even when the write is blocked by the OS.
- `test_privesc_root_transition` requires compiling a small C setuid binary; it is skipped if `gcc` is not available.
- `test_container_docker_sock` only triggers if `/var/run/docker.sock` exists on the system.
