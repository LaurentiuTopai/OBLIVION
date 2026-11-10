# Credential Access / Secrets Harvesting

**MITRE ATT&CK**: T1003.008, T1552.001, T1552.004  
**Syscalls monitored**: `open`, `openat`, `read`

---

## Why these syscalls?

### `open` / `openat` on `/etc/shadow` → `file_open` event
The `security_file_open` LSM hook fires on every file open call. `/etc/shadow` stores hashed
passwords for all local accounts and is readable only by root and `shadow` group members.
The EDR maintains a whitelist of processes that have a legitimate reason to open this file:
`sshd`, `login`, `su`, `sudo`, `passwd`, `unix_chkpwd` (the PAM helper), and `useradd`.
Any other process opening `/etc/shadow` indicates credential dumping — either by a local
attacker with root access or a rootkit harvesting credentials.

### `open` / `openat` on private key paths → `file_open` event
SSH private keys (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.) and certificate stores give
an attacker persistent access to remote systems. The EDR watches `file_open` events for path
suffixes matching common private key filenames. Access by any process other than `ssh`,
`sshd`, or the owning user's shell is flagged.

### `open` on credential files → `file_open` event
Application credential files (`.aws/credentials`, `.netrc`, browser credential databases)
are targeted by info-stealers and spyware. The EDR watches for processes accessing these
paths that do not match the expected accessing binary (e.g., `aws`, `curl`, `git`).

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `cred-shadow-file-access` | T1003.008 | 4 | Unauthorized process opened `/etc/shadow` |
| `cred-ssh-private-key-read` | T1552.004 | 4 | Unexpected process read SSH private key |
| `cred-aws-credentials-access` | T1552.001 | 4 | Unexpected process accessed AWS credentials file |
| `cred-pam-tampering` | T1556.003 | 5 | Write to PAM module directories |
