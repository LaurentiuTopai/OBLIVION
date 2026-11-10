# Privilege Escalation

**MITRE ATT&CK**: T1548.001, T1548.003, T1068, T1611  
**Syscalls monitored**: `chmod`, `fchmod`, `fchmodat`, `setuid`, `capset`, `unshare`, `clone`

---

## Why these syscalls?

### `chmod` / `fchmodat` → `path_chmod` / `inode_setattr` event
The `security_path_chmod` and `security_inode_setattr` LSM hooks fire when file permissions
are changed. The EDR checks if the new mode has the SUID bit (`04000`) or SGID bit (`02000`)
set. When a non-package-manager process sets these bits on a binary, it creates a setuid
backdoor: any user executing that binary gains the owner's privileges (typically root).

### `setuid` / credential commit → `task_fix_setuid` / `bprm_committed_creds` event
The `task_fix_setuid` LSM hook fires when a process changes its effective UID. The
`bprm_committed_creds` hook fires after execve when the new program's credentials take effect
(e.g., executing a setuid binary). The EDR checks for a transition where `OldEuid != 0` and
`NewEuid == 0` — a non-root process becoming root — by any process not on the known-safe list
(`sudo`, `su`, `pkexec`, etc.).

### `unshare` / `clone` with CLONE_NEWUSER → `userns_create` event
The `security_userns_create` LSM hook fires when a new user namespace is created. Unprivileged
user namespaces are the most common kernel exploit primitive: they allow a non-root process to
map its UID to 0 inside the namespace, gaining capabilities needed to trigger kernel bugs. The
EDR flags any non-root process (UID != 0) creating a user namespace except known sandbox
runtimes (`bwrap`, `chrome`, `firefox`).

### `capset` → `capset` event
The `security_capset` LSM hook fires when a process modifies its capability sets. `CAP_SYS_ADMIN`
is the most dangerous Linux capability — it allows mounting filesystems, loading kernel modules,
overriding namespace restrictions, and much more. The EDR flags any non-root process that gains
`CAP_SYS_ADMIN` via `capset`.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `privesc-suid-bit-set` | T1548.001 | 5 | SUID/SGID bit set on file by non-package-manager |
| `privesc-root-euid-transition` | T1068 | 5 | Non-root process gains EUID 0 via unknown binary |
| `privesc-unprivileged-userns` | T1611 | 4 | Non-root process creates user namespace |
| `privesc-cap-sys-admin-acquired` | T1548 | 5 | Non-root process gains CAP_SYS_ADMIN |
