# Defense Evasion / Anti-Forensics

**MITRE ATT&CK**: T1070.004, T1574.006, T1036.005  
**Syscalls monitored**: `unlink`, `unlinkat`, `inode_create`, `rename`, `open`, `openat`

---

## Why these syscalls?

### `unlink` / `unlinkat` → `inode_unlink` event
When the kernel fires `security_inode_unlink`, the EDR checks if the path being deleted matches
the calling process's own executable path (stored in `Proc.ExePath` from the last `execve`).
A binary deleting itself after execution is a classic anti-forensics pattern used by droppers
and malware to remove evidence of their presence from disk.

### `inode_create` + `rename` → `inode_create` / `inode_rename` events
The `security_inode_create` and `security_inode_rename` LSM hooks fire when new files are created
or renamed. Watching writes to `/etc/ld.so.preload` is critical: this file instructs the dynamic
linker (`ld-linux.so`) to load an arbitrary shared library into every new process. It is the most
common userland rootkit mechanism on Linux, allowing an attacker to intercept libc calls globally.

### `open` / `openat` → `file_open` event
The `security_file_open` LSM hook fires on every file open. Combined with path matching on
`/etc/ld.so.preload`, it catches reads of the file (attackers checking if their hook is active)
in addition to writes.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `defense-ld-preload-write` | T1574.006 | 5 | Write or create `/etc/ld.so.preload` |
| `defense-ld-preload-open` | T1574.006 | 4 | Unauthorized process reads `/etc/ld.so.preload` |
| `defense-binary-self-delete` | T1070.004 | 4 | Process deletes its own executable (stateful — Go detector) |
| `defense-tmp-exec-rename-to-sys` | T1036.005 | 4 | Binary renamed from `/tmp` into a system path |
