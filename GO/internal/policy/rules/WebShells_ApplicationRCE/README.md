# WebShells / Application RCE

**MITRE ATT&CK**: T1505.003, T1190  
**Syscalls monitored**: `execve`, `clone`, `fork`

---

## Why these syscalls?

### `execve` with parent process check → `exec` event
The `security_bprm_check` LSM hook fires before any new program is loaded. When this event
arrives, the EDR looks up the calling process's parent in the stateful process table using
`State.FindParent(ppid)`. If the parent process is a known web server or application server
(`nginx`, `apache2`, `php-fpm`, `java`, `node`, `python`, etc.) and the child being executed
is a shell or recon tool (`bash`, `sh`, `nc`, `wget`, `curl`, `whoami`), this indicates that
remote code execution was achieved through the application layer — the classic webshell pattern.

The check uses `parent_comms` in the declarative YAML engine which calls `State.FindParent()`
to traverse the in-memory process tree. This is a **stateful parent-child relationship check**:
the parent process entry must already exist in the state from a prior `exec` event.

### Why not check file writes to webroot?
Writing a `.php` or `.jsp` file to a webroot is also a webshell indicator, but it generates
too many false positives (legitimate deployments, CI/CD pipelines). The process spawn check is
more reliable as it triggers only when the webshell is actually executed.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `webshell-server-spawn-shell` | T1505.003 | 5 | Web server spawned an interactive shell |
| `webshell-server-spawn-recon` | T1190 | 4 | Web server spawned a reconnaissance binary |
| `webshell-server-spawn-downloader` | T1105 | 5 | Web server spawned a file downloader |
| `webshell-server-spawn-netcat` | T1059 | 5 | Web server spawned netcat/socat variant |
