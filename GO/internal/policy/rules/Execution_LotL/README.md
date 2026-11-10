# Execution — Living off the Land (LotL)

**MITRE ATT&CK**: T1059, T1620, T1218  
**Syscalls monitored**: `execve`, `execveat`, `memfd_create`

---

## Why these syscalls?

### `execve` / `execveat` → `exec` event
The `security_bprm_check` LSM hook fires before the kernel loads a new program image. The EDR
captures the full path of the binary being executed. When this path starts with `/tmp/`,
`/dev/shm/`, or `/var/tmp/`, it indicates the binary was dropped to a world-writable directory
and immediately executed — a standard dropper/stager pattern. Legitimate software is installed
under `/usr`, `/bin`, `/opt`, or `/home`.

### `execve` on `/memfd:` or `/proc/self/fd/` → `exec` event (fileless)
`memfd_create()` creates an anonymous in-memory file descriptor backed by RAM with no path on
the filesystem. Attackers use it with the `fexecve()` syscall to run a payload that never touches
disk. The kernel still fires `security_bprm_check` with the executable path set to
`/memfd:<name>` or resolved via `/proc/self/fd/<n>`. The EDR catches this by checking the prefix
of `ev.Path` for these pseudo-paths.

### `execveat` with `AT_EMPTY_PATH` → `exec` event
Similar to memfd execution, `execveat()` with an empty path string and a file descriptor allows
executing a binary by its fd, bypassing filesystem path checks entirely.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `exec-from-tmp` | T1059 | 3 | Binary executed from `/tmp`, `/dev/shm`, `/var/tmp` |
| `exec-fileless-memfd` | T1620 | 5 | Binary executed from memfd or `/proc/self/fd` |
| `exec-from-dev-shm` | T1059 | 4 | Executable run directly from `/dev/shm` or `/run/shm` |
| `exec-script-interpreter-from-tmp` | T1059 | 4 | Script interpreter run with script path in `/tmp` |
