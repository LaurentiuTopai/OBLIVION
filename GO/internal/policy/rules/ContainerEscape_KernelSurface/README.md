# Container Escape / Kernel Attack Surface

**MITRE ATT&CK**: T1611, T1543  
**Syscalls monitored**: `socket`, `connect`, `open`, `openat`, `unshare`, `clone`

---

## Why these syscalls?

### `open` on Docker/container sockets → `file_open` event
Container runtime sockets (`/var/run/docker.sock`, `/run/containerd/containerd.sock`,
`/run/crio/crio.sock`) are Unix domain sockets that provide full control over the container
daemon. Any process inside a container that opens these sockets can spawn privileged containers,
mount the host filesystem, and escape isolation entirely. The `security_file_open` hook fires
on every open call, including for Unix sockets. The EDR checks the exact path and allows only
the daemon processes themselves (`dockerd`, `containerd`, `kubelet`).

### `socket_connect` to container socket paths → `socket_connect` event
Some container escape techniques use TCP connections to the Docker API exposed on
`127.0.0.1:2375` (unauthenticated) or `2376` (TLS). The EDR flags connections to these
ports from non-daemon processes.

### `inode_create` in `/proc/sysrq-trigger` or `/proc/sys/kernel` → `inode_create` event
Writing to kernel tunables via `/proc/sys/kernel/` can alter fundamental kernel behavior.
`/proc/sysrq-trigger` can be used to crash the system or trigger kernel panic. These writes
are legitimate only from system administrators or initialization processes.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `container-docker-sock-access` | T1611 | 5 | Unauthorized access to Docker/containerd socket |
| `container-docker-api-tcp` | T1611 | 5 | Connection to Docker TCP API port 2375/2376 |
| `container-proc-kernel-write` | T1543 | 4 | Write to sensitive `/proc/sys/kernel/` parameter |
| `container-cgroup-escape-write` | T1611 | 5 | Write to cgroup `release_agent` (classic escape) |
