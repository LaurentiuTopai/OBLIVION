# Impact — Malware (Ransomware / Cryptominer / Wiper)

**MITRE ATT&CK**: T1486, T1496  
**Syscalls monitored**: `rename`, `unlink`, `open`, `socket`, `connect`

---

## Why these syscalls?

### `rename` / `renameat` → `inode_rename` event (ransomware)
The `security_inode_rename` LSM hook fires on every file rename. Ransomware encrypts files
in-place or by writing a new encrypted copy then renaming it over the original. The EDR tracks
rename events per process in a sliding time window (`Proc.RenameTimes`). When the rename rate
exceeds the configured threshold, a score point is added. Additionally, if the destination
extension differs from the source extension (e.g., `.jpg` → `.jpg.enc`), the new extension
is counted per process (`Proc.NewExts`). Repeated use of the same novel extension indicates
a ransomware encryption scheme. This is handled by the **stateful Go detector** (`ransomware.go`).

### `unlink` / `unlinkat` → `inode_unlink` event (ransomware / wiper)
The `security_inode_unlink` hook fires on every file deletion. Mass deletion is used both by
wipers (destroying data) and by ransomware (deleting originals after encryption). The EDR
tracks unlink events per process in the same sliding window as renames.

### `inode_create` → `inode_create` event (ransom note)
When ransomware finishes encrypting a directory, it typically drops a ransom note file with a
predictable name: `README.txt`, `HOW_TO_DECRYPT.txt`, `RESTORE_FILES.html`, etc. The EDR
watches for file creation events where the lowercase filename contains known ransom note keywords
(`readme`, `decrypt`, `recover`, `restore`, `how_to`, `ransom`). This is a high-confidence
indicator with minimal false positives.

### `socket_connect` to Stratum ports → `socket_connect` event (cryptominer)
Cryptomining pools use the Stratum protocol over specific TCP ports: `3333` (ETH), `4444`,
`5555`, `7777`, `8888`, `9999`, `14444`, `14433`, `45700`. The `security_socket_connect` hook
fires on every outbound connection. The EDR checks if the destination port matches the Stratum
port list and the destination IP is not loopback or private — a strong indicator of a miner
callback to a mining pool.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `ransomware-suspected` | T1486 | 5 | Stateful scoring: bulk rename+unlink+novel ext+ransom note (Go detector) |
| `impact-crypto-stratum-ports` | T1496 | 4 | Outbound connection to Stratum mining pool port |
| `impact-crypto-xmrig-exec` | T1496 | 4 | Known miner binary name executed |
| `impact-wiper-mass-unlink-tmp` | T1485 | 5 | Process from /tmp performing mass file deletion |
