# Persistence

**MITRE ATT&CK**: T1053.003, T1053.006, T1547.006, T1574.006  
**Syscalls monitored**: `inode_create`, `rename`, `open`, `openat`, `write`

---

## Why these syscalls?

### `inode_create` → `inode_create` event
The `security_inode_create` LSM hook fires when a new file is about to be created on disk.
The EDR checks if the destination directory is a known persistence location: cron directories
(`/etc/cron.d/`, `/var/spool/cron/`), systemd unit directories (`/etc/systemd/system/`),
init scripts (`/etc/init.d/`, `/etc/rc.local`), or SSH authorized keys (`~/.ssh/authorized_keys`).
Any process other than a package manager creating files in these locations is suspicious.

### `inode_rename` → `inode_rename` event
The `security_inode_rename` hook fires when a file is renamed or moved. The EDR checks the
**destination** path (`ev.Path2`) rather than the source, since an attacker may prepare the
persistence file in `/tmp` and then `mv` it into the target directory. This covers atomic writes
done via temp-file-then-rename patterns.

### `file_open` on PAM configuration → `file_open` event
The `/etc/pam.d/` directory contains the Pluggable Authentication Module stack configuration.
Writing to PAM config files allows an attacker to insert a custom module (`pam_so`) that grants
authentication bypass or credential harvesting. The `security_file_open` hook fires on every
open call; combined with write mode detection, it identifies unauthorized PAM tampering.

### SSH `authorized_keys` creation → `inode_create` event
Writing a new public key to `~/.ssh/authorized_keys` grants persistent passwordless SSH access
to any attacker who controls the corresponding private key. The EDR catches this by watching
for `inode_create` events with path containing `/.ssh/authorized_keys`.

---

## Rules

| Rule ID | Technique | Severity | Description |
|---|---|---|---|
| `persist-cron-job-creation` | T1053.003 | 4 | New file created in cron directories |
| `persist-systemd-unit-drop` | T1053.006 | 4 | New systemd unit file created outside package manager |
| `persist-ssh-authorized-key` | T1098.004 | 5 | Write to SSH authorized_keys file |
| `persist-pam-config-write` | T1556.003 | 5 | Write to PAM configuration file |
| `persist-initd-script-drop` | T1037.004 | 4 | New init.d / rc.local script created |
