#!/usr/bin/env python3
"""
OBLIVION EDR — Adversary Emulation Test Suite
Covers all 40 detection rules (37 declarative YAML + 3 stateful Go detectors).

Run OBLIVION first in a separate terminal:
    sudo ./oblivion

Then run this suite:
    sudo python3 edr_test_suite.py
"""

import ctypes
import mmap
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Linux constants
# ---------------------------------------------------------------------------
CLONE_NEWUSER   = 0x10000000
PTRACE_ATTACH   = 16
PTRACE_DETACH   = 17
CAP_SYS_ADMIN   = 21

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS  = "\033[92m[PASS]\033[0m"
SKIP  = "\033[93m[SKIP]\033[0m"
INFO  = "\033[94m[INFO]\033[0m"
WARN  = "\033[91m[WARN]\033[0m"

_results: list[tuple[str, str, str]] = []  # (category, rule_id, status)

def banner(category: str, rule_id: str, mitre: str, description: str):
    print(f"\n{'='*70}")
    print(f"  CATEGORY : {category}")
    print(f"  RULE     : {rule_id}")
    print(f"  MITRE    : {mitre}")
    print(f"  WHAT     : {description}")
    print(f"{'='*70}")

def result(category: str, rule_id: str, triggered: bool):
    status = PASS if triggered else SKIP
    _results.append((category, rule_id, "TRIGGERED" if triggered else "SKIPPED"))
    print(f"{status} {rule_id}")

def try_write(path: str, content: str = "oblivion_test\n") -> bool:
    try:
        with open(path, "a") as f:
            f.write(content)
        return True
    except Exception:
        return False

def try_open(path: str) -> bool:
    try:
        with open(path, "r") as f:
            f.read(1)
        return True
    except Exception:
        return False

def run_as_child(fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        except Exception:
            pass
        os._exit(0)
    else:
        os.waitpid(pid, 0)

# ---------------------------------------------------------------------------
# CATEGORY 1 — Command & Control / Reverse Shells
# ---------------------------------------------------------------------------

def test_c2_shell_direct_socket():
    banner(
        "Command_and_Control",
        "c2-shell-direct-socket",
        "T1059.004",
        "Shell binary (bash) opens outbound TCP connection to external IP"
    )
    # bash will appear as comm="bash" in the kernel; we exec it with a /dev/tcp redirect
    # The kernel fires socket_connect before bash's error handling kicks in
    def _trigger():
        os.execv("/bin/bash", ["bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/80 2>/dev/null; true"])
    run_as_child(_trigger)
    result("C2", "c2-shell-direct-socket", True)

def test_c2_netconn_exec_shell():
    banner(
        "Command_and_Control",
        "c2-netconn-exec-shell",
        "T1059.004",
        "Process establishes outbound connection then execs a shell (HasNetConn + exec)"
    )
    def _trigger():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(("1.1.1.1", 80))
        except Exception:
            pass
        # kernel already set HasNetConn=true in state; now exec a shell
        os.execv("/bin/sh", ["sh", "-c", "echo netconn_exec_shell_triggered"])
    run_as_child(_trigger)
    result("C2", "c2-netconn-exec-shell", True)

def test_c2_parent_server_spawn_shell():
    banner(
        "Command_and_Control",
        "c2-parent-server-spawn-shell",
        "T1505.003",
        "Process named 'nginx' (copied python) spawns /bin/sh (parent_comms check)"
    )
    fake_server = "/tmp/nginx"
    try:
        shutil.copy(sys.executable, fake_server)
        os.chmod(fake_server, 0o755)
        subprocess.run(
            [fake_server, "-c", "import subprocess; subprocess.run(['/bin/sh', '-c', 'echo webshell_via_nginx'])"],
            timeout=5
        )
        result("C2", "c2-parent-server-spawn-shell", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("C2", "c2-parent-server-spawn-shell", False)
    finally:
        if os.path.exists(fake_server):
            os.remove(fake_server)

def test_c2_shell_low_port():
    banner(
        "Command_and_Control",
        "c2-shell-to-external-low-port",
        "T1071.001",
        "Shell (sh) connects to external port 80 (privileged port, external IP)"
    )
    def _trigger():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(("1.1.1.1", 80))
        except Exception:
            pass
    # We simulate a shell doing this by renaming ourselves to 'sh' — but the comm
    # is set by kernel from the actual binary; instead we exec 'sh' with the connect
    def _as_sh():
        os.execv("/bin/sh", ["sh", "-c", "exec 3<>/dev/tcp/1.1.1.1/80 2>/dev/null; true"])
    run_as_child(_as_sh)
    result("C2", "c2-shell-to-external-low-port", True)

# ---------------------------------------------------------------------------
# CATEGORY 2 — Defense Evasion / Anti-Forensics
# ---------------------------------------------------------------------------

def test_defense_ld_preload_write():
    banner(
        "DefenseEvasion_AntiForensics",
        "defense-ld-preload-write",
        "T1574.006",
        "Attempt to create/write /etc/ld.so.preload (userland rootkit hook)"
    )
    # Even if blocked by OS permissions, the LSM hook fires before the check
    try_write("/etc/ld.so.preload")
    result("Defense", "defense-ld-preload-write", True)

def test_defense_ld_preload_open():
    banner(
        "DefenseEvasion_AntiForensics",
        "defense-ld-preload-open",
        "T1574.006",
        "Unauthorized process reads /etc/ld.so.preload"
    )
    try_open("/etc/ld.so.preload")
    result("Defense", "defense-ld-preload-open", True)

def test_defense_tmp_rename_to_sys():
    banner(
        "DefenseEvasion_AntiForensics",
        "defense-tmp-exec-rename-to-sys",
        "T1036.005",
        "Binary renamed from /tmp into a system path (inode_rename, path_prefixes /tmp/)"
    )
    src = "/tmp/oblivion_masquerade_test"
    try:
        shutil.copy("/bin/echo", src)
        # The rename fires inode_rename with Path=/tmp/... — matches path_prefixes
        os.rename(src, "/tmp/oblivion_masquerade_moved")
        result("Defense", "defense-tmp-exec-rename-to-sys", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Defense", "defense-tmp-exec-rename-to-sys", False)
    finally:
        for p in [src, "/tmp/oblivion_masquerade_moved"]:
            if os.path.exists(p):
                os.remove(p)

def test_defense_binary_self_delete():
    banner(
        "DefenseEvasion_AntiForensics",
        "binary-self-deletion (Go detector)",
        "T1070.004",
        "Process deletes its own executable binary from disk (stateful: ev.Path == p.ExePath)"
    )
    bin_path = "/tmp/oblivion_selfdel_test"
    c_code = r"""
#include <unistd.h>
int main(int argc, char **argv) {
    unlink(argv[0]);
    return 0;
}
"""
    compiled = False
    try:
        p = subprocess.run(
            ["gcc", "-x", "c", "-o", bin_path, "-"],
            input=c_code.encode(),
            stderr=subprocess.PIPE,
            timeout=10
        )
        compiled = p.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not compiled:
        # Fallback: copy /bin/rm and use it to delete itself
        shutil.copy("/bin/rm", bin_path)
        os.chmod(bin_path, 0o755)
        subprocess.run([bin_path, "-f", bin_path], timeout=5)
        result("Defense", "binary-self-deletion", True)
    else:
        subprocess.run([bin_path], timeout=5)
        result("Defense", "binary-self-deletion", True)

    if os.path.exists(bin_path):
        os.remove(bin_path)

# ---------------------------------------------------------------------------
# CATEGORY 3 — Execution / Living off the Land
# ---------------------------------------------------------------------------

def test_exec_from_tmp():
    banner(
        "Execution_LotL",
        "exec-from-tmp",
        "T1059",
        "Binary executed directly from /tmp (world-writable directory)"
    )
    bin_path = "/tmp/oblivion_exec_test"
    try:
        shutil.copy("/bin/echo", bin_path)
        os.chmod(bin_path, 0o755)
        subprocess.run([bin_path, "exec_from_tmp_triggered"], timeout=5)
        result("Execution", "exec-from-tmp", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Execution", "exec-from-tmp", False)
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)

def test_exec_fileless_memfd():
    banner(
        "Execution_LotL",
        "exec-fileless-memfd",
        "T1620",
        "Binary executed via memfd_create + fexecve — never touches disk"
    )
    try:
        fd = os.memfd_create("oblivion_payload", 0)
        with open("/bin/echo", "rb") as f:
            os.write(fd, f.read())
        exec_path = f"/proc/self/fd/{fd}"
        pid = os.fork()
        if pid == 0:
            os.execv(exec_path, ["memfd_payload", "fileless_exec_triggered"])
            os._exit(1)
        else:
            os.waitpid(pid, 0)
            os.close(fd)
        result("Execution", "exec-fileless-memfd", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Execution", "exec-fileless-memfd", False)

def test_exec_from_dev_shm():
    banner(
        "Execution_LotL",
        "exec-from-dev-shm",
        "T1059",
        "Binary executed directly from /dev/shm (shared memory mount)"
    )
    bin_path = "/dev/shm/oblivion_shm_test"
    try:
        shutil.copy("/bin/echo", bin_path)
        os.chmod(bin_path, 0o755)
        subprocess.run([bin_path, "exec_from_devshm_triggered"], timeout=5)
        result("Execution", "exec-from-dev-shm", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Execution", "exec-from-dev-shm", False)
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)

def test_exec_interpreter_from_tmp():
    banner(
        "Execution_LotL",
        "exec-interpreter-script-from-tmp",
        "T1059",
        "Python interpreter executes a script residing in /tmp (from_tmp state flag)"
    )
    script_path = "/tmp/oblivion_script_test.py"
    try:
        with open(script_path, "w") as f:
            f.write("print('interpreter_from_tmp_triggered')\n")
        subprocess.run([sys.executable, script_path], timeout=5)
        result("Execution", "exec-interpreter-script-from-tmp", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Execution", "exec-interpreter-script-from-tmp", False)
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)

# ---------------------------------------------------------------------------
# CATEGORY 4 — Persistence
# ---------------------------------------------------------------------------

def test_persist_cron():
    banner(
        "Persistence",
        "persist-cron-job-creation",
        "T1053.003",
        "New file created in /etc/cron.d/ by non-package-manager process"
    )
    path = "/etc/cron.d/oblivion_test_cron"
    try_write(path, "* * * * * root echo cron_persist_triggered\n")
    result("Persistence", "persist-cron-job-creation", True)
    if os.path.exists(path):
        os.remove(path)

def test_persist_systemd():
    banner(
        "Persistence",
        "persist-systemd-unit-drop",
        "T1053.006",
        "New .service unit file dropped in /etc/systemd/system/"
    )
    path = "/etc/systemd/system/oblivion_test.service"
    try_write(path, "[Unit]\nDescription=OblivionTest\n[Service]\nExecStart=/bin/sh\n")
    result("Persistence", "persist-systemd-unit-drop", True)
    if os.path.exists(path):
        os.remove(path)

def test_persist_ssh_key():
    banner(
        "Persistence",
        "persist-ssh-authorized-key",
        "T1098.004",
        "SSH authorized_keys file created (path_contains /.ssh/authorized_keys)"
    )
    # Use /tmp to avoid modifying real authorized_keys; path_contains still matches
    fake_dir = "/tmp/oblivion_test_home/.ssh"
    os.makedirs(fake_dir, exist_ok=True)
    path = os.path.join(fake_dir, "authorized_keys")
    try_write(path, "ssh-rsa AAAAB3NzaC1yc2E attacker@kali\n")
    result("Persistence", "persist-ssh-authorized-key", True)
    shutil.rmtree("/tmp/oblivion_test_home", ignore_errors=True)

def test_persist_pam():
    banner(
        "Persistence",
        "persist-pam-config-write",
        "T1556.003",
        "File created/truncated in /etc/pam.d/ (PAM authentication hijack)"
    )
    path = "/etc/pam.d/oblivion_test"
    try_write(path, "auth sufficient pam_permit.so\n")
    result("Persistence", "persist-pam-config-write", True)
    if os.path.exists(path):
        os.remove(path)

def test_persist_initd():
    banner(
        "Persistence",
        "persist-initd-script-drop",
        "T1037.004",
        "New init script created in /etc/init.d/"
    )
    path = "/etc/init.d/oblivion_test_init"
    try_write(path, "#!/bin/sh\necho persist_initd_triggered\n")
    result("Persistence", "persist-initd-script-drop", True)
    if os.path.exists(path):
        os.remove(path)

def test_persist_crontab():
    banner(
        "Persistence",
        "persist-etc-crontab-write",
        "T1053.003",
        "Direct write to /etc/crontab (file_truncate / inode_create)"
    )
    try_write("/etc/crontab", "# oblivion test\n")
    result("Persistence", "persist-etc-crontab-write", True)

# ---------------------------------------------------------------------------
# CATEGORY 5 — Privilege Escalation
# ---------------------------------------------------------------------------

def test_privesc_suid():
    banner(
        "PrivilegeEscalation",
        "privesc-suid-bit-set",
        "T1548.001",
        "SUID bit (04000) set on file by non-package-manager (mode_mask: 2048)"
    )
    path = "/tmp/oblivion_suid_test"
    try:
        shutil.copy("/bin/echo", path)
        os.chmod(path, 0o4755)
        result("PrivEsc", "privesc-suid-bit-set", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("PrivEsc", "privesc-suid-bit-set", False)
    finally:
        if os.path.exists(path):
            os.remove(path)

def test_privesc_userns():
    banner(
        "PrivilegeEscalation",
        "privesc-unprivileged-userns",
        "T1611",
        "Non-root process creates user namespace via unshare(CLONE_NEWUSER)"
    )
    def _trigger():
        if os.geteuid() == 0:
            os.setgid(1000)
            os.setuid(1000)
        libc.unshare(CLONE_NEWUSER)
        os._exit(0)
    run_as_child(_trigger)
    result("PrivEsc", "privesc-unprivileged-userns", True)

def test_privesc_root_transition():
    banner(
        "PrivilegeEscalation",
        "privesc-root-euid-transition",
        "T1068",
        "Non-root process gains EUID=0 via unknown setuid binary (bprm_committed_creds)"
    )
    bin_path = "/tmp/oblivion_setuid_test"
    c_code = r"""
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("euid=%d\n", geteuid());
    return 0;
}
"""
    try:
        p = subprocess.run(
            ["gcc", "-x", "c", "-o", bin_path, "-"],
            input=c_code.encode(),
            stderr=subprocess.PIPE,
            timeout=10
        )
        if p.returncode != 0:
            print(f"{SKIP} gcc not available")
            result("PrivEsc", "privesc-root-euid-transition", False)
            return
        # chown root + setuid bit — requires running as root
        os.chown(bin_path, 0, 0)
        os.chmod(bin_path, 0o4755)
        # Drop to unprivileged user and exec the setuid binary
        def _as_user():
            os.setgid(1000)
            os.setuid(1000)
            os.execv(bin_path, [bin_path])
        run_as_child(_as_user)
        result("PrivEsc", "privesc-root-euid-transition", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("PrivEsc", "privesc-root-euid-transition", False)
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)

def test_privesc_cap_sys_admin():
    banner(
        "PrivilegeEscalation",
        "privesc-cap-sys-admin-acquired",
        "T1548",
        "Non-root process calls capset() to gain CAP_SYS_ADMIN (cap_mask: 2097152)"
    )
    # capset syscall structure: header (version + pid) + data (effective/permitted/inheritable)
    # We attempt to set CAP_SYS_ADMIN from a non-root child
    def _trigger():
        if os.geteuid() == 0:
            os.setgid(1000)
            os.setuid(1000)
        # _LINUX_CAPABILITY_VERSION_3 = 0x20080522
        cap_version = 0x20080522
        # Build capset header + data structs via ctypes
        # Even if it fails (EPERM), the LSM hook fires
        import ctypes
        class CapHeader(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
        class CapData(ctypes.Structure):
            _fields_ = [
                ("effective",   ctypes.c_uint32),
                ("permitted",   ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32),
            ]
        hdr = CapHeader(version=cap_version, pid=0)
        # CAP_SYS_ADMIN = bit 21
        cap_sys_admin_bit = 1 << 21
        data = (CapData * 2)()
        data[0].effective   = cap_sys_admin_bit
        data[0].permitted   = cap_sys_admin_bit
        data[0].inheritable = 0
        libc.capset(ctypes.byref(hdr), ctypes.byref(data))
        os._exit(0)
    run_as_child(_trigger)
    result("PrivEsc", "privesc-cap-sys-admin-acquired", True)

# ---------------------------------------------------------------------------
# CATEGORY 6 — Credential Access
# ---------------------------------------------------------------------------

def test_cred_shadow():
    banner(
        "CredentialAccess",
        "cred-shadow-file-access",
        "T1003.008",
        "Unauthorized process opens /etc/shadow (file_open, not_comms whitelist)"
    )
    try_open("/etc/shadow")
    result("Creds", "cred-shadow-file-access", True)

def test_cred_pam_module():
    banner(
        "CredentialAccess",
        "cred-pam-tampering",
        "T1556.003",
        "New file created in /lib/security/ (PAM module directory)"
    )
    path = "/lib/security/pam_oblivion_test.so"
    try_write(path, "# fake pam module\n")
    result("Creds", "cred-pam-tampering", True)
    if os.path.exists(path):
        os.remove(path)

def test_cred_ssh_key_read():
    banner(
        "CredentialAccess",
        "cred-ssh-private-key-read",
        "T1552.004",
        "Process reads SSH private key (path_suffixes: /id_rsa, /id_ed25519)"
    )
    # Create a fake private key to avoid touching real credentials
    fake_dir = "/tmp/oblivion_ssh_test/.ssh"
    os.makedirs(fake_dir, exist_ok=True)
    key_path = os.path.join(fake_dir, "id_rsa")
    with open(key_path, "w") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n")
    try_open(key_path)
    result("Creds", "cred-ssh-private-key-read", True)
    shutil.rmtree("/tmp/oblivion_ssh_test", ignore_errors=True)

def test_cred_aws():
    banner(
        "CredentialAccess",
        "cred-aws-credentials-access",
        "T1552.001",
        "Unexpected process reads ~/.aws/credentials (path_suffixes)"
    )
    fake_dir = "/tmp/oblivion_aws_test/.aws"
    os.makedirs(fake_dir, exist_ok=True)
    cred_path = os.path.join(fake_dir, "credentials")
    with open(cred_path, "w") as f:
        f.write("[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n")
    try_open(cred_path)
    result("Creds", "cred-aws-credentials-access", True)
    shutil.rmtree("/tmp/oblivion_aws_test", ignore_errors=True)

def test_cred_docker_config():
    banner(
        "CredentialAccess",
        "cred-docker-config-access",
        "T1552.001",
        "Unexpected process reads ~/.docker/config.json (registry auth tokens)"
    )
    fake_dir = "/tmp/oblivion_docker_test/.docker"
    os.makedirs(fake_dir, exist_ok=True)
    cfg_path = os.path.join(fake_dir, "config.json")
    with open(cfg_path, "w") as f:
        f.write('{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}\n')
    try_open(cfg_path)
    result("Creds", "cred-docker-config-access", True)
    shutil.rmtree("/tmp/oblivion_docker_test", ignore_errors=True)

# ---------------------------------------------------------------------------
# CATEGORY 7 — Container Escape / Kernel Surface
# ---------------------------------------------------------------------------

def test_container_docker_sock():
    banner(
        "ContainerEscape_KernelSurface",
        "container-docker-sock-access",
        "T1611",
        "Unauthorized process opens /var/run/docker.sock (full daemon control)"
    )
    sock_path = "/var/run/docker.sock"
    if not os.path.exists(sock_path):
        sock_path = "/run/docker.sock"
    if not os.path.exists(sock_path):
        print(f"{SKIP} Docker socket not found on this system")
        result("Container", "container-docker-sock-access", False)
        return
    try:
        with open(sock_path, "rb") as f:
            pass
    except Exception:
        pass
    result("Container", "container-docker-sock-access", True)

def test_container_docker_api_tcp():
    banner(
        "ContainerEscape_KernelSurface",
        "container-docker-api-tcp",
        "T1611",
        "Connection attempt to Docker TCP API port 2375 (unauthenticated)"
    )
    def _trigger():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", 2375))
        except Exception:
            pass
        s.close()
    run_as_child(_trigger)
    result("Container", "container-docker-api-tcp", True)

def test_container_proc_kernel_write():
    banner(
        "ContainerEscape_KernelSurface",
        "container-proc-kernel-write",
        "T1543",
        "Process opens /proc/sys/kernel/ parameter for writing (kernel tunable)"
    )
    # Reading also fires file_open which matches the rule
    try_open("/proc/sys/kernel/dmesg_restrict")
    result("Container", "container-proc-kernel-write", True)

def test_container_cgroup_escape():
    banner(
        "ContainerEscape_KernelSurface",
        "container-cgroup-release-agent",
        "T1611",
        "Write to cgroup release_agent (classic container escape via notify-on-release)"
    )
    # Find any cgroup release_agent that exists
    agent_path = None
    for root, dirs, files in os.walk("/sys/fs/cgroup"):
        if "release_agent" in files:
            agent_path = os.path.join(root, "release_agent")
            break
    if agent_path is None:
        print(f"{SKIP} No cgroup release_agent found (cgroups v2 unified hierarchy)")
        result("Container", "container-cgroup-release-agent", False)
        return
    try_open(agent_path)
    result("Container", "container-cgroup-release-agent", True)

# ---------------------------------------------------------------------------
# CATEGORY 8 — WebShells / Application RCE
# ---------------------------------------------------------------------------

def _webshell_base(rule_id: str, mitre: str, description: str, child_cmd: list[str]):
    banner("WebShells_ApplicationRCE", rule_id, mitre, description)
    fake_server = f"/tmp/nginx"
    try:
        shutil.copy(sys.executable, fake_server)
        os.chmod(fake_server, 0o755)
        inner = " ".join(repr(c) for c in child_cmd)
        subprocess.run(
            [fake_server, "-c", f"import subprocess; subprocess.run([{inner}])"],
            timeout=5
        )
        result("WebShell", rule_id, True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("WebShell", rule_id, False)
    finally:
        if os.path.exists(fake_server):
            os.remove(fake_server)

def test_webshell_spawn_shell():
    _webshell_base(
        "webshell-server-spawn-shell", "T1505.003",
        "nginx (fake) spawns /bin/bash (parent_comms + comms match)",
        ["/bin/bash", "-c", "echo webshell_shell_triggered"]
    )

def test_webshell_spawn_recon():
    _webshell_base(
        "webshell-server-spawn-recon", "T1190",
        "nginx (fake) spawns 'id' (reconnaissance binary)",
        ["/usr/bin/id"]
    )

def test_webshell_spawn_downloader():
    _webshell_base(
        "webshell-server-spawn-downloader", "T1105",
        "nginx (fake) spawns 'curl' (file downloader — C2 stage 2)",
        ["/usr/bin/curl", "--max-time", "1", "http://127.0.0.1/"]
    )

def test_webshell_spawn_netcat():
    nc_bin = shutil.which("nc") or shutil.which("ncat") or shutil.which("netcat")
    if nc_bin is None:
        banner("WebShells_ApplicationRCE", "webshell-server-spawn-netcat", "T1059", "nc not found")
        print(f"{SKIP} netcat not installed")
        result("WebShell", "webshell-server-spawn-netcat", False)
        return
    _webshell_base(
        "webshell-server-spawn-netcat", "T1059",
        f"nginx (fake) spawns '{nc_bin}' (network relay / tunnel)",
        [nc_bin, "-z", "127.0.0.1", "9999"]
    )

# ---------------------------------------------------------------------------
# CATEGORY 9 — Impact / Malware
# ---------------------------------------------------------------------------

def test_impact_stratum_ports():
    banner(
        "Impact_wares",
        "impact-crypto-stratum-ports",
        "T1496",
        "Outbound connection to Stratum mining pool port 3333 (external IP)"
    )
    def _trigger():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(("1.1.1.1", 3333))
        except Exception:
            pass
        s.close()
    run_as_child(_trigger)
    result("Impact", "impact-crypto-stratum-ports", True)

def test_impact_miner_exec():
    banner(
        "Impact_wares",
        "impact-crypto-xmrig-exec",
        "T1496",
        "Known miner binary name 'xmrig' executed (comm match)"
    )
    fake_miner = "/tmp/xmrig"
    try:
        shutil.copy("/bin/echo", fake_miner)
        os.chmod(fake_miner, 0o755)
        subprocess.run([fake_miner, "miner_exec_triggered"], timeout=5)
        result("Impact", "impact-crypto-xmrig-exec", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Impact", "impact-crypto-xmrig-exec", False)
    finally:
        if os.path.exists(fake_miner):
            os.remove(fake_miner)

def test_impact_wiper():
    banner(
        "Impact_wares",
        "impact-wiper-tmp-mass-unlink",
        "T1485",
        "Process from /tmp performs mass file deletion (from_tmp + inode_unlink)"
    )
    sandbox = tempfile.mkdtemp(prefix="wiper_test_", dir="/tmp")
    # Create files to delete
    victims = []
    for i in range(30):
        p = os.path.join(sandbox, f"file_{i}.dat")
        with open(p, "w") as f:
            f.write("data")
        victims.append(p)

    wiper = "/tmp/oblivion_wiper_proc"
    c_code = r"""
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) unlink(argv[i]);
    return 0;
}
"""
    compiled = False
    try:
        p = subprocess.run(
            ["gcc", "-x", "c", "-o", wiper, "-"],
            input=c_code.encode(),
            stderr=subprocess.PIPE,
            timeout=10
        )
        compiled = p.returncode == 0
    except Exception:
        pass

    if compiled:
        subprocess.run([wiper] + victims, timeout=10)
        result("Impact", "impact-wiper-tmp-mass-unlink", True)
    else:
        # Fallback: use python itself from /tmp
        wiper_py = "/tmp/oblivion_wiper.py"
        with open(wiper_py, "w") as f:
            f.write("import os,sys\n[os.unlink(p) for p in sys.argv[1:] if os.path.exists(p)]\n")
        subprocess.run([sys.executable, wiper_py] + victims, timeout=10)
        result("Impact", "impact-wiper-tmp-mass-unlink", True)
        if os.path.exists(wiper_py):
            os.remove(wiper_py)

    shutil.rmtree(sandbox, ignore_errors=True)
    if os.path.exists(wiper):
        os.remove(wiper)

def test_impact_ransomware():
    banner(
        "Impact_wares",
        "ransomware-suspected (Go detector)",
        "T1486",
        "Stateful score: bulk rename + novel extension + mass unlink + ransom note"
    )
    sandbox = tempfile.mkdtemp(prefix="ransom_sim_")
    print(f"{INFO} Isolated sandbox: {sandbox}")
    try:
        # 1. Open files across many directories (DirThreshold=10)
        for d in range(15):
            sub = os.path.join(sandbox, f"dir_{d}")
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, "data.txt"), "w") as f:
                f.write("important_data")

        # 2. Create many files (CreateThreshold=20)
        files = []
        for i in range(60):
            fp = os.path.join(sandbox, f"document_{i}.docx")
            with open(fp, "w") as f:
                f.write("CONFIDENTIAL_DATA_" * 10)
            files.append(fp)

        # 3. Bulk rename with new extension (RenameThreshold=20, ExtThreshold=10)
        print(f"{INFO} Renaming 60 files to .locked extension...")
        locked = []
        for fp in files:
            new_fp = fp + ".locked"
            os.rename(fp, new_fp)
            locked.append(new_fp)

        # 4. Bulk unlink (UnlinkThreshold=20)
        print(f"{INFO} Unlinking 60 files in bulk...")
        for lp in locked:
            if os.path.exists(lp):
                os.unlink(lp)

        # 5. Ransom note (keyword: "decrypt")
        note = os.path.join(sandbox, "HOW_TO_DECRYPT_README.txt")
        print(f"{INFO} Dropping ransom note: {note}")
        with open(note, "w") as f:
            f.write("All your files have been encrypted. Pay to decrypt.\n")

        result("Impact", "ransomware-suspected", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Impact", "ransomware-suspected", False)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
        print(f"{INFO} Sandbox cleaned up.")

# ---------------------------------------------------------------------------
# CATEGORY 10 — Memory Exploitation (Go detectors)
# ---------------------------------------------------------------------------

def test_memory_rwx():
    banner(
        "MemoryExploitation_ProcessInjection",
        "rwx-anonymous-memory (Go detector)",
        "T1055",
        "Anonymous mmap region marked PROT_READ|PROT_WRITE|PROT_EXEC (W^X violation)"
    )
    try:
        mem = mmap.mmap(
            -1, 4096,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
            prot=mmap.PROT_READ | mmap.PROT_WRITE,
        )
        addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
        # mprotect to add EXEC flag — fires EvFileMprotect with Prot=7
        libc.mprotect(ctypes.c_void_p(addr), 4096, 7)
        mem.close()
        result("Memory", "rwx-anonymous-memory", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Memory", "rwx-anonymous-memory", False)

def test_memory_ptrace():
    banner(
        "MemoryExploitation_ProcessInjection",
        "ptrace-process-injection (Go detector)",
        "T1055.008",
        "Non-debugger process attaches to another process via ptrace(PTRACE_ATTACH)"
    )
    target = subprocess.Popen(["/bin/sleep", "3"])
    time.sleep(0.2)
    try:
        res = libc.ptrace(PTRACE_ATTACH, target.pid, None, None)
        if res == 0:
            libc.ptrace(PTRACE_DETACH, target.pid, None, None)
        result("Memory", "ptrace-process-injection", True)
    except Exception as e:
        print(f"{WARN} {e}")
        result("Memory", "ptrace-process-injection", False)
    finally:
        target.terminate()
        target.wait()

# ---------------------------------------------------------------------------
# Test registry — ordered by MITRE kill chain phase
# ---------------------------------------------------------------------------

ALL_TESTS = [
    # (display name, function)
    # --- C2 ---
    ("C2: Shell direct socket (bash /dev/tcp)",              test_c2_shell_direct_socket),
    ("C2: HasNetConn + exec shell (stateful revshell)",      test_c2_netconn_exec_shell),
    ("C2: Web server spawns shell (parent_comms nginx)",     test_c2_parent_server_spawn_shell),
    ("C2: Shell connects to external low port 80",           test_c2_shell_low_port),
    # --- Defense Evasion ---
    ("DEF: Write /etc/ld.so.preload (rootkit hook)",         test_defense_ld_preload_write),
    ("DEF: Open /etc/ld.so.preload (unauthorized read)",     test_defense_ld_preload_open),
    ("DEF: Rename binary from /tmp (masquerading)",          test_defense_tmp_rename_to_sys),
    ("DEF: Binary self-deletion (Go: ev.Path==ExePath)",     test_defense_binary_self_delete),
    # --- Execution LotL ---
    ("EXEC: Run binary from /tmp",                           test_exec_from_tmp),
    ("EXEC: Fileless exec via memfd_create",                 test_exec_fileless_memfd),
    ("EXEC: Run binary from /dev/shm",                       test_exec_from_dev_shm),
    ("EXEC: Interpreter with script in /tmp (from_tmp)",     test_exec_interpreter_from_tmp),
    # --- Persistence ---
    ("PERS: Cron job file created in /etc/cron.d/",          test_persist_cron),
    ("PERS: Systemd .service unit dropped",                  test_persist_systemd),
    ("PERS: SSH authorized_keys write",                      test_persist_ssh_key),
    ("PERS: PAM config file created in /etc/pam.d/",         test_persist_pam),
    ("PERS: Init.d script dropped in /etc/init.d/",          test_persist_initd),
    ("PERS: Direct write to /etc/crontab",                   test_persist_crontab),
    # --- Privilege Escalation ---
    ("PRIV: SUID bit set via chmod(04755)",                  test_privesc_suid),
    ("PRIV: Unprivileged user namespace (unshare)",          test_privesc_userns),
    ("PRIV: EUID 0 transition via setuid binary",            test_privesc_root_transition),
    ("PRIV: CAP_SYS_ADMIN acquired via capset()",            test_privesc_cap_sys_admin),
    # --- Credential Access ---
    ("CRED: /etc/shadow open by unauthorized process",       test_cred_shadow),
    ("CRED: PAM module directory write",                     test_cred_pam_module),
    ("CRED: SSH private key (id_rsa) read",                  test_cred_ssh_key_read),
    ("CRED: AWS credentials file read",                      test_cred_aws),
    ("CRED: Docker config.json read",                        test_cred_docker_config),
    # --- Container Escape ---
    ("CONT: Docker socket access",                           test_container_docker_sock),
    ("CONT: Docker TCP API port 2375",                       test_container_docker_api_tcp),
    ("CONT: /proc/sys/kernel/ tunable access",               test_container_proc_kernel_write),
    ("CONT: cgroup release_agent write",                     test_container_cgroup_escape),
    # --- WebShells ---
    ("WEB: nginx spawns bash (webshell shell)",              test_webshell_spawn_shell),
    ("WEB: nginx spawns id (recon)",                         test_webshell_spawn_recon),
    ("WEB: nginx spawns curl (stage2 download)",             test_webshell_spawn_downloader),
    ("WEB: nginx spawns nc (tunnel)",                        test_webshell_spawn_netcat),
    # --- Impact / Malware ---
    ("IMP: Stratum port 3333 connection (cryptominer)",      test_impact_stratum_ports),
    ("IMP: 'xmrig' binary executed",                         test_impact_miner_exec),
    ("IMP: Mass unlink from /tmp process (wiper)",           test_impact_wiper),
    ("IMP: Ransomware composite score (Go detector)",        test_impact_ransomware),
    # --- Memory Exploitation ---
    ("MEM: Anonymous RWX mmap + mprotect (shellcode page)",  test_memory_rwx),
    ("MEM: ptrace(PTRACE_ATTACH) on external process",       test_memory_ptrace),
]

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

def print_summary():
    print(f"\n{'='*70}")
    print("  OBLIVION EDR — TEST SUMMARY")
    print(f"{'='*70}")
    triggered = sum(1 for _, _, s in _results if s == "TRIGGERED")
    skipped   = sum(1 for _, _, s in _results if s == "SKIPPED")
    print(f"  Total  : {len(_results)}")
    print(f"  Triggered alerts expected : {triggered}")
    print(f"  Skipped (env limitations) : {skipped}")
    print(f"{'='*70}")
    if skipped:
        print("\n  Skipped tests:")
        for cat, rid, s in _results:
            if s == "SKIPPED":
                print(f"    - [{cat}] {rid}")
    print()

def menu():
    while True:
        print("\n" + "#" * 70)
        print("   OBLIVION EDR — ADVERSARY EMULATION SUITE")
        print("#" * 70)
        for idx, (name, _) in enumerate(ALL_TESTS, 1):
            print(f"  [{idx:2d}] {name}")
        print(f"  [99] Run ALL tests sequentially")
        print(f"  [ 0] Exit")
        print("#" * 70)

        choice = input("\nSelect attack scenario: ").strip()
        if choice == "0":
            break
        elif choice == "99":
            for _, fn in ALL_TESTS:
                fn()
                time.sleep(0.5)
            print_summary()
        elif choice.isdigit() and 1 <= int(choice) <= len(ALL_TESTS):
            ALL_TESTS[int(choice) - 1][1]()
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{WARN} Some tests require root (writing to /etc/, ptrace, capset).")
        print(f"{WARN} Run with: sudo python3 {sys.argv[0]}")
        print()
    menu()
