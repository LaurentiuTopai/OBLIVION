#!/usr/bin/env python3
import ctypes
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

STEP = 0.5
BASE = tempfile.mkdtemp(prefix="oblivion_proc_")
libc = ctypes.CDLL("libc.so.6", use_errno=True)


def in_child(fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        except Exception as e:
            print(f"    (copil) eroare: {e}")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)


def sleeper():
    return subprocess.Popen(["sleep", "30"])


def t_exec():
    subprocess.run(["ls", BASE], stdout=subprocess.DEVNULL)


def t_exec_script():
    s = os.path.join(BASE, "s.sh")
    with open(s, "w") as f:
        f.write("#!/bin/sh\ntrue\n")
    os.chmod(s, 0o755)
    subprocess.run([s])


def t_exec_tmp():
    dst = os.path.join(BASE, "mytrue")
    shutil.copy("/bin/true", dst)
    os.chmod(dst, 0o755)
    subprocess.run([dst])


def t_exec_setuid():
    dst = os.path.join(BASE, "suid_true")
    shutil.copy("/bin/true", dst)
    os.chown(dst, 0, 0)
    os.chmod(dst, 0o4755)

    def child():
        os.setuid(1000)
        os.execv(dst, [dst])
    in_child(child)


def t_fork():
    in_child(lambda: None)


def t_threads():
    ts = [threading.Thread(target=lambda: time.sleep(0.1)) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def t_setuid():
    in_child(lambda: os.setuid(1000))


def t_setgid():
    in_child(lambda: os.setgid(1000))


def t_setresuid():
    in_child(lambda: os.setresuid(1000, 1000, 1000))


def t_userns():
    subprocess.run(["unshare", "-U", "true"])


def t_capset():
    class Hdr(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32),
                    ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    def child():
        hdr = Hdr(0x20080522, 0)
        data = (Data * 2)()
        libc.capget(ctypes.byref(hdr), data)
        mask = ~(1 << 13) & 0xFFFFFFFF
        data[0].effective &= mask
        data[0].permitted &= mask
        data[0].inheritable &= mask
        r = libc.capset(ctypes.byref(hdr), data)
        print(f"    capset -> {r}")
    in_child(child)


def t_ptrace_attach():
    p = sleeper()
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long,
                            ctypes.c_void_p, ctypes.c_void_p]

    def child():
        r = libc.ptrace(16, p.pid, None, None)
        print(f"    ptrace ATTACH -> {r}")
        if r == 0:
            os.waitpid(p.pid, 0)
            libc.ptrace(17, p.pid, None, None)
    in_child(child)
    p.kill()
    p.wait()


def t_ptrace_read():
    p = sleeper()
    try:
        open(f"/proc/{p.pid}/environ", "rb").read()
    except Exception as e:
        print(f"    {e}")
    p.kill()
    p.wait()


def t_proc_mem():
    p = sleeper()
    try:
        with open(f"/proc/{p.pid}/mem", "rb") as f:
            f.seek(0x400000)
            f.read(1)
    except Exception as e:
        print(f"    {e}")
    p.kill()
    p.wait()


def t_kill_term():
    p = sleeper()
    os.kill(p.pid, signal.SIGTERM)
    p.wait()


def t_kill_9():
    p = sleeper()
    os.kill(p.pid, signal.SIGKILL)
    p.wait()


def t_kill_stop():
    p = sleeper()
    os.kill(p.pid, signal.SIGSTOP)
    time.sleep(0.2)
    os.kill(p.pid, signal.SIGCONT)
    os.kill(p.pid, signal.SIGKILL)
    p.wait()


def t_kill_zero():
    p = sleeper()
    os.kill(p.pid, 0)
    p.kill()
    p.wait()


TESTS = [
    ("exec", t_exec),
    ("exec_script", t_exec_script),
    ("exec_tmp", t_exec_tmp),
    ("exec_setuid", t_exec_setuid),
    ("fork", t_fork),
    ("threads", t_threads),
    ("setuid", t_setuid),
    ("setgid", t_setgid),
    ("setresuid", t_setresuid),
    ("userns", t_userns),
    ("capset", t_capset),
    ("ptrace", t_ptrace_attach),
    ("ptrace_read", t_ptrace_read),
    ("proc_mem", t_proc_mem),
    ("kill_term", t_kill_term),
    ("kill_9", t_kill_9),
    ("kill_stop", t_kill_stop),
    ("kill_zero", t_kill_zero),
]


def main():
    only = sys.argv[1:]
    print(f"Director de test: {BASE}  (uid={os.getuid()}, pid={os.getpid()})")
    for name, fn in TESTS:
        if only and name not in only:
            continue
        print(f"\n=== {name}")
        try:
            fn()
        except Exception as e:
            print(f"    EROARE: {e}")
        time.sleep(STEP)
    shutil.rmtree(BASE, ignore_errors=True)
    print("\nCuratat.")


if __name__ == "__main__":
    main()
