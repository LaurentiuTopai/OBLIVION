#!/usr/bin/env python3
import os
import stat
import subprocess
import sys
import tempfile
import time
import mmap
import ctypes
'''
Teste pentru hook-urile de fisier ale lui Oblivion,test pentru toate cele 19 hookuri de la file/mmap/inode
'''
BASE = tempfile.mkdtemp(prefix="oblivion_test_")
STEP = 0.3


def p(name):
    return os.path.join(BASE, name)


def run(title, fn):
    print(f"\n=== {title}")
    try:
        fn()
    except Exception as e:
        print(f"    EROARE: {e}")
    time.sleep(STEP)


def t_create():
    open(p("a.txt"), "w").close()

def t_write():
    with open(p("a.txt"), "w") as f:
        f.write("date")

def t_truncate():
    os.truncate(p("a.txt"), 0)

def t_rename():
    os.rename(p("a.txt"), p("b.txt"))

def t_rename_overwrite():
    open(p("x"), "w").close()
    open(p("y"), "w").close()
    os.rename(p("x"), p("y"))

def t_unlink():
    os.unlink(p("b.txt"))

def t_mkdir():
    os.mkdir(p("d"), 0o755)

def t_rmdir():
    os.rmdir(p("d"))

def t_chmod():
    os.chmod(p("y"), 0o755)

def t_chmod_setuid():
    os.chmod(p("y"), 0o4755)

def t_chown():
    os.chown(p("y"), 0, 0)

def t_symlink():
    os.symlink("/etc/hostname", p("s"))

def t_readlink():
    os.readlink(p("s"))

def t_follow_link():
    open(p("s")).close()

def t_hardlink():
    os.link(p("y"), p("y2"))

def t_mknod_fifo():
    os.mkfifo(p("pipe"))

def t_mknod_dev():
    os.mknod(p("null"), 0o600 | stat.S_IFCHR, os.makedev(1, 3))

def t_utimes():
    os.utime(p("y"), (0, 0))

def t_mprotect_anon():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    addr = libc.mmap(None, 4096, 0x3, 0x22, -1, 0)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    r = libc.mprotect(addr, 4096, 0x5)
    print(f"    mprotect -> {r}")

def t_mmap_exec_file():
    subprocess.run(["/bin/true"])


TESTS = [
    ("create", t_create), ("write", t_write), ("truncate", t_truncate),
    ("rename", t_rename), ("rename peste existent", t_rename_overwrite),
    ("unlink", t_unlink), ("mkdir", t_mkdir), ("rmdir", t_rmdir),
    ("chmod", t_chmod), ("chmod setuid", t_chmod_setuid),
    ("chown", t_chown), ("utimes", t_utimes),
    ("symlink", t_symlink), ("readlink", t_readlink),
    ("follow_link", t_follow_link), ("hardlink", t_hardlink),
    ("mknod fifo", t_mknod_fifo), ("mknod device", t_mknod_dev),
    ("mprotect anonim W->X", t_mprotect_anon),
    ("mmap_file exec", t_mmap_exec_file),
]


def main():
    only = sys.argv[1:]
    print(f"Director de test: {BASE}  (uid={os.getuid()})")
    if os.getuid() != 0:
        print("Nota: chown si mknod device cer root, vor da EROARE fara sudo.")
    for name, fn in TESTS:
        if only and name not in only:
            continue
        run(name, fn)
    subprocess.run(["rm", "-rf", BASE])
    print("\nCuratat.")


if __name__ == "__main__":
    main()
