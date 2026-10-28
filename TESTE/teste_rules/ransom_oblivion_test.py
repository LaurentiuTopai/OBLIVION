#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import tempfile
import time

BASE = tempfile.mkdtemp(prefix="oblivion_ransom_")
DIRS = 20
FILES_PER_DIR = 25


def sh(cmd):
    subprocess.run(cmd, shell=True, cwd=BASE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_files():
    script = (
        "import os\n"
        f"for d in range({DIRS}):\n"
        f"    os.makedirs('{BASE}/d%d' % d, exist_ok=True)\n"
        f"    for f in range({FILES_PER_DIR}):\n"
        f"        open('{BASE}/d%d/doc%d.txt' % (d, f), 'w').write('date' * 100)\n"
    )
    subprocess.run([sys.executable, "-c", script])


def ransomware():
    print("\n=== ransomware simulat: asteptat 1 alerta")
    setup_files()
    time.sleep(1)
    for d in range(DIRS):
        dd = os.path.join(BASE, f"d{d}")
        for f in range(FILES_PER_DIR):
            src = os.path.join(dd, f"doc{f}.txt")
            with open(src, "rb") as fh:
                data = fh.read()
            enc = src + ".tmp"
            with open(enc, "wb") as fh:
                fh.write(bytes(b ^ 0x5A for b in data))
            os.rename(enc, src + ".locked")
            os.unlink(src)
        with open(os.path.join(dd, "README_DECRYPT.txt"), "w") as fh:
            fh.write("fisierele tale sunt criptate")
    time.sleep(1)


def benign_tar():
    print("\n=== benign: tar xf arhiva mare: asteptat 0 alerte")
    setup_files()
    arc = os.path.join(tempfile.gettempdir(), "obl_benign.tar")
    sh(f"tar cf {arc} .")
    out = os.path.join(BASE, "extract")
    os.makedirs(out)
    subprocess.run(["tar", "xf", arc, "-C", out])
    os.unlink(arc)


def benign_rm():
    print("\n=== benign: rm -rf director mare: asteptat 0 alerte")
    setup_files()
    subprocess.run(["rm", "-rf", BASE + "/d0", BASE + "/d1", BASE + "/d2", BASE + "/d3", BASE + "/d4"])


def benign_git():
    print("\n=== benign: git checkout intre branch-uri: asteptat 0 alerte")
    repo = os.path.join(BASE, "repo")
    os.makedirs(repo)
    sh("cd repo && git init -q && git config user.email a@b.c && git config user.name t")
    for d in range(10):
        os.makedirs(os.path.join(repo, f"s{d}"), exist_ok=True)
        for f in range(30):
            open(os.path.join(repo, f"s{d}", f"f{f}.txt"), "w").write(f"a{d}{f}")
    sh("cd repo && git add -A && git commit -qm one")
    sh("cd repo && git checkout -qb other")
    for d in range(10):
        for f in range(30):
            open(os.path.join(repo, f"s{d}", f"f{f}.txt"), "w").write(f"b{d}{f}")
    sh("cd repo && git commit -qam two")
    subprocess.run(["git", "checkout", "-q", "master"], cwd=repo, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", "-q", "other"], cwd=repo, stderr=subprocess.DEVNULL)


def benign_rename_few():
    print("\n=== benign: cateva rename-uri razlete: asteptat 0 alerte")
    for i in range(5):
        p = os.path.join(BASE, f"x{i}")
        open(p, "w").close()
        os.rename(p, p + ".bak")
        time.sleep(1)


TESTS = {
    "ransom": ransomware,
    "tar": benign_tar,
    "rm": benign_rm,
    "git": benign_git,
    "rename": benign_rename_few,
}


def main():
    only = sys.argv[1:] or list(TESTS)
    print(f"Director de test: {BASE}")
    for name in only:
        TESTS[name]()
        time.sleep(2)
    shutil.rmtree(BASE, ignore_errors=True)
    print("\nCurat.")


if __name__ == "__main__":
    main()
