"""
Build a clean, whitelist-based submission archive for GraphQL Shield.

  python scripts/package_submission.py            # build GraphQLShield_Submission.zip + MANIFEST.sha256
  python scripts/package_submission.py --verify    # verify an existing archive against MANIFEST.sha256

The whitelist deliberately excludes VCS metadata, virtualenvs, caches, compiled
artifacts, databases, secrets (.env), logs and any nested archives, so the outer
`CCNS Project.zip`-style leakage reviewed previously cannot recur.
"""

import hashlib
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARCHIVE = os.path.join(ROOT, "GraphQLShield_Submission.zip")
MANIFEST = os.path.join(ROOT, "MANIFEST.sha256")

INCLUDE_FILES = [
    "requirements.txt",
    "constraints.txt",
    "README.md",
    "SETUP.md",
    "DEMO_RUNBOOK.md",
    "LIVE_DEMONSTRATION_GUIDE.md",
    ".env.example",
    ".gitignore",
    "CCNS_Project_Report.docx",
    "CCNS_Presentation.pptx",
    "VIVA_QA.docx",
]

INCLUDE_DIRS = ["app", "tests", "scripts", "data", "docs", "tools", ".github"]

EXCLUDE_DIRS = {
    "__pycache__", "node_modules", ".git", ".venv", "venv",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
}

EXCLUDE_EXT = {".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".log", ".zip", ".env", ".pyo"}

EXCLUDE_NAMES = {".env"}


def _iter_files():
    for name in INCLUDE_FILES:
        path = os.path.join(ROOT, name)
        if os.path.isfile(path):
            yield name, path
        else:
            print(f"  [warn] listed file not found, skipping: {name}")

    for d in INCLUDE_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            print(f"  [warn] listed dir not found, skipping: {d}")
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in EXCLUDE_DIRS]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in EXCLUDE_EXT or fn in EXCLUDE_NAMES:
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ROOT).replace("\\", "/")
                yield rel, full


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build():
    files = sorted(_iter_files(), key=lambda t: t[0])
    manifest_lines = []
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, full in files:
            zf.write(full, rel)
            manifest_lines.append(f"{_sha256(full)}  {rel}")
        manifest_text = "\n".join(manifest_lines) + "\n"
        zf.writestr("MANIFEST.sha256", manifest_text)

    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(manifest_lines) + "\n")

    size = os.path.getsize(ARCHIVE)
    print(f"Built {os.path.basename(ARCHIVE)}")
    print(f"  files:  {len(files) + 1} (incl. MANIFEST.sha256)")
    print(f"  size:   {size:,} bytes")
    print(f"  manifest: {os.path.basename(MANIFEST)} ({len(manifest_lines)} entries)")

    leaked = [r for r, _ in files if r.endswith((".zip", ".db", ".pyc")) or r.endswith(".env")]
    if leaked:
        print(f"  [ERROR] excluded types leaked into archive: {leaked}")
        return 1
    return 0


def verify():
    if not os.path.isfile(ARCHIVE):
        print(f"[ERROR] archive not found: {ARCHIVE}")
        return 1
    with zipfile.ZipFile(ARCHIVE, "r") as zf:
        names = zf.namelist()
        if "MANIFEST.sha256" not in names:
            print("[ERROR] archive has no MANIFEST.sha256")
            return 1
        manifest_text = zf.read("MANIFEST.sha256").decode("utf-8")
        expected = {}
        for line in manifest_text.strip().splitlines():
            digest, rel = line.split("  ", 1)
            expected[rel] = digest

        ok = True
        for rel, digest in expected.items():
            if rel not in names:
                print(f"[FAIL] missing from archive: {rel}")
                ok = False
                continue
            actual = hashlib.sha256(zf.read(rel)).hexdigest()
            if actual != digest:
                print(f"[FAIL] hash mismatch: {rel}")
                ok = False

        extra = [n for n in names if n != "MANIFEST.sha256" and n not in expected]
        if extra:
            print(f"[warn] {len(extra)} unexpected entries: {extra[:10]}")

    print(f"Verified {len(expected)} files in {os.path.basename(ARCHIVE)}: "
          f"{'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(verify() if "--verify" in sys.argv else build())
