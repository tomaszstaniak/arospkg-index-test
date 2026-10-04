#!/usr/bin/env python3
"""Check an arospkg-index checkout the way its pull requests are checked.

    ci_check_index.py INDEX_DIR [--base REF] [--out-dir DIR] [--cache DIR]

For every manifest changed since REF (all of them without --base): download
the archive at its url, within the client's limits, and check that its size
and SHA-256 are the manifest's; then generate both catalogue files with
mkindex.py into OUT_DIR, which also checks subdir and icon against the
downloaded archives. Exit 1 on any problem.

Nothing from the checkout is executed: manifests are read as TOML data,
archives are only listed, never unpacked or run. That is what lets this run
on an untrusted pull request without secrets.
"""
import argparse
import hashlib
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mkindex  # noqa: E402
DOWNLOAD_MAX = 64 * 1024 * 1024
TIMEOUT = 300


def released(index_dir, base):
    """(id, arch, abi) -> (version, revision, sha256) of every approved manifest at base."""
    out = {}
    ls = subprocess.run(["git", "ls-tree", "--name-only", base, "manifests/"], cwd=index_dir,
                        capture_output=True, text=True, check=True).stdout.split()
    for path in ls:
        if not path.endswith(".toml"):
            continue
        text = subprocess.run(["git", "show", f"{base}:{path}"], cwd=index_dir,
                              capture_output=True, text=True, check=True).stdout
        try:
            m = tomllib.loads(text)
        except Exception:
            continue
        if m.get("status") == "approved" and m.get("sha256"):
            out[(m.get("id"), m.get("arch"), m.get("abi"))] = (m.get("version"), m.get("revision", 0), m["sha256"])
    return out


def changed(index_dir, base):
    out = subprocess.run(["git", "diff", "--name-only", "--diff-filter=AMR", f"{base}...HEAD", "--",
                          "manifests/", "overrides/"],
                         cwd=index_dir, capture_output=True, text=True, check=True).stdout
    names = set()
    for line in out.splitlines():
        names.add(Path(line).name)
    return sorted(index_dir / "manifests" / n for n in names if (index_dir / "manifests" / n).exists())


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "arospkg-index-check"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read(DOWNLOAD_MAX + 1)
    if len(data) > DOWNLOAD_MAX:
        raise ValueError(f"larger than {DOWNLOAD_MAX} bytes")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("index_dir")
    ap.add_argument("--base", help="check only manifests changed since this git ref")
    ap.add_argument("--out-dir", default=None, help="where the trial catalogue goes (default: a temporary directory)")
    ap.add_argument("--cache", default=".cache/ci-archives")
    ap.add_argument("--use-local-copies", metavar="DIR", help=argparse.SUPPRESS)
    a = ap.parse_args()
    index_dir = Path(a.index_dir).resolve()
    base_ok = a.base and subprocess.run(["git", "rev-parse", "--verify", "--quiet", a.base + "^{commit}"],
                                        cwd=index_dir, capture_output=True).returncode == 0
    if a.base and not base_ok:
        print(f"{a.base}: not a commit here (a first push?); checking every manifest")
    files = changed(index_dir, a.base) if base_ok else sorted((index_dir / "manifests").glob("*.toml"))
    cache = Path(a.cache).resolve()
    base_entries = released(index_dir, a.base) if base_ok else {}
    problems = 0
    for f in files:
        m = tomllib.loads(f.read_text(encoding="utf-8"))
        ov = mkindex.overrides_for(f)
        if isinstance(ov, str):
            print(f"{f.name}: {ov}"); problems += 1; continue
        m = {**m, **(ov or {})}
        if m.get("status") != "approved" or m.get("excluded"):
            continue
        url = m.get("url", "")
        if not url.startswith("https://"):
            print(f"{f.name}: url is not https://"); problems += 1; continue
        # The rule submit applies, enforced here too: a pull request can be
        # written by hand, so the tool that prepares one is no boundary.
        key = (m.get("id"), m.get("arch"), m.get("abi"))
        was = base_entries.get(key)
        if was and was[0] == m.get("version") and was[1] == m.get("revision", 0) and was[2] != m.get("sha256"):
            print(f"{f.name}: version {was[0]} revision {was[1]} is published with sha256 {was[2]}; "
                  f"different bytes need a new revision or version")
            problems += 1
            continue
        try:
            # Keyed by the whole URL: two uploads named release.zip must not
            # stand in for each other.
            dest = cache / hashlib.sha256(url.encode()).hexdigest()[:24] / url.rsplit("/", 1)[-1]
            if a.use_local_copies:          # tests: the bytes "at" the url
                data = (Path(a.use_local_copies) / url.rsplit("/", 1)[-1]).read_bytes()
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            else:
                data = download(url, dest)
        except Exception as exc:
            print(f"{f.name}: cannot download {url}: {exc}"); problems += 1; continue
        sha = hashlib.sha256(data).hexdigest()
        if sha != m.get("sha256") or len(data) != m.get("size"):
            print(f"{f.name}: the file at its url is {len(data)} bytes, sha256 {sha}; "
                  f"the manifest says {m.get('size')} bytes, sha256 {m.get('sha256')}")
            problems += 1
            continue
        # An archive this check cannot read has not been checked: that fails,
        # where the generator's local run would only warn.
        try:
            names = mkindex.archive_names(dest)
        except Exception as exc:
            print(f"{f.name}: cannot list the archive ({exc}); its layout is unchecked"); problems += 1; continue
        more = mkindex.check_members(m, names)
        for p in more:
            print(f"{f.name}: {p}")
        if more:
            problems += 1
            continue
        print(f"{f.name}: archive matches and its layout passes ({len(data)} bytes)", flush=True)
    sys.stdout.flush()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(a.out_dir) if a.out_dir else Path(tmp)
        out.mkdir(parents=True, exist_ok=True)
        # The trial starts from the published index.json, so its rule (keep
        # the packages it lists) is checked against the real file.
        prev = index_dir / "index.json"
        if prev.exists() and out.resolve() != index_dir:
            (out / "index.json").write_bytes(prev.read_bytes())
        # The layouts were checked above, against archives keyed by URL; the
        # generator's own lookup is by file name, so it is skipped.
        r = subprocess.run([sys.executable, str(HERE / "mkindex.py"), "--manifests", str(index_dir / "manifests"),
                            "--out-dir", str(out), "--no-archive-check"])
        if r.returncode:
            problems += 1
    if problems:
        print(f"\n{problems} problem(s)")
        sys.exit(1)
    print("\nall checks pass")


if __name__ == "__main__":
    main()
