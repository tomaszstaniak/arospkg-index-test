#!/usr/bin/env python3
"""Build arospkg-index/index-v2.json and index.json from APPROVED manifests.

index-v2.json holds every published package and is what clients after 0.3.2
fetch. index.json is the same data restricted to the packages it already
listed, within what clients up to 0.3.2 can read (OLD_CLIENT_MAXTOK).

The approved manifests and the index live in the arospkg-index repository,
beside this one; that is the only copy. Unreviewed candidates stay here, in
index/candidates/, and never reach it.

This is the publication half of the pipeline. It reads the manifests, not the
catalogue -- which is the whole point of the split. The earlier version of this
tool generated the index directly from the catalogue with `depends: []` hard
coded, so a dependency written into a manifest by hand could never reach the
index. It was a catalogue importer wearing the name of an index generator.

    catalogue  --import_catalogue.py-->  candidates.json + skeletons
    manifests  --mkindex.py---------->   index-v2.json, index.json

A manifest enters the index only if it is approved AND complete. "Complete"
is checked, not assumed:

  * status == "approved"
  * sha256 present and 64 hex characters
  * depends_checked == true -- an empty `depends` with depends_checked false
    means nobody has looked, which is not the same as having no dependencies,
    and shipping the first as the second is how a package manager installs
    something that cannot run. `depends_checked` asserts a deliberate review
    informed by tools/deps.py, not that a scan was run.
  * every id in `depends` resolves to another published manifest for the SAME
    architecture. Without this an approved manifest could name a package that
    does not exist and the index would publish it, so the failure would land on
    a user at install time instead of on us at generation time.

`requires_system` is separate from `depends` and is deliberately NOT closed
over: it names things the machine must already provide (a library that ships
with the OS, a device, a datatype). "No package in the index provides X" and
"this machine does not have X" are different conditions and get different
messages, so they are different fields.

Everything rejected is listed with its reason. A quiet index is a lying index.
"""

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import catalogue as cat

SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# Requirement types the client can actually decide. Anything else is published
# but will come back "undetermined" on every machine, so listing them here is
# how the host tool says which ones carry a real verdict.
REQ_TYPES = ("library",)
REQUIRED = ("id", "version", "arch", "url", "size", "sha256", "kind")
# The ABIs the 0.3 client knows. It refuses an entry with any other value,
# or with none, before downloading -- so publishing one only produces an
# entry nobody can install.
# The same list as pkg_abi_known() in src/libpkg/entries.c.
ABIS = ("v0", "v1", "v11")
# CPUs an entry may name: those the client is built for. Kept apart from
# catalogue.SUPPORTED_ARCH, which decides what the importer offers as
# candidates; widening that would import every i386 upload at once.
ARCHES = ("x86_64", "aarch64", "i386")

# What the 0.3 client can hold, from its fixed buffers (src/libpkg/pkg.h,
# entries.c, internal.h, req.h). Past these it truncates without a word.
# Fields the client ACTS on are refused when they do not fit: a cut url
# fetches another address, a cut subdir installs nothing. Fields it only
# shows are a note: a shortened summary is a display limit, not wrong data.
OPERATIONAL_MAX = {"id": 63, "version": 63, "arch": 15, "abi": 7, "url": 511,
                   "subdir": 127, "icon": 127}
DISPLAY_MAX = {"summary": 159, "category": 63, "kind": 15, "license": 63}
SOURCE_MAX = 255
REQ_MAX = {"id": 63, "type": 23}
# The client does not decode JSON escapes: a string reaches it exactly as it
# stands in the file. So every string must be one json.dumps writes without
# an escape -- printable ASCII other than '"' and '\' -- or the client would
# act on something other than what the manifest says (measured 2026-09-29:
# a '"' in version made every later upgrade compare unequal).
PLAIN = re.compile(r'^[\x20-\x21\x23-\x5b\x5d-\x7e]*$')
# What a client can read; every key and value is one JSON value.
# Clients up to 0.3.2 hold 8192 values in a fixed array and take 4 MiB, and
# they read the same published file, so an index past that breaks them with
# "the index is not valid JSON". That is their limit, not the format's.
OLD_CLIENT_MAXTOK = 8192
OLD_CLIENT_MAXBYTES = 4 * 1024 * 1024
# Later clients allocate what the file needs, up to these guards against a
# broken or hostile file (src/libpkg/json.h PKG_JSON_MAXTOK, ops.c INDEX_MAX).
CLIENT_MAXTOK = 1 << 20
CLIENT_MAXBYTES = 16 * 1024 * 1024
REVISION_MAX = 2**31 - 1
# post_install_notes: what the client holds (src/libpkg/pkg.h PKG_NOTES_*).
# Refused, not shortened, past these: a cut sentence can say the opposite.
NOTES_LINES, NOTES_LINE = 8, 159


# Filled in from the uploaded file when a package is submitted, never written
# by its author: what the author's copy says could only disagree with the file.
PUBLICATION_FIELDS = ("url", "size", "sha256", "status")


def check(m, stage="index"):
    """Return a list of reasons this manifest cannot be published.

    stage "index": a manifest in arospkg-index, complete and approved.
    stage "author": the manifest an author ships in the archive
    (.arospkg/manifest.toml); the same rules, without the publication fields,
    which it must not carry."""
    problems = []
    if stage == "author":
        for k in PUBLICATION_FIELDS:
            if k in m:
                problems.append(f"{k}: set when the archive is submitted, from the uploaded file; "
                                "remove it from the manifest")
        m = {**m, "status": "approved", "url": "https://placeholder.invalid/p.zip",
             "size": 1, "sha256": "0" * 64}
    # A deliberate exclusion is not the same as an unreviewed skeleton, and
    # collapsing the two would hide a decision inside a backlog count.
    if m.get("excluded"):
        return [f'excluded: {m["excluded"]}']
    if m.get("status") != "approved":
        problems.append(f'status is {m.get("status", "missing")!r}, not "approved"')
    for k in REQUIRED:
        if m.get(k) in (None, ""):
            problems.append(f"missing {k}")
    sha = m.get("sha256", "")
    if sha and not SHA_RE.match(sha):
        problems.append("sha256 is not 64 hex characters")
    if not m.get("depends_checked", False):
        problems.append("depends_checked is false (not investigated)")
    if m.get("arch") not in ARCHES:
        problems.append(f'arch {m.get("arch")!r} is not one we build for')
    if m.get("id") and not cat.ID_RE.match(str(m["id"])):
        problems.append(f'id {m["id"]!r} is not a legal package id')
    if m.get("abi") not in ABIS:
        problems.append(f'abi {m.get("abi")!r} is not one the client knows '
                        f'({", ".join(ABIS)}); it would refuse the entry')
    url = m.get("url")
    if isinstance(url, str) and url and not url.startswith("https://"):
        problems.append("url is not https://; the client fetches nothing else")
    size = m.get("size")
    if size not in (None, "") and (isinstance(size, bool) or not isinstance(size, int) or size <= 0):
        problems.append(f"size {size!r} is not a positive integer")
    if "revision" in m:
        r = m["revision"]
        if isinstance(r, bool) or not isinstance(r, int) or not 1 <= r <= REVISION_MAX:
            problems.append(f"revision {r!r} is not an integer from 1 to {REVISION_MAX}")
    problems += check_strings(m)
    problems += check_requires(m.get("requires_system", []))
    problems += check_notes(m.get("post_install_notes"))
    return problems


def check_notes(v):
    """post_install_notes: optional plain lines a user reads after installing."""
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        return ["post_install_notes: not a list of strings; write one string per line"]
    problems = []
    if len(v) > NOTES_LINES:
        problems.append(f"post_install_notes: {len(v)} lines; maximum is {NOTES_LINES}")
    # Counted from 0, as requires_system[i] is.
    for i, line in enumerate(v):
        if not line.strip():
            problems.append(f"post_install_notes[{i}]: empty; remove the line")
        elif not PLAIN.match(line):
            problems.append(f"post_install_notes[{i}]: has a character the client would read "
                            "differently; use printable ASCII without '\"' or '\\'")
        elif len(line) > NOTES_LINE:
            problems.append(f"post_install_notes[{i}]: {len(line)} characters; maximum is {NOTES_LINE}")
    return problems


def check_strings(m):
    """Every string the index carries, against what the 0.3 client can read."""
    problems = []
    fields = [(k, m.get(k)) for k in list(OPERATIONAL_MAX) + list(DISPLAY_MAX)]
    src = m.get("source")
    if isinstance(src, dict):
        fields.append(("source.repository", src.get("repository")))
    for k, v in fields:
        if v is None or v == "":
            continue
        if not isinstance(v, str):
            problems.append(f"{k} is not a string")
        elif not PLAIN.match(v):
            problems.append(f"{k} {v!r} has a character the 0.3 client would read "
                            "differently: use printable ASCII without '\"' or '\\'")
        else:
            limit = OPERATIONAL_MAX.get(k)
            if limit and len(v) > limit:
                problems.append(f"{k} is {len(v)} characters; the client keeps {limit}")
    for k, limit in DISPLAY_MAX.items():
        v = m.get(k)
        if isinstance(v, str) and len(v) > limit:
            print(f"  note: {m.get('id')}: {k} is {len(v)} characters; the client shows {limit}")
    if isinstance(src, dict) and isinstance(src.get("repository"), str) \
            and len(src["repository"]) > SOURCE_MAX:
        print(f"  note: {m.get('id')}: source.repository is longer than the {SOURCE_MAX} the client shows")
    for k in ("depends", "installs_on", "runs_on", "does_not_run_on"):
        v = m.get(k, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and PLAIN.match(x) for x in v):
            problems.append(f"{k} must be a list of plain ASCII strings")
    return problems


def check_requires(reqs):
    """requires_system must have a shape the client can read.

    The client refuses a malformed entry rather than skipping it -- a
    requirement silently dropped is indistinguishable from a package with no
    requirements. That refusal would land on a user at install time, so the
    same check runs here, where it lands on us at generation time instead.

    One TOML trap is worth knowing about: every key after a `[[requires_system]]`
    header belongs to that table, so the scalar keys must come BEFORE the table
    arrays in a manifest. Putting `kind` after them silently moved it inside a
    requirement and this tool reported `missing kind`.
    """
    problems = []
    if not isinstance(reqs, list):
        return ["requires_system is not a list"]
    for i, r in enumerate(reqs):
        if not isinstance(r, dict):
            problems.append(f"requires_system[{i}] is not a table")
            continue
        for k, limit in REQ_MAX.items():
            v = r.get(k)
            if isinstance(v, str) and v and (not PLAIN.match(v) or len(v) > limit):
                problems.append(f"requires_system[{i}] {k} {v!r} is not plain ASCII of "
                                f"at most {limit} characters")
        if not r.get("id"):
            problems.append(f"requires_system[{i}] has no id")
        if not r.get("type"):
            problems.append(f"requires_system[{i}] has no type")
        elif r["type"] not in REQ_TYPES:
            # Not a rejection: an honest "undetermined" is a legitimate
            # outcome, and refusing the manifest would mean only requirements
            # we can check may be declared, which is backwards.
            print(f'  note: requires_system[{i}] type {r["type"]!r} cannot be '
                  f"checked by the client; it will report undetermined")
        mv = r.get("min_version", 0)
        if isinstance(mv, bool) or not isinstance(mv, int) or mv < 0:
            problems.append(f"requires_system[{i}] min_version {mv!r} is not a "
                            "non-negative integer")
        extra = set(r) - {"id", "type", "min_version"}
        if extra:
            problems.append(f"requires_system[{i}] has unknown key(s) "
                            f"{', '.join(sorted(extra))}")
    return problems


def archive_names(path):
    """Member names in a ZIP or an LHA.

    The client picks its reader from the archive's first bytes, and since it
    reads LHA this tool has to as well: handing an LHA to zipfile raised
    BadZipFile, which would have crashed the generator on the first LHA
    manifest rather than checking it. LHA listing shells out to `lha`, which
    is not part of the client and is only ever used here, on the host.
    """
    import subprocess
    import zipfile
    head = path.open("rb").read(8)
    if head[:4] == b"PK\x03\x04":
        return set(zipfile.ZipFile(path).namelist())
    if head[2:3] == b"-" and head[6:7] == b"-":
        out = subprocess.run(["lha", "lq", str(path)], capture_output=True,
                             text=True, check=True).stdout
        # lhasa has no names-only listing, so the name is whatever follows the
        # timestamp column -- `Sep 20 09:24` for this year, `Sep 20  2024`
        # otherwise. Anchoring on that keeps names containing spaces intact,
        # which splitting on whitespace would not.
        stamp = re.compile(r" [A-Z][a-z]{2} +\d{1,2} +(?:\d{2}:\d{2}|\d{4}) (.+)$")
        names = set()
        for ln in out.splitlines():
            hit = stamp.search(ln)
            if hit:
                names.add(hit.group(1))
        if not names:
            raise ValueError("lha listed no members")
        return names
    raise ValueError("not a ZIP or LHA archive")


# What the client refuses in an archive member (src/libpkg/ops.c), and its
# limits on what it installs.
MEMBER_MAX, PKGPATH_MAX, FILES_MAX = 511, 255, 2048


# Fields an override may not change: they identify the entry or come from the
# uploaded file.
OVERRIDE_FIXED = ("id", "arch", "abi", "url", "size", "sha256")


def overrides_for(manifest_file):
    """overrides/<same file name> beside manifests/: a dict, None when there
    is none, or a string saying why it cannot be used."""
    p = manifest_file.parent.parent / "overrides" / manifest_file.name
    if not p.is_file():
        return None
    try:
        ov = tomllib.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        return f"overrides/{p.name}: unparseable: {exc}"
    bad = sorted(set(ov) & set(OVERRIDE_FIXED))
    if bad:
        return f"overrides/{p.name}: may not change {', '.join(bad)}"
    return ov


def variant_file(m):
    """The manifest file name of a variant: <id>.<arch>.<abi>.toml. Files named
    <id>.<arch>.toml, from before the ABI was part of the name, are still read."""
    return f"{m['id']}.{m['arch']}.{m['abi']}.toml"


def check_members(m, names, where="the archive"):
    """The member names of an archive, or of a drawer about to be packed,
    against the client's rules and the manifest's subdir and icon."""
    problems = []
    sub = m.get("subdir") or ""
    files = 0
    for n in sorted(names):
        rel = n[len(sub) + 1:] if sub and n.startswith(sub + "/") else (n if not sub else None)
        parts = n.rstrip("/").split("/")
        if n.startswith(("/", "\\")) or ":" in n or ".." in parts \
                or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in n):
            problems.append(f"member {n[:60]!r}: the client refuses this name (absolute, a volume, "
                            "'..' or a control character); rename it")
        elif len(n.encode()) > MEMBER_MAX:
            problems.append(f"member {n[:60]}...: longer than the {MEMBER_MAX} bytes the client reads")
        elif rel is not None and len(rel.rstrip("/").encode()) > PKGPATH_MAX:
            problems.append(f"member {rel[:60]}...: path inside the package longer than {PKGPATH_MAX} bytes")
        if rel is not None and not n.endswith("/"):
            files += 1
    if files > FILES_MAX:
        problems.append(f"subdir: {files} files; the client installs at most {FILES_MAX}")
    if m.get("icon") and m["icon"] not in names:
        problems.append(f'icon: {m["icon"]!r} is not at that path in {where}')
    if sub and not any(n.startswith(sub + "/") for n in names):
        problems.append(f'subdir: {sub!r} is not in {where}')
    return problems


def check_archive(m, cache):
    """subdir and icon must exist in the archive. Checked here, where it lands on
    us, because the client refuses an icon the archive lacks -- which is right,
    and which a wrong path in a published manifest would turn into a package
    nobody can install. `sdllopan` shipped with the icon INSIDE its drawer named
    as the drawer icon; this is the check that would have caught it."""
    name = m.get("url", "").rsplit("/", 1)[-1]
    hits = list(Path(cache).rglob(name)) if name else []
    if not hits:
        return [], [f"archive {name} not in {cache}: subdir and icon unchecked"]
    try:
        names = archive_names(hits[0])
    except Exception as exc:
        return [], [f"{name}: cannot list ({exc}): subdir and icon unchecked"]
    return check_members(m, names), []


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifests", default="../arospkg-index/manifests")
    ap.add_argument("--out-dir", default="../arospkg-index",
                    help="writes index-v2.json (every package) and index.json "
                         "(for clients up to 0.3.2) here")
    ap.add_argument("--out", help=argparse.SUPPRESS)
    ap.add_argument("--no-archive-check", action="store_true",
                    help="skip subdir/icon against cached archives (ci_check_index.py checks them itself)")
    ap.add_argument("--verbose", action="store_true", help="list every rejection")
    ap.add_argument("--cache", default=".cache/archives",
                    help="downloaded archives, to check subdir and icon against")
    args = ap.parse_args()
    if args.out:
        sys.exit("--out is gone: use --out-dir DIR, which gets index-v2.json and index.json")

    files = sorted(Path(args.manifests).glob("*.toml"))
    published, rejected, seen = [], [], {}
    # Manifests marked approved that did not make it into the index. Leaving
    # out a skeleton or an exclusion is the normal work of this tool; leaving
    # out something a person approved means the index would be incomplete,
    # and then the previous index is kept rather than overwritten.
    failed = set()

    for f in files:
        try:
            m = tomllib.loads(f.read_text(encoding="utf-8"))
        except Exception as exc:
            rejected.append((f.name, [f"unparseable: {exc}"]))
            if re.search(r'(?m)^\s*status\s*=\s*"approved"', f.read_text(encoding="utf-8", errors="replace")):
                failed.add(f.name)
            continue
        # A maintainer's deliberate correction to an author's entry, kept apart
        # so the author's next submission does not erase it, and applied here,
        # where every catalogue file is made.
        ov = overrides_for(f)
        if ov is not None:
            if isinstance(ov, str):
                rejected.append((f.name, [ov])); failed.add(f.name); continue
            m = {**m, **ov}
        approved = m.get("status") == "approved" and not m.get("excluded")

        problems = check(m)
        if not problems and not args.no_archive_check:
            more, warn = check_archive(m, args.cache)
            problems += more
            for w in warn:
                print(f"  warning: {f.name}: {w}")
        if problems:
            rejected.append((f.name, problems))
            if approved: failed.add(f.name)
            continue

        # A variant is its id, CPU and ABI: x86_64/v1 and x86_64/v11 builds of
        # one program are two entries, and the client picks its own.
        key = (m["id"].lower(), m["arch"], m["abi"])
        if key in seen:
            rejected.append((f.name, [f"duplicate (id, arch, abi) with {seen[key]}"]))
            failed.add(f.name)
            continue
        seen[key] = f.name

        published.append({
            "id": m["id"], "version": m["version"], "summary": m.get("summary", ""),
            "arch": m["arch"], "abi": m.get("abi") or None,
            "category": m.get("category", ""), "url": m["url"], "size": m["size"],
            "sha256": m["sha256"], "depends": m.get("depends", []),
            "requires_system": m.get("requires_system", []),
            # Carried through so a client can refuse a package on a system
            # where it is known not to run. Installing correctly and running
            # are different claims and the index must not conflate them.
            "installs_on": m.get("installs_on", []),
            "runs_on": m.get("runs_on", []),
            "does_not_run_on": m.get("does_not_run_on", []),
            "kind": m["kind"], "subdir": m.get("subdir", ""),
            "icon": m.get("icon", ""),
            "install": m.get("install", {}),
            # This port's release counter (docs/reference/metadata.md): absent means
            # the first packaging, and the client shows nothing for it. It was
            # never emitted before openloco stated one, so every upgrade test
            # ran on hand-written indexes.
            **({"revision": int(m["revision"])} if m.get("revision") else {}),
            # Where the source is, and under what licence, when the manifest
            # says: what `apkg show` prints. Older clients skip unknown keys.
            **({"source": m["source"]["repository"]}
               if isinstance(m.get("source"), dict) and m["source"].get("repository") else {}),
            **({"license": m["license"]} if m.get("license") else {}),
            # Shown after installing, by show and in the window. Older
            # clients skip unknown keys (tests/fixtures: checked with 0.3.2).
            **({"post_install_notes": m["post_install_notes"]} if m.get("post_install_notes") else {}),
        })

    # Closure. An approved manifest may name a dependency that does not exist;
    # publishing it would move the failure from us to a user at install time.
    # Iterated to a fixed point: dropping a package can orphan its dependents.
    while True:
        have = {(p["id"].lower(), p["arch"]) for p in published}
        broken = []
        for p in published:
            missing = [d for d in p["depends"] if (d.lower(), p["arch"]) not in have]
            if missing:
                broken.append((p, missing))
        if not broken:
            break
        for p, missing in broken:
            published.remove(p)
            failed.add(f'{p["id"]}.{p["arch"]}.toml')
            rejected.append((f'{p["id"]}.{p["arch"]}.toml',
                             [f"depends on {', '.join(missing)}, not in the index "
                              f"for {p['arch']}"]))

    packages = sorted(published, key=lambda p: (p["id"], p["arch"]))
    outdir = Path(args.out_dir)
    v2_path, old_path = outdir / "index-v2.json", outdir / "index.json"
    # Clients up to 0.3.2 fetch index.json and read at most OLD_CLIENT_MAXTOK
    # values. It keeps the packages it already lists, with their metadata
    # brought up to date from the same manifests (Archives replaces files
    # under the same URL, so an old hash would fail the download); packages
    # new since then go to index-v2.json only. Nothing is shortened to fit.
    if old_path.exists():
        prev = json.loads(old_path.read_text(encoding="utf-8"))
        # By (id, arch, abi): a build for another ABI of a package it lists is
        # new, so it stays out, and index.json keeps one entry per (id, arch),
        # which is all clients up to 0.3.2 were tested with.
        keep = {(p["id"], p["arch"], p.get("abi")) for p in prev.get("packages", [])}
        old_packages = [p for p in packages if (p["id"], p["arch"], p["abi"]) in keep]
    else:
        old_packages = packages
    texts = {}
    for path, pkgs in ((v2_path, packages), (old_path, old_packages)):
        texts[path] = json.dumps({"schema": 1, "source": cat.CATALOGUE, "packages": pkgs},
                                 indent=2) + "\n"

    print(f"manifests read         {len(files)}")
    print(f"published              {len(published)}")
    print(f"rejected               {len(rejected)}")
    if rejected:
        by_reason = {}
        for _, probs in rejected:
            by_reason[probs[0]] = by_reason.get(probs[0], 0) + 1
        for reason, n in sorted(by_reason.items(), key=lambda kv: -kv[1]):
            print(f"  {n:>4}  {reason}")
        if args.verbose:
            print()
            for name, probs in rejected:
                print(f"  {name}: {'; '.join(probs)}")
    stop = []
    if failed:
        stop.append(f"{len(failed)} approved manifest(s) not published: {', '.join(sorted(failed))}")
    for path, maxtok, maxbytes, who in ((v2_path, CLIENT_MAXTOK, CLIENT_MAXBYTES, "later clients"),
                                        (old_path, OLD_CLIENT_MAXTOK, OLD_CLIENT_MAXBYTES, "clients up to 0.3.2")):
        ntok, nbytes = json_values(json.loads(texts[path])), len(texts[path].encode())
        npk = len(packages if path == v2_path else old_packages)
        print(f"{path.name:<16} {npk} packages, {ntok} JSON values ({100 * ntok // maxtok}% of {maxtok}), "
              f"{nbytes} bytes ({100 * nbytes // maxbytes}% of {maxbytes}); for {who}")
        if ntok > maxtok or nbytes > maxbytes:
            stop.append(f"{path.name} is larger than {who} read. Its packages are kept and "
                        f"nothing is shortened: decide which to drop from it by hand")
    if len(old_packages) < len(packages):
        print(f"  {len(packages) - len(old_packages)} package(s) only in index-v2.json")
    if stop:
        for why in stop:
            print(f"\nNOT WRITTEN: {why}")
        print(f"{v2_path} and {old_path} are unchanged.")
        sys.exit(1)
    # Each written beside and renamed over, so a failure half-way cannot leave
    # a truncated index where a good one was.
    outdir.mkdir(parents=True, exist_ok=True)
    for path, text in texts.items():
        tmp = path.with_name(path.name + ".part")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        print(f"written {path}")


def json_values(v):
    """What the client's reader counts: every object, array, key and value."""
    if isinstance(v, dict):
        return 1 + sum(1 + json_values(x) for x in v.values())
    if isinstance(v, list):
        return 1 + sum(json_values(x) for x in v)
    return 1


if __name__ == "__main__":
    main()
