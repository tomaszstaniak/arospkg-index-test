"""Shared helpers for reading the AROS Archives catalogue.

The catalogue is FULLINDEX.readme:

    category filename size date version :description

Encoding: it is Latin-1. Decoding as UTF-8 raises, and grepping it under a
UTF-8 locale silently matches nothing at all -- which looks exactly like an
empty file and has cost time twice. Do not "simplify" the decode.
"""

import re

BASE = "https://archives.arosworld.org"
CATALOGUE = f"{BASE}/share/FULLINDEX.readme"

# The download URL is /share/<category>/<filename>. It is NOT download.php?path=,
# which answers 200 with Content-Type "directory" and a few hundred bytes of
# HTML. Verified 2026-09-06 against four entries on both architectures.
def download_url(category, filename):
    return f"{BASE}/share/{category}/{filename}"


# The "-v11" suffix is an ABI marker, not decoration, and getting this wrong
# inverts the whole index. From deadwood (AROS developer), 2026-09-11:
#
#   "The role of the x86_64-aros-v11 suffix is exactly that - to distinguish
#    between the ABIv1 and ABIv11 binaries and let them live together on the
#    archives. The -v11 marks binaries usable with current distributions like
#    AROS One. Archives without such marker are intended for ABIv1."
#
# So:
#   x86_64-aros-v11  -> ABIv11 -> AROS One and other current distributions
#   x86_64-aros      -> ABIv1  -> mainline
#   aarch64-aros     -> ABIv1  -> mainline
#
# We build against mainline, which is ABIv1. The first version of this tool
# offered the 168 "-v11" entries and skipped everything else, which is exactly
# backwards: those are the packages that install perfectly on mainline and
# crash on startup. Measured before this was understood -- eight of eight.
#
# Longer, more specific tags first, or "x86_64-aros-v11" matches "x86_64" and
# the ABI is lost.
ARCH_TAGS = [
    ("x86_64-aros-v11", ("x86_64", "v11")),
    ("aarch64-aros-v11",("aarch64", "v11")),
    ("aarch64-aros",    ("aarch64", "v1")),
    ("x86_64-aros",     ("x86_64", "v1")),
    ("i386-aros",       ("i386", "v1")),
    ("os3-68k-aros",    ("m68k", None)),
    ("68k-aros",        ("m68k", None)),
    ("ppc-aros",        ("ppc", None)),
    ("ppc-morphos",     ("ppc", None)),
    ("aarch64",         ("aarch64", "v1")),
    ("x86_64",          ("x86_64", "v1")),
    ("i386",            ("i386", "v1")),
    ("os3-68k",         ("m68k", None)),
    ("68k",             ("m68k", None)),
    ("ppc",             ("ppc", None)),
    ("source",          ("source", None)),
]

SUPPORTED_ARCH = {"x86_64", "aarch64"}

# BOTH ABIs are catalogued, and the client filters at install time.
#
# An earlier version of this file offered only "v1", on the reasoning that we
# target mainline. That was right when there was one build and wrong now that
# there are two: `pkg` ships for ABIv1 and ABIv11, each refuses a package for
# the other before downloading, and each hides the other's packages from
# `search`. So a single index serving both is correct, and filtering here would
# only hide from the ABIv11 build the 173 packages it can actually run.
#
# Which is also the honest shape of the problem: the index is a catalogue of
# what exists, and which entries are usable is a property of the machine
# reading it, not of the file.
SUPPORTED_ABI = {"v1", "v11"}

# Kept as a name some callers still use.
SUPPORTED = SUPPORTED_ARCH

# Longest first: ".tar.gz" before ".gz", and ".tar" must be present at all --
# leaving it out produced the id "protrekkr.tar".
SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz",
            ".lha", ".lzx", ".lzh", ".zip", ".7z", ".rar",
            ".tar", ".gz", ".bz2", ".xz")

ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


def detect_arch(filename):
    lowered = filename.lower()
    for tag, (arch, abi) in ARCH_TAGS:
        if f".{tag}." in lowered or f"-{tag}." in lowered or f"_{tag}." in lowered:
            return arch, abi
    return None, None


def suggest_id(filename):
    """Suggest a package id from a filename.

    A SUGGESTION, never an answer. The catalogue bakes versions into names, so
    this happily produces `python-2.5.2` and `python-2.7.18` as two unrelated
    programs. Only a human approving the manifest can decide that both are
    `python`, and which one the id should belong to.
    """
    stem = filename.lower()
    for suffix in SUFFIXES:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    for tag, _ in ARCH_TAGS:
        for sep in (".", "-", "_"):
            marker = sep + tag
            if stem.endswith(marker):
                stem = stem[: -len(marker)]
            stem = stem.replace(marker + ".", ".")
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem).strip("-._")
    stem = re.sub(r"-{2,}", "-", stem)
    if not stem or not stem[0].isalpha():
        stem = "pkg-" + stem
    return stem[:64]


def parse(text):
    """Return (entries, malformed). Malformed lines are reported, never dropped
    silently: a parser that quietly discards input is how an index goes stale."""
    entries, bad = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line or line.startswith(";"):
            continue
        head, sep, description = line.partition(" :")
        if not sep:
            bad.append((lineno, raw)); continue
        f = head.split()
        if len(f) < 4:
            bad.append((lineno, raw)); continue
        try:
            size = int(f[2])
        except ValueError:
            bad.append((lineno, raw)); continue
        arch, abi = detect_arch(f[1])
        entries.append({
            "category": f[0], "filename": f[1], "size": size, "date": f[3],
            "version": " ".join(f[4:]) if len(f) > 4 else "",
            "summary": description.strip(), "arch": arch, "abi": abi,
            "url": download_url(f[0], f[1]),
        })
    return entries, bad
