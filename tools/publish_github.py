"""Open a pull request in the catalogue repository for one submitted manifest.

Kept apart from apkg-pack so the way a submission reaches the catalogue can
change (another host, another review process) without touching how packages
are described, checked or packed. Uses git and the gh CLI with whatever
authentication they already have; it stores no credentials.

An author normally cannot push to the catalogue repository, so the branch
goes to their fork of it, created when missing, and the pull request is
opened from there. Someone who can push uses a branch in the repository
itself. Either way the work happens in a fresh clone, so nothing staged or
changed in another checkout can end up in the pull request.
"""
import atexit
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(cwd, *cmd, check=True):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)
    except subprocess.CalledProcessError as exc:
        print(f"{' '.join(cmd)}: {exc.stderr.strip() or exc.stdout.strip()}", file=sys.stderr)
        sys.exit(1)


def checkout(repo):
    """A fresh clone of repo's default branch, removed when the program ends."""
    tmp = Path(tempfile.mkdtemp(prefix="apkg-pack-"))
    atexit.register(shutil.rmtree, tmp, True)
    run(None, "gh", "repo", "clone", repo, str(tmp / "index"), "--", "-q", "--depth", "1")
    # Commits made here carry the user's own git identity, as any commit would.
    return tmp / "index"


def ensure_fork(work, repo, me):
    """The clone URL of me's fork of repo: the existing one, or a new one.
    A repository of the same name that is not a fork of repo is not used."""
    name = repo.split("/")[1]
    r = run(work, "gh", "api", f"repos/{me}/{name}", check=False)
    if r.returncode == 0:
        info = json.loads(r.stdout)
        parent = (info.get("parent") or {}).get("full_name", "")
        if not info.get("fork") or parent.lower() != repo.lower():
            print(f"{me}/{name} exists and is not a fork of {repo}; rename it or fork by hand",
                  file=sys.stderr)
            sys.exit(1)
        print(f"using your fork {me}/{name}")
        return info["clone_url"]
    run(work, "gh", "repo", "fork", repo, "--clone=false", "--remote=false")
    print(f"forked {repo} to {me}/{name}")
    return json.loads(run(work, "gh", "api", f"repos/{me}/{name}").stdout)["clone_url"]


def open_pr(work, repo, manifest, m):
    rev = m.get("revision", 0)
    branch = f"submit/{m['id']}-{m['arch']}-{m['abi']}-{m['version']}-r{rev}"
    me = run(work, "gh", "api", "user", "--jq", ".login").stdout.strip()
    info = json.loads(run(work, "gh", "api", f"repos/{repo}").stdout)
    can_push = bool(info.get("permissions", {}).get("push"))
    # The same release submitted twice must not open a second pull request.
    existing = run(work, "gh", "pr", "list", "--repo", repo, "--state", "open", "--head", branch,
                   "--json", "url,headRepositoryOwner").stdout
    for pr in json.loads(existing or "[]"):
        if pr.get("headRepositoryOwner", {}).get("login") in (me, repo.split("/")[0]):
            print(f"a pull request for this release is already open: {pr['url']}")
            return
    title = f"Submit {m['id']} {m['version']}" + (f" revision {rev}" if rev else "") + \
            f" for {m['arch']}/{m['abi']}"
    run(work, "git", "switch", "-q", "-c", branch)
    run(work, "git", "add", "--", str(manifest.relative_to(work)))
    run(work, "git", "commit", "-q", "-m", f"{title}\n\nFrom {m['url']}\nsha256 {m['sha256']}, {m['size']} bytes.")
    if can_push:
        remote, head = "origin", branch
    else:
        fork = ensure_fork(work, repo, me)
        remote, head = "fork", f"{me}:{branch}"
        run(work, "git", "remote", "add", "fork", fork)
    # Only this branch, only to the chosen remote.
    run(work, "git", "push", "-q", remote, f"refs/heads/{branch}:refs/heads/{branch}")
    url = run(work, "gh", "pr", "create", "--repo", repo, "--base", info.get("default_branch", "main"),
              "--head", head, "--title", title, "--body",
              f"Archive: {m['url']}\n\nsha256 `{m['sha256']}`, {m['size']} bytes.\n\n"
              "Prepared by apkg-pack submit from the archive's own manifest. The check on "
              "this pull request downloads the archive again and applies the catalogue's rules.").stdout.strip()
    print(f"opened {url}" + ("" if can_push else f" (from {me}/{repo.split('/')[1]})"))
