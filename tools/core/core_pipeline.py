#!/usr/bin/env python3
"""Local-only pinned vp_core replay. Never builds, executes or fetches upstream code."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

class PipelineError(RuntimeError):
    pass

ROOT = Path(__file__).resolve().parents[2]
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENERATED_PATH = "integration/vp_core"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def environment():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    return env


def git(repo, *args, env=None, input=None):
    """Disable hooks, filters, external diff, fsmonitor and network protocols."""
    base = ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "core.fsmonitor=false",
            "-c", "protocol.allow=never", "-c", "diff.external=", "-C", str(repo)]
    # Local checkout attributes must not cause execution of configured filter programs.
    keys = subprocess.run(base + ["config", "--name-only", "--get-regexp", r"^filter\..*\.(clean|smudge|process|required)$"],
                          env=environment(), capture_output=True, text=True)
    if keys.returncode not in (0, 1):
        raise PipelineError("cannot inspect Git filter configuration")
    safe = []
    for key in keys.stdout.splitlines():
        safe.extend(["-c", key + ("=false" if key.endswith(".required") else "=")])
    command = base[:1] + safe + base[1:] + list(args)
    result = subprocess.run(command, env=env or environment(), input=input,
                            capture_output=True, text=True)
    if result.returncode:
        raise PipelineError(f"git {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def require(condition, message):
    if not condition:
        raise PipelineError(message)


def safe_file(root, relative):
    require(isinstance(relative, str), "patch path must be a string")
    parts = Path(relative).parts
    require(not Path(relative).is_absolute() and ".." not in parts, "unsafe patch path")
    require(relative.startswith("patches/vp_core/") and relative.endswith(".patch"), "unexpected patch path")
    path = root / relative
    require(path.is_file() and not path.is_symlink(), "patch is missing or is a symlink")
    require(path.resolve().is_relative_to(root.resolve()), "patch path escapes product root")
    return path


def patchset_hash(upstream, patches):
    # Ordered list: reordering even independent patches changes release identity.
    return sha256(canonical({"upstream_commit": upstream["commit"],
                             "upstream_tree": upstream["tree"], "patches": patches}))


def load_lock(root, *, accept_patch_edits=False):
    lock = json.loads((root / "core-lock.json").read_text())
    require(lock.get("schema_version") == 1, "unsupported core-lock schema")
    upstream, patchset, integration = lock["upstream"], lock["patchset"], lock["integration"]
    series = tomllib.loads((root / "patches/vp_core/series.toml").read_text())
    require(series.get("schema_version") == 1, "unsupported series schema")
    if accept_patch_edits:
        # Explicit proposal lane: current series is reviewed input, never accepted
        # by normal verify/prepare and never written back to core-lock.json.
        patchset["patches"] = [{"id": item["id"], "path": item["path"],
            "sha256": sha256(safe_file(root, item["path"]).read_bytes())} for item in series["patch"]]
        patchset["sha256"] = patchset_hash(upstream, patchset["patches"])
    require(HEX40.fullmatch(upstream["commit"]) and HEX40.fullmatch(upstream["tree"]), "invalid upstream Git identity")
    require(integration["path"] == GENERATED_PATH, "integration destination is not the reserved local worktree")
    require(HEX40.fullmatch(integration["patched_tree"]) and HEX40.fullmatch(integration["commit"]), "invalid patched Git identity")
    require(HEX64.fullmatch(patchset["sha256"]), "invalid patchset digest")
    patches = patchset["patches"]
    require(isinstance(patches, list) and bool(patches), "an explicit nonempty patch series is required")
    seen = set()
    for patch in patches:
        require(set(patch) == {"id", "path", "sha256"}, "unexpected patch identity fields")
        require(patch["id"] not in seen, "duplicate patch id")
        seen.add(patch["id"])
        path = safe_file(root, patch["path"])
        require(HEX64.fullmatch(patch["sha256"]), "invalid patch digest")
        require(sha256(path.read_bytes()) == patch["sha256"], "patch content digest mismatch")
    require(patchset_hash(upstream, patches) == patchset["sha256"], "patchset identity mismatch")
    require([p["id"] for p in series["patch"]] == [p["id"] for p in patches], "series order/id mismatch")
    require([p["path"] for p in series["patch"]] == [p["path"] for p in patches], "series path mismatch")
    return lock


def verify_source(source, upstream):
    require(source.exists() and not source.is_symlink(), "upstream must be an existing local checkout, not a symlink")
    require(Path(git(source, "rev-parse", "--show-toplevel")).resolve() == source.resolve(), "upstream argument is not a repository root")
    require(git(source, "rev-parse", "HEAD") == upstream["commit"], "upstream HEAD differs from pinned/explicit candidate commit")
    require(git(source, "rev-parse", "HEAD^{tree}") == upstream["tree"], "upstream tree differs from lock")
    require(not git(source, "status", "--porcelain=v1", "--untracked-files=all"), "upstream checkout/index is dirty")


def deterministic_commit(worktree, tree, lock):
    env = environment()
    env.update(GIT_AUTHOR_NAME="VP Core Integration", GIT_AUTHOR_EMAIL="core-integration@example.invalid",
               GIT_COMMITTER_NAME="VP Core Integration", GIT_COMMITTER_EMAIL="core-integration@example.invalid",
               GIT_AUTHOR_DATE="2000-01-01T00:00:00Z", GIT_COMMITTER_DATE="2000-01-01T00:00:00Z")
    message = ("vp-product local integration\n\n"
               f"Upstream: {lock['upstream']['commit']}\nPatchset-SHA256: {lock['patchset']['sha256']}\n")
    return git(worktree, "-c", "commit.gpgSign=false", "commit-tree", tree,
               "-p", lock["upstream"]["commit"], env=env, input=message)


def apply_series(root, worktree, lock, check_expected=True):
    for patch in lock["patchset"]["patches"]:
        path = safe_file(root, patch["path"])
        # Check and apply the exact same in-memory bytes, not a mutable file path.
        content = path.read_bytes()
        require(sha256(content) == patch["sha256"], "patch changed after lock validation")
        patch_text = content.decode("utf-8")
        # No --unsafe-paths, no 3-way/fuzz fallback and no executable repository hooks.
        git(worktree, "apply", "--check", "--index", "--whitespace=error-all", "-", input=patch_text)
        git(worktree, "apply", "--index", "--whitespace=error-all", "-", input=patch_text)
    git(worktree, "diff", "--no-ext-diff", "--no-textconv", "--cached", "--check")
    tree = git(worktree, "write-tree")
    commit = deterministic_commit(worktree, tree, lock)
    if check_expected:
        require(tree == lock["integration"]["patched_tree"], "replay produced unexpected patched tree")
        require(commit == lock["integration"]["commit"], "replay produced unexpected integration commit")
    git(worktree, "checkout", "--detach", commit)
    require(not git(worktree, "status", "--porcelain=v1", "--untracked-files=all"), "generated worktree is not clean")
    return {"patched_tree": tree, "commit": commit}


def replay(root, source, lock, check_expected=True):
    """Disposable linked worktree. Only Git metadata/objects touch the source repo."""
    verify_source(source, lock["upstream"])
    with tempfile.TemporaryDirectory(prefix="vp-core-replay-") as temp:
        path = Path(temp) / "worktree"
        added = False
        try:
            git(source, "worktree", "add", "--detach", str(path), lock["upstream"]["commit"])
            added = True
            result = apply_series(root, path, lock, check_expected)
        finally:
            if added:
                # Only our disposable path; never reset/remove an existing user worktree.
                git(source, "worktree", "remove", "--force", str(path))
            verify_source(source, lock["upstream"])
    return result


def verify_integration(root, source, lock):
    path = root / GENERATED_PATH
    require(path.exists() and not path.is_symlink() and not path.parent.is_symlink(), "integration worktree is missing or symlinked")
    require(Path(git(path, "rev-parse", "--show-toplevel")).resolve() == path.resolve(), "integration path is not a worktree root")
    def common(repo):
        value = Path(git(repo, "rev-parse", "--git-common-dir"))
        return (repo / value).resolve() if not value.is_absolute() else value.resolve()
    require(common(path) == common(source), "integration is not linked to the selected source checkout")
    require(git(path, "rev-parse", "HEAD") == lock["integration"]["commit"], "existing integration commit mismatch; preserve it and reconcile explicitly")
    require(git(path, "rev-parse", "HEAD^{tree}") == lock["integration"]["patched_tree"], "existing integration tree mismatch")
    require(not git(path, "status", "--porcelain=v1", "--untracked-files=all"), "integration has local changes; refusing overwrite")
    require(git(path, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD", "integration must have detached HEAD")
    return path


def prepare(root, source, lock):
    replay(root, source, lock)  # Prove the complete series before creating permanent output.
    path = root / GENERATED_PATH
    if path.exists() or path.is_symlink():
        return verify_integration(root, source, lock)
    require(not path.parent.is_symlink(), "integration parent is symlinked")
    path.parent.mkdir(parents=True, exist_ok=True)
    git(source, "worktree", "add", "--detach", str(path), lock["upstream"]["commit"])
    # On unexpected failure preserve the worktree for diagnosis instead of reset.
    apply_series(root, path, lock)
    verify_source(source, lock["upstream"])
    return verify_integration(root, source, lock)


def candidate_lock(root, source, lock, commit):
    require(bool(HEX40.fullmatch(commit)), "candidate must be an explicit full commit id")
    candidate = copy.deepcopy(lock)
    candidate["upstream"]["commit"] = commit
    candidate["upstream"]["tree"] = git(source, "rev-parse", commit + "^{tree}")
    candidate["patchset"]["sha256"] = patchset_hash(candidate["upstream"], candidate["patchset"]["patches"])
    result = replay(root, source, candidate, check_expected=False)
    candidate["integration"].update(result)
    candidate["verification"] = {"git_replay": "passed", "rust_execution": "not-run", "interop": "not-run", "platform": "not-run", "release_eligible": False}
    return candidate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["verify", "prepare", "check", "upgrade-check", "propose-lock"])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--upstream", type=Path, default=ROOT.parent / "vp_core")
    parser.add_argument("--candidate-commit")
    parser.add_argument("--output", type=Path, help="new candidate lock path; never overwrites any existing file")
    args = parser.parse_args(argv)
    try:
        root, source = args.root.resolve(), args.upstream.absolute()
        lock = load_lock(root, accept_patch_edits=args.command == "propose-lock")
        if args.command in ("upgrade-check", "propose-lock"):
            require(args.candidate_commit and args.output, "candidate proposal requires --candidate-commit and --output")
            require(not args.output.exists() and not args.output.is_symlink(), "candidate output already exists; refusing overwrite")
            candidate = candidate_lock(root, source, lock, args.candidate_commit)
            with args.output.open("x") as file:
                json.dump(candidate, file, indent=2); file.write("\n")
            result = {"candidate_lock": str(args.output), "release_eligible": False}
        else:
            verify_source(source, lock["upstream"])
            if args.command == "verify":
                result = replay(root, source, lock)
            elif args.command == "prepare":
                result = {"integration": str(prepare(root, source, lock))}
            else:
                result = {"integration": str(verify_integration(root, source, lock))}
        print(json.dumps({"status": "passed", "scope": "git/source-integrity-only", "rust_execution": "not-run", **result}, indent=2))
        return 0
    except (PipelineError, OSError, KeyError, ValueError, TypeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
