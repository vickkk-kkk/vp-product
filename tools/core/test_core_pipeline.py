"""Only locally authored toy files/Git operations; no vp_core/Rust execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("pipeline", Path(__file__).with_name("core_pipeline.py"))
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)

class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vp-pipeline-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "product"
        self.source = Path(self.temp.name) / "source"
        self.root.mkdir(); self.source.mkdir()
        (self.root / "patches/vp_core").mkdir(parents=True)
        p.git(self.source, "init", "--quiet")
        (self.source / "sample.txt").write_text("original\n")
        self.commit("base")
        upstream = {"repository_url": "https://example.invalid/not-fetched.git",
                    "commit": p.git(self.source, "rev-parse", "HEAD"),
                    "tree": p.git(self.source, "rev-parse", "HEAD^{tree}")}
        (self.source / "sample.txt").write_text("patched\n")
        patch = self.root / "patches/vp_core/0001.patch"
        patch.write_text(p.git(self.source, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index") + "\n")
        p.git(self.source, "restore", "--", "sample.txt")
        entry = {"id": "P01", "path": "patches/vp_core/0001.patch", "sha256": p.sha256(patch.read_bytes())}
        self.lock = {"schema_version": 1, "upstream": upstream,
                     "patchset": {"patches": [entry], "sha256": p.patchset_hash(upstream, [entry])},
                     "integration": {"path": p.GENERATED_PATH, "patched_tree": "0" * 40, "commit": "0" * 40}}
        (self.root / "patches/vp_core/series.toml").write_text('schema_version = 1\n[[patch]]\nid = "P01"\npath = "patches/vp_core/0001.patch"\n')
        self.lock["integration"].update(p.replay(self.root, self.source, self.lock, False))
        self.write_lock()

    def write_lock(self):
        (self.root / "core-lock.json").write_text(json.dumps(self.lock))

    def commit(self, message):
        p.git(self.source, "add", "--all")
        env = p.environment()
        env.update(GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid",
                   GIT_AUTHOR_DATE="2001-01-01T00:00:00Z", GIT_COMMITTER_DATE="2001-01-01T00:00:00Z")
        p.git(self.source, "-c", "commit.gpgSign=false", "commit", "--no-verify", "--quiet", "-m", message, env=env)

    def test_replay_is_deterministic_and_source_stays_clean(self):
        first = p.replay(self.root, self.source, self.lock)
        self.assertEqual(first, p.replay(self.root, self.source, self.lock))
        self.assertEqual((self.source / "sample.txt").read_text(), "original\n")
        self.assertEqual(p.git(self.source, "status", "--porcelain=v1"), "")
        self.assertEqual(p.git(self.source, "worktree", "list", "--porcelain").count("worktree "), 1)

    def test_prepare_is_clean_detached_and_idempotent(self):
        path = p.prepare(self.root, self.source, self.lock)
        self.assertEqual(path, p.prepare(self.root, self.source, self.lock))
        self.assertEqual((path / "sample.txt").read_text(), "patched\n")
        self.assertEqual(p.git(path, "status", "--porcelain=v1"), "")
        self.assertEqual(p.git(path, "rev-parse", "--abbrev-ref", "HEAD"), "HEAD")

    def test_dirty_source_rejected_before_replay(self):
        (self.source / "sample.txt").write_text("private local edit\n")
        with self.assertRaisesRegex(p.PipelineError, "dirty"):
            p.replay(self.root, self.source, self.lock)
        self.assertEqual((self.source / "sample.txt").read_text(), "private local edit\n")

    def test_untracked_source_rejected(self):
        (self.source / "notes.txt").write_text("local note\n")
        with self.assertRaisesRegex(p.PipelineError, "dirty"):
            p.replay(self.root, self.source, self.lock)

    def test_changed_base_head_rejected(self):
        (self.source / "new.txt").write_text("change\n"); self.commit("new base")
        with self.assertRaisesRegex(p.PipelineError, "HEAD differs"):
            p.replay(self.root, self.source, self.lock)

    def test_changed_base_tree_rejected(self):
        self.lock["upstream"]["tree"] = "1" * 40
        with self.assertRaisesRegex(p.PipelineError, "tree differs"):
            p.replay(self.root, self.source, self.lock)

    def test_patch_content_tamper_rejected(self):
        path = self.root / self.lock["patchset"]["patches"][0]["path"]
        path.write_text(path.read_text() + "tampered\n")
        with self.assertRaisesRegex(p.PipelineError, "digest mismatch"):
            p.load_lock(self.root)

    def test_patchset_identity_tamper_rejected(self):
        self.lock["patchset"]["sha256"] = "1" * 64; self.write_lock()
        with self.assertRaisesRegex(p.PipelineError, "identity mismatch"):
            p.load_lock(self.root)

    def test_series_mismatch_rejected(self):
        (self.root / "patches/vp_core/series.toml").write_text('schema_version = 1\n[[patch]]\nid = "different"\npath = "patches/vp_core/0001.patch"\n')
        with self.assertRaisesRegex(p.PipelineError, "order/id mismatch"):
            p.load_lock(self.root)

    def test_patch_path_escape_rejected(self):
        self.lock["patchset"]["patches"][0]["path"] = "patches/vp_core/../../../outside.patch"
        self.write_lock()
        with self.assertRaisesRegex(p.PipelineError, "unsafe patch path"):
            p.load_lock(self.root)

    def test_symlink_patch_rejected(self):
        patch = self.root / "patches/vp_core/0001.patch"
        saved = self.root / "saved.patch"; patch.rename(saved); patch.symlink_to(saved)
        with self.assertRaisesRegex(p.PipelineError, "symlink"):
            p.load_lock(self.root)

    def test_unexpected_replay_tree_rejected_and_temp_removed(self):
        self.lock["integration"]["patched_tree"] = "1" * 40
        with self.assertRaisesRegex(p.PipelineError, "unexpected patched tree"):
            p.replay(self.root, self.source, self.lock)
        self.assertEqual(p.git(self.source, "worktree", "list", "--porcelain").count("worktree "), 1)

    def test_dirty_integration_never_overwritten(self):
        path = p.prepare(self.root, self.source, self.lock)
        (path / "sample.txt").write_text("keep this private change\n")
        with self.assertRaisesRegex(p.PipelineError, "local changes"):
            p.prepare(self.root, self.source, self.lock)
        self.assertEqual((path / "sample.txt").read_text(), "keep this private change\n")

    def test_integration_parent_symlink_rejected(self):
        outside = Path(self.temp.name) / "outside"; outside.mkdir()
        (self.root / "integration").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(p.PipelineError, "symlinked"):
            p.prepare(self.root, self.source, self.lock)
        self.assertEqual(list(outside.iterdir()), [])

    def test_upgrade_conflict_is_failure_and_does_not_repin(self):
        original = (self.root / "core-lock.json").read_bytes()
        (self.source / "sample.txt").write_text("upstream conflict\n"); self.commit("conflict")
        with self.assertRaisesRegex(p.PipelineError, "apply failed"):
            p.candidate_lock(self.root, self.source, self.lock, p.git(self.source, "rev-parse", "HEAD"))
        self.assertEqual((self.root / "core-lock.json").read_bytes(), original)
        self.assertEqual(p.git(self.source, "worktree", "list", "--porcelain").count("worktree "), 1)

    def test_upgrade_candidate_explicit_and_never_release_certified(self):
        original = (self.root / "core-lock.json").read_bytes()
        (self.source / "new.txt").write_text("compatible addition\n"); self.commit("candidate")
        new_commit = p.git(self.source, "rev-parse", "HEAD")
        candidate = p.candidate_lock(self.root, self.source, self.lock, new_commit)
        self.assertEqual(candidate["upstream"]["commit"], new_commit)
        self.assertNotEqual(candidate["patchset"]["sha256"], self.lock["patchset"]["sha256"])
        self.assertFalse(candidate["verification"]["release_eligible"])
        self.assertEqual(candidate["verification"]["rust_execution"], "not-run")
        self.assertEqual((self.root / "core-lock.json").read_bytes(), original)

    def test_patch_tamper_after_loading_is_rejected(self):
        lock = p.load_lock(self.root)
        patch = self.root / "patches/vp_core/0001.patch"
        patch.write_text(patch.read_text().replace("+patched", "+tampered"))
        with self.assertRaisesRegex(p.PipelineError, "changed after lock"):
            p.replay(self.root, self.source, lock)

    def test_checkout_hooks_and_filters_are_not_executed(self):
        marker = Path(self.temp.name) / "must-not-exist"
        hook = self.source / ".git/hooks/post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        p.git(self.source, "config", "filter.poison.smudge", f"touch '{marker}'; cat")
        p.git(self.source, "config", "filter.poison.clean", f"touch '{marker}'; cat")
        p.git(self.source, "config", "filter.poison.required", "true")
        (self.source / ".gitattributes").write_text("sample.txt filter=poison\n")
        self.commit("candidate with attributes")
        p.candidate_lock(self.root, self.source, self.lock, p.git(self.source, "rev-parse", "HEAD"))
        self.assertFalse(marker.exists())

    def test_edited_patch_requires_explicit_proposal_and_does_not_repin(self):
        original = (self.root / "core-lock.json").read_bytes()
        patch = self.root / "patches/vp_core/0001.patch"
        patch.write_text(patch.read_text().replace("+patched", "+reviewed-change"))
        with self.assertRaises(p.PipelineError):
            p.load_lock(self.root)
        proposal_input = p.load_lock(self.root, accept_patch_edits=True)
        proposal = p.candidate_lock(self.root, self.source, proposal_input, self.lock["upstream"]["commit"])
        self.assertNotEqual(proposal["patchset"]["sha256"], self.lock["patchset"]["sha256"])
        self.assertNotEqual(proposal["integration"]["patched_tree"], self.lock["integration"]["patched_tree"])
        self.assertFalse(proposal["verification"]["release_eligible"])
        self.assertEqual((self.root / "core-lock.json").read_bytes(), original)

    def test_candidate_output_is_never_overwritten(self):
        output = self.root / "candidate.json"; output.write_text("keep")
        result = p.main(["upgrade-check", "--root", str(self.root), "--upstream", str(self.source),
                         "--candidate-commit", self.lock["upstream"]["commit"], "--output", str(output)])
        self.assertEqual(result, 1)
        self.assertEqual(output.read_text(), "keep")

if __name__ == "__main__":
    unittest.main()
