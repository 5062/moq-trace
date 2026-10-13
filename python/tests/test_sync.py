from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

from moq_trace.run import suite
from moq_trace.run.config import Sync
from moq_trace.run.placement import sync_script


def _git(directory: pathlib.Path, *args: str) -> str:
    # Local file remotes stand in for the hosting service; git refuses them as
    # submodule sources unless the file protocol is allowed.
    command = ["git", "-c", "protocol.file.allow=always", "-c", "init.defaultBranch=main", *args]
    environment = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com"}
    environment |= {"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_GLOBAL": "/dev/null"}
    result = subprocess.run(command, cwd=directory, check=True, capture_output=True, text=True, env=environment)
    return result.stdout.strip()


def _repository(directory: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    directory.mkdir(parents=True)
    _git(directory, "init", "--quiet")
    for name, text in files.items():
        (directory / name).write_text(text)
    _git(directory, "add", ".")
    _git(directory, "commit", "--quiet", "-m", "initial")
    return directory


class SyncScriptTests(unittest.TestCase):
    """Run the checkout script against real repositories, as a host's shell would."""

    def setUp(self) -> None:
        self.root = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.wanted = _repository(self.root / "wanted", {"lib.txt": "wanted\n"})
        self.unwanted = _repository(self.root / "unwanted", {"lib.txt": "unwanted\n"})
        self.origin = _repository(self.root / "origin", {"README": "one\n"})
        _git(self.origin, "submodule", "--quiet", "add", str(self.wanted), "wanted")
        _git(self.origin, "submodule", "--quiet", "add", str(self.unwanted), "unwanted")
        _git(self.origin, "commit", "--quiet", "-m", "submodules")

    def _sync(self, checkout: pathlib.Path) -> None:
        sync = Sync(repository=str(self.origin), revision=_git(self.origin, "rev-parse", "HEAD"))
        checkout.mkdir(exist_ok=True)
        script = sync_script(sync, ["wanted"])
        environment = {**os.environ, "GIT_CONFIG_COUNT": "1"}
        environment |= {"GIT_CONFIG_KEY_0": "protocol.file.allow", "GIT_CONFIG_VALUE_0": "always"}
        subprocess.run(["sh", "-c", script], cwd=checkout, check=True, capture_output=True, env=environment)

    def test_a_missing_checkout_is_cloned_and_an_existing_one_follows_the_commit(self) -> None:
        checkout = self.root / "host"
        self._sync(checkout)

        self.assertEqual(_git(checkout, "rev-parse", "HEAD"), _git(self.origin, "rev-parse", "HEAD"))
        self.assertEqual((checkout / "wanted/lib.txt").read_text(), "wanted\n")
        # A submodule no role needs is never fetched.
        self.assertEqual(list((checkout / "unwanted").iterdir()), [])

        (self.origin / "README").write_text("two\n")
        _git(self.origin, "commit", "--quiet", "-am", "second")
        self._sync(checkout)

        self.assertEqual((checkout / "README").read_text(), "two\n")

    def test_local_changes_on_the_host_stop_the_checkout(self) -> None:
        checkout = self.root / "host"
        self._sync(checkout)
        (checkout / "README").write_text("edited on the host\n")
        (self.origin / "README").write_text("two\n")
        _git(self.origin, "commit", "--quiet", "-am", "second")

        with self.assertRaises(subprocess.CalledProcessError):
            self._sync(checkout)
        self.assertEqual((checkout / "README").read_text(), "edited on the host\n")


class RevisionTests(unittest.TestCase):
    """The commit remote hosts are brought to is the controller's, and only a clean one."""

    def test_the_revision_is_head_and_uncommitted_changes_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(pathlib.Path(directory) / "suite", {"tracked": "one\n"})
            loaded = suite.Suite(profiles=root, protocol="p", root=root)
            # Untracked files, such as build output, do not reach a host either way.
            (root / "untracked").write_text("x\n")
            self.assertEqual(suite.revision(loaded), _git(root, "rev-parse", "HEAD"))

            (root / "tracked").write_text("two\n")
            with self.assertRaisesRegex(ValueError, r"uncommitted changes \(tracked\); .*commit and push first"):
                suite.revision(loaded)


if __name__ == "__main__":
    unittest.main()
