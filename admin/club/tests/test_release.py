# SPDX-FileCopyrightText: 2026 Sairibus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import io

spec = importlib.util.spec_from_file_location("club_release", Path(__file__).resolve().parents[1] / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_complete_client_inventory_is_required(self):
        names = sorted(release.EXPECTED_TESTS)
        release.validate_tests({"tests": [{"name": name} for name in names]})
        for invalid in [[], names[:-1], names[:-1] + [names[0]], names + ["OtherTest"]]:
            with self.subTest(names=invalid):
                with self.assertRaises(ValueError):
                    release.validate_tests({"tests": [{"name": name} for name in invalid]})

    def test_valid_release_identifies_suffix(self):
        self.assertEqual(release.validate("v35.0.0-sairibus.1", "refs/heads/main", "a" * 40, "a" * 40), "sairibus.1")

    def test_unmerged_and_stale_commits_are_rejected(self):
        for ref, head, main in [("refs/heads/feature", "a" * 40, "a" * 40),
                                ("refs/tags/v35.0.0-sairibus.1", "a" * 40, "a" * 40),
                                ("refs/heads/main", "a" * 40, "b" * 40),
                                ("refs/heads/main", "main", "main")]:
            with self.subTest(ref=ref, head=head):
                with self.assertRaises(ValueError):
                    release.validate("v35.0.0-sairibus.1", ref, head, main)

    def test_existing_tag_cannot_reuse_another_commit(self):
        with self.assertRaises(ValueError):
            release.validate("v35.0.0-sairibus.1", "refs/heads/main", "a" * 40, "a" * 40,
                             ["refs/tags/v35.0.0-sairibus.1"])
        release.validate("v35.0.0-sairibus.1", "refs/heads/main", "a" * 40, "a" * 40,
                         ["refs/tags/v35.0.0-sairibus.10"])

    def test_tags_cannot_inject_paths_or_commands(self):
        for tag in ["v35.0.0", "../installer", "v35.0.0-sairibus.0", "v35.0.0-sairibus.1;false", "v35.0.0-sairibus.1\n"]:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    release.validate(tag, "refs/heads/main", "a" * 40, "a" * 40)

    def test_manifest_matches_actual_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            installer = directory / "Nextcloud-35.0.0-sairibus.1-windows-x64.exe"
            installer.write_bytes(b"MZsynthetic executable")
            release.checksums(directory, "v35.0.0-sairibus.1", "a" * 40)
            for row in (directory / "SHA256SUMS").read_text().splitlines():
                digest, name = row.split("  ", 1)
                self.assertEqual(hashlib.sha256((directory / name).read_bytes()).hexdigest(), digest)
            info = json.loads((directory / "build-info.json").read_text())
            self.assertEqual(info["source_commit"], "a" * 40)
            self.assertEqual(info["browser_login_helper"], release.HELPER)
            self.assertEqual(info["signature"], "unsigned")
            self.assertFalse(info["official_updater"])
            self.assertEqual(info["packaging_recipe"]["upstream_commit"], release.BLUEPRINTS_COMMIT)
            self.assertEqual(info["packaging_recipe"]["patch_sha256"], hashlib.sha256(release.RECIPE_PATCH.read_bytes()).hexdigest())

    def test_missing_or_invalid_installer_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            installer = directory / "Nextcloud-35.0.0-sairibus.1-windows-x64.exe"
            with self.assertRaises(ValueError):
                release.checksums(directory, "v35.0.0-sairibus.1", "a" * 40)
            installer.write_bytes(b"not an executable")
            with self.assertRaises(ValueError):
                release.checksums(directory, "v35.0.0-sairibus.1", "a" * 40)

    def test_linked_installer_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "elsewhere.exe"
            target.write_bytes(b"MZsynthetic executable")
            installer = directory / "Nextcloud-35.0.0-sairibus.1-windows-x64.exe"
            installer.symlink_to(target)
            with self.assertRaises(ValueError):
                release.checksums(directory, "v35.0.0-sairibus.1", "a" * 40)


class PublicationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bash"), "The publication workflow runs in Bash.")
    def test_workflow_publishes_a_regular_latest_release(self):
        workflow = Path(__file__).resolve().parents[3] / ".github/workflows/club-release.yml"
        lines = workflow.read_text().splitlines()
        start = next(i for i, line in enumerate(lines) if line.strip().startswith("gh release create "))
        command = "\n".join(line.strip() for line in lines[start:])
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            gh = directory / "gh"
            gh.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['GH_ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))\n"
            )
            gh.chmod(0o755)
            captured = directory / "arguments.json"
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"],
                       RELEASE_TAG="v35.0.0-sairibus.3", GH_ARGUMENTS=str(captured))
            subprocess.run(["bash", "-eu", "-c", command], cwd=directory, env=env, check=True)
            arguments = json.loads(captured.read_text())
            self.assertEqual(arguments[:3], ["release", "create", "v35.0.0-sairibus.3"])
            for asset in ["artifacts/Nextcloud-35.0.0-sairibus.3-windows-x64.exe",
                          "artifacts/build-info.json", "artifacts/SHA256SUMS"]:
                self.assertIn(asset, arguments)
            self.assertIn("--verify-tag", arguments)
            self.assertIn("--latest", arguments)
            self.assertFalse(any(arg.startswith(("--prerelease", "--draft")) for arg in arguments))
            self.assertNotIn("--latest=false", arguments)
            self.assertEqual(arguments[arguments.index("--title") + 1],
                             "Nextcloud v35.0.0-sairibus.3 — Sairibus")


class HelperPackagingTests(unittest.TestCase):
    def test_download_checks_bytes_against_the_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "helper.exe"
            content = b"MZsynthetic helper"
            digest = hashlib.sha256(content).hexdigest()
            with patch.object(release.urllib.request, "urlopen", return_value=io.BytesIO(content)):
                release.download_verified("https://example.invalid/helper", digest, target)
            self.assertEqual(target.read_bytes(), content)
            with patch.object(release.urllib.request, "urlopen", return_value=io.BytesIO(content)):
                with self.assertRaises(ValueError):
                    release.download_verified("https://example.invalid/helper", "0" * 64, target)
            self.assertFalse(target.exists())

    def test_dependency_notices_include_nested_licenses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "LICENSE").write_text("synthetic top-level license")
            (root / "nested").mkdir()
            (root / "nested/NOTICE.txt").write_text("synthetic dependency notice")
            (root / "private.txt").write_text("excluded fixture data")
            output = release.license_notices([{"Dir": str(root), "Path": "example.invalid/helper", "Version": "v1"}])
            self.assertIn("synthetic top-level license", output)
            self.assertIn("synthetic dependency notice", output)
            self.assertNotIn("excluded fixture data", output)
            (root / "LICENSE").unlink()
            (root / "nested/NOTICE.txt").unlink()
            with self.assertRaises(ValueError):
                release.license_notices([{"Dir": str(root), "Path": "example.invalid/helper"}])
