# SPDX-FileCopyrightText: 2026 Sairibus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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
            self.assertEqual(info["signature"], "unsigned")
            self.assertFalse(info["official_updater"])

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
