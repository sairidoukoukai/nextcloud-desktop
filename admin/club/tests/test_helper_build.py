# SPDX-FileCopyrightText: 2026 Sairibus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("helper_release", Path(__file__).resolve().parents[1] / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class HelperBuildTests(unittest.TestCase):
    binary = b"MZsynthetic source-built helper"

    def test_build_environment_ignores_ambient_go_configuration(self):
        with patch.dict(os.environ, {"GOFLAGS": "-race", "GOROOT": "untrusted", "GOTOOLCHAIN": "auto", "GOINSECURE": "*"}):
            env = release.helper_environment(Path("owned"))
        self.assertEqual(env["GOFLAGS"], "")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOROOT"], str(Path("owned/go")))
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOWORK"], "off")
        self.assertEqual(env["GOINSECURE"], "")
        self.assertEqual((env["GOOS"], env["GOARCH"], env["CGO_ENABLED"]), ("windows", "amd64", "0"))

    def flow(self, output, *, mismatch=False, fail=None):
        pin = copy.deepcopy(release.HELPER)
        pin["windows_amd64"]["sha256"] = "0" * 64 if mismatch else hashlib.sha256(self.binary).hexdigest()
        commands = []

        def download(url, digest, target):
            self.assertEqual((url, digest), (pin["source_url"], pin["source_sha256"]))
            root = "cloudflared-" + pin["source_commit"]
            with tarfile.open(target, "w:gz") as archive:
                for name, data in [("LICENSE", b"synthetic dependency license"), ("token/placeholder", b""),
                                   ("cmd/cloudflared/access/placeholder", b"")]:
                    member = tarfile.TarInfo(root + "/" + name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

        def run(argv, **kwargs):
            commands.append(argv)
            operation = "git" if argv[0] == "git" else argv[1]
            if operation == fail:
                raise subprocess.CalledProcessError(1, argv)
            if operation == "git":
                self.assertIn("--whitespace=error-all", argv)
                self.assertEqual(hashlib.sha256(Path(argv[-1]).read_bytes()).hexdigest(), pin["patch_sha256"])
            elif operation == "mod":
                return subprocess.CompletedProcess(argv, 0, json.dumps({"Path": "example.invalid/dependency", "Dir": str(kwargs["cwd"])}))
            elif operation == "test":
                self.assertIn("./token", argv)
                self.assertIn("./cmd/cloudflared/access", argv)
                for name in ["token/sairibus_retry_test.go", "cmd/cloudflared/access/sairibus_retry_test.go"]:
                    self.assertTrue((kwargs["cwd"] / name).is_file())
            elif operation == "build":
                self.assertIn("-trimpath", argv)
                self.assertIn("-buildvcs=false", argv)
                self.assertIn("-mod=readonly", argv)
                self.assertIn("-buildid=", argv[argv.index("-ldflags") + 1])
                self.assertEqual(kwargs["env"]["GOAMD64"], "v1")
                Path(argv[argv.index("-o") + 1]).write_bytes(self.binary)
            else:
                self.fail("Unexpected build operation")
            return subprocess.CompletedProcess(argv, 0, "")

        def toolchain(stage):
            (stage / "go").mkdir()
            (stage / "go/LICENSE").write_text("synthetic Go runtime license")
            return stage / "go/bin/go"

        with patch.object(release, "HELPER", pin), patch.object(release, "download_verified", download), \
             patch.object(release, "helper_toolchain", toolchain), patch.object(release.subprocess, "run", run):
            release.install_helper(output)
        return commands

    def test_source_build_installs_only_verified_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "installed"
            commands = self.flow(output)
            self.assertEqual((output / "nextcloud-cloudflared.exe").read_bytes(), self.binary)
            self.assertIn("synthetic dependency license", (output / "nextcloud-cloudflared-LICENSE.txt").read_text())
            self.assertIn("synthetic Go runtime license", (output / "nextcloud-cloudflared-LICENSE.txt").read_text())
            self.assertEqual([a[1] for a in commands], ["apply", "mod", "test", "build"])

    def test_binary_mismatch_never_installs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "installed"
            with self.assertRaisesRegex(ValueError, "binary digest"):
                self.flow(output, mismatch=True)
            self.assertFalse((output / "nextcloud-cloudflared.exe").exists())

    def test_failed_patch_or_test_or_build_never_installs(self):
        for operation in ["git", "test", "build"]:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "installed"
                with self.assertRaises(subprocess.CalledProcessError):
                    self.flow(output, fail=operation)
                self.assertFalse((output / "nextcloud-cloudflared.exe").exists())

    def test_toolchain_version_is_verified(self):
        def download(url, digest, target):
            self.assertEqual(digest, release.HELPER["go"]["windows_amd64"]["sha256"])
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("go/bin/go.exe", b"MZsynthetic compiler")
        for version in ["go1.0", release.HELPER["go"]["version"]]:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                result = subprocess.CompletedProcess([], 0, "go version " + version + " windows/amd64\n")
                with patch.object(release.sys, "platform", "win32"), patch.object(release, "download_verified", download), \
                     patch.object(release.subprocess, "run", return_value=result):
                    if version != release.HELPER["go"]["version"]:
                        with self.assertRaisesRegex(ValueError, "pinned Go"):
                            release.helper_toolchain(Path(temporary))
                    else:
                        self.assertEqual(release.helper_toolchain(Path(temporary)), Path(temporary) / "go/bin/go.exe")
