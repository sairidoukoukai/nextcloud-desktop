#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sairibus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

"""Validate releases and write checksums for the club's Windows installer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

UPSTREAM_BASE = "76ef152f8c98009c910f124af1da20876e3915e9"
BLUEPRINTS_COMMIT = "d9829275a569d3cf83e42ad9c50140074d01dd9f"
RECIPE_PATCH = Path(__file__).resolve().parent / "patches/0001-nextcloud-blueprint-packaging.patch"
HELPER = json.loads((Path(__file__).resolve().parent / "cloudflared.json").read_text())
HELPER_PATCH = Path(__file__).resolve().parent / "patches/0002-cloudflared-login-retry.patch"
EXPECTED_TESTS = {
    "CloudflareAccessTest", "CookiesTest", "AccountWizardControllerTest",
    "AccountWizardWindowQmlTest", "SettingsDialogTest", "PushNotificationsTest",
    "RemoteWipeTest", "AccountStateTest", "ConnectionValidatorTest",
    "WindowCloseQmlTest", "SyncEngineTest", "SyncCfApiTest", "UnifiedSharingTest",
}


def validate_tests(report):
    names = [test["name"] for test in report.get("tests", [])]
    if len(names) != len(EXPECTED_TESTS) or set(names) != EXPECTED_TESTS:
        raise ValueError("CTest must register exactly the thirteen required client suites.")


def validate(tag, ref, head, main, existing_refs=()):
    if ref != "refs/heads/main":
        raise ValueError("Releases must run from main.")
    if not re.fullmatch(r"[0-9a-f]{40}", head or "") or head != main:
        raise ValueError("The build commit must equal the current main commit.")
    if not re.fullmatch(r"v35\.0\.0-sairibus\.[1-9][0-9]*", tag or ""):
        raise ValueError("Expected a tag such as v35.0.0-sairibus.1.")
    if f"refs/tags/{tag}" in existing_refs:
        raise ValueError("The release tag already exists.")
    return tag.removeprefix("v35.0.0-")


def download_verified(url, expected, target):
    maximum_bytes = 128 * 1024 * 1024
    size = 0
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as output:
        while data := response.read(1024 * 1024):
            size += len(data)
            if size > maximum_bytes:
                raise ValueError("Pinned helper download exceeds the size limit.")
            output.write(data)
            digest.update(data)
    if digest.hexdigest() != expected:
        target.unlink(missing_ok=True)
        raise ValueError("Pinned helper download checksum mismatch.")


def license_notices(modules):
    sections = []
    for module in modules:
        directory = Path(module["Dir"])
        notices = sorted(p for p in directory.rglob("*") if p.is_file() and not p.is_symlink()
                         and p.name.upper().split(".")[0] in {"LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS"})
        if not notices:
            raise ValueError("Missing dependency license: " + module["Path"])
        for notice in notices:
            if notice.stat().st_size > 1024 * 1024:
                raise ValueError("Dependency license exceeds the size limit.")
            sections.append(f"{module['Path']} {module.get('Version', '')} — {notice.relative_to(directory)}\n"
                            + notice.read_text(encoding="utf-8", errors="replace"))
    return "\n\n".join(sections) + "\n"


def helper_environment(stage):
    return dict(os.environ, GOMODCACHE=str(stage / "modules"), GOCACHE=str(stage / "build-cache"),
                GOROOT=str(stage / "go"), GOPATH=str(stage / "gopath"), GO111MODULE="on",
                GOENV="off", GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="", CGO_ENABLED="0",
                GOOS="windows", GOARCH="amd64", GOAMD64="v1", GOEXPERIMENT="", GOMAXPROCS="2",
                GOPRIVATE="", GONOSUMDB="", GONOPROXY="", GOINSECURE="", GOSUMDB="sum.golang.org",
                GOPROXY="https://proxy.golang.org,direct")


def helper_toolchain(stage):
    platform = "windows_amd64" if sys.platform == "win32" else "linux_amd64"
    pin = HELPER["go"][platform]
    archive = stage / Path(pin["url"]).name
    download_verified(pin["url"], pin["sha256"], archive)
    if platform == "windows_amd64":
        with zipfile.ZipFile(archive) as contents:
            for entry in contents.infolist():
                if not entry.filename.startswith("go/") or ".." in Path(entry.filename).parts:
                    raise ValueError("Invalid pinned Go archive path.")
            contents.extractall(stage)
    else:
        with tarfile.open(archive) as contents:
            contents.extractall(stage, filter="data")
    executable = stage / "go/bin" / ("go.exe" if platform == "windows_amd64" else "go")
    version = subprocess.run([str(executable), "version"], env=helper_environment(stage),
                             check=True, capture_output=True, text=True, timeout=30).stdout.split()
    if len(version) != 4 or version[2] != HELPER["go"]["version"]:
        raise ValueError("The helper must use the pinned Go toolchain.")
    return executable


def build_helper(source, executable, go, env):
    test_env = dict(env, GOOS="windows" if sys.platform == "win32" else "linux")
    subprocess.run([str(go), "test", "-p=2", "-mod=readonly", "-trimpath", "./token", "./cmd/cloudflared/access", "-count=1", "-timeout=180s"],
                   cwd=source, env=test_env, check=True, timeout=600)
    flags = ("-s -w -buildid= -X main.Version=" + HELPER["version"]
             + " -X main.BuildTime=2000-01-01T00:00:00Z -X main.BuildType=sairibus")
    subprocess.run([str(go), "build", "-p=2", "-mod=readonly", "-trimpath", "-buildvcs=false",
                    "-ldflags", flags, "-o", str(executable), "./cmd/cloudflared"],
                   cwd=source, env=env, check=True, timeout=1200)
    with executable.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != HELPER["windows_amd64"]["sha256"]:
            raise ValueError("Source-built helper does not match the pinned binary digest.")


def install_helper(directory):
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nextcloud-helper-") as temporary:
        stage = Path(temporary)
        executable = stage / "cloudflared.exe"
        archive = stage / "source.tar.gz"
        download_verified(HELPER["source_url"], HELPER["source_sha256"], archive)
        with tarfile.open(archive) as contents:
            contents.extractall(stage / "source", filter="data")
        source = stage / "source" / ("cloudflared-" + HELPER["source_commit"])
        patch = HELPER_PATCH.read_text().encode("utf-8")
        if hashlib.sha256(patch).hexdigest() != HELPER["patch_sha256"]:
            raise ValueError("The helper retry patch does not match its pin.")
        patchfile = stage / "retry.patch"
        patchfile.write_bytes(patch)
        subprocess.run(["git", "apply", "--whitespace=error-all", str(patchfile)],
                       cwd=source, check=True, capture_output=True, timeout=30)
        shutil.copyfile(Path(__file__).resolve().parent / "tests/helper_retry_test.go", source / "token/sairibus_retry_test.go")
        shutil.copyfile(Path(__file__).resolve().parent / "tests/helper_token_check_test.go", source / "cmd/cloudflared/access/sairibus_retry_test.go")
        env = helper_environment(stage)
        go = helper_toolchain(stage)
        # Go authenticates module archives against the pinned source's go.sum.
        downloaded = subprocess.run([str(go), "mod", "download", "-json"], cwd=source, env=env,
                                    check=True, capture_output=True, text=True, timeout=600).stdout
        modules = [{"Path": "github.com/cloudflare/cloudflared", "Version": HELPER["version"], "Dir": str(source)}]
        decoder = json.JSONDecoder()
        remaining = downloaded.lstrip()
        while remaining:
            module, offset = decoder.raw_decode(remaining)
            if module.get("Error") or not module.get("Dir"):
                raise ValueError("Could not authenticate a helper dependency.")
            modules.append(module)
            remaining = remaining[offset:].lstrip()
        notices = license_notices(modules)
        go_license = stage / "go/LICENSE"
        if not go_license.is_file() or go_license.stat().st_size > 1024 * 1024:
            raise ValueError("The pinned Go runtime license is missing or invalid.")
        notices += "\nGo runtime " + HELPER["go"]["version"] + " — LICENSE\n" + go_license.read_text(encoding="utf-8")
        build_helper(source, executable, go, env)
        (directory / "nextcloud-cloudflared-LICENSE.txt").write_text(notices, encoding="utf-8")
        shutil.copyfile(executable, directory / HELPER["windows_amd64"]["installed_name"])


def checksums(directory, tag, source):
    validate(tag, "refs/heads/main", source, source)
    installer = directory / f"Nextcloud-{tag.removeprefix('v')}-windows-x64.exe"
    if installer.is_symlink() or not installer.is_file():
        raise ValueError("The expected installer is missing or linked.")
    with installer.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError("The installer is not a Windows executable.")
    info = directory / "build-info.json"
    info.write_text(json.dumps({
        "release_tag": tag, "source_commit": source, "upstream_base": UPSTREAM_BASE,
        "platform": "windows-x64", "signature": "unsigned", "official_updater": False,
        "browser_login_helper": HELPER,
        "packaging_recipe": {
            "upstream_commit": BLUEPRINTS_COMMIT,
            "patch_path": "admin/club/patches/0001-nextcloud-blueprint-packaging.patch",
            "patch_sha256": hashlib.sha256(RECIPE_PATCH.read_bytes()).hexdigest(),
        },
    }, indent=2) + "\n")
    rows = []
    for path in [installer, info]:
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        rows.append(f"{digest}  {path.name}\n")
    (directory / "SHA256SUMS").write_text("".join(rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "checksums", "test-list", "helper"])
    parser.add_argument("path", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "helper":
            if args.path is None:
                raise ValueError("Specify the helper installation directory.")
            install_helper(args.path)
            return
        if args.command == "test-list":
            if args.path is None:
                raise ValueError("Specify the CTest inventory file.")
            validate_tests(json.loads(args.path.read_text(encoding="utf-8-sig")))
            return
        tag = os.environ.get("RELEASE_TAG", "")
        source = os.environ.get("GITHUB_SHA", "")
        refs = [item["ref"] for item in json.loads(os.environ.get("TAG_REFS", "[]"))]
        suffix = validate(tag, os.environ.get("GITHUB_REF", ""), source, os.environ.get("MAIN_SHA", ""), refs)
        if args.command == "checksums":
            if args.path is None:
                raise ValueError("Specify the artifact directory.")
            checksums(args.path, tag, source)
        if output := os.environ.get("GITHUB_OUTPUT"):
            with open(output, "a") as stream:
                stream.write(f"suffix={suffix}\n")
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
