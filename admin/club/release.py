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

UPSTREAM_BASE = "ce977e31810bc9f2cdffc4828cc0a14bd0792110"
BLUEPRINTS_COMMIT = "d9829275a569d3cf83e42ad9c50140074d01dd9f"
RECIPE_PATCH = Path(__file__).resolve().parent / "patches/0001-nextcloud-blueprint-packaging.patch"
EXPECTED_TESTS = {
    "CloudflareAccessTest", "CookiesTest", "AccountWizardControllerTest",
    "AccountWizardWindowQmlTest", "SettingsDialogTest", "PushNotificationsTest",
    "RemoteWipeTest", "AccountStateTest", "ConnectionValidatorTest",
}


def validate_tests(report):
    names = [test["name"] for test in report.get("tests", [])]
    if len(names) != len(EXPECTED_TESTS) or set(names) != EXPECTED_TESTS:
        raise ValueError("CTest must register exactly the nine required client suites.")


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
    parser.add_argument("command", choices=["validate", "checksums", "test-list"])
    parser.add_argument("path", nargs="?", type=Path)
    args = parser.parse_args()
    try:
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
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
