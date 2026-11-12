# SPDX-FileCopyrightText: 2026 Sairibus contributors
# SPDX-License-Identifier: GPL-2.0-or-later

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
OFFICIAL_IDENTIFIERS = {
    "APPLICATION_NAME": "Nextcloud",
    "APPLICATION_SHORTNAME": "Nextcloud",
    "APPLICATION_EXECUTABLE": "nextcloud",
    "APPLICATION_VENDOR": "Nextcloud GmbH",
    "WIN_SHELLEXT_CONTEXT_MENU_GUID": "{BC6988AB-ACE2-4B81-84DC-DC34F9B24401}",
    "WIN_SHELLEXT_OVERLAY_GUID_ERROR": "{E0342B74-7593-4C70-9D61-22F294AAFE05}",
    "WIN_SHELLEXT_OVERLAY_GUID_OK": "{E1094E94-BE93-4EA2-9639-8475C68F3886}",
    "WIN_SHELLEXT_OVERLAY_GUID_OK_SHARED": "{E243AD85-F71B-496B-B17E-B8091CBE93D2}",
    "WIN_SHELLEXT_OVERLAY_GUID_SYNC": "{E3D6DB20-1D83-4829-B5C9-941B31C0C35A}",
    "WIN_SHELLEXT_OVERLAY_GUID_WARNING": "{E4977F33-F93A-4A0A-9D3C-83DEA0EE8483}",
    "WIN_MSI_UPGRADE_CODE": "FD2FCCA9-BB8F-4485-8F70-A0621B84A7F4",
    "CFAPI_SHELLEXT_APPID_REG": "{E314A650-DCA4-416E-974E-18EA37C213EA}",
    "CFAPI_SHELLEXT_CUSTOM_STATE_HANDLER_CLASS_ID": "1E62D59A-6EA4-476C-B707-4A32E88ED822",
    "CFAPI_SHELLEXT_THUMBNAIL_HANDLER_CLASS_ID": "6FF9B5B6-389F-444A-9FDD-A286C36EA079",
}


def release_identity():
    """Return the identifiers NEXTCLOUD.cmake sets for a release (non-dev) build."""
    text = (ROOT / "NEXTCLOUD.cmake").read_text()
    release = text.split("else()", 1)[1]
    branch, rest = release.split("endif()", 1)
    pattern = r'set\(\s*(\w+)\s+"([^"]*)"'
    values = dict(re.findall(pattern, rest))
    values.update(re.findall(pattern, branch))
    values["DISABLE_ACCOUNT_MIGRATION"] = re.search(r'option\(\s*DISABLE_ACCOUNT_MIGRATION\s+"[^"]*"\s+(\w+)\s*\)', text).group(1)
    return values


class BrandingTests(unittest.TestCase):
    def test_client_identity_differs_from_the_official_client(self):
        values = release_identity()
        for name, official in OFFICIAL_IDENTIFIERS.items():
            with self.subTest(name=name):
                self.assertIn(name, values)
                self.assertNotEqual(values[name].upper(), official.upper())
        guids = [values[name].strip("{}").upper() for name in OFFICIAL_IDENTIFIERS if "GUID" in name or "CODE" in name or "CFAPI" in name]
        self.assertEqual(len(guids), len(set(guids)))
        self.assertEqual(values["DISABLE_ACCOUNT_MIGRATION"], "ON")

    def test_installer_uses_the_client_identity(self):
        values = release_identity()
        patch = (ROOT / "admin/club/patches/0001-nextcloud-blueprint-packaging.patch").read_text()
        added = dict(re.findall(r'^\+\s+self\.defines\["(\w+)"\] = "([^"]*)"', patch, re.M))
        display = re.search(r'^\+\s+self\.displayName = "([^"]*)"', patch, re.M).group(1)
        executable = values["APPLICATION_EXECUTABLE"]
        self.assertEqual(display, values["APPLICATION_NAME"])
        self.assertEqual(added["company"], values["APPLICATION_VENDOR"])
        self.assertEqual(added["executable"], f"bin/{executable}.exe")
        helper = json.loads((ROOT / "admin/club/cloudflared.json").read_text())["windows_amd64"]["installed_name"]
        kept = re.search(r'^\+bin/\(\?!\((.*)\)\)\.\*\\\.exe$', patch, re.M).group(1).split("|")
        for name in [executable, executable + "cmd", Path(helper).stem]:
            with self.subTest(name=name):
                self.assertIn(name, kept)
        script = (ROOT / "admin/club/build-windows.ps1").read_text()
        self.assertIn(f"$product = '{values['APPLICATION_NAME']}'", script)
        self.assertIn(f"'bin/{executable}.exe'", script)
        self.assertIn(f"@('{executable}.exe', '{executable}sync.dll', '{executable}_csync.dll')", script)
        # src/gui/CMakeLists.txt installs the Start Menu tile manifest named after the executable.
        self.assertTrue((ROOT / f"theme/{executable}.VisualElementsManifest.xml").is_file())
