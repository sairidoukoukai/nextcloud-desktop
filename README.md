<!--
SPDX-FileCopyrightText: 2026 Sairibus contributors
SPDX-FileCopyrightText: 2017 Nextcloud GmbH and Nextcloud contributors
SPDX-License-Identifier: GPL-2.0-or-later
-->
# Nextcloud Desktop with Cloudflare Access

An unofficial fork maintained by 再履バス同好会 (Sairibus), based on Nextcloud Desktop 35.0.0. It adds Cloudflare Access Service Token settings to the classic desktop client and retains Nextcloud's browser login and per-device app password.

[Download releases](https://github.com/sairidoukoukai/nextcloud-desktop/releases) · [Upstream project](https://github.com/nextcloud/desktop)

## Install and connect

The first release targets Windows x64. Preview installers are unsigned. This fork disables the official automatic updater; install subsequent releases from this repository.

1. Obtain a separate Cloudflare **Client ID** and **Client Secret** for your device from the server operator.
2. Enter the HTTPS Nextcloud address in the account wizard. Open **Cloudflare Access…** before checking the server, enable it, and enter the token pair.
3. Complete the normal browser login. Nextcloud then issues the device's app password for synchronization.

Existing accounts can update the token under **Settings → Advanced → Cloudflare Access**. Installing the client does not grant server access: the operator must authorize the token and enable Nextcloud's native login flow.

## Credential handling

The service token is stored in the operating system's credential store. One HTTPS hostname and port can be configured per profile; its accounts share the token. Replacing that origin requires disabling the existing setting first. Requests to other origins receive no token.

Diagnostic logs redact token headers and credential exchanges. The client discards reusable Access cookies. Access failures preserve the native app password until a fresh, bounded `status.php` check confirms the protected server is reachable. Keep that endpoint under the same Access policy as DAV and API requests.

Retire a device by revoking both its Cloudflare Service Token and its Nextcloud app password. Keep the token out of support messages and installers. macOS File Provider is unsupported; classic macOS sync is the intended path. macOS and Linux installers are not part of the initial Windows release.

## Build and release

The [Windows build script](admin/club/build-windows.ps1) uses pinned Craft, CraftMaster and blueprint commits from the [build configuration](admin/club/craftmaster.ini). It builds the client, runs nine focused test suites, packages an installer, and checks a silent installation in the disposable runner.

A [small patch](admin/club/patches/0001-nextcloud-blueprint-packaging.patch) repairs the pinned recipe's missing Python import and Start Menu launcher. The build checks the recipe revision and clean tree before applying it. `build-info.json` records the patch checksum.

The installation check uses NSIS's explicit all-users mode on a fresh 64-bit runner. It compares the installed executable and sync libraries with the tested build and checks the Start Menu shortcut's target.

The **Sairibus Windows release** workflow runs manually from `main`. It rejects other refs, stale source commits, invalid tags and existing tags. Publication rechecks `main` and the artifact checksums. Releases include `SHA256SUMS`, `build-info.json`, and the complete source archives.

Release automation uses standard GitHub-hosted runners. No signing credentials or server credentials are required. Review changes through pull requests before running a release.

For local development, follow the [upstream development documentation](doc). The focused test targets are `CloudflareAccessTest`, `CookiesTest`, `AccountWizardControllerTest`, `SettingsDialogTest`, `PushNotificationsTest`, `RemoteWipeTest`, `AccountStateTest` and `ConnectionValidatorTest`; CTest also runs `AccountWizardWindowQmlTest`.

## Provenance and license

Service Token support began with [Gedudo's implementation](https://github.com/Gedudo/desktop/commit/98ed7e1b8a048f27194806482ce1fdf0e3bb1875), associated with [upstream issue #11094](https://github.com/nextcloud/desktop/issues/11094). This fork adds credential-preservation, cookie, logging and origin-replacement fixes with regression tests. The Git history retains authorship and AI-assistance disclosures.

This project is licensed under [GPL-2.0-or-later](COPYING). It is maintained independently of Nextcloud GmbH. Contributions to upstream remain subject to [Nextcloud's contribution policy](https://github.com/nextcloud/.github/blob/master/AI_POLICY.md).
