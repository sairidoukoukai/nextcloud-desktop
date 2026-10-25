<!--
SPDX-FileCopyrightText: 2026 Sairibus contributors
SPDX-FileCopyrightText: 2017 Nextcloud GmbH and Nextcloud contributors
SPDX-License-Identifier: GPL-2.0-or-later
-->
# Nextcloud Desktop with Cloudflare Access

An unofficial fork maintained by 再履バス同好会 (Sairibus), based on Nextcloud Desktop 35.0.0 with the subsequent `stable-35.0` fixes through [`76ef152`](https://github.com/nextcloud/desktop/commit/76ef152f8c98009c910f124af1da20876e3915e9). It connects the classic desktop client through Cloudflare Access browser login and Nextcloud's per-device authorization.

[Download releases](https://github.com/sairidoukoukai/nextcloud-desktop/releases) · [Upstream project](https://github.com/nextcloud/desktop)

## Install and connect

Releases target Windows x64. Installers are unsigned. This fork disables the official automatic updater; install subsequent releases from this repository.

1. Enter **https://nc.sairibus.com** in the account wizard and continue.
2. Sign in with your **再バ同アカウント** in the browser using a passkey or email code.
3. Approve the device in Nextcloud, then choose the folders to sync.

The installer includes Cloudflare's login component. Members need no Client ID, Client Secret, WARP or separate command-line installation. When the Access session expires, open **Settings → Advanced**, select the account and choose **Browser sign-in**. The existing Nextcloud device password is retained.

The server operator controls eligibility and must enable device authorization. The club's member UID review still applies. Other Cloudflare-protected servers can use administrator-issued service credentials through **Cloudflare Access…**.

## Credential handling

Browser sessions are stored in the operating system's credential store, separately for each local account UUID and exact HTTPS origin. Each account retains its own Nextcloud device password. Reauthentication requires the same central identity used during setup.

The bundled helper runs with a disposable private cache. Application and organization tokens written there are removed after completion or cancellation. The client checks the helper's pinned SHA-256 before starting it. HTTP diagnostics redact Access headers and cookies and omit protected request bodies. Cross-origin requests receive no Access token.

To retire a device, revoke its Nextcloud application password and its Cloudflare session. Removing an account also clears its locally stored Access session. The legacy service-credential mode shares one origin's credentials within a profile.

macOS File Provider is unsupported. This release provides a Windows x64 installer.

## Build and release

The [Windows build script](admin/club/build-windows.ps1) uses pinned Craft, CraftMaster and blueprint commits from the [build configuration](admin/club/craftmaster.ini). It builds the client, runs thirteen focused test suites, packages an installer, and checks a silent installation in the disposable runner.

A [small patch](admin/club/patches/0001-nextcloud-blueprint-packaging.patch) repairs the pinned recipe's missing Python import and Start Menu launcher. The build checks the recipe revision and clean tree before applying it. `build-info.json` records the patch checksum.

The installation check uses NSIS's explicit all-users mode on a fresh 64-bit runner. It compares the installed executable and sync libraries with the tested build and checks the Start Menu shortcut's target.

The **Sairibus Windows release** workflow runs manually from `main`. It rejects other refs, stale source commits, invalid tags and existing tags. Publication rechecks `main` and the artifact checksums. Each publication is a regular GitHub release marked as Latest. Releases include `SHA256SUMS`, `build-info.json`, and the complete source archives.

The installer bundles official cloudflared 2026.10.3, verified against [the pinned binary and source hashes](admin/club/cloudflared.json). Dependency license notices are collected from the authenticated Go modules and included with the helper. The silent installation check verifies the installed helper and notices.

Release automation uses standard GitHub-hosted runners. No signing credentials or server credentials are required. Review changes through pull requests before running a release.

For local development, follow the [upstream development documentation](doc). The focused test targets are `CloudflareAccessTest`, `CookiesTest`, `AccountWizardControllerTest`, `SettingsDialogTest`, `PushNotificationsTest`, `RemoteWipeTest`, `AccountStateTest`, `ConnectionValidatorTest`, `SyncEngineTest`, `SyncCfApiTest`, `UnifiedSharingTest`, and `WindowCloseQmlTest`; CTest also runs `AccountWizardWindowQmlTest`. `SyncCfApiTest` runs on Windows.

## Provenance and license

Service Token support began with [Gedudo's implementation](https://github.com/Gedudo/desktop/commit/98ed7e1b8a048f27194806482ce1fdf0e3bb1875), associated with [upstream issue #11094](https://github.com/nextcloud/desktop/issues/11094). This fork adds credential-preservation, cookie, logging and origin-replacement fixes with regression tests. The Git history retains authorship and AI-assistance disclosures.

This project is licensed under [GPL-2.0-or-later](COPYING). It is maintained independently of Nextcloud GmbH. Contributions to upstream remain subject to [Nextcloud's contribution policy](https://github.com/nextcloud/.github/blob/master/AI_POLICY.md).
