<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Cloudflare Access

The classic desktop client can connect through Cloudflare Access while using
Nextcloud's own browser approval and per-device application password.

## Sairibus browser login

Enter `https://nc.sairibus.com` in the account wizard and continue. The client
opens the browser for 再バ同アカウント sign-in. Use a passkey or an email code,
then approve the device in Nextcloud and choose the folders to synchronize.

The Windows installer bundles cloudflared built from pinned source with a small
login retry patch. The patch and pinned Go toolchain are recorded in
`admin/club/cloudflared.json` and the release's `build-info.json`. It runs
`access login --no-verbose --auto-close` for the exact HTTPS origin. The client
checks the binary hash before execution and stores the resulting application
JWT in QtKeychain. Each local account UUID has its own credential entry; a
session for another central identity cannot replace it.

Temporary metadata and token-transfer failures are retried with a delay, using
the same browser handoff. Metadata discovery has a 30-second budget; the client
allows five minutes for the whole sign-in. Cancellation stops the helper.

The helper's application and organization token cache lives in an owned,
disposable directory with private permissions. The client deletes it after the
helper exits, including cancellation and timeout. It leaves the user's regular
cloudflared configuration untouched.

Cloudflare session lifetime follows the server policy. To renew a session,
select the account under **Settings → Advanced** and choose **Browser sign-in**.
The client retains the Nextcloud device password when Access expires or is
unreachable. It sends `cf-access-token` only to the bound origin, strips it from
other requests and redacts it from diagnostics. Protected request bodies are
omitted from HTTP logs.

## Administrator-issued service credentials

Other servers can use **Cloudflare Access…** in the setup wizard. Enter the
operator-issued Client ID and Client Secret. Existing accounts can edit them
under **Settings → Advanced**. This mode stores one shared service credential
per profile and HTTPS origin. Disable it before replacing the origin.

## Server configuration

Create a service token and authorize it in a **Service Auth** policy for the
Access application. The client sends `CF-Access-Client-Id` and
`CF-Access-Client-Secret` alongside its normal Nextcloud authentication.
See [Cloudflare's service-token documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).

Browser login opens in the external browser, where the user authenticates
through Cloudflare Access before completing Nextcloud login. Configure the
Access application's policies to support that browser authentication as well
as the client's service token. The client does not pass its service token to
the browser.

If access is denied, check the token's expiry, Client ID and Client Secret,
and its authorization in the Access application's policy. A server error can
also originate from Nextcloud itself. Token rotation requires replacing the
credentials in Advanced settings and selecting Apply.

Keep the Nextcloud `status.php` endpoint under the same Access policy as the
server's DAV and API paths. When an authenticated request returns HTTP 401, the
client checks that exact status endpoint using a fresh connection with the
service token. This check sends no Nextcloud credentials or cookies. A failed
check preserves the native login so a service-token update can restore access.
A valid installed-server response allows the normal Nextcloud reauthentication
flow. Redirected, cached or malformed status responses cannot trigger it.

## Supported sync engines

Cloudflare Access is supported by the classic sync engine on Windows, Linux,
and macOS, including the classic engine's virtual-file implementations.
The macOS File Provider engine uses a separate network stack and is not
supported. Switch the server's accounts to classic sync before enabling
Cloudflare Access; the client does not migrate those accounts automatically.
