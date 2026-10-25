<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Cloudflare Access

The classic desktop client can send Cloudflare Access credentials alongside Nextcloud authentication. Nextcloud still checks its own account permissions and issues the device application password through its browser login flow.

## Browser sign-in

Enter the HTTPS Nextcloud server address, including its installation path. Open **Cloudflare Access…** in the account wizard and choose **Browser sign-in**. Complete the Access login in the browser, return to the wizard, and continue with Nextcloud's device approval. Existing accounts can renew their Access session under **Settings → Advanced → Cloudflare Access**.

Browser sign-in requires a build containing a verified `cloudflared` helper. The client runs `access login --no-verbose --auto-close` for the server address. The helper uses a private temporary cache, which the client removes on completion, cancellation, or timeout. The whole sign-in has a five-minute deadline.

Each account stores its Access application token in the system credential store. Renewal must retain the same Access issuer, subject, and application audience. If the saved identity cannot be recovered, remove the Nextcloud account and add it again. An expired Access session pauses requests until it is renewed.

The client sends the token only within the configured HTTPS server and installation path. It strips Access credentials from requests outside that scope and handles redirects manually. Tokens and protected request bodies are omitted from HTTP diagnostics.

## Administrator-issued service tokens

In the same settings, enter the administrator-issued Client ID and Client Secret and select **Apply**. Each Nextcloud account has its own configuration and credential entry. The Access application must authorize the token with a Service Auth policy. The client sends `CF-Access-Client-Id` and `CF-Access-Client-Secret` alongside Nextcloud authentication. The service token is not passed to the external browser; that browser must also have permission to complete Nextcloud's device approval.

Service credentials apply to the configured HTTPS hostname and port. Use a dedicated hostname when other applications share the server. Rotation requires replacing the credentials in settings. See [Cloudflare's service-token documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).

## Rejected requests and remote wipe

An HTTP401 response may come from Access or Nextcloud. For a request carrying Access credentials, the client preserves its Nextcloud device password and reports the authentication problem. A public `status.php` response is not used to decide which layer rejected the request. Renew Access first; if the Nextcloud device password was revoked, sign out explicitly and authorize the device again.

A separate remote-wipe check can still honor an authenticated successful response containing boolean `wipe:true`. Denied, malformed, redirected, or unsuccessful checks preserve the native credentials. A pending wipe acknowledgement retains an in-memory copy of the Access credentials through local account deletion; it does not restore the deleted credential-store entry.

## Policy and platform requirements

The browser-token flow supports Access self-hosted HTTP applications whose policies permit reusable application tokens. Configure one application to cover the Nextcloud paths needed for login, DAV, APIs, and notifications. Different applications on separate paths can require different audiences, which this client does not combine.

WARP requirements, device posture checks, and other Access policies remain enforced. Policies requiring a browser binding cookie cannot be satisfied by the application token alone. The helper uses its own system networking configuration; it does not inherit the client's per-account proxy, custom certificate approvals, or TLS client certificate.

The integration covers the classic sync engine, including its virtual files. The macOS File Provider engine uses a separate network stack and is unsupported. Switch to classic sync before enabling Access. Browser helper bundling is available for Windows and Linux. macOS browser sign-in requires signing integration that preserves the pinned helper bytes; its CMake helper configuration is disabled. macOS classic sync can use service credentials.

## Building with the browser helper

Packagers supply a platform-native `cloudflared` executable using `CLOUDFLARED_HELPER`, its independently verified SHA256 using `CLOUDFLARED_HELPER_SHA256`, and its license notice using `CLOUDFLARED_HELPER_LICENSE`. CMake verifies the digest and installs the helper beside the client executable. The client checks the same digest before each execution. No helper is downloaded at runtime or discovered through PATH.

Builds without a bundled helper can use administrator-issued service credentials. The helper distribution, supported versions, and platform signing must be agreed with the project before release.
