<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Cloudflare Access

The desktop client's classic sync engine can use a Cloudflare Access service
token to reach a protected Nextcloud server. Nextcloud authentication is still
required.

For a new account, enter the HTTPS server address in the account setup wizard,
then select **Cloudflare Access…** before continuing to the server check. Enable
the setting, enter the service token's **Client ID** and **Client Secret**, and
select **Apply**. For an existing account, open **Settings → Advanced**, select
the account under **Cloudflare Access**, and update its credentials there.
Both places edit the same configuration. Applying this configuration saves it
even if account setup is subsequently cancelled.

The configuration applies to one server origin per local client profile. All
accounts on that hostname and HTTPS port share it. A path in the entered URL
is removed: the headers apply to every path on that origin. Different hosts,
ports, and unencrypted connections receive no service-token headers.
To replace the configured server, first disable its Cloudflare Access setting
and select **Apply**. Enabling a different server then replaces the saved pair.

The token pair is stored in the operating system's credential store. The
configuration file contains the server origin, enabled flag, and a reference
to the credential-store entry. Disabling Cloudflare Access retains the token
for later use and stops adding its headers to new requests.

The client rejects `CF_Authorization` cookies so that a cached Access session
cannot outlive a service-token change. Normal Nextcloud cookies are retained.
HTTP diagnostics redact cookies and service-token headers. Request and response
bodies are omitted for service-token requests and credential exchanges.

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
