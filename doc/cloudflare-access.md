<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Cloudflare Access

The desktop client's classic sync engine can use a Cloudflare Access service
token to reach a protected Nextcloud server. Nextcloud authentication is still
required.

In **Settings → Advanced**, enable **Cloudflare Access**, enter the HTTPS server
URL and the service token's **Client ID** and **Client Secret**, then select
**Apply**. The account setup wizard also offers **Cloudflare Access…** before
checking the server address. Both places edit the same configuration. Applying
this configuration saves it even if account setup is subsequently cancelled.

The configuration applies to one server origin per local client profile. All
accounts on that hostname and HTTPS port share it. A path in the entered URL
is removed: the headers apply to every path on that origin. Different hosts,
ports, and unencrypted connections receive no service-token headers.

The token pair is stored in the operating system's credential store. The
configuration file contains the server origin, enabled flag, and a reference
to the credential-store entry. Disabling Cloudflare Access retains the token
for later use and stops adding its headers to new requests.

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

## Supported sync engines

Cloudflare Access is supported by the classic sync engine on Windows, Linux,
and macOS, including the classic engine's virtual-file implementations.
The macOS File Provider engine uses a separate network stack and is not
supported. Switch the server's accounts to classic sync before enabling
Cloudflare Access; the client does not migrate those accounts automatically.
