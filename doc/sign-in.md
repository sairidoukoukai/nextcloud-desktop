<!--
  - SPDX-FileCopyrightText: 2026 Sairibus contributors
  - SPDX-License-Identifier: GPL-2.0-or-later
-->

# Signing in to nc.sairibus.com

Add the account in the setup wizard with the server address
`https://nc.sairibus.com`. The client opens your default browser three times
in a row:

1. The club sign-in page. Sign in with your 再バ同アカウント, using a passkey or an
   email code.
2. Nextcloud's device approval page. Select **Grant access**.
3. A short page confirming the sign-in. Close the tab.

The browser reuses the first sign-in for the later pages, so one email code is
enough. Keep the same browser open until the wizard continues.

## What the client keeps

Each account on this computer keeps two credentials in the Windows credential
store: its sign-in for this computer and its Nextcloud app password. Signing out
of the website, the club's other services or the browser leaves syncing
running.

A sign-in left unused for 90 days, or older than a year, ends. The client then
opens the browser to sign in again and keeps your folders and app password.

## When the client asks again

- **The browser opens by itself**: the sign-in for this computer ended. Sign
  in once more.
- **A Nextcloud approval page opens**: the app password was revoked. Approve
  the device again.
- **"The server refused this computer's sign-in"**: your account no longer has
  Nextcloud access. Ask a club administrator.

## Retiring a computer

Remove the account in the client's settings. This ends the computer's sign-in
and deletes its app password on the server. For a computer you no longer
have, ask a club administrator to revoke its app password.
