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

Each club account can be added once per computer. To add a second club account,
sign out of the first one in the browser before starting the wizard.

## What the client keeps

Each account on this computer keeps two credentials in the Windows credential
store: its sign-in for this computer and its Nextcloud app password. Signing out
of the website, the club's other services or the browser leaves syncing
running.

A sign-in left unused for 90 days, or older than a year, ends. The client then
renews it from the browser if the browser is still signed in. Otherwise it
shows a notification and waits until you choose **Log in**, or opens the sign-in
page the next time it starts. Your folders stay as they are.

## When the client asks again

- **"Sign in to keep syncing"**: the sign-in for this computer ended or its app
  password stopped working. Click the notification, or choose **Log in** for
  the account in the tray menu, then sign in in the browser.
- **A Nextcloud approval page opens**: after you choose **Log in**, the app
  password needs a new approval. Select **Grant access**.
- **"The server refused this computer's sign-in"**: your account no longer has
  Nextcloud access. Ask a club administrator.
- **"Keep syncing these folders as …?"**: the account was set up under an
  older Nextcloud ID. Choose **Yes** if the name shown is yours; **No** signs
  the account out.

## Retiring a computer

Remove the account in the client's settings. This ends the computer's sign-in
and deletes its app password on the server. For a computer you no longer
have, ask a club administrator to revoke its app password.
