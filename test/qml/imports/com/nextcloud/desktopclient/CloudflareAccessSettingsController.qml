/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

import QtQml

QtObject {
    property bool enabled: false
    property bool busy: false
    property string serverUrl: ""
    property string clientId: ""
    property string clientSecret: ""
    property string error: ""
    signal changed()
    signal saved(bool success)

    function resetError() {
        error = ""
        changed()
    }

    function isConfiguredForServer(url) {
        return serverUrl.length > 0 && url === serverUrl
    }

    function save(enable, url, id, secret) {
        if (enable && (!url.startsWith("https://") || id.length === 0 || secret.length === 0)) {
            error = "Enter the server URL and service token."
            changed()
            saved(false)
            return
        }
        enabled = enable
        if (enable) {
            serverUrl = url
            clientId = id
            clientSecret = secret
        }
        error = ""
        changed()
        saved(true)
    }
}
