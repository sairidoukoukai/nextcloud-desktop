/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Style
import "../../tray"

Dialog {
    id: root

    required property QtObject controller
    required property string serverUrl
    property bool draftEnabled: false
    property bool dirty: false

    modal: true
    width: Style.wizardDialogMaximumWidth
    padding: Style.wizardWindowMargin
    header: null
    footer: null
    closePolicy: controller.busy ? Popup.NoAutoClose : Popup.CloseOnEscape

    function load() {
        const configured = controller.isConfiguredForServer(root.serverUrl)
        draftEnabled = configured && controller.enabled
        clientId.text = configured ? controller.clientId : ""
        clientSecret.text = configured ? controller.clientSecret : ""
        dirty = false
    }

    onServerUrlChanged: {
        if (visible) {
            controller.resetError()
            load()
        }
    }

    onOpened: {
        controller.resetError()
        load()
    }
    onClosed: {
        clientId.clear()
        clientSecret.clear()
        dirty = false
    }

    Connections {
        target: root.controller
        function onChanged() {
            if (root.visible && !root.dirty)
                root.load()
        }
        function onSaved(success) {
            if (success && root.visible)
                root.close()
        }
    }

    background: Rectangle {
        radius: Style.wizardDialogRadius
        color: Style.wizardWindowBackground
    }

    contentItem: ColumnLayout {
        spacing: Style.wizardDialogSpacing
        Accessible.role: Accessible.Dialog
        Accessible.name: qsTr("Cloudflare Access")

        EnforcedPlainTextLabel {
            text: qsTr("Cloudflare Access")
            color: Style.wizardPrimaryText
            font.bold: true
            font.pixelSize: Style.wizardBodyFontPixelSize
            Layout.fillWidth: true
        }

        EnforcedPlainTextLabel {
            objectName: "cloudflareAccessServer"
            text: root.serverUrl
            color: Style.wizardSecondaryText
            wrapMode: Text.WrapAnywhere
            Layout.fillWidth: true
        }

        Switch {
            objectName: "cloudflareAccessEnabled"
            text: qsTr("Enable Cloudflare Access")
            checked: root.draftEnabled
            enabled: !root.controller.busy
            onToggled: {
                root.draftEnabled = checked
                root.dirty = true
            }
        }

        GridLayout {
            columns: 2
            enabled: root.draftEnabled && !root.controller.busy
            Layout.fillWidth: true

            EnforcedPlainTextLabel { text: qsTr("Client ID"); color: Style.wizardPrimaryText }
            WizardTextField {
                id: clientId
                objectName: "cloudflareAccessClientId"
                Accessible.name: qsTr("Client ID")
                Layout.fillWidth: true
                onTextEdited: root.dirty = true
            }
            EnforcedPlainTextLabel { text: qsTr("Client Secret"); color: Style.wizardPrimaryText }
            WizardTextField {
                id: clientSecret
                objectName: "cloudflareAccessClientSecret"
                Accessible.name: qsTr("Client Secret")
                echoMode: TextInput.Password
                Layout.fillWidth: true
                onTextEdited: root.dirty = true
            }
        }

        EnforcedPlainTextLabel {
            text: qsTr("Only one HTTPS server can use Cloudflare Access in this profile. Credentials are shared by its accounts and sent to every path on the same hostname and port. macOS File Provider is not supported.")
            color: Style.wizardSecondaryText
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        EnforcedPlainTextLabel {
            objectName: "cloudflareAccessError"
            text: root.controller.error
            visible: text.length > 0
            color: Style.wizardPrimaryText
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        RowLayout {
            Layout.fillWidth: true
            Item { Layout.fillWidth: true }
            WizardButton {
                text: qsTr("Cancel")
                enabled: !root.controller.busy
                onClicked: root.close()
            }
            WizardButton {
                objectName: "cloudflareAccessApply"
                text: qsTr("Apply")
                primary: true
                enabled: !root.controller.busy && root.serverUrl.length > 0
                    && (root.draftEnabled || root.controller.isConfiguredForServer(root.serverUrl))
                onClicked: root.controller.save(root.draftEnabled, root.serverUrl, clientId.text, clientSecret.text)
            }
        }
    }
}
