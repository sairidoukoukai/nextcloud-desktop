/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

import QtQuick
import QtTest
import com.nextcloud.desktopclient
import Style

import "../../../src/gui/wizard/qml"

Item {
    id: testRoot

    width: 200
    height: 100

    Component {
        id: controllerComponent

        AccountWizardController {}
    }

    Component {
        id: windowComponent

        AccountWizardWindow {}
    }

    TestCase {
        id: testCase

        property var wizard: null

        name: "AccountWizardWindow"
        when: windowShown

        function test_cloudflareDialogDraftAndCancel() {
            const window = createWizard(AccountWizardController.ServerStep)
            const button = findChild(window, "cloudflareAccessButton")
            verify(button)
            compare(button.enabled, false)
            window.controller.serverUrl = "https://cloud.example"
            compare(button.enabled, true)
            mouseClick(button)
            const dialog = findChild(window, "cloudflareAccessDialog")
            verify(dialog)
            tryCompare(dialog, "visible", true)
            const enabled = findChild(dialog, "cloudflareAccessEnabled")
            const secret = findChild(dialog, "cloudflareAccessClientSecret")
            compare(findChild(dialog, "cloudflareAccessServerUrl"), null)
            const server = findChild(dialog, "cloudflareAccessServer")
            const apply = findChild(dialog, "cloudflareAccessApply")
            verify(enabled && secret && server && apply)
            compare(server.text, window.controller.serverUrl)
            compare(secret.echoMode, TextInput.Password)
            const savedEnabled = enabled.checked
            mouseClick(enabled)
            compare(secret.enabled, enabled.checked)
            secret.text = "unsaved-draft"
            dialog.close()
            tryCompare(dialog, "visible", false)
            compare(secret.text, "")
            mouseClick(button)
            tryCompare(dialog, "visible", true)
            compare(enabled.checked, savedEnabled)
            compare(server.text, window.controller.serverUrl)
            compare(secret.text, "")
            dialog.close()
            window.controller.serverUrl = "https://other.example"
            mouseClick(button)
            tryCompare(dialog, "visible", true)
            compare(server.text, "https://other.example")
            compare(secret.text, "")
            compare(window.controller.cloudflareAccess.enabled, false)
            dialog.close()
        }

        function test_cloudflareDialogApplyAndValidation() {
            const window = createWizard(AccountWizardController.ServerStep)
            window.controller.serverUrl = "https://cloud.example"
            mouseClick(findChild(window, "cloudflareAccessButton"))
            const dialog = findChild(window, "cloudflareAccessDialog")
            tryCompare(dialog, "visible", true)
            mouseClick(findChild(dialog, "cloudflareAccessEnabled"))
            const apply = findChild(dialog, "cloudflareAccessApply")
            mouseClick(apply)
            compare(dialog.visible, true)
            verify(findChild(dialog, "cloudflareAccessError").text.length > 0)
            findChild(dialog, "cloudflareAccessClientId").text = "client"
            findChild(dialog, "cloudflareAccessClientSecret").text = "secret"
            mouseClick(apply)
            tryCompare(dialog, "visible", false)
            compare(window.controller.cloudflareAccess.enabled, true)
            compare(window.controller.cloudflareAccess.serverUrl, window.controller.serverUrl)
            compare(window.controller.cloudflareAccess.clientSecret, "secret")
            mouseClick(findChild(window, "cloudflareAccessButton"))
            tryCompare(dialog, "visible", true)
            compare(findChild(dialog, "cloudflareAccessClientSecret").text, "secret")
            window.controller.serverUrl = "https://other.example"
            compare(findChild(dialog, "cloudflareAccessServer").text, window.controller.serverUrl)
            compare(findChild(dialog, "cloudflareAccessEnabled").checked, false)
            compare(findChild(dialog, "cloudflareAccessClientSecret").text, "")
            compare(apply.enabled, false)
            compare(window.controller.cloudflareAccess.serverUrl, "https://cloud.example")
            dialog.close()
        }

        function createWizard(step) {
            const controller = createTemporaryObject(controllerComponent, testRoot, { currentStep: step })
            verify(controller)
            wizard = windowComponent.createObject(testRoot, { controller: controller, visible: true })
            verify(wizard)
            return wizard
        }

        // The window must go before its temporary controller, which is destroyed right after cleanup().
        function cleanup() {
            if (wizard) {
                wizard.destroy()
                wizard = null
                wait(0)
            }
        }

        function findVisibleButton(item, text) {
            if (item.visible && item.text === text && item.hasOwnProperty("clicked")) {
                return item
            }
            for (let i = 0; i < item.children.length; ++i) {
                const found = findVisibleButton(item.children[i], text)
                if (found) {
                    return found
                }
            }
            return null
        }

        function buttonLabel(button) {
            for (let i = 0; i < button.contentItem.children.length; ++i) {
                const child = button.contentItem.children[i]
                if (child.objectName === "wizardButtonText") {
                    return child
                }
            }
            return null
        }

        function relabel(wizard, text, newText) {
            const button = findVisibleButton(wizard.contentItem, text)
            verify(button, "no visible button labelled " + text)
            button.text = newText
            return button
        }

        function test_widthIsConstantAcrossSteps() {
            const wizard = createWizard(AccountWizardController.ServerStep)
            const steps = [
                AccountWizardController.BrowserAuthStep,
                AccountWizardController.BasicAuthStep,
                AccountWizardController.SyncOptionsStep,
                AccountWizardController.ServerStep
            ]

            compare(wizard.minimumWidth, Style.accountWizardWidth)
            compare(wizard.width, Style.accountWizardWidth)
            for (const step of steps) {
                wizard.controller.currentStep = step
                compare(wizard.width, Style.accountWizardWidth, "width changed at step " + step)
                compare(wizard.minimumWidth, Style.accountWizardWidth)
            }
            compare(wizard.height, Style.compactDialogHeight)
        }

        function test_syncOptionsFooterFitsGermanLabels() {
            if (Qt.platform.os !== "osx") {
                skip("Style.accountWizardWidth was measured with the macOS system font")
            }

            const wizard = createWizard(AccountWizardController.SyncOptionsStep)
            const buttons = [
                relabel(wizard, "Cancel", "Abbrechen"),
                relabel(wizard, "Set up later", "Später einrichten"),
                relabel(wizard, "Advanced", "Fortgeschritten"),
                relabel(wizard, "Done", "Erledigt")
            ]

            for (const button of buttons) {
                const label = buttonLabel(button)
                verify(label)
                tryVerify(() => label.width > 0)
                verify(!label.truncated, button.text + " is truncated")
            }
        }

        function test_chooseButtonGrowsWithLabel() {
            const wizard = createWizard(AccountWizardController.SyncOptionsStep)
            const button = relabel(wizard, "Choose", "Auswählen")
            const label = buttonLabel(button)

            tryVerify(() => button.implicitWidth > Style.wizardInlineButtonMinimumWidth)
            tryCompare(button, "width", button.implicitWidth)
            verify(!label.truncated)
        }

        function test_chooseButtonKeepsMinimumWidthForShortLabel() {
            const wizard = createWizard(AccountWizardController.SyncOptionsStep)
            const button = relabel(wizard, "Choose", "OK")

            tryVerify(() => button.implicitWidth < Style.wizardInlineButtonMinimumWidth)
            tryCompare(button, "width", Style.wizardInlineButtonMinimumWidth)
        }

        function test_overlongFooterLabelElidesInsideWindow() {
            const wizard = createWizard(AccountWizardController.SyncOptionsStep)
            const button = relabel(wizard, "Set up later", "Später einrichten ".repeat(20))
            const label = buttonLabel(button)

            tryVerify(() => label.truncated)
            const rightEdge = button.mapToItem(wizard.contentItem, button.width, 0).x
            verify(rightEdge <= wizard.width - Style.wizardWindowMargin, "button overflows to " + rightEdge)
        }
    }
}
