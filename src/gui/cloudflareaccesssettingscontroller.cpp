/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cloudflareaccesssettingscontroller.h"
#include "cloudflarebrowserlogin.h"

#include "accountmanager.h"
#include "cloudflareaccess.h"

using namespace Qt::StringLiterals;

namespace OCC
{

CloudflareAccessSettingsController::CloudflareAccessSettingsController(QObject *parent, CloudflareAccess *access, CloudflareBrowserLogin *browserLogin)
    : QObject(parent)
    , _browserLogin(browserLogin ? browserLogin : new CloudflareBrowserLogin(this))
{
    connect(_browserLogin, &CloudflareBrowserLogin::finished, this, [this](const QByteArray &token, const QString &error) {
        _validationError = error;
        if (!_accountAccess || !error.isEmpty()) {
            Q_EMIT changed();
            Q_EMIT browserFinished(false);
            return;
        }
        _browserSaving = true;
        Q_EMIT changed();
        _accountAccess->saveBrowserToken(_browserUrl, token);
    });
    setAccountAccess(access);
}

void CloudflareAccessSettingsController::setAccountAccess(CloudflareAccess *access)
{
    if (_browserLogin->busy() || _browserSaving || _saving) {
        return;
    }
    if (_accountAccess == access) {
        return;
    }
    if (_accountAccess) {
        disconnect(_accountAccess, nullptr, this, nullptr);
    }
    _accountAccess = access;
    if (access) {
        connect(access, &QObject::destroyed, this, [this] {
            const auto serviceSaving = _saving;
            const auto browserSaving = _browserSaving;
            _saving = _browserSaving = false;
            _validationError = tr("The selected Nextcloud account was closed.");
            _browserLogin->cancel();
            Q_EMIT changed();
            if (serviceSaving) {
                Q_EMIT saved(false);
            }
            if (browserSaving) {
                Q_EMIT browserFinished(false);
            }
        });
        connect(access, &CloudflareAccess::changed, this, &CloudflareAccessSettingsController::changed);
        connect(access, &CloudflareAccess::saved, this, [this](bool success) {
            if (_saving) {
                _saving = false;
                Q_EMIT changed();
                Q_EMIT saved(success);
            }
            if (!_browserSaving) {
                return;
            }
            _browserSaving = false;
            _validationError = success ? QString{} : _accountAccess->error();
            Q_EMIT changed();
            Q_EMIT browserFinished(success);
        });
    }
}

void CloudflareAccessSettingsController::signInBrowser(const QString &serverUrl)
{
    if (busy()) {
        return;
    }
    _validationError = _accountAccess ? accountCompatibilityError(QUrl(serverUrl)) : tr("Select a Nextcloud account first.");
    if (!_validationError.isEmpty()) {
        Q_EMIT changed();
        Q_EMIT browserFinished(false);
        return;
    }
    _browserUrl = serverUrl;
    _browserLogin->start(QUrl(serverUrl));
    Q_EMIT changed();
}

void CloudflareAccessSettingsController::cancelBrowserSignIn()
{
    _browserLogin->cancel();
    if (_browserSaving && _accountAccess) {
        _accountAccess->cancelPending();
    }
}

CloudflareAccess *CloudflareAccessSettingsController::configuration() const
{
    return _accountAccess.data();
}

bool CloudflareAccessSettingsController::browserAvailable() const
{
    return _browserLogin->available();
}

bool CloudflareAccessSettingsController::browserMode() const
{
    return configuration() && configuration()->browserMode();
}

bool CloudflareAccessSettingsController::enabled() const
{
    return configuration() && configuration()->enabled();
}
bool CloudflareAccessSettingsController::busy() const
{
    return _saving || _browserSaving || _browserLogin->busy() || (configuration() && configuration()->busy());
}
QString CloudflareAccessSettingsController::serverUrl() const
{
    return configuration() ? configuration()->serverUrl().toString() : QString{};
}
QString CloudflareAccessSettingsController::clientId() const
{
    return configuration() ? configuration()->clientId() : QString{};
}
QString CloudflareAccessSettingsController::clientSecret() const
{
    return configuration() ? configuration()->clientSecret() : QString{};
}
QString CloudflareAccessSettingsController::error() const
{
    if (!_validationError.isEmpty()) {
        return _validationError;
    }
    return configuration() && (_showSaveError || !configuration()->ready()) ? configuration()->error() : QString{};
}

void CloudflareAccessSettingsController::resetError()
{
    if (_saving) {
        return;
    }
    _validationError.clear();
    _showSaveError = false;
    Q_EMIT changed();
}

bool CloudflareAccessSettingsController::isConfiguredForServer(const QString &serverUrl) const
{
    const auto server = QUrl(serverUrl);
    return configuration() && server.scheme() == "https"_L1 && !configuration()->serverUrl().isEmpty()
        && (configuration()->browserMode() ? CloudflareAccess::browserServer(server) == configuration()->serverUrl()
                                           : CloudflareAccess::origin(server) == configuration()->serverUrl());
}

void CloudflareAccessSettingsController::save(bool enabled, const QString &serverUrl, const QString &clientId, const QString &clientSecret)
{
    _validationError.clear();
    _showSaveError = true;
    if (!configuration()) {
        _validationError = tr("Select a Nextcloud account first.");
        Q_EMIT changed();
        Q_EMIT saved(false);
        return;
    }
    if (configuration()->busy()) {
        _validationError = tr("Cloudflare Access credentials are busy. Please try again.");
        Q_EMIT changed();
        Q_EMIT saved(false);
        return;
    }
    _saving = true;
    configuration()->save(enabled, serverUrl, clientId, clientSecret, accountCompatibilityError);
}

QString CloudflareAccessSettingsController::accountCompatibilityError(const QUrl &server)
{
#ifdef BUILD_FILE_PROVIDER_MODULE
    const auto accounts = AccountManager::instance()->accounts();
    for (const auto &state : accounts) {
        const auto account = state->account();
        if (!account->fileProviderDomainIdentifier().isEmpty() && CloudflareAccess::origin(account->url()) == CloudflareAccess::origin(server)) {
            return tr("Cloudflare Access does not support macOS File Provider. Use classic sync for this server before enabling Cloudflare Access.");
        }
    }
#else
    Q_UNUSED(server)
#endif
    return {};
}

}
