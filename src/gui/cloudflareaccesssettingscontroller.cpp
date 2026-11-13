/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cloudflareaccesssettingscontroller.h"

#include "accountmanager.h"
#include "cloudflareaccess.h"

using namespace Qt::StringLiterals;

namespace OCC
{

CloudflareAccessSettingsController::CloudflareAccessSettingsController(QObject *parent, CloudflareAccess *access)
    : QObject(parent)
    , _access(access ? access : CloudflareAccess::instance())
{
    connect(_access, &CloudflareAccess::changed, this, &CloudflareAccessSettingsController::changed);
    connect(_access, &CloudflareAccess::saved, this, [this](bool success) {
        if (_saving) {
            _saving = false;
            Q_EMIT saved(success);
        }
    });
}

bool CloudflareAccessSettingsController::enabled() const
{
    return _access->enabled();
}
bool CloudflareAccessSettingsController::busy() const
{
    return _access->busy();
}
QString CloudflareAccessSettingsController::serverUrl() const
{
    return _access->serverUrl().toString();
}
QString CloudflareAccessSettingsController::clientId() const
{
    return _access->clientId();
}
QString CloudflareAccessSettingsController::clientSecret() const
{
    return _access->clientSecret();
}
QString CloudflareAccessSettingsController::error() const
{
    if (!_validationError.isEmpty()) {
        return _validationError;
    }
    return _showSaveError || !_access->ready() ? _access->error() : QString{};
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
    return server.scheme() == "https"_L1 && !_access->serverUrl().isEmpty() && CloudflareAccess::origin(server) == _access->serverUrl();
}

void CloudflareAccessSettingsController::save(bool enabled, const QString &serverUrl, const QString &clientId, const QString &clientSecret)
{
    _validationError.clear();
    _showSaveError = true;
    if (_access->busy()) {
        _validationError = tr("Cloudflare Access credentials are busy. Please try again.");
        Q_EMIT changed();
        Q_EMIT saved(false);
        return;
    }
    _saving = true;
    _access->save(enabled, serverUrl, clientId, clientSecret, accountCompatibilityError);
}

QString CloudflareAccessSettingsController::accountCompatibilityError(const QUrl &server)
{
#ifdef BUILD_FILE_PROVIDER_MODULE
    const auto accounts = AccountManager::instance()->accounts();
    for (const auto &state : accounts) {
        const auto account = state->account();
        if (!account->fileProviderDomainIdentifier().isEmpty() && CloudflareAccess::origin(account->url()) == server) {
            return tr("Cloudflare Access does not support macOS File Provider. Use classic sync for this server before enabling Cloudflare Access.");
        }
    }
#else
    Q_UNUSED(server)
#endif
    return {};
}

}
