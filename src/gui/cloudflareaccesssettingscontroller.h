/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QObject>

class QUrl;

namespace OCC
{

class CloudflareAccess;

class CloudflareAccessSettingsController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool enabled READ enabled NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString serverUrl READ serverUrl NOTIFY changed)
    Q_PROPERTY(QString clientId READ clientId NOTIFY changed)
    Q_PROPERTY(QString clientSecret READ clientSecret NOTIFY changed)
    Q_PROPERTY(QString error READ error NOTIFY changed)

public:
    explicit CloudflareAccessSettingsController(QObject *parent = nullptr, CloudflareAccess *access = nullptr);
    [[nodiscard]] bool enabled() const;
    [[nodiscard]] bool busy() const;
    [[nodiscard]] QString serverUrl() const;
    [[nodiscard]] QString clientId() const;
    [[nodiscard]] QString clientSecret() const;
    [[nodiscard]] QString error() const;
    Q_INVOKABLE void resetError();
    Q_INVOKABLE [[nodiscard]] bool isConfiguredForServer(const QString &serverUrl) const;
    Q_INVOKABLE void save(bool enabled, const QString &serverUrl, const QString &clientId, const QString &clientSecret);

Q_SIGNALS:
    void changed();
    void saved(bool success);

private:
    [[nodiscard]] static QString accountCompatibilityError(const QUrl &server);
    CloudflareAccess *_access;
    QString _validationError;
    bool _saving = false;
    bool _showSaveError = false;
};

}
