/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "owncloudlib.h"

#include <QMutex>
#include <QNetworkRequest>
#include <QObject>
#include <QUrl>

#include <chrono>
#include <functional>
#include <optional>

namespace OCC
{

class OWNCLOUDSYNC_EXPORT CloudflareAccess : public QObject
{
    Q_OBJECT

public:
    static constexpr auto SessionIdentityAttribute = static_cast<QNetworkRequest::Attribute>(QNetworkRequest::User + 4);
    static constexpr auto ConfigurationEpochAttribute = static_cast<QNetworkRequest::Attribute>(QNetworkRequest::User + 2);
    using Completion = std::function<void(const QByteArray &, const QString &)>;
    // Complete on the owning thread. An absent value reads, a nonempty value writes, and an empty value deletes.
    using CredentialStore = std::function<void(const QString &, const std::optional<QByteArray> &, Completion)>;
    using ConfigurationCheck = std::function<QString(const QUrl &)>;

    explicit CloudflareAccess(QObject *parent = nullptr,
                              CredentialStore store = {},
                              std::chrono::milliseconds storageTimeout = std::chrono::seconds(30),
                              const QString &scope = {});

    [[nodiscard]] bool enabled() const;
    [[nodiscard]] bool busy() const;
    [[nodiscard]] bool ready() const;
    [[nodiscard]] QUrl serverUrl() const;
    [[nodiscard]] QString clientId() const;
    [[nodiscard]] QString clientSecret() const;
    [[nodiscard]] QString error() const;
    [[nodiscard]] bool browserMode() const;
    [[nodiscard]] static bool hasCredentials(const QNetworkRequest &request);
    [[nodiscard]] static QString browserTokenError(const QByteArray &token);
    [[nodiscard]] bool protects(const QUrl &url) const;
    [[nodiscard]] static QUrl origin(const QUrl &url);
    [[nodiscard]] static QUrl browserServer(const QUrl &url);
    /** @brief Copy the current credentials into memory for a pending remote-wipe acknowledgement. */
    [[nodiscard]] CloudflareAccess *snapshot(QObject *parent) const;
    [[nodiscard]] static QString validate(bool enabled, const QString &url, const QString &id, const QString &secret);
    // Removes old token headers, then applies the current configuration. An error prevents sending the request.
    static void removeCredentials(QNetworkRequest &request);
    [[nodiscard]] QString prepareRequest(QNetworkRequest &request) const;
    [[nodiscard]] bool matchesCurrentRequest(const QNetworkRequest &request) const;

    void load();
    void clear();
    void cancelPending();
    void saveBrowserToken(const QString &url, const QByteArray &token);
    void save(bool enabled, const QString &url, const QString &id, const QString &secret, ConfigurationCheck check = {});

Q_SIGNALS:
    void changed();
    void configurationChanged();
    void saved(bool success);

private:
    CloudflareAccess(QObject *parent, const CloudflareAccess &source);
    void saveToken(bool enabled, const QString &url, const QString &id, const QString &secret, const QByteArray &browserToken, ConfigurationCheck check);
    void storeCredential(const QString &key, const std::optional<QByteArray> &data, Completion completion);
    void removeCredential(const QString &key);
    [[nodiscard]] QString credentialKey() const;

    mutable QRecursiveMutex _mutex;
    CredentialStore _store;
    std::chrono::milliseconds _storageTimeout;
    QString _configFile;
    QString _settingsGroup;
    QString _scope;
    QString _instanceId;
    QByteArray _browserToken;
    bool _browserMode = false;
    qint64 _expiresAt = 0;
    QString _credentialEntry;
    bool _enabled = false;
    bool _busy = false;
    bool _ready = false;
    QUrl _serverUrl;
    QString _clientId;
    QString _clientSecret;
    QString _error;
    quint64 _generation = 0;
};

}
