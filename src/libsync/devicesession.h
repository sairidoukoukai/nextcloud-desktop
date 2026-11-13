/*
 * SPDX-FileCopyrightText: 2026 Sairibus contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "owncloudlib.h"

#include <QByteArray>
#include <QDateTime>
#include <QMutex>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkRequest>
#include <QObject>
#include <QPointer>
#include <QStringList>
#include <QTimer>
#include <QUrl>

#include <chrono>
#include <functional>
#include <optional>

class QNetworkReply;

namespace OCC
{

/** Tokens from the club's identity provider for the public desktop client. */
struct OWNCLOUDSYNC_EXPORT DeviceTokens {
    QByteArray accessToken;
    QByteArray refreshToken;
    qint64 expiresAt = 0;
    QStringList scopes;

    [[nodiscard]] bool offline() const;
    /** Parses a token endpoint response. Returns nothing and sets @p error for an unusable response. */
    static std::optional<DeviceTokens> parse(const QByteArray &body, QString *error = nullptr);
};

/**
 * One account's device session for the club's Nextcloud.
 *
 * Requests to the server carry a short-lived access token in X-Sairibus-Device-Token
 * next to the Nextcloud app password. The session renews that token from a refresh
 * token: during sign-in an online one held in memory, afterwards the account's own
 * offline session kept in the system credential store.
 */
class OWNCLOUDSYNC_EXPORT DeviceSession : public QObject
{
    Q_OBJECT

public:
    static constexpr auto TokenHeader = "X-Sairibus-Device-Token";
    static constexpr auto ClientId = "nextcloud-desktop";
    static constexpr auto RefreshMarginSeconds = 60;

    enum class Status {
        Unloaded, ///< The credential store has not been read yet.
        Loading,
        Absent, ///< No device session: the account signs in from the start.
        Lost, ///< The offline session ended: the account takes a new offline grant.
        Online, ///< Sign-in in progress, with an online grant held in memory.
        Offline, ///< The account's offline session is stored and usable.
    };
    Q_ENUM(Status)

    struct Endpoints {
        QUrl server;
        QUrl issuer;
    };

    using Completion = std::function<void(const QByteArray &, const QString &)>;
    /** Completes on the owning thread. An absent value reads, a nonempty value writes and an empty value deletes. */
    using CredentialStore = std::function<void(const QString &, const std::optional<QByteArray> &, Completion)>;

    [[nodiscard]] static Endpoints defaultEndpoints();
    /** Replaces the endpoints of sessions created afterwards. Tests use local servers. */
    static void setDefaultEndpoints(const Endpoints &endpoints);
    [[nodiscard]] static QUrl origin(const QUrl &url);
    /** Whether @p url belongs to the club's Nextcloud, which requires device sign-in. */
    [[nodiscard]] static bool requiredFor(const QUrl &url);
    /** A 401 whose Bearer challenge asks for a new device token; the app password is unaffected. */
    [[nodiscard]] static bool isTokenChallenge(const QNetworkReply *reply);
    static void removeToken(QNetworkRequest &request);
    /** Logs the gateway's refusal of a device request outside the device paths; such a request is a client bug. */
    static void reportRefusedPath(QNetworkReply *reply);

    explicit DeviceSession(QObject *parent = nullptr, CredentialStore store = {}, const Endpoints &endpoints = defaultEndpoints());
    ~DeviceSession() override;

    /** Supplies the credential store entry name; read when the store is first used. */
    void setStorageKey(std::function<QString()> key);
    /** Replaces the system credential store. Tests keep entries in memory. */
    void setCredentialStore(CredentialStore store);
    /** Supplies the account's proxy for requests to the identity provider. */
    void setProxyProvider(std::function<QNetworkProxy()> proxy);

    [[nodiscard]] Endpoints endpoints() const;
    [[nodiscard]] Status status() const;
    [[nodiscard]] bool appliesTo(const QUrl &url) const;
    [[nodiscard]] bool canRefresh() const;
    [[nodiscard]] bool refreshing() const;
    [[nodiscard]] bool backingOff() const;
    [[nodiscard]] bool hasFreshToken() const;
    [[nodiscard]] QString error() const;

    /** Adds the current token to requests for the server, removes it from all others and disables automatic redirects. */
    void decorate(QNetworkRequest &request) const;

    void load();
    /** Keeps the tokens of an online sign-in in memory. */
    void adoptOnline(const DeviceTokens &tokens);
    /** Stores the offline grant's refresh token, then replaces the online grant with it. */
    void adoptOffline(const DeviceTokens &tokens, std::function<void(bool, const QString &)> done = {});
    /** Renews the access token. Concurrent calls share a single request. */
    void refresh();
    /** Renews the access token and reports whether the renewal succeeded. */
    void refreshThen(QObject *context, std::function<void(bool)> done);
    /** Refreshes when less than a minute remains, or at once after a network change or wake. */
    void ensureFresh();
    void networkChanged();
    /** Drops all tokens and deletes the stored refresh token. */
    void forget();
    /**
     * Ends this device: revokes the offline session, then deletes the app password at the server.
     * Runs on after the account is gone.
     */
    void retire(const QString &user, const QString &appPassword);

Q_SIGNALS:
    void statusChanged();
    void tokenRefreshed();
    void refreshFailed();
    void sessionLost();

private:
    void setStatus(Status status);
    void storeCredential(const std::optional<QByteArray> &data, Completion completion);
    void finishRefresh(bool success);
    void cancelRefresh();
    void scheduleRefresh();
    void backOff();
    void adoptAccessToken(const DeviceTokens &tokens);
    [[nodiscard]] QString storageKey() const;
    [[nodiscard]] QNetworkRequest tokenRequest() const;

    mutable QMutex _mutex;
    CredentialStore _store;
    Endpoints _endpoints;
    std::function<QString()> _storageKey;
    std::function<QNetworkProxy()> _proxy;
    QNetworkAccessManager _network;
    Status _status = Status::Unloaded;
    QByteArray _accessToken;
    QByteArray _refreshToken;
    qint64 _expiresAt = 0;
    QString _error;
    QPointer<QNetworkReply> _refreshReply;
    QList<std::pair<QPointer<QObject>, std::function<void(bool)>>> _waiters;
    QTimer _expiryTimer;
    QTimer _watchTimer;
    QTimer _backoffTimer;
    QDateTime _lastWatch;
    int _failures = 0;
    bool _refreshing = false;
    bool _adopting = false;
    QString _subject;
    quint64 _generation = 0;
};

}
