/*
 * SPDX-FileCopyrightText: 2026 Sairibus contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "devicesession.h"

#include "common/utility.h"
#include "creds/keychainchunk.h"
#include "theme.h"

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QNetworkReply>
#include <QRegularExpression>

#include <algorithm>

using namespace Qt::StringLiterals;

namespace OCC
{

Q_LOGGING_CATEGORY(lcDeviceSession, "nextcloud.sync.devicesession", QtInfoMsg)

namespace
{
constexpr auto maximumAccessTokenBytes = 8192;
constexpr auto maximumRefreshTokenBytes = 16384;
constexpr auto requestTimeout = std::chrono::seconds(30);
constexpr auto watchInterval = std::chrono::seconds(30);
// A watch tick that arrives this late means the computer slept.
constexpr auto wakeThresholdSeconds = 90;
constexpr auto firstBackoffSeconds = 5;
constexpr auto maximumBackoffSeconds = 300;

DeviceSession::Endpoints &configuredEndpoints()
{
    static auto endpoints = DeviceSession::Endpoints{QUrl(u"https://nc.sairibus.com"_s), QUrl(u"https://auth.sairibus.com/realms/sairibus"_s)};
    return endpoints;
}

QByteArray formBody(const QList<std::pair<QByteArray, QByteArray>> &fields)
{
    auto body = QByteArray();
    for (const auto &[name, value] : fields) {
        if (!body.isEmpty()) {
            body += '&';
        }
        body += name + '=' + value.toPercentEncoding();
    }
    return body;
}

bool printable(const QByteArray &value)
{
    return std::all_of(value.cbegin(), value.cend(), [](const char character) {
        return character > 0x20 && character < 0x7f;
    });
}

QNetworkRequest identityRequest(const QUrl &url)
{
    auto request = QNetworkRequest(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded"_ba);
    request.setHeader(QNetworkRequest::UserAgentHeader, Utility::userAgentString());
    request.setRawHeader("Accept"_ba, "application/json"_ba);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setTransferTimeout(requestTimeout);
    return request;
}

QUrl identityEndpoint(const QUrl &issuer, const QString &name)
{
    auto url = issuer;
    url.setPath(issuer.path() + "/protocol/openid-connect/"_L1 + name);
    return url;
}

QString translated(const char *text)
{
    return QCoreApplication::translate("OCC::DeviceSession", text);
}

/** Reads (no data), writes (data) or deletes (empty data) an entry; system credential store jobs belong to @p context. */
void useStore(const DeviceSession::CredentialStore &store,
              const QString &key,
              const std::optional<QByteArray> &data,
              QObject *context,
              DeviceSession::Completion completion)
{
    if (key.isEmpty()) {
        completion({}, translated("The account has no credential store entry."));
        return;
    }
    if (store) {
        store(key, data, std::move(completion));
        return;
    }
    if (!data) {
        const auto job = new KeychainChunk::ReadJob(key, context);
        QObject::connect(job, &KeychainChunk::ReadJob::finished, context, [completion](KeychainChunk::ReadJob *incoming) {
            completion(incoming->error() == QKeychain::NoError ? incoming->binaryData() : QByteArray{},
                       incoming->error() == QKeychain::NoError || incoming->error() == QKeychain::EntryNotFound
                           ? QString{}
                           : translated("Could not read the sign-in from the system credential store."));
        });
        job->start();
    } else if (data->isEmpty()) {
        const auto job = new KeychainChunk::DeleteJob(key, context);
        QObject::connect(job, &KeychainChunk::DeleteJob::finished, context, [completion](KeychainChunk::DeleteJob *) {
            completion({}, {});
        });
        job->start();
    } else {
        const auto job = new KeychainChunk::WriteJob(key, *data, context);
        QObject::connect(job, &KeychainChunk::WriteJob::finished, context, [completion](KeychainChunk::WriteJob *incoming) {
            completion({}, incoming->error() == QKeychain::NoError ? QString{} : translated("Could not save the sign-in in the system credential store."));
        });
        job->start();
    }
}

QByteArray storedRefreshToken(const QByteArray &data, const QUrl &issuer)
{
    const auto stored = QJsonDocument::fromJson(data).object();
    const auto token = stored.value("refresh_token"_L1).toString().toLatin1();
    return printable(token) && stored.value("issuer"_L1).toString() == issuer.toString() ? token : QByteArray{};
}

QString accessTokenSubject(const QByteArray &accessToken)
{
    const auto payload = accessToken.split('.').value(1);
    return QJsonDocument::fromJson(QByteArray::fromBase64(payload, QByteArray::Base64UrlEncoding)).object().value("sub"_L1).toString();
}

/** Revokes the offline session and deletes the app password after the account is gone. */
class DeviceRetirement : public QObject
{
public:
    DeviceRetirement(const DeviceSession::Endpoints &endpoints,
                     const QByteArray &accessToken,
                     qint64 expiresAt,
                     const QByteArray &refreshToken,
                     bool revokeSession,
                     const QString &user,
                     const QString &appPassword,
                     const QNetworkProxy &proxy)
        : QObject(QCoreApplication::instance())
        , _endpoints(endpoints)
        , _accessToken(accessToken)
        , _expiresAt(expiresAt)
        , _refreshToken(refreshToken)
        , _revoke(revokeSession)
        , _user(user)
        , _appPassword(appPassword)
    {
        _network.setProxy(proxy);
        constexpr auto limit = std::chrono::minutes(2);
        QTimer::singleShot(limit, this, &QObject::deleteLater);
    }

    /** Takes the offline session from the credential store entry first, then deletes the entry. */
    void startFromStore(const DeviceSession::CredentialStore &store, const QString &key)
    {
        useStore(store, key, std::nullopt, this, [this, store, key](const QByteArray &data, const QString &) {
            _refreshToken = storedRefreshToken(data, _endpoints.issuer);
            _revoke = true;
            useStore(store, key, QByteArray{}, this, [](const QByteArray &, const QString &) { });
            start();
        });
    }

    void start()
    {
        if (_refreshToken.isEmpty()) {
            deleteAppPassword();
        } else if (_appPassword.isEmpty() || _expiresAt - QDateTime::currentSecsSinceEpoch() > DeviceSession::RefreshMarginSeconds) {
            afterToken();
        } else {
            // The app password deletion needs a valid device token; take one before revoking the session.
            const auto reply = _network.post(identityRequest(identityEndpoint(_endpoints.issuer, u"token"_s)),
                                             formBody({{"grant_type", "refresh_token"},
                                                       {"client_id", DeviceSession::ClientId},
                                                       {"refresh_token", _refreshToken}}));
            connect(reply, &QNetworkReply::finished, this, [this, reply] {
                reply->deleteLater();
                if (const auto tokens = DeviceTokens::parse(reply->readAll());
                    reply->error() == QNetworkReply::NoError && tokens) {
                    _accessToken = tokens->accessToken;
                    if (!tokens->refreshToken.isEmpty()) {
                        _refreshToken = tokens->refreshToken;
                    }
                } else {
                    _accessToken.clear();
                }
                afterToken();
            });
        }
    }

private:
    void afterToken()
    {
        if (_revoke) {
            revoke();
        } else {
            deleteAppPassword();
        }
    }

    void revoke()
    {
        const auto reply = _network.post(identityRequest(identityEndpoint(_endpoints.issuer, u"revoke"_s)),
                                         formBody({{"client_id", DeviceSession::ClientId}, {"token", _refreshToken}, {"token_type_hint", "refresh_token"}}));
        connect(reply, &QNetworkReply::finished, this, [this, reply] {
            reply->deleteLater();
            const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (status == 200) {
                qCInfo(lcDeviceSession) << "Revoked the offline session of a removed account";
            } else {
                qCWarning(lcDeviceSession) << "Could not revoke the offline session of a removed account" << status << reply->error();
            }
            _refreshToken.clear();
            deleteAppPassword();
        });
    }

    void deleteAppPassword()
    {
        if (_user.isEmpty() || _appPassword.isEmpty()) {
            deleteLater();
            return;
        }
        if (_accessToken.isEmpty()) {
            qCWarning(lcDeviceSession) << "Could not delete the app password of a removed account: no device token";
            deleteLater();
            return;
        }
        auto url = _endpoints.server;
        url.setPath(u"/ocs/v2.php/core/apppassword"_s);
        auto request = identityRequest(url);
        request.setHeader(QNetworkRequest::ContentTypeHeader, QVariant());
        request.setRawHeader("OCS-APIRequest"_ba, "true"_ba);
        request.setRawHeader("Authorization"_ba, "Basic "_ba + QByteArray(_user.toUtf8() + ':' + _appPassword.toUtf8()).toBase64());
        request.setRawHeader(DeviceSession::TokenHeader, _accessToken);
        const auto reply = _network.deleteResource(request);
        connect(reply, &QNetworkReply::finished, this, [this, reply] {
            reply->deleteLater();
            const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (status == 200) {
                qCInfo(lcDeviceSession) << "Deleted the app password of a removed account";
            } else {
                qCWarning(lcDeviceSession) << "Could not delete the app password of a removed account" << status << reply->error();
            }
            deleteLater();
        });
    }

    QNetworkAccessManager _network;
    DeviceSession::Endpoints _endpoints;
    QByteArray _accessToken;
    qint64 _expiresAt;
    QByteArray _refreshToken;
    bool _revoke;
    QString _user;
    QString _appPassword;
};

}

bool DeviceTokens::offline() const
{
    return scopes.contains(u"offline_access"_s);
}

std::optional<DeviceTokens> DeviceTokens::parse(const QByteArray &body, QString *error)
{
    const auto fail = [error](const QString &message) {
        if (error) {
            *error = message;
        }
        return std::nullopt;
    };
    const auto json = QJsonDocument::fromJson(body).object();
    auto tokens = DeviceTokens();
    tokens.accessToken = json.value("access_token"_L1).toString().toLatin1();
    tokens.refreshToken = json.value("refresh_token"_L1).toString().toLatin1();
    tokens.scopes = json.value("scope"_L1).toString().split(u' ', Qt::SkipEmptyParts);
    const auto lifetime = json.value("expires_in"_L1).toInteger();
    static const auto jwt = QRegularExpression(u"\\A[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\z"_s);
    if (tokens.accessToken.size() > maximumAccessTokenBytes || !jwt.match(QString::fromLatin1(tokens.accessToken)).hasMatch()
        || json.value("token_type"_L1).toString().compare("Bearer"_L1, Qt::CaseInsensitive) != 0 || lifetime <= 0) {
        return fail(QCoreApplication::translate("OCC::DeviceSession", "The sign-in service returned an unusable token."));
    }
    if (tokens.refreshToken.size() > maximumRefreshTokenBytes || !printable(tokens.refreshToken)) {
        return fail(QCoreApplication::translate("OCC::DeviceSession", "The sign-in service returned an unusable token."));
    }
    tokens.expiresAt = QDateTime::currentSecsSinceEpoch() + lifetime;
    return tokens;
}

static QSet<const DeviceSession *> &liveSessions()
{
    static auto sessions = QSet<const DeviceSession *>();
    return sessions;
}

QString DeviceSession::subjectOf(const DeviceTokens &tokens)
{
    return accessTokenSubject(tokens.accessToken);
}

bool DeviceSession::subjectUsedElsewhere(const QString &subject) const
{
    if (subject.isEmpty()) {
        return false;
    }
    for (const auto session : std::as_const(liveSessions())) {
        if (session != this && session->_subject == subject && session->_status != Status::Absent && session->_endpoints.issuer == _endpoints.issuer) {
            return true;
        }
    }
    return false;
}

DeviceSession::Endpoints DeviceSession::defaultEndpoints()
{
    return configuredEndpoints();
}

void DeviceSession::setDefaultEndpoints(const Endpoints &endpoints)
{
    configuredEndpoints() = endpoints;
}

QUrl DeviceSession::origin(const QUrl &url)
{
    if (!url.isValid() || url.host().isEmpty() || (url.scheme() != "https"_L1 && url.scheme() != "http"_L1)) {
        return {};
    }
    auto result = QUrl();
    result.setScheme(url.scheme());
    result.setHost(url.host().toLower());
    const auto standardPort = url.scheme() == "https"_L1 ? 443 : 80;
    if (url.port(standardPort) != standardPort) {
        result.setPort(url.port());
    }
    return result;
}

bool DeviceSession::requiredFor(const QUrl &url)
{
    const auto server = origin(configuredEndpoints().server);
    return !server.isEmpty() && origin(url) == server;
}

bool DeviceSession::isTokenChallenge(const QNetworkReply *reply)
{
    if (!reply || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 401) {
        return false;
    }
    if (!reply->request().hasRawHeader(TokenHeader) && !requiredFor(reply->url())) {
        return false;
    }
    return reply->rawHeader("WWW-Authenticate"_ba).trimmed().toLower().startsWith("bearer");
}

void DeviceSession::removeToken(QNetworkRequest &request)
{
    if (request.hasRawHeader(TokenHeader)) {
        auto headers = request.headers();
        headers.removeAll(QLatin1StringView(TokenHeader));
        request.setHeaders(headers);
    }
}

void DeviceSession::reportRefusedPath(QNetworkReply *reply)
{
    if (reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 403) {
        return;
    }
    const auto body = reply->peek(64);
    if (body.startsWith("Browser login required") || body.startsWith("Member login required")) {
        qCWarning(lcDeviceSession) << "Client bug: the gateway refused a device request outside the device paths:" << reply->request().url().path();
    }
}

DeviceSession::DeviceSession(QObject *parent, CredentialStore store, const Endpoints &endpoints)
    : QObject(parent)
    , _store(std::move(store))
    , _endpoints(endpoints)
{
    liveSessions().insert(this);
    _network.setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
    _expiryTimer.setSingleShot(true);
    connect(&_expiryTimer, &QTimer::timeout, this, &DeviceSession::ensureFresh);
    _backoffTimer.setSingleShot(true);
    connect(&_backoffTimer, &QTimer::timeout, this, &DeviceSession::refresh);
    _watchTimer.setInterval(watchInterval);
    connect(&_watchTimer, &QTimer::timeout, this, [this] {
        const auto now = QDateTime::currentDateTimeUtc();
        const auto woke = _lastWatch.isValid() && _lastWatch.secsTo(now) > wakeThresholdSeconds;
        _lastWatch = now;
        if (woke) {
            qCInfo(lcDeviceSession) << "Renewing the device token after the computer woke";
            networkChanged();
        } else {
            ensureFresh();
        }
    });
}

DeviceSession::~DeviceSession()
{
    liveSessions().remove(this);
    ++_generation;
    _waiters.clear();
    if (_refreshReply) {
        _refreshReply->abort();
    }
}

void DeviceSession::cancelRefresh()
{
    ++_generation;
    _adopting = false;
    if (_refreshReply) {
        _refreshReply->abort();
        _refreshReply = nullptr;
    }
    _backoffTimer.stop();
    if (_refreshing) {
        finishRefresh(false);
    }
}

void DeviceSession::setStorageKey(std::function<QString()> key)
{
    _storageKey = std::move(key);
}

void DeviceSession::setCredentialStore(CredentialStore store)
{
    _store = std::move(store);
}

void DeviceSession::setProxyProvider(std::function<QNetworkProxy()> proxy)
{
    _proxy = std::move(proxy);
}

DeviceSession::Endpoints DeviceSession::endpoints() const
{
    return _endpoints;
}

DeviceSession::Status DeviceSession::status() const
{
    return _status;
}

bool DeviceSession::appliesTo(const QUrl &url) const
{
    const auto server = origin(_endpoints.server);
    return !server.isEmpty() && origin(url) == server;
}

bool DeviceSession::canRefresh() const
{
    return (_status == Status::Online || _status == Status::Offline) && !_refreshToken.isEmpty();
}

bool DeviceSession::refreshing() const
{
    return _refreshing;
}

bool DeviceSession::backingOff() const
{
    return _backoffTimer.isActive();
}

bool DeviceSession::hasFreshToken() const
{
    const auto lock = QMutexLocker(&_mutex);
    return !_accessToken.isEmpty() && _expiresAt - QDateTime::currentSecsSinceEpoch() >= RefreshMarginSeconds;
}

QString DeviceSession::error() const
{
    return _error;
}

void DeviceSession::decorate(QNetworkRequest &request) const
{
    removeToken(request);
    const auto lock = QMutexLocker(&_mutex);
    if (_accessToken.isEmpty() || !appliesTo(request.url())) {
        return;
    }
    request.setRawHeader(TokenHeader, _accessToken);
    // Qt would copy the header to the redirect target. Redirects are followed by
    // sending a new request, which decides about the token again.
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
}

void DeviceSession::setStatus(Status status)
{
    if (_status == status) {
        return;
    }
    _status = status;
    if (status == Status::Online || status == Status::Offline) {
        _lastWatch = QDateTime::currentDateTimeUtc();
        _watchTimer.start();
    } else {
        _watchTimer.stop();
        _expiryTimer.stop();
        _backoffTimer.stop();
    }
    Q_EMIT statusChanged();
}

QString DeviceSession::storageKey() const
{
    return _storageKey ? _storageKey() : QString{};
}

void DeviceSession::storeCredential(const std::optional<QByteArray> &data, Completion completion)
{
    useStore(_store, storageKey(), data, this, std::move(completion));
}

void DeviceSession::load()
{
    if (_status != Status::Unloaded) {
        return;
    }
    setStatus(Status::Loading);
    const auto generation = _generation;
    storeCredential(std::nullopt, [this, generation](const QByteArray &data, const QString &error) {
        if (generation != _generation || _status != Status::Loading) {
            return;
        }
        if (!error.isEmpty()) {
            // The store may be locked for a moment; reading again later keeps the stored session.
            qCWarning(lcDeviceSession) << "Could not read the stored offline session:" << error;
            _error = error;
            setStatus(Status::Unloaded);
            Q_EMIT refreshFailed();
            return;
        }
        const auto refreshToken = storedRefreshToken(data, _endpoints.issuer);
        if (refreshToken.isEmpty()) {
            setStatus(Status::Absent);
            return;
        }
        _subject = QJsonDocument::fromJson(data).object().value("subject"_L1).toString();
        _refreshToken = refreshToken;
        setStatus(Status::Offline);
        refresh();
    });
}

void DeviceSession::adoptOnline(const DeviceTokens &tokens)
{
    cancelRefresh();
    _subject = accessTokenSubject(tokens.accessToken);
    _refreshToken = tokens.refreshToken;
    _error.clear();
    _failures = 0;
    adoptAccessToken(tokens);
    setStatus(Status::Online);
    finishRefresh(true);
}

void DeviceSession::adoptOffline(const DeviceTokens &tokens, std::function<void(bool, const QString &)> done)
{
    if (!done) {
        done = [](bool, const QString &) { };
    }
    if (tokens.refreshToken.isEmpty() || !tokens.offline()) {
        done(false, tr("The sign-in did not grant offline access for this computer."));
        return;
    }
    // A browser signed in to another club account must not take over this account.
    const auto subject = accessTokenSubject(tokens.accessToken);
    if (!_subject.isEmpty() && subject != _subject) {
        qCWarning(lcDeviceSession) << "The offline grant belongs to another account";
        done(false, tr("The browser is signed in to a different account. Sign in with the account used for this computer."));
        return;
    }
    cancelRefresh();
    _adopting = true;
    const auto generation = _generation;
    const auto payload = QJsonDocument(QJsonObject{{"issuer"_L1, _endpoints.issuer.toString()},
                                                   {"subject"_L1, subject},
                                                   {"refresh_token"_L1, QString::fromLatin1(tokens.refreshToken)}})
                             .toJson(QJsonDocument::Compact);
    const QPointer<DeviceSession> guard(this);
    const auto key = storageKey();
    const auto store = _store;
    const auto endpoints = _endpoints;
    const auto proxy = _proxy ? _proxy() : QNetworkProxy(QNetworkProxy::DefaultProxy);
    storeCredential(payload, [this, guard, generation, tokens, subject, done, key, store, endpoints, proxy](const QByteArray &, const QString &error) {
        if (!guard || generation != _generation) {
            // The sign-in was abandoned while the grant was being stored: remove and revoke it.
            if (error.isEmpty()) {
                useStore(store, key, QByteArray{}, QCoreApplication::instance(), [](const QByteArray &, const QString &) { });
            }
            (new DeviceRetirement(endpoints, {}, 0, tokens.refreshToken, true, {}, {}, proxy))->start();
            done(false, tr("The sign-in was cancelled."));
            return;
        }
        _adopting = false;
        if (!error.isEmpty()) {
            _error = error;
            finishRefresh(false);
            done(false, error);
            return;
        }
        // The online grant is no longer needed once the offline session is stored.
        _subject = subject;
        _refreshToken = tokens.refreshToken;
        _error.clear();
        _failures = 0;
        adoptAccessToken(tokens);
        setStatus(Status::Offline);
        finishRefresh(true);
        done(true, {});
    });
}

void DeviceSession::adoptAccessToken(const DeviceTokens &tokens)
{
    {
        const auto lock = QMutexLocker(&_mutex);
        _accessToken = tokens.accessToken;
        _expiresAt = tokens.expiresAt;
    }
    scheduleRefresh();
    Q_EMIT tokenRefreshed();
}

void DeviceSession::scheduleRefresh()
{
    const auto lock = QMutexLocker(&_mutex);
    const auto due = std::max<qint64>(0, _expiresAt - QDateTime::currentSecsSinceEpoch() - RefreshMarginSeconds);
    _expiryTimer.start(std::chrono::seconds(due));
}

QNetworkRequest DeviceSession::tokenRequest() const
{
    return identityRequest(identityEndpoint(_endpoints.issuer, u"token"_s));
}

void DeviceSession::refresh()
{
    if (_refreshing || _adopting) {
        return;
    }
    if (!canRefresh()) {
        finishRefresh(false);
        return;
    }
    _refreshing = true;
    _backoffTimer.stop();
    const auto generation = _generation;
    const auto offline = _status == Status::Offline;
    if (_proxy) {
        _network.setProxy(_proxy());
    }
    const auto reply = _network.post(tokenRequest(),
                                     formBody({{"grant_type", "refresh_token"}, {"client_id", ClientId}, {"refresh_token", _refreshToken}}));
    _refreshReply = reply;
    connect(reply, &QNetworkReply::finished, this, [this, reply, generation, offline] {
        reply->deleteLater();
        if (generation != _generation) {
            return;
        }
        _refreshReply = nullptr;
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body = reply->readAll();
        auto parseError = QString();
        const auto tokens = status == 200 ? DeviceTokens::parse(body, &parseError) : std::nullopt;
        if (status == 400 && QJsonDocument::fromJson(body).object().value("error"_L1).toString() == "invalid_grant"_L1) {
            qCWarning(lcDeviceSession) << "The identity provider ended the device session";
            {
                const auto lock = QMutexLocker(&_mutex);
                _accessToken.clear();
                _expiresAt = 0;
            }
            _refreshToken.clear();
            _error = tr("This computer's sign-in has ended. Sign in again to keep syncing.");
            if (offline) {
                storeCredential(QByteArray{}, [](const QByteArray &, const QString &) { });
            }
            setStatus(offline ? Status::Lost : Status::Absent);
            finishRefresh(false);
            Q_EMIT refreshFailed();
            Q_EMIT sessionLost();
            return;
        }
        if (!tokens) {
            qCWarning(lcDeviceSession) << "Could not renew the device token; keeping the session" << status << reply->error() << parseError;
            _error = tr("Could not renew this computer's sign-in. Retrying.");
            backOff();
            finishRefresh(false);
            Q_EMIT refreshFailed();
            return;
        }
        auto renewed = *tokens;
        if (renewed.refreshToken.isEmpty()) {
            renewed.refreshToken = _refreshToken;
        }
        // A rotated refresh token replaces the old one at once; the old one must never be sent again.
        _refreshToken = renewed.refreshToken;
        if (!offline) {
            _error.clear();
            _failures = 0;
            adoptAccessToken(renewed);
            finishRefresh(true);
            return;
        }
        const auto payload =
            QJsonDocument(QJsonObject{{"issuer"_L1, _endpoints.issuer.toString()}, {"refresh_token"_L1, QString::fromLatin1(renewed.refreshToken)}})
                .toJson(QJsonDocument::Compact);
        // Store the rotated token before the new access token is used, so a crash
        // cannot leave only a spent token behind.
        storeCredential(payload, [this, generation, renewed](const QByteArray &, const QString &error) {
            if (generation != _generation) {
                return;
            }
            if (!error.isEmpty()) {
                qCWarning(lcDeviceSession) << "Could not store the renewed offline session:" << error;
                _error = error;
                backOff();
                finishRefresh(false);
                Q_EMIT refreshFailed();
                return;
            }
            _error.clear();
            _failures = 0;
            adoptAccessToken(renewed);
            finishRefresh(true);
        });
    });
}

void DeviceSession::refreshThen(QObject *context, std::function<void(bool)> done)
{
    if (!canRefresh() && !_adopting) {
        QTimer::singleShot(0, context, [done] {
            done(false);
        });
        return;
    }
    _waiters.append({QPointer<QObject>(context), std::move(done)});
    refresh();
}

void DeviceSession::finishRefresh(bool success)
{
    _refreshing = false;
    const auto waiters = std::exchange(_waiters, {});
    for (const auto &[context, done] : waiters) {
        if (context) {
            done(success);
        }
    }
}

void DeviceSession::backOff()
{
    ++_failures;
    const auto delay = std::min(maximumBackoffSeconds, firstBackoffSeconds << std::min(_failures - 1, 8));
    _backoffTimer.start(std::chrono::seconds(delay));
}

void DeviceSession::ensureFresh()
{
    if (canRefresh() && !_refreshing && !_adopting && !_backoffTimer.isActive() && !hasFreshToken()) {
        refresh();
    }
}

void DeviceSession::networkChanged()
{
    if (canRefresh() && !_refreshing && !_adopting) {
        _failures = 0;
        refresh();
    }
}

void DeviceSession::forget()
{
    cancelRefresh();
    {
        const auto lock = QMutexLocker(&_mutex);
        _accessToken.clear();
        _expiresAt = 0;
    }
    const auto stored = _status == Status::Offline || _status == Status::Lost;
    _refreshToken.clear();
    _subject.clear();
    _error.clear();
    if (stored) {
        storeCredential(QByteArray{}, [](const QByteArray &, const QString &) { });
    }
    setStatus(Status::Absent);
}

void DeviceSession::retire(const QString &user, const QString &appPassword)
{
    auto accessToken = QByteArray();
    auto expiresAt = qint64{0};
    {
        const auto lock = QMutexLocker(&_mutex);
        accessToken = _accessToken;
        expiresAt = _expiresAt;
    }
    // Online grants belong to the browser's session; they only renew the token for the app password deletion.
    const auto offline = _status == Status::Offline;
    const auto unread = _status == Status::Unloaded || _status == Status::Loading;
    const auto proxy = _proxy ? _proxy() : QNetworkProxy(QNetworkProxy::DefaultProxy);
    const auto retirement = new DeviceRetirement(_endpoints, accessToken, expiresAt, canRefresh() ? _refreshToken : QByteArray{}, offline, user, appPassword, proxy);
    const auto store = _store;
    const auto key = storageKey();
    forget();
    if (unread) {
        retirement->startFromStore(store, key);
    } else {
        retirement->start();
    }
}

}
