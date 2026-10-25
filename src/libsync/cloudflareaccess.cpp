/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cloudflareaccess.h"
#include <QDateTime>
#include <QJsonArray>
#include <QRegularExpression>

#include "configfile.h"
#include "creds/keychainchunk.h"
#include "theme.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFileInfo>
#include <QHttpHeaders>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QSettings>
#include <QTimer>
#include <QUuid>

#include <algorithm>

using namespace Qt::StringLiterals;

namespace OCC
{

CloudflareAccess::CloudflareAccess(QObject *parent, CredentialStore store, std::chrono::milliseconds storageTimeout, const QString &scope)
    : QObject(parent)
    , _store(std::move(store))
    , _storageTimeout(storageTimeout)
    , _configFile(ConfigFile().configFile())
    , _settingsGroup(scope.isEmpty() ? u"CloudflareAccess"_s : u"CloudflareAccessAccounts/"_s + scope)
    , _scope(scope)
    , _instanceId(QUuid::createUuid().toString(QUuid::WithoutBraces))
{
    load();
}

CloudflareAccess *CloudflareAccess::instance()
{
    static auto service = QPointer<CloudflareAccess>();
    if (!service) {
        service = new CloudflareAccess(QCoreApplication::instance());
    }
    return service;
}

bool CloudflareAccess::enabled() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _enabled;
}
bool CloudflareAccess::busy() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _busy;
}
bool CloudflareAccess::ready() const
{
    const auto lock = QMutexLocker(&_mutex);
    return !_enabled || (_ready && (!_browserMode || _expiresAt > QDateTime::currentSecsSinceEpoch()));
}
QUrl CloudflareAccess::serverUrl() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _serverUrl;
}
QString CloudflareAccess::clientId() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _clientId;
}
QString CloudflareAccess::clientSecret() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _clientSecret;
}
QString CloudflareAccess::error() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _browserMode && _ready && _expiresAt <= QDateTime::currentSecsSinceEpoch()
        ? tr("Your Cloudflare Access session expired. Sign in again in Advanced settings.")
        : _error;
}

bool CloudflareAccess::browserMode() const
{
    const auto lock = QMutexLocker(&_mutex);
    return _browserMode;
}

bool CloudflareAccess::hasCredentials(const QNetworkRequest &request)
{
    return request.hasRawHeader("CF-Access-Client-Id"_ba) || request.hasRawHeader("cf-access-token"_ba);
}

QString CloudflareAccess::browserTokenError(const QByteArray &token)
{
    constexpr auto maximumTokenBytes = 16384;
    const auto parts = token.split('.');
    if (token.size() > maximumTokenBytes || parts.size() != 3
        || !QRegularExpression("\\A[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\z"_L1).match(QString::fromLatin1(token)).hasMatch()) {
        return tr("The browser did not return a valid Cloudflare Access session.");
    }
    const auto header = QJsonDocument::fromJson(QByteArray::fromBase64(parts[0], QByteArray::Base64UrlEncoding)).object();
    const auto claims = QJsonDocument::fromJson(QByteArray::fromBase64(parts[1], QByteArray::Base64UrlEncoding)).object();
    const auto issuer = QUrl(claims.value("iss"_L1).toString());
    const auto subject = claims.value("custom"_L1).toObject().value("sairibus_subject"_L1).toString();
    if (header.value("alg"_L1).toString() != "RS256"_L1 || claims.value("type"_L1).toString() != "app"_L1 || issuer.scheme() != "https"_L1
        || !issuer.host().endsWith(".cloudflareaccess.com"_L1) || !issuer.userInfo().isEmpty() || issuer.hasQuery() || issuer.hasFragment()
        || issuer.port(443) != 443 || (!issuer.path().isEmpty() && issuer.path() != "/"_L1) || claims.contains("common_name"_L1)
        || claims.value("sub"_L1).toString().isEmpty() || !QRegularExpression("\\A[0-9a-fA-F-]{36}\\z"_L1).match(subject).hasMatch()) {
        return tr("Sign in with your Sairibus account to connect this device.");
    }
    const auto expiresAt = claims.value("exp"_L1).toInteger();
    if (expiresAt <= QDateTime::currentSecsSinceEpoch()) {
        return tr("Your Cloudflare Access session expired. Sign in again in Advanced settings.");
    }
    // The helper and Cloudflare edge verify signatures. These claims only guide
    // local session lifetime and prevent accidentally switching account identity.
    return {};
}

QUrl CloudflareAccess::origin(const QUrl &url)
{
    if (!url.isValid() || url.host().isEmpty() || (url.scheme() != "https"_L1 && url.scheme() != "wss"_L1)) {
        return {};
    }
    auto result = QUrl();
    result.setScheme("https"_L1);
    result.setHost(url.host());
    if (url.port(443) != 443) {
        result.setPort(url.port());
    }
    return result;
}

bool CloudflareAccess::protects(const QUrl &url) const
{
    const auto lock = QMutexLocker(&_mutex);
    return _enabled && !_serverUrl.isEmpty() && origin(url) == _serverUrl;
}

QString CloudflareAccess::validate(bool enabled, const QString &url, const QString &id, const QString &secret)
{
    if (!enabled) {
        return {};
    }
    const auto parsed = QUrl(url.trimmed(), QUrl::StrictMode);
    if (!parsed.isValid() || parsed.scheme() != "https"_L1 || parsed.host().isEmpty() || parsed.authority().contains(u'@') || parsed.hasQuery()
        || parsed.hasFragment() || parsed.port(443) <= 0) {
        return tr("Enter an HTTPS server URL without a username, password, query, or fragment.");
    }
    const auto validHeader = [](const QString &value) {
        constexpr auto firstVisibleAscii = 0x21;
        constexpr auto lastVisibleAscii = 0x7e;
        return !value.isEmpty() && std::all_of(value.cbegin(), value.cend(), [](const QChar character) {
            return character.unicode() >= firstVisibleAscii && character.unicode() <= lastVisibleAscii;
        });
    };
    if (!validHeader(id) || !validHeader(secret)) {
        return tr("Enter a Client ID and Client Secret containing only visible ASCII characters without spaces.");
    }
    return {};
}

QString CloudflareAccess::prepareRequest(QNetworkRequest &request) const
{
    const auto lock = QMutexLocker(&_mutex);
    auto headers = request.headers();
    headers.removeAll("CF-Access-Client-Id"_L1);
    headers.removeAll("CF-Access-Client-Secret"_L1);
    headers.removeAll("cf-access-token"_L1);
    request.setHeaders(headers);
    request.setAttribute(ConfigurationEpochAttribute, {});
    request.setAttribute(SessionIdentityAttribute, {});
    if (!protects(request.url())) {
        return {};
    }
    if (!ready()) {
        return error().isEmpty() ? tr("Cloudflare Access credentials are still loading.") : error();
    }
    if (_browserMode) {
        request.setRawHeader("cf-access-token"_ba, _browserToken);
    } else {
        request.setRawHeader("CF-Access-Client-Id"_ba, _clientId.toLatin1());
        request.setRawHeader("CF-Access-Client-Secret"_ba, _clientSecret.toLatin1());
    }
    request.setAttribute(ConfigurationEpochAttribute, QVariant::fromValue(_generation));
    request.setAttribute(SessionIdentityAttribute, _instanceId);
    const auto policy = request.attribute(QNetworkRequest::RedirectPolicyAttribute);
    if (policy.isValid() && policy.toInt() != QNetworkRequest::ManualRedirectPolicy) {
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::SameOriginRedirectPolicy);
    }
    return {};
}

bool CloudflareAccess::matchesCurrentRequest(const QNetworkRequest &request) const
{
    const auto lock = QMutexLocker(&_mutex);
    return _enabled && _ready && !_busy && origin(request.url()) == _serverUrl && request.attribute(ConfigurationEpochAttribute).isValid()
        && request.attribute(ConfigurationEpochAttribute).toULongLong() == _generation && request.attribute(SessionIdentityAttribute).toString() == _instanceId;
}

QString CloudflareAccess::credentialKey() const
{
    const auto profile = QFileInfo(_configFile).absoluteFilePath().toUtf8();
    return Theme::instance()->appName() + ":cloudflare-access:"_L1 + QString::fromLatin1(QCryptographicHash::hash(profile, QCryptographicHash::Sha256).toHex())
        + u':' + _scope;
}

void CloudflareAccess::storeCredential(const QString &key, const std::optional<QByteArray> &data, Completion completion)
{
    const auto guard = QPointer<CloudflareAccess>(this);
    const auto generation = _generation;
    const auto writing = data.has_value();
    const auto complete = [guard, generation, key, writing, completion = std::move(completion)](const QByteArray &value, const QString &error) {
        if (!guard) {
            return;
        }
        const auto lock = QMutexLocker(&guard->_mutex);
        if (guard && guard->_generation == generation && guard->_busy) {
            guard->_busy = false;
            completion(value, error);
        } else if (guard && writing && error.isEmpty() && guard->_credentialEntry != key) {
            guard->removeCredential(key);
        }
    };
    QTimer::singleShot(_storageTimeout, this, [complete] {
        complete({}, tr("Timed out accessing Cloudflare Access credentials. Check your system credential store and try again."));
    });
    if (_store) {
        _store(key, data, complete);
    } else if (data) {
        const auto job = new KeychainChunk::WriteJob(key, *data, this);
        connect(job, &KeychainChunk::WriteJob::finished, this, [complete](const auto incoming) {
            complete({},
                     incoming->error() == QKeychain::NoError ? QString{} : tr("Could not save Cloudflare Access credentials in the system credential store."));
        });
        job->start();
    } else {
        const auto job = new KeychainChunk::ReadJob(key, this);
        connect(job, &KeychainChunk::ReadJob::finished, this, [complete](const auto incoming) {
            complete(incoming->binaryData(),
                     incoming->error() == QKeychain::NoError
                         ? QString{}
                         : tr("Could not load Cloudflare Access credentials. Enter the service token again in Advanced settings."));
        });
        job->start();
    }
}

void CloudflareAccess::removeCredential(const QString &key)
{
    if (key.isEmpty()) {
        return;
    }
    if (_store) {
        _store(key, QByteArray{}, [](const QByteArray &, const QString &) { });
    } else {
        const auto job = new KeychainChunk::DeleteJob(key, this);
        job->start();
    }
}

void CloudflareAccess::load()
{
    const auto lock = QMutexLocker(&_mutex);
    ++_generation;
    auto settings = QSettings(_configFile, QSettings::IniFormat);
    settings.beginGroup(_settingsGroup);
    _enabled = settings.value("Enabled"_L1, false).toBool();
    _browserMode = settings.value("BrowserLogin"_L1, false).toBool();
    _browserToken.clear();
    _expiresAt = 0;
    _serverUrl = origin(settings.value("ServerUrl"_L1).toUrl());
    _credentialEntry = settings.value("CredentialKey"_L1).toString();
    _ready = false;
    _busy = true;
    _clientId.clear();
    _clientSecret.clear();
    _error.clear();
    Q_EMIT changed();
    if (_credentialEntry.isEmpty() && !_enabled) {
        _busy = false;
        Q_EMIT changed();
        return;
    }
    storeCredential(_credentialEntry, std::nullopt, [this](const QByteArray &data, const QString &error) {
        const auto token = QJsonDocument::fromJson(data).object();
        _clientId = token.value("id"_L1).toString();
        _clientSecret = token.value("secret"_L1).toString();
        _error = error;
        if (_error.isEmpty()) {
            _browserToken = token.value("token"_L1).toString().toLatin1();
            _error = _browserMode ? browserTokenError(_browserToken) : validate(true, _serverUrl.toString(), _clientId, _clientSecret);
            if (_browserMode && _error.isEmpty()) {
                _expiresAt = QJsonDocument::fromJson(QByteArray::fromBase64(_browserToken.split('.')[1], QByteArray::Base64UrlEncoding))
                                 .object()
                                 .value("exp"_L1)
                                 .toInteger();
            }
            if (token.value("origin"_L1).toString() != _serverUrl.toString()) {
                _error = tr("Cloudflare Access credentials do not match the configured server. Enter the service token again.");
            }
        }
        _ready = _error.isEmpty();
        if (!_ready) {
            _clientId.clear();
            _clientSecret.clear();
        }
        Q_EMIT changed();
        Q_EMIT configurationChanged();
    });
}

void CloudflareAccess::save(bool enabled, const QString &url, const QString &id, const QString &secret, ConfigurationCheck check)
{
    saveToken(enabled, url, id, secret, {}, std::move(check));
}

void CloudflareAccess::saveBrowserToken(const QString &url, const QByteArray &token)
{
    saveToken(true, url, {}, {}, token, {});
}

void CloudflareAccess::cancelPending()
{
    const auto lock = QMutexLocker(&_mutex);
    if (!_busy) {
        return;
    }
    ++_generation;
    _busy = false;
    _error = tr("Browser sign-in was cancelled.");
    Q_EMIT changed();
    Q_EMIT saved(false);
}

void CloudflareAccess::clear()
{
    const auto lock = QMutexLocker(&_mutex);
    const auto cancelled = _busy;
    ++_generation;
    removeCredential(_credentialEntry);
    auto settings = QSettings(_configFile, QSettings::IniFormat);
    settings.remove(_settingsGroup);
    settings.sync();
    _credentialEntry.clear();
    _browserToken.clear();
    _clientId.clear();
    _clientSecret.clear();
    _enabled = _busy = _ready = _browserMode = false;
    _error.clear();
    Q_EMIT changed();
    Q_EMIT configurationChanged();
    if (cancelled) {
        Q_EMIT saved(false);
    }
}

void CloudflareAccess::saveToken(bool enabled,
                                 const QString &url,
                                 const QString &id,
                                 const QString &secret,
                                 const QByteArray &browserToken,
                                 ConfigurationCheck check)
{
    const auto lock = QMutexLocker(&_mutex);
    const auto browser = !browserToken.isEmpty();
    const auto tokenError = browser ? browserTokenError(browserToken) : QString{};
    const auto validation = tokenError.isEmpty() ? validate(enabled, url, browser ? "browser"_L1 : id, browser ? "browser"_L1 : secret) : tokenError;
    if (!validation.isEmpty()) {
        _error = validation;
        Q_EMIT changed();
        Q_EMIT saved(false);
        return;
    }
    const auto server = enabled ? origin(QUrl(url.trimmed())) : _serverUrl;
    if (enabled && _enabled && server != _serverUrl) {
        _error = tr("Only one server can use Cloudflare Access in this profile. Disable the current server's Cloudflare Access setting before replacing it.");
        Q_EMIT changed();
        Q_EMIT saved(false);
        return;
    }
    if (enabled && check) {
        if (const auto compatibilityError = check(server); !compatibilityError.isEmpty()) {
            _error = compatibilityError;
            Q_EMIT changed();
            Q_EMIT saved(false);
            return;
        }
    }
    if (browser && _browserMode && !_browserToken.isEmpty()) {
        const auto subject = [](const QByteArray &value) {
            const auto parts = value.split('.');
            return QJsonDocument::fromJson(QByteArray::fromBase64(parts.value(1), QByteArray::Base64UrlEncoding))
                .object()
                .value("custom"_L1)
                .toObject()
                .value("sairibus_subject"_L1)
                .toString();
        };
        if (subject(browserToken) != subject(_browserToken)) {
            _error = tr("Sign in with the same Sairibus account used when adding this Nextcloud account.");
            Q_EMIT changed();
            Q_EMIT saved(false);
            return;
        }
    }
    const auto payload =
        QJsonDocument(QJsonObject{{"origin"_L1, server.toString()}, {"id"_L1, id}, {"secret"_L1, secret}, {"token"_L1, QString::fromLatin1(browserToken)}})
            .toJson(QJsonDocument::Compact);
    if (enabled && payload.size() > KeychainChunk::ChunkSize * KeychainChunk::MaxChunks) {
        _error = tr("Cloudflare Access credentials are too long for the system credential store.");
        Q_EMIT changed();
        Q_EMIT saved(false);
        return;
    }
    ++_generation;
    _busy = true;
    _error.clear();
    Q_EMIT changed();
    const auto entry = enabled ? credentialKey() + u':' + QUuid::createUuid().toString(QUuid::WithoutBraces) : _credentialEntry;
    const auto persist = [this, enabled, server, id, secret, browserToken, browser, entry, check](const QByteArray &, const QString &error) {
        _error = error;
        if (_error.isEmpty() && enabled && check) {
            _error = check(server);
        }
        if (_error.isEmpty()) {
            auto settings = QSettings(_configFile, QSettings::IniFormat);
            settings.beginGroup(_settingsGroup);
            settings.setValue("Enabled"_L1, enabled);
            settings.setValue("BrowserLogin"_L1, browser);
            if (!server.isEmpty()) {
                settings.setValue("ServerUrl"_L1, server);
            }
            settings.setValue("CredentialKey"_L1, entry);
            settings.sync();
            if (settings.status() != QSettings::NoError) {
                _error = tr("Could not save Cloudflare Access settings.");
            } else {
                _enabled = enabled;
                _serverUrl = server;
                if (enabled) {
                    _clientId = id;
                    _clientSecret = secret;
                    _browserMode = browser;
                    _browserToken = browserToken;
                    _expiresAt = browser ? QJsonDocument::fromJson(QByteArray::fromBase64(browserToken.split('.')[1], QByteArray::Base64UrlEncoding))
                                               .object()
                                               .value("exp"_L1)
                                               .toInteger()
                                         : 0;
                    _ready = true;
                    const auto previous = _credentialEntry;
                    _credentialEntry = entry;
                    if (previous != entry) {
                        removeCredential(previous);
                    }
                }
            }
        }
        if (!_error.isEmpty() && enabled) {
            removeCredential(entry);
        }
        Q_EMIT changed();
        if (_error.isEmpty()) {
            Q_EMIT configurationChanged();
        }
        Q_EMIT saved(_error.isEmpty());
    };
    if (!enabled) {
        _busy = false;
        persist({}, {});
        return;
    }
    storeCredential(entry, payload, persist);
}
}
