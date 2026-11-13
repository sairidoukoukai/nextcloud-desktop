/*
 * SPDX-FileCopyrightText: 2026 Sairibus contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "devicesession.h"

#include <QByteArray>
#include <QCryptographicHash>
#include <QHash>
#include <QSet>
#include <QStringList>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>
#include <QUrlQuery>

#include <functional>
#include <optional>

namespace OCC::Test
{

using namespace Qt::StringLiterals;

struct HttpRequest {
    QByteArray method;
    QUrl url;
    QMap<QByteArray, QByteArray> headers; // lower-case names
    QByteArray body;
    QByteArray raw;

    [[nodiscard]] QString path() const
    {
        return url.path();
    }
    [[nodiscard]] QByteArray header(const QByteArray &name) const
    {
        return headers.value(name.toLower());
    }
    [[nodiscard]] bool hasHeader(const QByteArray &name) const
    {
        return headers.contains(name.toLower());
    }
    [[nodiscard]] QString form(const QString &name) const
    {
        auto copy = body;
        copy.replace('+', ' ');
        return QUrlQuery(QString::fromLatin1(copy)).queryItemValue(name, QUrl::FullyDecoded);
    }
};

struct HttpResponse {
    int status = 200;
    QByteArray body;
    QList<std::pair<QByteArray, QByteArray>> headers;
    bool drop = false; ///< Closes the connection without a response.

    static HttpResponse json(int status, const QJsonObject &object)
    {
        return {status, QJsonDocument(object).toJson(QJsonDocument::Compact), {{"Content-Type", "application/json"}}};
    }
};

/** A plain HTTP/1.1 server on 127.0.0.1 that records requests. A handler may defer its answer. */
class HttpTestServer : public QTcpServer
{
public:
    using Handler = std::function<std::optional<HttpResponse>(const HttpRequest &, QTcpSocket *)>;
    Handler handler;
    QList<HttpRequest> requests;

    HttpTestServer()
    {
        connect(this, &QTcpServer::pendingConnectionAvailable, this, [this] {
            while (const auto socket = nextPendingConnection()) {
                connect(socket, &QAbstractSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QIODevice::readyRead, socket, [this, socket] {
                    read(socket);
                });
            }
        });
        static_cast<void>(listen(QHostAddress::LocalHost));
    }

    [[nodiscard]] QUrl url(const QString &path = {}) const
    {
        auto result = QUrl(QStringLiteral("http://127.0.0.1:%1").arg(serverPort()));
        result.setPath(path);
        return result;
    }

    [[nodiscard]] QList<HttpRequest> requestsTo(const QString &path) const
    {
        auto matching = QList<HttpRequest>();
        for (const auto &request : requests) {
            if (request.path() == path) {
                matching.append(request);
            }
        }
        return matching;
    }

    static void reply(QTcpSocket *socket, const HttpResponse &response)
    {
        if (!socket) {
            return;
        }
        if (response.drop) {
            socket->abort();
            return;
        }
        QByteArray data = "HTTP/1.1 " + QByteArray::number(response.status) + " Test\r\n";
        for (const auto &[name, value] : response.headers) {
            data += name + ": " + value + "\r\n";
        }
        data += "Content-Length: " + QByteArray::number(response.body.size()) + "\r\nConnection: close\r\n\r\n" + response.body;
        socket->write(data);
        socket->disconnectFromHost();
    }

private:
    void read(QTcpSocket *socket)
    {
        QByteArray data = socket->property("request").toByteArray() + socket->readAll();
        socket->setProperty("request", data);
        const auto end = data.indexOf("\r\n\r\n");
        if (end < 0 || socket->property("complete").toBool()) {
            return;
        }
        auto request = HttpRequest();
        const auto lines = data.first(end).split('\n');
        const auto requestLine = lines.value(0).trimmed().split(' ');
        request.method = requestLine.value(0);
        request.url = url().resolved(QUrl(QString::fromLatin1(requestLine.value(1))));
        auto length = 0;
        for (const auto &line : lines.mid(1)) {
            const auto colon = line.indexOf(':');
            if (colon > 0) {
                const auto name = line.first(colon).trimmed().toLower();
                const auto value = line.mid(colon + 1).trimmed();
                request.headers.insert(name, value);
                if (name == "content-length") {
                    length = value.toInt();
                }
            }
        }
        if (data.size() < end + 4 + length) {
            return;
        }
        socket->setProperty("complete", true);
        request.body = data.mid(end + 4, length);
        request.raw = data;
        requests.append(request);
        if (const auto response = handler ? handler(request, socket) : std::optional<HttpResponse>(HttpResponse{404, {}, {}})) {
            reply(socket, *response);
        }
    }
};

inline const auto deviceTestAppPassword = QString(72, u'A');

inline QByteArray jwt(int number)
{
    return "eyJhbGciOiJSUzI1NiJ9."_ba
        + QJsonDocument(QJsonObject{{u"n"_s, number}}).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)
        + ".c2lnbmF0dXJl"_ba;
}

inline QByteArray jwtFor(const QString &subject)
{
    return "eyJhbGciOiJSUzI1NiJ9."_ba
        + QJsonDocument(QJsonObject{{u"sub"_s, subject}}).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)
        + ".c2lnbmF0dXJl"_ba;
}

inline HttpResponse bearerChallenge()
{
    return {401, "Device sign-in required", {{"WWW-Authenticate", R"(Bearer realm="nc.sairibus.com", error="invalid_token")"}}};
}

/** The club's Keycloak realm as far as the desktop client uses it. */
class FakeIdentity
{
public:
    struct Code {
        QString scope;
        QByteArray challenge;
        QString redirect;
    };

    HttpTestServer server;
    QStringList *log;
    bool browserSession = false;
    int issued = 0;
    int lifetime = 300;
    QSet<QByteArray> accessTokens;
    QSet<QByteArray> refreshTokens;
    QHash<QByteArray, QString> refreshScopes;
    QHash<QByteArray, Code> codes;
    QByteArray lastAccess;
    QByteArray lastRefresh;
    QList<QByteArray> revoked;
    HttpTestServer::Handler refreshOverride;

    explicit FakeIdentity(QStringList *eventLog)
        : log(eventLog)
    {
        server.handler = [this](const HttpRequest &request, QTcpSocket *socket) {
            return handle(request, socket);
        };
    }

    [[nodiscard]] QUrl issuer() const
    {
        return server.url(u"/realms/sairibus"_s);
    }
    [[nodiscard]] QString endpoint(const QString &name) const
    {
        return issuer().path() + "/protocol/openid-connect/"_L1 + name;
    }

    void seed(const QByteArray &refresh, const QString &scope = u"openid offline_access"_s)
    {
        refreshTokens.insert(refresh);
        refreshScopes.insert(refresh, scope);
    }

    HttpResponse issue(const QString &scope)
    {
        ++issued;
        lastAccess = jwt(issued);
        lastRefresh = "refresh-" + QByteArray::number(issued) + (scope.contains("offline_access"_L1) ? "-offline" : "");
        accessTokens.insert(lastAccess);
        seed(lastRefresh, scope);
        return HttpResponse::json(200,
                                  {{u"access_token"_s, QString::fromLatin1(lastAccess)},
                                   {u"token_type"_s, u"Bearer"_s},
                                   {u"expires_in"_s, lifetime},
                                   {u"refresh_token"_s, QString::fromLatin1(lastRefresh)},
                                   {u"scope"_s, scope}});
    }

    HttpResponse rotate(const QByteArray &token)
    {
        if (!refreshTokens.remove(token)) {
            return HttpResponse::json(400, {{u"error"_s, u"invalid_grant"_s}});
        }
        return issue(refreshScopes.value(token));
    }

    std::optional<HttpResponse> handle(const HttpRequest &request, QTcpSocket *socket)
    {
        if (request.form(u"client_id"_s) != "nextcloud-desktop"_L1) {
            return HttpResponse::json(400, {{u"error"_s, u"invalid_client"_s}});
        }
        if (request.path() == endpoint(u"token"_s) && request.form(u"grant_type"_s) == "authorization_code"_L1) {
            const auto code = codes.take(request.form(u"code"_s).toLatin1());
            const auto challenge = QCryptographicHash::hash(request.form(u"code_verifier"_s).toLatin1(), QCryptographicHash::Sha256)
                                       .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
            if (code.scope.isEmpty() || challenge != code.challenge || request.form(u"redirect_uri"_s) != code.redirect) {
                return HttpResponse::json(400, {{u"error"_s, u"invalid_grant"_s}});
            }
            log->append(u"idp:code "_s + code.scope);
            return issue(code.scope);
        }
        if (request.path() == endpoint(u"token"_s) && request.form(u"grant_type"_s) == "refresh_token"_L1) {
            log->append(u"idp:refresh "_s + request.form(u"refresh_token"_s));
            if (refreshOverride) {
                return refreshOverride(request, socket);
            }
            return rotate(request.form(u"refresh_token"_s).toLatin1());
        }
        if (request.path() == endpoint(u"revoke"_s)) {
            log->append(u"idp:revoke "_s + request.form(u"token"_s));
            revoked.append(request.form(u"token"_s).toLatin1());
            refreshTokens.remove(revoked.last());
            return HttpResponse{200, {}, {}};
        }
        return HttpResponse{404, {}, {}};
    }

    /** What the member's browser receives from the authorization endpoint. */
    QUrl authorize(const QUrl &url)
    {
        const auto query = QUrlQuery(url);
        const auto scope = query.queryItemValue(u"scope"_s, QUrl::FullyDecoded);
        const auto prompt = query.queryItemValue(u"prompt"_s, QUrl::FullyDecoded);
        log->append(u"browser:auth "_s + scope + (prompt.isEmpty() ? QString{} : u" prompt="_s + prompt));
        auto redirect = QUrl(query.queryItemValue(u"redirect_uri"_s, QUrl::FullyDecoded));
        auto result = QUrlQuery();
        result.addQueryItem(u"state"_s, query.queryItemValue(u"state"_s, QUrl::FullyDecoded));
        if (query.queryItemValue(u"client_id"_s) != "nextcloud-desktop"_L1 || query.queryItemValue(u"code_challenge_method"_s) != "S256"_L1
            || redirect.host() != "127.0.0.1"_L1 || redirect.path() != "/"_L1) {
            result.addQueryItem(u"error"_s, u"invalid_request"_s);
        } else if (prompt == "none"_L1 && !browserSession) {
            result.addQueryItem(u"error"_s, u"login_required"_s);
        } else {
            browserSession = true;
            const auto code = "code-" + QByteArray::number(codes.size() + issued + 1);
            codes.insert(code, {scope, query.queryItemValue(u"code_challenge"_s).toLatin1(), redirect.toString()});
            result.addQueryItem(u"code"_s, QString::fromLatin1(code));
        }
        redirect.setQuery(result);
        return redirect;
    }
};

/** The club's Nextcloud behind its gateway, with Login Flow V2. */
class FakeNextcloud
{
public:
    HttpTestServer server;
    QStringList *log;
    FakeIdentity *identity;
    bool granted = false;
    bool issued = false;
    HttpTestServer::Handler other;

    FakeNextcloud(QStringList *eventLog, FakeIdentity *provider)
        : log(eventLog)
        , identity(provider)
    {
        server.handler = [this](const HttpRequest &request, QTcpSocket *socket) -> std::optional<HttpResponse> {
            const auto token = request.header(DeviceSession::TokenHeader);
            if (request.path() == "/index.php/login/v2"_L1) {
                log->append(u"nc:login"_s);
                if (!identity->accessTokens.contains(token)) {
                    return bearerChallenge();
                }
                return HttpResponse::json(200,
                                          {{u"poll"_s, QJsonObject{{u"token"_s, u"poll-token"_s}, {u"endpoint"_s, server.url(u"/login/v2/poll"_s).toString()}}},
                                           {u"login"_s, server.url(u"/login/v2/flow/flow-token"_s).toString()}});
            }
            if (request.path() == "/login/v2/poll"_L1) {
                if (!identity->accessTokens.contains(token)) {
                    log->append(u"nc:poll bearer"_s);
                    return bearerChallenge();
                }
                if (issued) {
                    return HttpResponse{403, {}, {}};
                }
                if (!granted || request.form(u"token"_s) != "poll-token"_L1) {
                    log->append(u"nc:poll pending"_s);
                    return HttpResponse{404, {}, {}};
                }
                issued = true;
                log->append(u"nc:poll granted"_s);
                return HttpResponse::json(200, {{u"server"_s, server.url().toString()}, {u"loginName"_s, u"u123456a"_s}, {u"appPassword"_s, deviceTestAppPassword}});
            }
            return other ? other(request, socket) : HttpResponse{404, {}, {}};
        };
    }
};

}
