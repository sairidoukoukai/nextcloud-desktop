/*
 * SPDX-FileCopyrightText: 2026 Sairibus contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "deviceauthorization.h"

#include "common/utility.h"
#include "theme.h"

#include <QCryptographicHash>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QNetworkReply>
#include <QRandomGenerator>
#include <QTcpSocket>
#include <QUrlQuery>

using namespace Qt::StringLiterals;

namespace OCC
{

Q_LOGGING_CATEGORY(lcDeviceAuthorization, "nextcloud.sync.deviceauthorization", QtInfoMsg)

namespace
{
constexpr auto interactiveTimeout = std::chrono::minutes(10);
constexpr auto silentTimeout = std::chrono::minutes(2);
constexpr auto maximumCallbackBytes = 16384;

QByteArray randomToken(int bytes)
{
    auto data = QByteArray(bytes, Qt::Uninitialized);
    QRandomGenerator::system()->fillRange(reinterpret_cast<quint32 *>(data.data()), bytes / static_cast<int>(sizeof(quint32)));
    return data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
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

}

DeviceAuthorization::DeviceAuthorization(const QUrl &issuer, QObject *parent, BrowserOpener opener)
    : QObject(parent)
    , _issuer(issuer)
    , _opener(opener ? std::move(opener) : BrowserOpener([](const QUrl &url) {
        return QDesktopServices::openUrl(url);
    }))
{
    _network.setRedirectPolicy(QNetworkRequest::ManualRedirectPolicy);
    _timeout.setSingleShot(true);
    connect(&_timeout, &QTimer::timeout, this, [this] {
        finish(Outcome::Failed, tr("The browser sign-in timed out. Try again when you are ready."));
    });
    connect(&_server, &QTcpServer::newConnection, this, [this] {
        while (const auto socket = _server.nextPendingConnection()) {
            connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
                readCallback(socket);
            });
        }
    });
}

DeviceAuthorization::~DeviceAuthorization()
{
    _busy = false;
    if (_exchange) {
        _exchange->abort();
    }
}

bool DeviceAuthorization::busy() const
{
    return _busy;
}

DeviceTokens DeviceAuthorization::tokens() const
{
    return _tokens;
}

QString DeviceAuthorization::error() const
{
    return _error;
}

void DeviceAuthorization::start(Grant grant, bool silent)
{
    if (_busy) {
        return;
    }
    _grant = grant;
    _tokens = {};
    _error.clear();
    _callbackReceived = false;
    _verifier = randomToken(48);
    _state = randomToken(24);
    if (!_server.listen(QHostAddress::LocalHost, 0)) {
        _error = tr("Could not prepare the browser sign-in on this computer.");
        Q_EMIT finished(Outcome::Failed);
        return;
    }
    _redirectUri = QUrl(u"http://127.0.0.1:%1/"_s.arg(_server.serverPort()));
    auto fields = QList<std::pair<QByteArray, QByteArray>>{
        {"client_id", DeviceSession::ClientId},
        {"redirect_uri", _redirectUri.toString().toLatin1()},
        {"response_type", "code"},
        {"scope", grant == Grant::Offline ? "openid offline_access" : "openid"},
        {"state", _state},
        {"code_challenge", QCryptographicHash::hash(_verifier, QCryptographicHash::Sha256).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)},
        {"code_challenge_method", "S256"},
    };
    if (silent) {
        fields.emplaceBack("prompt", "none");
    }
    auto url = _issuer;
    url.setPath(_issuer.path() + "/protocol/openid-connect/auth"_L1);
    url.setQuery(QString::fromLatin1(formBody(fields)), QUrl::TolerantMode);
    _busy = true;
    _timeout.start(silent ? std::chrono::milliseconds(silentTimeout) : std::chrono::milliseconds(interactiveTimeout));
    qCInfo(lcDeviceAuthorization) << "Opening the browser for" << (grant == Grant::Offline ? "an offline" : "an online") << "grant" << (silent ? "without a prompt" : "");
    if (!_opener(url)) {
        finish(Outcome::Failed, tr("Could not open the browser. Check the default browser setting and try again."));
    }
}

void DeviceAuthorization::cancel()
{
    if (_busy) {
        finish(Outcome::Failed, tr("The browser sign-in was cancelled."));
    }
}

void DeviceAuthorization::respond(QTcpSocket *socket, int status, const QString &message)
{
    const auto title = Theme::instance()->appNameGUI().toHtmlEscaped();
    const auto body = QString(u"<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta name=\"color-scheme\" content=\"light dark\">"
                              "<title>%1</title></head><body style=\"font-family:system-ui,sans-serif;margin:3em auto;max-width:32em;padding:0 1em\">"
                              "<p>%2</p></body></html>"_s)
                          .arg(title, message.toHtmlEscaped())
                          .toUtf8();
    const auto reason = status == 200 ? "OK"_ba : (status == 400 ? "Bad Request"_ba : "Not Found"_ba);
    socket->write("HTTP/1.1 " + QByteArray::number(status) + ' ' + reason
                  + "\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: "
                  + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body);
    socket->disconnectFromHost();
}

void DeviceAuthorization::readCallback(QTcpSocket *socket)
{
    QByteArray data = socket->property("request").toByteArray() + socket->readAll();
    if (data.size() > maximumCallbackBytes) {
        socket->abort();
        return;
    }
    socket->setProperty("request", data);
    const auto end = data.indexOf("\r\n");
    if (end < 0 || !data.contains("\r\n\r\n")) {
        return;
    }
    const auto line = data.first(end).split(' ');
    const auto target = line.size() == 3 && line[0] == "GET" ? QUrl(u"http://127.0.0.1"_s + QString::fromLatin1(line[1])) : QUrl();
    if (!_busy || _callbackReceived || !target.isValid() || target.path() != "/"_L1) {
        respond(socket, 404, tr("Nothing to see here."));
        return;
    }
    const auto query = QUrlQuery(target);
    // A stray request without this sign-in's state cannot end it.
    if (query.queryItemValue(u"state"_s, QUrl::FullyDecoded).toLatin1() != _state) {
        respond(socket, 400, tr("This sign-in link has expired. Return to the app and try again."));
        return;
    }
    _callbackReceived = true;
    _server.close();
    const auto error = query.queryItemValue(u"error"_s, QUrl::FullyDecoded);
    const auto code = query.queryItemValue(u"code"_s, QUrl::FullyDecoded).toLatin1();
    if (!error.isEmpty() || code.isEmpty()) {
        const auto loginRequired = error == "login_required"_L1;
        respond(socket,
                200,
                loginRequired ? tr("Continue in the browser window that opens next.") : tr("The sign-in did not finish. Return to the app and try again."));
        qCInfo(lcDeviceAuthorization) << "The browser returned" << (error.isEmpty() ? u"no code"_s : error);
        finish(loginRequired ? Outcome::LoginRequired : Outcome::Failed, tr("The sign-in did not finish. Try again."));
        return;
    }
    respond(socket, 200, tr("Signed in. You can close this tab and return to %1.").arg(Theme::instance()->appNameGUI()));
    exchange(code);
}

void DeviceAuthorization::exchange(const QByteArray &code)
{
    auto url = _issuer;
    url.setPath(_issuer.path() + "/protocol/openid-connect/token"_L1);
    auto request = QNetworkRequest(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded"_ba);
    request.setHeader(QNetworkRequest::UserAgentHeader, Utility::userAgentString());
    request.setRawHeader("Accept"_ba, "application/json"_ba);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setTransferTimeout(std::chrono::seconds(30));
    _exchange = _network.post(request,
                              formBody({{"grant_type", "authorization_code"},
                                        {"client_id", DeviceSession::ClientId},
                                        {"code", code},
                                        {"redirect_uri", _redirectUri.toString().toLatin1()},
                                        {"code_verifier", _verifier}}));
    connect(_exchange, &QNetworkReply::finished, this, [this, reply = _exchange.data()] {
        reply->deleteLater();
        if (!_busy) {
            return;
        }
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        auto parseError = QString();
        const auto tokens = status == 200 ? DeviceTokens::parse(reply->readAll(), &parseError) : std::nullopt;
        if (!tokens) {
            qCWarning(lcDeviceAuthorization) << "The code exchange failed" << status << reply->error() << parseError;
            finish(Outcome::Failed, tr("The sign-in service did not complete the sign-in. Try again."));
            return;
        }
        if (_grant == Grant::Offline && (tokens->refreshToken.isEmpty() || !tokens->offline())) {
            finish(Outcome::Failed, tr("The sign-in did not grant offline access for this computer."));
            return;
        }
        _tokens = *tokens;
        finish(Outcome::Succeeded);
    });
}

void DeviceAuthorization::finish(Outcome outcome, const QString &error)
{
    if (!_busy) {
        return;
    }
    _busy = false;
    _timeout.stop();
    _server.close();
    if (_exchange) {
        _exchange->abort();
    }
    _verifier.clear();
    _state.clear();
    _error = error;
    Q_EMIT finished(outcome);
}

DeviceEnrollment::DeviceEnrollment(DeviceSession *session, QObject *parent, DeviceAuthorization::BrowserOpener opener)
    : QObject(parent)
    , _session(session)
    , _authorization(new DeviceAuthorization(session->endpoints().issuer, this, std::move(opener)))
{
    connect(_authorization, &DeviceAuthorization::finished, this, &DeviceEnrollment::authorizationFinished);
}

bool DeviceEnrollment::busy() const
{
    return _phase != Phase::Idle;
}

DeviceSession *DeviceEnrollment::session() const
{
    return _session;
}

void DeviceEnrollment::signInOnline()
{
    if (busy()) {
        return;
    }
    _phase = Phase::Online;
    _authorization->start(DeviceAuthorization::Grant::Online, false);
}

void DeviceEnrollment::completeOffline(Prompt prompt)
{
    if (busy()) {
        return;
    }
    const auto silent = prompt != Prompt::Always;
    _phase = silent ? Phase::SilentOffline : Phase::InteractiveOffline;
    _promptIfNeeded = prompt == Prompt::IfNeeded;
    _authorization->start(DeviceAuthorization::Grant::Offline, silent);
}

void DeviceEnrollment::cancel()
{
    if (_phase == Phase::Idle) {
        return;
    }
    _phase = Phase::Idle;
    _authorization->cancel();
}

void DeviceEnrollment::authorizationFinished(DeviceAuthorization::Outcome outcome)
{
    const auto phase = std::exchange(_phase, Phase::Idle);
    if (phase == Phase::Idle) {
        return;
    }
    if (!_session) {
        Q_EMIT failed(tr("The account was removed."));
        return;
    }
    if (outcome == DeviceAuthorization::Outcome::LoginRequired && phase == Phase::SilentOffline && _promptIfNeeded) {
        // The browser has no session any more; ask again with a sign-in page.
        _phase = Phase::InteractiveOffline;
        _authorization->start(DeviceAuthorization::Grant::Offline, false);
        return;
    }
    if (outcome != DeviceAuthorization::Outcome::Succeeded) {
        Q_EMIT failed(_authorization->error());
        return;
    }
    if (_session->subjectUsedElsewhere(DeviceSession::subjectOf(_authorization->tokens()))) {
        // One member, one account per computer: two accounts would share one offline session.
        Q_EMIT failed(tr("This club account is already connected on this computer. Sign out of it in the browser to add another account."));
        return;
    }
    if (phase == Phase::Online) {
        _session->adoptOnline(_authorization->tokens());
        Q_EMIT onlineSignedIn();
        return;
    }
    _phase = Phase::Storing;
    _session->adoptOffline(_authorization->tokens(), [this, guard = QPointer<DeviceEnrollment>(this)](bool success, const QString &error) {
        if (!guard || _phase != Phase::Storing) {
            return;
        }
        _phase = Phase::Idle;
        if (success) {
            Q_EMIT offlineReady();
        } else {
            Q_EMIT failed(error);
        }
    });
}

}
