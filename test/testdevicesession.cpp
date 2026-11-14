/*
 * SPDX-FileCopyrightText: 2026 Sairibus contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accessmanager.h"
#include "account.h"
#include "gui/creds/httpcredentialsgui.h"
#include "gui/creds/webflowcredentials.h"
#include "deviceauthorization.h"
#include "devicesession.h"
#include "devicetestserver.h"
#include "gui/creds/flow2auth.h"
#include "httplogger.h"
#include "networkjobs.h"

#include <QCryptographicHash>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QScopeGuard>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTest>
#include <QTimer>
#include <QApplication>
#include <QMutex>

#include <cstdio>

using namespace OCC;
using namespace OCC::Test;
using namespace Qt::StringLiterals;

namespace
{

constexpr auto flowTimeout = 30000;
const auto appPassword = deviceTestAppPassword;

using Store = QHash<QString, QByteArray>;

DeviceSession::CredentialStore memoryStore(Store &entries, QStringList *log = nullptr)
{
    return [&entries, log](const QString &key, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
        if (data && data->isEmpty()) {
            entries.remove(key);
            if (log) {
                log->append(u"store:delete"_s);
            }
        } else if (data) {
            entries.insert(key, *data);
            if (log) {
                log->append(u"store:write "_s + QJsonDocument::fromJson(*data).object().value("refresh_token"_L1).toString());
            }
        }
        done(entries.value(key), {});
    };
}

QString storedRefreshToken(const Store &entries)
{
    return entries.isEmpty() ? QString{} : QJsonDocument::fromJson(entries.cbegin().value()).object().value("refresh_token"_L1).toString();
}

DeviceTokens seededTokens(const QByteArray &access, const QByteArray &refresh, qint64 lifetime = 300)
{
    auto tokens = DeviceTokens();
    tokens.accessToken = access;
    tokens.refreshToken = refresh;
    tokens.expiresAt = QDateTime::currentSecsSinceEpoch() + lifetime;
    tokens.scopes = {u"openid"_s, u"offline_access"_s};
    return tokens;
}

}

/** The member's default browser. */
class FakeBrowser : public QObject
{
    Q_OBJECT

public:
    FakeIdentity *identity = nullptr;
    FakeNextcloud *nextcloud = nullptr;
    QStringList *log = nullptr;
    QNetworkAccessManager network;

public Q_SLOTS:
    void open(const QUrl &url)
    {
        if (url.path().endsWith("/protocol/openid-connect/auth"_L1)) {
            const auto callback = identity->authorize(url);
            QTimer::singleShot(0, this, [this, callback] {
                const auto reply = network.get(QNetworkRequest(callback));
                connect(reply, &QNetworkReply::finished, reply, &QObject::deleteLater);
            });
        } else if (url.path().startsWith("/login/v2/flow/"_L1)) {
            log->append(u"browser:flow"_s);
            // Nextcloud's own sign-in reuses the identity provider's browser session.
            nextcloud->granted = identity->browserSession;
            // The online token lapses while the member approves the device.
            identity->accessTokens.clear();
        } else {
            log->append(u"browser:other "_s + url.toString());
        }
    }
};

class TestDeviceSession : public QObject
{
    Q_OBJECT

    QStringList _log;
    Store _store;
    std::unique_ptr<FakeIdentity> _identity;
    std::unique_ptr<FakeNextcloud> _nextcloud;
    FakeBrowser _browser;

    AccountPtr createAccount(AbstractCredentials *credentials = new WebFlowCredentials)
    {
        auto account = Account::create();
        account->setUrl(_nextcloud->server.url());
        account->setCredentials(credentials);
        account->deviceSession()->setCredentialStore(memoryStore(_store, &_log));
        return account;
    }

    std::unique_ptr<DeviceSession> offlineSession(const QByteArray &refresh = "refresh-seed"_ba, qint64 lifetime = 300)
    {
        auto session = std::make_unique<DeviceSession>(nullptr, memoryStore(_store, &_log));
        session->setStorageKey([] {
            return u"test-entry"_s;
        });
        _identity->seed(refresh);
        _identity->accessTokens.insert(jwt(1000));
        auto stored = false;
        session->adoptOffline(seededTokens(jwt(1000), refresh, lifetime), [&stored](bool success, const QString &) {
            stored = success;
        });
        [&] {
            QVERIFY(stored);
        }();
        return session;
    }

    static QByteArray headerFor(DeviceSession &session, const QUrl &url)
    {
        auto request = QNetworkRequest(url);
        session.decorate(request);
        return request.rawHeader(DeviceSession::TokenHeader);
    }

private Q_SLOTS:
    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
        QDesktopServices::setUrlHandler(u"http"_s, &_browser, "open");
    }

    void cleanupTestCase()
    {
        QDesktopServices::unsetUrlHandler(u"http"_s);
    }

    void init()
    {
        _log.clear();
        _store.clear();
        _identity = std::make_unique<FakeIdentity>(&_log);
        _nextcloud = std::make_unique<FakeNextcloud>(&_log, _identity.get());
        QVERIFY(_identity->server.isListening());
        QVERIFY(_nextcloud->server.isListening());
        _browser.identity = _identity.get();
        _browser.nextcloud = _nextcloud.get();
        _browser.log = &_log;
        DeviceSession::setDefaultEndpoints({_nextcloud->server.url(), _identity->issuer()});
    }

    void signInRunsOnlineThenLoginFlowThenOfflineGrant_data()
    {
        QTest::addColumn<bool>("browserSessionEnded");
        QTest::newRow("browser session kept") << false;
        QTest::newRow("login_required falls back to a sign-in page") << true;
    }

    void signInRunsOnlineThenLoginFlowThenOfflineGrant()
    {
        QFETCH(bool, browserSessionEnded);
        const auto account = createAccount();
        const auto session = account->deviceSession();
        DeviceEnrollment enrollment(session);
        QSignalSpy online(&enrollment, &DeviceEnrollment::onlineSignedIn);
        QSignalSpy offline(&enrollment, &DeviceEnrollment::offlineReady);
        QSignalSpy failed(&enrollment, &DeviceEnrollment::failed);

        // Step 1: an online grant, kept in memory.
        enrollment.signInOnline();
        QTRY_COMPARE(online.size(), 1);
        QCOMPARE(session->status(), DeviceSession::Status::Online);
        QVERIFY(_store.isEmpty());

        // Step 2: Login Flow V2 with the online token; the browser step uses the same browser session.
        Flow2Auth flow(account.data(), nullptr);
        QSignalSpy result(&flow, &Flow2Auth::result);
        flow.start();
        QTRY_COMPARE_WITH_TIMEOUT(result.size(), 1, flowTimeout);
        QVERIFY2(result[0][0].value<Flow2Auth::Result>() == Flow2Auth::LoggedIn, qPrintable(result[0][1].toString() + u" | "_s + _log.join(u", "_s)));
        QCOMPARE(result[0][2].toString(), u"u123456a"_s);
        QCOMPARE(result[0][3].toString(), appPassword);
        const auto initiation = _nextcloud->server.requestsTo(u"/index.php/login/v2"_s);
        QCOMPARE(initiation.size(), 1);
        QCOMPARE(initiation[0].header(DeviceSession::TokenHeader), jwt(1));
        QVERIFY(!initiation[0].hasHeader("authorization"));
        QVERIFY(!initiation[0].hasHeader("cookie"));
        for (const auto &poll : _nextcloud->server.requestsTo(u"/login/v2/poll"_s)) {
            QVERIFY(poll.hasHeader(DeviceSession::TokenHeader));
            QVERIFY(!poll.hasHeader("authorization"));
            QVERIFY(!poll.hasHeader("cookie"));
        }
        // The online token lapsed during polling and was renewed from the online grant.
        QVERIFY(_log.contains(u"nc:poll bearer"_s));
        QVERIFY(_log.contains(u"idp:refresh refresh-1"_s));
        QVERIFY(_store.isEmpty());

        // Step 3: the offline grant, silently when the browser session survived.
        if (browserSessionEnded) {
            _identity->browserSession = false;
        }
        enrollment.completeOffline();
        QTRY_COMPARE(offline.size(), 1);
        QCOMPARE(failed.size(), 0);

        const auto stepOne = _log.indexOf(u"browser:auth openid"_s);
        const auto stepTwo = _log.indexOf(u"nc:login"_s);
        const auto browserStep = _log.indexOf(u"browser:flow"_s);
        const auto stepThree = _log.indexOf(u"browser:auth openid offline_access prompt=none"_s);
        QVERIFY2(stepOne >= 0 && stepOne < stepTwo && stepTwo < browserStep && browserStep < stepThree, qPrintable(_log.join(u", "_s)));
        QCOMPARE(_log.contains(u"browser:auth openid offline_access"_s), browserSessionEnded);
        QCOMPARE(_log.count(u"idp:code openid offline_access"_s), 1);
        // Nothing reached the credential store before the offline grant.
        QVERIFY(_log.indexOf(QRegularExpression(u"^store:.*"_s)) > stepThree);

        QCOMPARE(session->status(), DeviceSession::Status::Offline);
        QVERIFY(storedRefreshToken(_store).endsWith("-offline"_L1));
        QCOMPARE(storedRefreshToken(_store).toLatin1(), _identity->lastRefresh);
        QCOMPARE(headerFor(*session, _nextcloud->server.url(u"/status.php"_s)), _identity->lastAccess);

        // The step-1 grant is gone: renewals use the account's own offline session.
        QSignalSpy refreshed(session, &DeviceSession::tokenRefreshed);
        session->refresh();
        QTRY_COMPARE(refreshed.size(), 1);
        const auto renewal = _log.filter(u"idp:refresh"_s).last();
        QVERIFY2(renewal.endsWith("-offline"_L1), qPrintable(renewal));
    }

    void offlineGrantWithoutPromptLeavesTheSignInToTheMember()
    {
        const auto account = createAccount();
        DeviceEnrollment enrollment(account->deviceSession());
        QSignalSpy offline(&enrollment, &DeviceEnrollment::offlineReady);
        QSignalSpy failed(&enrollment, &DeviceEnrollment::failed);
        _identity->browserSession = false;

        enrollment.completeOffline(DeviceEnrollment::Prompt::Never);
        QTRY_COMPARE(failed.size(), 1);
        QCOMPARE(offline.size(), 0);
        QVERIFY(!enrollment.busy());
        // No sign-in page opened.
        QCOMPARE(_log.filter(u"browser:auth"_s), QStringList{u"browser:auth openid offline_access prompt=none"_s});
        QVERIFY(_store.isEmpty());
    }

    void refreshesOneAtATimeAndStoresTheRotatedTokenFirst()
    {
        auto session = offlineSession();
        const auto server = _nextcloud->server.url(u"/remote.php/dav/files/u123456a"_s);
        auto held = QList<std::pair<QPointer<QTcpSocket>, QByteArray>>();
        _identity->refreshOverride = [&held](const HttpRequest &request, QTcpSocket *socket) -> std::optional<HttpResponse> {
            held.append({socket, request.form(u"refresh_token"_s).toLatin1()});
            return std::nullopt;
        };
        auto pendingWrite = DeviceSession::Completion();
        auto written = QByteArray();
        session->setCredentialStore([&](const QString &, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
            written = data.value_or(QByteArray{});
            pendingWrite = std::move(done);
        });

        auto results = QList<bool>();
        for (auto i = 0; i < 3; ++i) {
            session->refreshThen(this, [&results](bool success) {
                results.append(success);
            });
        }
        session->refresh();
        session->ensureFresh();
        QTRY_COMPARE(held.size(), 1);
        QTest::qWait(200);
        QCOMPARE(_identity->server.requestsTo(_identity->endpoint(u"token"_s)).size(), 1);
        QCOMPARE(held[0].second, "refresh-seed"_ba);

        HttpTestServer::reply(held[0].first, _identity->rotate(held[0].second));
        QTRY_VERIFY(pendingWrite);
        // The rotated token reaches the store before the new access token is used.
        QCOMPARE(QJsonDocument::fromJson(written).object().value("refresh_token"_L1).toString().toLatin1(), _identity->lastRefresh);
        QCOMPARE(headerFor(*session, server), jwt(1000));
        QVERIFY(results.isEmpty());
        std::exchange(pendingWrite, {})({}, {});
        QCOMPARE(results, (QList<bool>{true, true, true}));
        QCOMPARE(headerFor(*session, server), _identity->lastAccess);

        // The next renewal sends the rotated token; the spent one is never sent again.
        const auto rotated = _identity->lastRefresh;
        session->refresh();
        QTRY_COMPARE(held.size(), 2);
        QCOMPARE(held[1].second, rotated);

        // A failed store write keeps the access token unused and the rotated token in memory.
        HttpTestServer::reply(held[1].first, _identity->rotate(held[1].second));
        QTRY_VERIFY(pendingWrite);
        const auto unsaved = _identity->lastRefresh;
        QSignalSpy failed(session.get(), &DeviceSession::refreshFailed);
        std::exchange(pendingWrite, {})({}, u"synthetic store failure"_s);
        QCOMPARE(failed.size(), 1);
        QVERIFY(headerFor(*session, server) != _identity->lastAccess);
        session->networkChanged();
        QTRY_COMPARE(held.size(), 3);
        QCOMPARE(held[2].second, unsaved);
        HttpTestServer::reply(held[2].first, _identity->rotate(held[2].second));
        QTRY_VERIFY(pendingWrite);
        std::exchange(pendingWrite, {})({}, {});
        QCOMPARE(headerFor(*session, server), _identity->lastAccess);
        for (const auto &request : _identity->server.requests) {
            QVERIFY(!request.raw.contains(DeviceSession::TokenHeader));
        }
    }

    void refreshErrorsKeepOrEndTheSession_data()
    {
        QTest::addColumn<int>("status");
        QTest::addColumn<QByteArray>("error");
        QTest::addColumn<bool>("ends");
        QTest::newRow("network error") << 0 << QByteArray() << false;
        QTest::newRow("server error") << 503 << QByteArray() << false;
        QTest::newRow("internal error") << 500 << QByteArray() << false;
        QTest::newRow("rate limit") << 429 << QByteArray() << false;
        QTest::newRow("invalid_grant") << 400 << "invalid_grant"_ba << true;
    }

    void refreshErrorsKeepOrEndTheSession()
    {
        QFETCH(int, status);
        QFETCH(QByteArray, error);
        QFETCH(bool, ends);
        auto session = offlineSession();
        _identity->refreshOverride = [status, error](const HttpRequest &, QTcpSocket *) -> std::optional<HttpResponse> {
            if (status == 0) {
                return HttpResponse{0, {}, {}, true};
            }
            return error.isEmpty() ? HttpResponse{status, "unavailable", {}} : HttpResponse::json(status, {{u"error"_s, QString::fromLatin1(error)}});
        };
        QSignalSpy failed(session.get(), &DeviceSession::refreshFailed);
        QSignalSpy lost(session.get(), &DeviceSession::sessionLost);
        auto result = std::optional<bool>();
        session->refreshThen(this, [&result](bool success) {
            result = success;
        });
        QTRY_VERIFY(result.has_value());
        QCOMPARE(*result, false);
        QCOMPARE(failed.size(), 1);
        QCOMPARE(lost.size(), ends ? 1 : 0);
        if (ends) {
            QCOMPARE(session->status(), DeviceSession::Status::Lost);
            QVERIFY(_store.isEmpty());
            QVERIFY(!session->canRefresh());
            QVERIFY(headerFor(*session, _nextcloud->server.url()).isEmpty());
            return;
        }
        // Transient failures keep the session and its token, and retry later.
        QCOMPARE(session->status(), DeviceSession::Status::Offline);
        QCOMPARE(storedRefreshToken(_store), u"refresh-seed"_s);
        QCOMPARE(headerFor(*session, _nextcloud->server.url()), jwt(1000));
        _identity->refreshOverride = {};
        QSignalSpy refreshed(session.get(), &DeviceSession::tokenRefreshed);
        session->networkChanged();
        QTRY_COMPARE(refreshed.size(), 1);
        QCOMPARE(_log.filter(u"idp:refresh"_s), (QStringList{u"idp:refresh refresh-seed"_s, u"idp:refresh refresh-seed"_s}));
    }

    void onlineGrantEndsWithoutTouchingTheStore()
    {
        DeviceSession session(nullptr, memoryStore(_store, &_log));
        session.setStorageKey([] {
            return u"test-entry"_s;
        });
        auto tokens = seededTokens(jwt(7), "refresh-online");
        tokens.scopes = {u"openid"_s};
        session.adoptOnline(tokens);
        QSignalSpy lost(&session, &DeviceSession::sessionLost);
        session.refresh();
        QTRY_COMPARE(lost.size(), 1);
        QCOMPARE(session.status(), DeviceSession::Status::Absent);
        QVERIFY(!_log.contains(u"store:delete"_s));
    }

    void challengesMapToTheRightCredential_data()
    {
        QTest::addColumn<QByteArray>("challenge");
        QTest::addColumn<QByteArray>("body");
        QTest::addColumn<bool>("deviceToken");
        QTest::newRow("bearer") << R"(Bearer realm="nc.sairibus.com")"_ba << "Device sign-in required"_ba << true;
        QTest::newRow("bearer invalid_token") << R"(Bearer realm="nc.sairibus.com", error="invalid_token")"_ba << QByteArray() << true;
        QTest::newRow("basic") << R"(Basic realm="Nextcloud")"_ba << QByteArray() << false;
        QTest::newRow("central_login_required") << R"(Basic realm="Nextcloud")"_ba << R"({"error":"central_login_required"})"_ba << false;
    }

    void challengesMapToTheRightCredential()
    {
        QFETCH(QByteArray, challenge);
        QFETCH(QByteArray, body);
        QFETCH(bool, deviceToken);
        _nextcloud->other = [&](const HttpRequest &, QTcpSocket *) -> std::optional<HttpResponse> {
            return HttpResponse{401, body, {{"WWW-Authenticate", challenge}, {"Content-Type", "application/json"}}};
        };
        QNetworkAccessManager network;
        const auto reply = network.get(QNetworkRequest(_nextcloud->server.url(u"/remote.php/dav/files/u123456a/"_s)));
        QSignalSpy finished(reply, &QNetworkReply::finished);
        QTRY_COMPARE(finished.size(), 1);
        QCOMPARE(DeviceSession::isTokenChallenge(reply), deviceToken);
        // A device token challenge never counts against the app password.
        WebFlowCredentials webFlow(u"u123456a"_s, appPassword);
        QCOMPARE(webFlow.stillValid(reply), deviceToken);
        HttpCredentialsGui basic(u"u123456a"_s, appPassword, {}, {});
        QCOMPARE(basic.stillValid(reply), deviceToken);
        reply->deleteLater();
    }

    void bearerChallengeRenewsOnceAndRetries()
    {
        const auto account = createAccount(new WebFlowCredentials(u"u123456a"_s, appPassword));
        const auto session = account->deviceSession();
        _identity->seed("refresh-seed");
        session->adoptOffline(seededTokens(jwt(1000), "refresh-seed"));
        QTRY_COMPARE(session->status(), DeviceSession::Status::Offline);
        auto rejectAll = false;
        _nextcloud->other = [&](const HttpRequest &request, QTcpSocket *) -> std::optional<HttpResponse> {
            if (rejectAll || !_identity->accessTokens.contains(request.header(DeviceSession::TokenHeader))) {
                return bearerChallenge();
            }
            return HttpResponse{200, "ok", {}};
        };
        QSignalSpy invalid(account.data(), &Account::invalidCredentials);
        const auto url = _nextcloud->server.url(u"/ocs/v2.php/cloud/user"_s);

        // The token lapsed: the job renews it once and succeeds.
        auto job = new SimpleNetworkJob(account);
        QSignalSpy done(job, &SimpleNetworkJob::finishedSignal);
        job->startRequest("GET", url);
        QTRY_COMPARE(done.size(), 1);
        auto requests = _nextcloud->server.requestsTo(url.path());
        QCOMPARE(requests.size(), 2);
        QCOMPARE(requests[0].header(DeviceSession::TokenHeader), jwt(1000));
        QCOMPARE(requests[1].header(DeviceSession::TokenHeader), _identity->lastAccess);
        QVERIFY(requests[1].header("authorization").startsWith("Basic "));
        QCOMPARE(_log.filter(u"idp:refresh"_s).size(), 1);

        // A renewed token that is still refused ends the job after one retry, and the app password stays.
        rejectAll = true;
        job = new SimpleNetworkJob(account);
        QSignalSpy refused(job, &SimpleNetworkJob::finishedSignal);
        job->startRequest("GET", url);
        QTRY_COMPARE(refused.size(), 1);
        QTest::qWait(200);
        QCOMPARE(_nextcloud->server.requestsTo(url.path()).size(), 4);
        QCOMPARE(_log.filter(u"idp:refresh"_s).size(), 2);
        QCOMPARE(invalid.size(), 0);
        QCOMPARE(account->credentials()->password(), appPassword);
    }

    void refusedDevicePathsAreReported()
    {
        const auto account = createAccount();
        auto tokens = seededTokens(jwt(7), "refresh-online");
        tokens.scopes = {u"openid"_s};
        account->deviceSession()->adoptOnline(tokens);
        _nextcloud->other = [](const HttpRequest &, QTcpSocket *) -> std::optional<HttpResponse> {
            return HttpResponse{403, "Browser login required", {{"Content-Type", "text/plain; charset=utf-8"}}};
        };
        QTest::ignoreMessage(QtWarningMsg, QRegularExpression(u"Client bug: .*/index.php/204"_s));
        const auto reply = account->networkAccessManager()->get(QNetworkRequest(_nextcloud->server.url(u"/index.php/204"_s)));
        QSignalSpy finished(reply, &QNetworkReply::finished);
        QTRY_COMPARE(finished.size(), 1);
        reply->deleteLater();
    }

    void tokenNeverLeavesTheServer()
    {
        auto session = offlineSession();
        HttpTestServer other;
        other.handler = [](const HttpRequest &, QTcpSocket *) -> std::optional<HttpResponse> {
            return HttpResponse{200, "elsewhere", {}};
        };
        // Other hosts, ports and schemes get no token, and a copied header is removed.
        QVERIFY(!headerFor(*session, _nextcloud->server.url()).isEmpty());
        QVERIFY(headerFor(*session, other.url()).isEmpty());
        auto https = _nextcloud->server.url();
        https.setScheme(u"https"_s);
        QVERIFY(headerFor(*session, https).isEmpty());
        auto copied = QNetworkRequest(other.url(u"/landing"_s));
        copied.setRawHeader(DeviceSession::TokenHeader, jwt(1000));
        session->decorate(copied);
        QVERIFY(!copied.hasRawHeader(DeviceSession::TokenHeader));

        // Qt never follows a redirect with the token.
        _nextcloud->other = [&other](const HttpRequest &, QTcpSocket *) -> std::optional<HttpResponse> {
            return HttpResponse{302, {}, {{"Location", other.url(u"/landing"_s).toEncoded()}}};
        };
        AccessManager manager;
        manager.setDeviceSession(session.get());
        auto request = QNetworkRequest(_nextcloud->server.url(u"/remote.php/dav/redirect"_s));
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        const auto reply = manager.get(request);
        QSignalSpy finished(reply, &QNetworkReply::finished);
        QTRY_COMPARE(finished.size(), 1);
        QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 302);
        QVERIFY(other.requests.isEmpty());
        reply->deleteLater();

        // A job that follows the redirect itself sends the next request without the token.
        const auto account = createAccount(new WebFlowCredentials(u"u123456a"_s, appPassword));
        _identity->accessTokens.insert(jwt(2000));
        account->deviceSession()->adoptOffline(seededTokens(jwt(2000), "refresh-account"));
        QTRY_COMPARE(account->deviceSession()->status(), DeviceSession::Status::Offline);
        const auto job = new SimpleNetworkJob(account);
        QSignalSpy done(job, &SimpleNetworkJob::finishedSignal);
        job->startRequest("GET", _nextcloud->server.url(u"/remote.php/dav/redirect"_s));
        QTRY_COMPARE(done.size(), 1);
        QCOMPARE(_nextcloud->server.requests.last().header(DeviceSession::TokenHeader), jwt(2000));
        QCOMPARE(other.requests.size(), 1);
        QVERIFY(!other.requests[0].hasHeader(DeviceSession::TokenHeader));
        QVERIFY(!other.requests[0].hasHeader("authorization"));
    }

    void tokensStayOutOfLogs()
    {
        // Network threads log too, so the capture needs a lock.
        static QMutex lock;
        static QStringList messages;
        messages.clear();
        const auto previous = qInstallMessageHandler([](QtMsgType, const QMessageLogContext &, const QString &message) {
            const auto locker = QMutexLocker(&lock);
            messages.append(message);
        });
        const auto restore = qScopeGuard([previous] {
            qInstallMessageHandler(previous);
            QLoggingCategory::setFilterRules({});
        });
        QLoggingCategory::setFilterRules(u"nextcloud.*.debug=true"_s);

        QCOMPARE(HttpLogger::redactedHeaderValue("X-Sairibus-Device-Token", jwt(5)), "[redacted]"_ba);
        QCOMPARE(HttpLogger::redactedHeaderValue("x-sairibus-device-token", jwt(5)), "[redacted]"_ba);

        const auto account = createAccount(new WebFlowCredentials(u"u123456a"_s, appPassword));
        const auto session = account->deviceSession();
        DeviceEnrollment enrollment(session);
        QSignalSpy online(&enrollment, &DeviceEnrollment::onlineSignedIn);
        enrollment.signInOnline();
        QTRY_COMPARE(online.size(), 1);
        QSignalSpy refreshed(session, &DeviceSession::tokenRefreshed);
        session->refresh();
        QTRY_COMPARE(refreshed.size(), 1);
        _nextcloud->other = [](const HttpRequest &, QTcpSocket *) -> std::optional<HttpResponse> {
            return HttpResponse{200, "ok", {{"Content-Type", "text/plain"}}};
        };
        const auto job = new SimpleNetworkJob(account);
        QSignalSpy done(job, &SimpleNetworkJob::finishedSignal);
        job->startRequest("GET", _nextcloud->server.url(u"/ocs/v2.php/cloud/user"_s));
        QTRY_COMPARE(done.size(), 1);
        session->retire(u"u123456a"_s, appPassword);
        QTest::qWait(500);

        QTest::qWait(0);
        qInstallMessageHandler(previous);
        const auto locker = QMutexLocker(&lock);
        QVERIFY(!messages.isEmpty());
        auto secrets = QList<QByteArray>{appPassword.toLatin1(), QByteArray("u123456a:" + appPassword.toLatin1()).toBase64()};
        for (auto i = 1; i <= _identity->issued; ++i) {
            secrets.append(jwt(i));
            secrets.append("refresh-" + QByteArray::number(i));
        }
        for (const auto &message : std::as_const(messages)) {
            for (const auto &secret : std::as_const(secrets)) {
                QVERIFY2(!message.contains(QString::fromLatin1(secret)), qPrintable(u"A log message contains a credential: "_s + message.left(200)));
            }
        }
    }

    void removingAnAccountRevokesThenDeletesTheAppPassword_data()
    {
        QTest::addColumn<qint64>("lifetime");
        QTest::newRow("fresh token") << qint64{300};
        QTest::newRow("expired token") << qint64{-10};
    }

    void removingAnAccountRevokesThenDeletesTheAppPassword()
    {
        QFETCH(qint64, lifetime);
        auto session = offlineSession("refresh-seed", lifetime);
        _nextcloud->other = [this](const HttpRequest &request, QTcpSocket *) -> std::optional<HttpResponse> {
            _log.append(u"nc:"_s + QString::fromLatin1(request.method) + u' ' + request.path());
            return HttpResponse::json(200, {{u"ocs"_s, QJsonObject{}}});
        };
        session->retire(u"u123456a"_s, appPassword);
        QCOMPARE(session->status(), DeviceSession::Status::Absent);
        QVERIFY(_store.isEmpty());
        QTRY_VERIFY(_log.contains(u"nc:DELETE /ocs/v2.php/core/apppassword"_s));
        const auto revoked = _log.indexOf(QRegularExpression(u"^idp:revoke .*"_s));
        QVERIFY2(revoked >= 0 && revoked < _log.indexOf(u"nc:DELETE /ocs/v2.php/core/apppassword"_s), qPrintable(_log.join(u", "_s)));
        const auto deletion = _nextcloud->server.requests.last();
        QCOMPARE(deletion.header("authorization"), "Basic " + QByteArray("u123456a:" + appPassword.toLatin1()).toBase64());
        QCOMPARE(deletion.header("ocs-apirequest"), "true"_ba);
        if (lifetime > 0) {
            QCOMPARE(_identity->revoked, (QList<QByteArray>{"refresh-seed"}));
            QCOMPARE(deletion.header(DeviceSession::TokenHeader), jwt(1000));
        } else {
            // A stale token is renewed first; the rotated refresh token is the one revoked.
            QCOMPARE(_identity->revoked, (QList<QByteArray>{_identity->lastRefresh}));
            QCOMPARE(deletion.header(DeviceSession::TokenHeader), _identity->lastAccess);
        }
    }

    void offlineGrantMustMatchTheSignedInAccount()
    {
        DeviceSession session(nullptr, memoryStore(_store, &_log));
        session.setStorageKey([] {
            return u"test-entry"_s;
        });
        auto online = seededTokens(jwtFor(u"alice"_s), "refresh-online");
        online.scopes = {u"openid"_s};
        session.adoptOnline(online);
        auto result = std::optional<bool>();
        session.adoptOffline(seededTokens(jwtFor(u"bob"_s), "refresh-bob-offline"), [&result](bool success, const QString &) {
            result = success;
        });
        QCOMPARE(result, std::optional<bool>(false));
        QVERIFY(_store.isEmpty());
        QCOMPARE(session.status(), DeviceSession::Status::Online);
        session.adoptOffline(seededTokens(jwtFor(u"alice"_s), "refresh-alice-offline"), [&result](bool success, const QString &) {
            result = success;
        });
        QCOMPARE(result, std::optional<bool>(true));
        QCOMPARE(storedRefreshToken(_store), u"refresh-alice-offline"_s);
    }

    void unreadSessionsAreRetiredFromTheStore()
    {
        _identity->seed("refresh-stored");
        _store.insert(u"test-entry"_s,
                      QJsonDocument(QJsonObject{{u"issuer"_s, _identity->issuer().toString()}, {u"refresh_token"_s, u"refresh-stored"_s}}).toJson());
        _nextcloud->other = [this](const HttpRequest &request, QTcpSocket *) -> std::optional<HttpResponse> {
            _log.append(u"nc:"_s + QString::fromLatin1(request.method) + u' ' + request.path());
            return HttpResponse::json(200, {{u"ocs"_s, QJsonObject{}}});
        };
        DeviceSession session(nullptr, memoryStore(_store, &_log));
        session.setStorageKey([] {
            return u"test-entry"_s;
        });
        QCOMPARE(session.status(), DeviceSession::Status::Unloaded);
        session.retire(u"u123456a"_s, deviceTestAppPassword);
        QTRY_VERIFY(_log.contains(u"nc:DELETE /ocs/v2.php/core/apppassword"_s));
        QVERIFY(_store.isEmpty());
        QCOMPARE(_identity->revoked, (QList<QByteArray>{_identity->lastRefresh}));
        QCOMPARE(_nextcloud->server.requests.last().header(DeviceSession::TokenHeader), _identity->lastAccess);
    }

    void unreadableStoreKeepsTheSession()
    {
        DeviceSession session(nullptr, [](const QString &, const std::optional<QByteArray> &, DeviceSession::Completion done) {
            done({}, u"synthetic locked store"_s);
        });
        session.setStorageKey([] {
            return u"test-entry"_s;
        });
        QSignalSpy failed(&session, &DeviceSession::refreshFailed);
        session.load();
        QCOMPARE(failed.size(), 1);
        QCOMPARE(session.status(), DeviceSession::Status::Unloaded);
    }

    void abandonedOfflineGrantIsRemovedAndRevoked()
    {
        auto pending = DeviceSession::Completion();
        DeviceSession session(nullptr, [&](const QString &key, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
            if (data && !data->isEmpty()) {
                _store.insert(key, *data);
                pending = std::move(done);
                return;
            }
            if (data) {
                _store.remove(key);
            }
            done(_store.value(key), {});
        });
        session.setStorageKey([] {
            return u"test-entry"_s;
        });
        _identity->seed("refresh-late-offline");
        session.adoptOffline(seededTokens(jwt(9), "refresh-late-offline"));
        QVERIFY(pending);
        session.forget();
        std::exchange(pending, {})({}, {});
        QVERIFY(_store.isEmpty());
        QTRY_COMPARE(_identity->revoked, (QList<QByteArray>{"refresh-late-offline"}));
        QCOMPARE(session.status(), DeviceSession::Status::Absent);
    }

    void oneAccountPerMember()
    {
        // The member already has an account on this computer.
        DeviceSession first(nullptr, memoryStore(_store, &_log));
        first.setStorageKey([] {
            return u"first-entry"_s;
        });
        first.adoptOffline(seededTokens(jwtFor(u"alice"_s), "refresh-alice-offline"));
        QCOMPARE(first.status(), DeviceSession::Status::Offline);

        DeviceSession second(nullptr, memoryStore(_store, &_log));
        second.setStorageKey([] {
            return u"second-entry"_s;
        });
        DeviceEnrollment enrollment(&second);
        QSignalSpy failed(&enrollment, &DeviceEnrollment::failed);
        QSignalSpy online(&enrollment, &DeviceEnrollment::onlineSignedIn);
        _identity->subject = u"alice"_s;
        enrollment.signInOnline();
        QTRY_COMPARE(failed.size(), 1);
        QCOMPARE(online.size(), 0);
        QCOMPARE(second.status(), DeviceSession::Status::Unloaded);

        // Another member signs in normally.
        _identity->subject = u"bob"_s;
        enrollment.signInOnline();
        QTRY_COMPARE(online.size(), 1);
        QCOMPARE(second.status(), DeviceSession::Status::Online);
    }
};

int main(int argc, char *argv[])
{
    // Keep the test log when the process ends abnormally.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    QApplication application(argc, argv);
    QTEST_SET_MAIN_SOURCE_PATH
    TestDeviceSession test;
    return QTest::qExec(&test, argc, argv);
}
#include "testdevicesession.moc"
