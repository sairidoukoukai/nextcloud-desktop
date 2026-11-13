/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accessmanager.h"
#include "account.h"
#include "accountstate.h"
#include "cloudflareaccess.h"
#include "cloudflareaccesstestserver.h"
#include "cloudflarenativecredentialstestutils.h"
#include "cmd/simplesslerrorhandler.h"
#include "configfile.h"
#include "deviceauthorization.h"
#include "devicesession.h"
#include "devicetestserver.h"
#include "networkjobs.h"
#include "pushnotifications.h"
#include "pushnotificationstestutils.h"
#include "syncenginetestutils.h"

#include <QDesktopServices>
#include <QScopeGuard>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTest>

using namespace OCC;
using namespace Qt::StringLiterals;

namespace
{

// Distinct from the default 12345 used by PushNotificationsTest, so both can run in parallel.
constexpr quint16 webSocketPort = 12346;

// Counts connectivity checks at the point where slotCheckConnection() decides to call them.
class ConnectivityCountingAccountState : public AccountState
{
public:
    explicit ConnectivityCountingAccountState(const AccountPtr &account)
        : AccountState(account)
    {
    }

    void checkConnectivity() override
    {
        ++checkConnectivityCount;
    }

    int checkConnectivityCount = 0;
};

AccountPtr createPushAccount()
{
    auto account = FakeWebSocketServer::createAccount(u"admin"_s, u"password"_s, QUrl(u"http://localhost"_s), QUrl(u"ws://localhost:%1"_s.arg(webSocketPort)));

    // Becoming Connected fetches navigation apps; answer every request without a server.
    auto qnam = new FakeQNAM({});
    qnam->setOverride([qnam](QNetworkAccessManager::Operation operation, const QNetworkRequest &request, QIODevice *) -> QNetworkReply * {
        return new FakeErrorReply(operation, request, qnam, 404);
    });
    account->setCredentials(new FakeCredentials{qnam});
    return account;
}

// Club account credentials; loaded at once unless they wait for the keychain, as at start-up.
class DeviceAccountCredentials : public FakeCredentials
{
public:
    DeviceAccountCredentials(std::function<QNetworkAccessManager *()> network, const QString &user, bool loaded = true)
        : FakeCredentials(nullptr)
        , _network(std::move(network))
    {
        setUserName(user);
        _wasFetched = loaded;
    }

    // Checking connectivity while disconnected replaces the account's network manager, so each call needs a new one.
    [[nodiscard]] QNetworkAccessManager *createQNAM() const override { return _network(); }

    void fetchFromKeychain(const QString &) override
    {
        _wasFetched = true;
        Q_EMIT fetched();
    }

    // What Login Flow V2 does for an existing account: a new login name and app password.
    void signInAgain(const QString &user)
    {
        setUserName(user);
        Q_EMIT asked();
    }

private:
    std::function<QNetworkAccessManager *()> _network;
};

// The club's Nextcloud as the account sees it: OCS reports the user ID of the app password, everything else is missing.
struct ClubServer
{
    // Empty while the server refuses the account's app password.
    QString userId;
    // The next lookups that fail, as when the device token expired.
    int failingLookups = 0;
    int lookups = 0;
};

std::function<QNetworkAccessManager *()> clubServer(const std::shared_ptr<ClubServer> &server)
{
    return [server] {
        auto qnam = new FakeQNAM({});
        qnam->setOverride([qnam, server](QNetworkAccessManager::Operation operation, const QNetworkRequest &request, QIODevice *) -> QNetworkReply * {
            if (request.url().path().endsWith("/ocs/v1.php/cloud/user"_L1)) {
                ++server->lookups;
                if (server->failingLookups > 0) {
                    --server->failingLookups;
                    return new FakeErrorReply(operation, request, qnam, 500);
                }
                if (server->userId.isEmpty()) {
                    return new FakeErrorReply(operation, request, qnam, 401);
                }
                const auto body = QJsonDocument(QJsonObject{{u"ocs"_s, QJsonObject{{u"meta"_s, QJsonObject{{u"statuscode"_s, 100}}},
                                                                                 {u"data"_s, QJsonObject{{u"id"_s, server->userId}, {u"display-name"_s, u"Member"_s}}}}}})
                                      .toJson(QJsonDocument::Compact);
                return new FakePayloadReply(operation, request, body, qnam);
            }
            return new FakeErrorReply(operation, request, qnam, 404);
        });
        return qnam;
    };
}

std::shared_ptr<ClubServer> clubServerFor(const QString &userId)
{
    auto server = std::make_shared<ClubServer>();
    server->userId = userId;
    return server;
}

}

/** The member's default browser, answering the club's sign-in page at once. */
class AccountStateBrowser : public QObject
{
    Q_OBJECT

public:
    OCC::Test::FakeIdentity *identity = nullptr;
    QList<QUrl> opened;
    QNetworkAccessManager network;

public Q_SLOTS:
    void open(const QUrl &url)
    {
        opened.append(url);
        if (identity && url.path().endsWith("/protocol/openid-connect/auth"_L1)) {
            const auto reply = network.get(QNetworkRequest(identity->authorize(url)));
            connect(reply, &QNetworkReply::finished, reply, &QObject::deleteLater);
        }
    }
};

namespace
{
}

class TestAccountState : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void cloudflareFailurePreservesNativeCredentials_data()
    {
        QTest::addColumn<QString>("statusOutcome");
        for (const auto &outcome :
             {"edge-401"_L1, "edge-403"_L1, "malformed"_L1, "uninstalled"_L1, "string-installed"_L1, "redirect"_L1, "timeout"_L1, "native-401"_L1}) {
            QTest::newRow(qPrintable(outcome)) << QString(outcome);
        }
    }

    void cloudflareFailurePreservesNativeCredentials()
    {
        QFETCH(QString, statusOutcome);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto previous = ConfigFile().configPath();
        const auto restore = qScopeGuard([&] {
            ConfigFile::setConfDir(previous);
        });
        ConfigFile::setConfDir(directory.path());
        auto entries = QHash<QString, QByteArray>();
        CloudflareAccess access(nullptr, [&](const QString &key, const std::optional<QByteArray> &data, CloudflareAccess::Completion done) {
            if (data) {
                entries[key] = *data;
            }
            done(entries.value(key), {});
        });
        CloudflareAccessTestServer server;
        QVERIFY(server.isListening());
        const auto base = server.baseUrl();
        access.save(true, base, "client"_L1, "old-secret"_L1);
        server.respond = [&](const QByteArray &request) {
            if (request.toLower().contains("cf-access-client-secret: new-secret")) {
                return CloudflareAccessTestServer::response(200, "{\"installed\":true}");
            }
            if (!request.startsWith("GET /status.php ")) {
                return CloudflareAccessTestServer::response(401, "{}");
            }
            if (statusOutcome == "timeout"_L1) {
                return QByteArray{};
            }
            if (statusOutcome == "redirect"_L1) {
                return CloudflareAccessTestServer::response(302, {}, (base + "/elsewhere"_L1).toUtf8());
            }
            if (statusOutcome == "malformed"_L1) {
                return CloudflareAccessTestServer::response(200, "{broken");
            }
            if (statusOutcome == "uninstalled"_L1) {
                return CloudflareAccessTestServer::response(200, "{\"installed\":false}");
            }
            if (statusOutcome == "string-installed"_L1) {
                return CloudflareAccessTestServer::response(200, "{\"installed\":\"true\"}");
            }
            return CloudflareAccessTestServer::response(statusOutcome == "native-401"_L1 ? 200 : (statusOutcome == "edge-403"_L1 ? 403 : 401),
                                                        "{\"installed\":true}");
        };
        const auto account = Account::create();
        account->setUrl(QUrl(base));
        account->setTrustCertificates(true);
        account->setSslErrorHandler(new SimpleSslErrorHandler);
        const auto credentials = new CloudflareNativeTestCredentials(new AccessManager(nullptr, &access));
        account->setCredentials(credentials);
        ConnectivityCountingAccountState state(account);
        QSignalSpy invalid(account.data(), &Account::invalidCredentials);
        QSignalSpy edgeFailure(account.data(), &Account::cloudflareAccessCheckFailed);
        auto request = QNetworkRequest();
        request.setRawHeader("Authorization", "Basic native-device-secret");
        account->sendRequest("GET", QUrl(base + "/request"_L1), request);
        if (statusOutcome == "native-401"_L1) {
            QTRY_COMPARE(invalid.count(), 1);
            QCOMPARE(credentials->forgotten, 1);
            QCOMPARE(state.state(), AccountState::AskingCredentials);
            QVERIFY(!credentials->ready());
            QCOMPARE(edgeFailure.count(), 0);
        } else {
            QTRY_COMPARE_WITH_TIMEOUT(edgeFailure.count(), 1, 12000);
            QCOMPARE(invalid.count(), 0);
            QCOMPARE(credentials->forgotten, 0);
            QCOMPARE(credentials->password(), "native-device-secret"_L1);
            QVERIFY(!state.isSignedOut());
            const auto checks = state.checkConnectivityCount;
            access.save(true, base, "client"_L1, "new-secret"_L1);
            QTRY_VERIFY(state.checkConnectivityCount > checks);
            const auto job = account->sendRequest("GET", QUrl(base + "/request"_L1), request);
            connect(job, &SimpleNetworkJob::finishedSignal, account.data(), [](QNetworkReply *reply) {
                QCOMPARE(reply->error(), QNetworkReply::NoError);
                QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 200);
            });
            QSignalSpy resumed(job, &SimpleNetworkJob::finishedSignal);
            QTRY_COMPARE(resumed.count(), 1);
            QVERIFY(server.requests.last().toLower().contains("cf-access-client-secret: new-secret"));
            QCOMPARE(credentials->forgotten, 0);
        }
        QVERIFY(server.requests.size() >= 2);
        QVERIFY(server.requests.at(1).startsWith("GET /status.php "));
        QVERIFY(!server.requests.at(1).toLower().contains("authorization:"));
        QVERIFY(!server.requests.at(1).toLower().contains("cookie:"));
    }

    void obsoleteCloudflareFailureCannotSignOut_data()
    {
        QTest::addColumn<QString>("change");
        for (const auto &change : {"old-request"_L1,
                                   "old-request-new-credentials"_L1,
                                   "old-request-refreshed"_L1,
                                   "rotate"_L1,
                                   "disable"_L1,
                                   "sign-out"_L1,
                                   "replace-credentials"_L1,
                                   "refresh-pending"_L1,
                                   "change-url"_L1,
                                   "coalesced"_L1}) {
            QTest::newRow(qPrintable(change)) << QString(change);
        }
    }

    void obsoleteCloudflareFailureCannotSignOut()
    {
        QFETCH(QString, change);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto previous = ConfigFile().configPath();
        const auto restore = qScopeGuard([&] {
            ConfigFile::setConfDir(previous);
        });
        ConfigFile::setConfDir(directory.path());
        CloudflareAccess access(nullptr, [](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            done({}, {});
        });
        CloudflareAccessTestServer server;
        QVERIFY(server.isListening());
        const auto base = server.baseUrl();
        const auto delayedOriginal = change.startsWith("old-request"_L1);
        access.save(true, base, "client"_L1, "old-secret"_L1);
        server.respond = [&](const QByteArray &request) {
            if (delayedOriginal || request.startsWith("GET /status.php ")) {
                return QByteArray{};
            }
            return CloudflareAccessTestServer::response(401, "{}");
        };
        const auto account = Account::create();
        account->setUrl(QUrl(base));
        account->setTrustCertificates(true);
        account->setSslErrorHandler(new SimpleSslErrorHandler);
        auto credentials = new CloudflareNativeTestCredentials(new AccessManager(nullptr, &access));
        account->setCredentials(credentials);
        ConnectivityCountingAccountState state(account);
        QSignalSpy invalid(account.data(), &Account::invalidCredentials);
        account->sendRequest("GET", QUrl(base + "/request"_L1));
        QTRY_COMPARE(server.requests.size(), delayedOriginal ? 1 : 2);
        if (change == "sign-out"_L1) {
            state.signOutByUi();
        } else if (change == "replace-credentials"_L1 || change == "old-request-new-credentials"_L1) {
            credentials = new CloudflareNativeTestCredentials(new AccessManager(nullptr, &access));
            account->setCredentials(credentials);
        } else if (change == "refresh-pending"_L1 || change == "old-request-refreshed"_L1) {
            credentials->refreshPassword();
        } else if (change == "disable"_L1) {
            access.save(false, {}, {}, {});
        } else if (change == "coalesced"_L1) {
            const auto job = account->sendRequest("GET", QUrl(base + "/another-request"_L1));
            QSignalSpy completed(job, &SimpleNetworkJob::finishedSignal);
            QTRY_COMPARE(completed.count(), 1);
            QCOMPARE(server.requests.size(), 3);
        } else if (change == "change-url"_L1) {
            account->setUrl(QUrl("https://other.example"_L1));
        } else {
            access.save(true, base, "client"_L1, "new-secret"_L1);
        }
        for (const auto socket : server.findChildren<QSslSocket *>()) {
            socket->write(CloudflareAccessTestServer::response(delayedOriginal ? 401 : 200, "{\"installed\":true}"));
            socket->disconnectFromHost();
        }
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QTest::qWait(100);
        QCOMPARE(invalid.count(), change == "coalesced"_L1 ? 1 : 0);
        QCOMPARE(credentials->forgotten, change == "sign-out"_L1 || change == "coalesced"_L1 ? 1 : 0);
        const auto requiresLogin = change == "sign-out"_L1 || change == "coalesced"_L1;
        QCOMPARE(state.state(), requiresLogin ? AccountState::AskingCredentials : AccountState::Disconnected);
        QCOMPARE(credentials->ready(), !requiresLogin);
        QCOMPARE(server.requests.size(), delayedOriginal ? 1 : (change == "coalesced"_L1 ? 3 : 2));
    }


    void otherServersKeepTheStockSignIn()
    {
        AccountStateBrowser browser;
        QDesktopServices::setUrlHandler(u"https"_s, &browser, "open");
        QDesktopServices::setUrlHandler(u"http"_s, &browser, "open");
        const auto restore = qScopeGuard([] {
            QDesktopServices::unsetUrlHandler(u"https"_s);
            QDesktopServices::unsetUrlHandler(u"http"_s);
        });
        const auto user = u"admin"_s;
        const auto account = Account::create();
        account->setUrl(QUrl(u"https://cloud.example"_s));
        account->setCredentials(new DeviceAccountCredentials(clubServer(clubServerFor(user)), user));
        // Jobs hold the state by AccountStatePtr, so it lives on the heap as in the client.
        const auto state = AccountStatePtr(new AccountState(account));
        QTest::qWait(300);
        // No device sign-in and no browser for a server other than the club's.
        QVERIFY(browser.opened.isEmpty());
        QCOMPARE(account->deviceSession()->status(), DeviceSession::Status::Unloaded);
        QVERIFY(state->state() != AccountState::AskingCredentials);
    }

    void clubAccountWithoutDeviceSessionSignsInAtStart()
    {
        AccountStateBrowser browser;
        QDesktopServices::setUrlHandler(u"https"_s, &browser, "open");
        const auto restore = qScopeGuard([] {
            QDesktopServices::unsetUrlHandler(u"https"_s);
            DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.sairibus.com"_s), QUrl(u"https://auth.sairibus.com/realms/sairibus"_s)});
        });
        DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.example"_s), QUrl(u"https://auth.example/realms/sairibus"_s)});
        const auto user = u"cjyet-yo"_s;
        const auto store = std::make_shared<QHash<QString, QByteArray>>();
        const auto account = Account::create();
        account->setUrl(QUrl(u"https://nc.example"_s));
        account->setDavUser(user);
        account->setCredentials(new DeviceAccountCredentials(clubServer(clubServerFor(user)), user));
        account->deviceSession()->setCredentialStore([store](const QString &key, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
            if (data) { data->isEmpty() ? void(store->remove(key)) : void(store->insert(key, *data)); }
            done(store->value(key), {});
        });
        // Jobs hold the state by AccountStatePtr, so it lives on the heap as in the client.
        const auto state = AccountStatePtr(new AccountState(account));
        // An account set up before device sign-in has no device session: the browser opens for step 1.
        QTRY_COMPARE(browser.opened.size(), 1);
        QCOMPARE(QUrlQuery(browser.opened[0]).queryItemValue(u"scope"_s, QUrl::FullyDecoded), u"openid"_s);
        QCOMPARE(state->state(), AccountState::AskingCredentials);
    }

    void changedUserIdKeepsTheAccount_data()
    {
        QTest::addColumn<bool>("ownSession");
        QTest::addColumn<bool>("confirmed");
        QTest::newRow("device session of this account") << true << false;
        QTest::newRow("first device sign-in, confirmed") << false << true;
        QTest::newRow("first device sign-in, another member") << false << false;
    }

    void changedUserIdKeepsTheAccount()
    {
        QFETCH(bool, ownSession);
        QFETCH(bool, confirmed);
        QStringList log;
        OCC::Test::FakeIdentity identity(&log);
        identity.subject = u"7a13bcce-8c7e-4444-b935-f00d04665df9"_s;
        AccountStateBrowser browser;
        browser.identity = &identity;
        QDesktopServices::setUrlHandler(u"http"_s, &browser, "open");
        auto asked = QStringList();
        AccountState::setUserChangeConfirmation([&asked, confirmed](const QString &previous, const QString &user, const QString &, std::function<void(bool)> done) {
            asked = {previous, user};
            done(confirmed);
        });
        const auto restore = qScopeGuard([] {
            QDesktopServices::unsetUrlHandler(u"http"_s);
            AccountState::setUserChangeConfirmation({});
            DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.sairibus.com"_s), QUrl(u"https://auth.sairibus.com/realms/sairibus"_s)});
        });
        DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.example"_s), identity.issuer()});
        // The server migrated this member's ID from cjyet-yo to the OUID u723741i and refuses the old app password.
        const auto serverUser = u"u723741i"_s;
        const auto server = clubServerFor({});
        const auto store = std::make_shared<QHash<QString, QByteArray>>();
        const auto account = Account::create();
        account->setUrl(QUrl(u"https://nc.example"_s));
        account->setDavUser(u"cjyet-yo"_s);
        const auto credentials = new DeviceAccountCredentials(clubServer(server), u"cjyet-yo"_s);
        account->setCredentials(credentials);
        account->deviceSession()->setCredentialStore([store](const QString &key, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
            if (data) { data->isEmpty() ? void(store->remove(key)) : void(store->insert(key, *data)); }
            done(store->value(key), {});
        });
        if (ownSession) {
            identity.seed("refresh-own-offline");
            auto tokens = DeviceTokens();
            tokens.accessToken = OCC::Test::jwtFor(identity.subject, 1000);
            tokens.refreshToken = "refresh-own-offline";
            tokens.expiresAt = QDateTime::currentSecsSinceEpoch() + 300;
            tokens.scopes = {u"openid"_s, u"offline_access"_s};
            account->deviceSession()->adoptOffline(tokens);
            QCOMPARE(account->deviceSession()->status(), DeviceSession::Status::Offline);
        }
        QSignalSpy saved(account.data(), &Account::wantsAccountSaved);
        // Jobs hold the state by AccountStatePtr, so it lives on the heap as in the client.
        const auto state = AccountStatePtr(new AccountState(account));
        if (!ownSession) {
            // Step 1 runs in the browser because the account has no device session yet.
            QTRY_COMPARE(account->deviceSession()->status(), DeviceSession::Status::Online);
        }
        QTest::qWait(200);

        QCOMPARE(account->davUser(), u"cjyet-yo"_s);

        // Login Flow V2 issued a new app password for the member's current ID.
        server->userId = serverUser;
        credentials->signInAgain(serverUser);
        if (ownSession || confirmed) {
            QTRY_COMPARE(account->davUser(), u"u723741i"_s);
            QVERIFY(saved.size() >= 1);
            QVERIFY(account->davUrl().path().endsWith(u"/remote.php/dav/files/u723741i"_s) || account->davUrl().path().endsWith(u"/remote.php/dav/files/u723741i/"_s));
            QCOMPARE(account->credentials()->user(), u"u723741i"_s);
            QCOMPARE(asked, ownSession ? QStringList{} : (QStringList{u"cjyet-yo"_s, u"u723741i"_s}));
        } else {
            QTRY_COMPARE(state->state(), AccountState::SignedOut);
            QCOMPARE(asked, (QStringList{u"cjyet-yo"_s, u"u723741i"_s}));
            QCOMPARE(account->davUser(), u"cjyet-yo"_s);
            QCOMPARE(account->deviceSession()->status(), DeviceSession::Status::Absent);
        }
    }

    // A new app password stored by an earlier run, whose ID change was never adopted.
    void storedSignInAdoptsTheServerUserAtStart_data()
    {
        QTest::addColumn<bool>("ownSession");
        QTest::newRow("device session of this account") << true;
        QTest::newRow("no device session yet") << false;
    }

    void storedSignInAdoptsTheServerUserAtStart()
    {
        QFETCH(bool, ownSession);
        QStringList log;
        OCC::Test::FakeIdentity identity(&log);
        identity.subject = u"7a13bcce-8c7e-4444-b935-f00d04665df9"_s;
        AccountStateBrowser browser;
        browser.identity = &identity;
        QDesktopServices::setUrlHandler(u"http"_s, &browser, "open");
        auto asked = QStringList();
        AccountState::setUserChangeConfirmation([&asked](const QString &previous, const QString &user, const QString &, std::function<void(bool)> done) {
            asked = {previous, user};
            done(true);
        });
        const auto restore = qScopeGuard([] {
            QDesktopServices::unsetUrlHandler(u"http"_s);
            AccountState::setUserChangeConfirmation({});
            DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.sairibus.com"_s), QUrl(u"https://auth.sairibus.com/realms/sairibus"_s)});
        });
        DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.example"_s), identity.issuer()});
        const auto store = std::make_shared<QHash<QString, QByteArray>>();
        const auto account = Account::create();
        account->setUrl(QUrl(u"https://nc.example"_s));
        // The keychain holds the app password of u723741i; the account still syncs as cjyet-yo.
        account->setDavUser(u"cjyet-yo"_s);
        account->setCredentials(new DeviceAccountCredentials(clubServer(clubServerFor(u"u723741i"_s)), u"u723741i"_s, false));
        account->deviceSession()->setCredentialStore([store](const QString &key, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
            if (data) { data->isEmpty() ? void(store->remove(key)) : void(store->insert(key, *data)); }
            done(store->value(key), {});
        });
        if (ownSession) {
            identity.seed("refresh-own-offline");
            auto tokens = DeviceTokens();
            tokens.accessToken = OCC::Test::jwtFor(identity.subject, 1000);
            tokens.refreshToken = "refresh-own-offline";
            tokens.expiresAt = QDateTime::currentSecsSinceEpoch() + 300;
            tokens.scopes = {u"openid"_s, u"offline_access"_s};
            account->deviceSession()->adoptOffline(tokens);
        }
        const auto state = AccountStatePtr(new AccountState(account));

        QTRY_COMPARE(account->davUser(), u"u723741i"_s);
        // Without a device session the browser signs in first, and the member confirms the change.
        QCOMPARE(asked, ownSession ? QStringList{} : (QStringList{u"cjyet-yo"_s, u"u723741i"_s}));
        QCOMPARE(browser.opened.isEmpty(), ownSession);
    }

    void failedUserLookupIsRetried()
    {
        QStringList log;
        OCC::Test::FakeIdentity identity(&log);
        identity.subject = u"7a13bcce-8c7e-4444-b935-f00d04665df9"_s;
        const auto restore = qScopeGuard([] {
            DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.sairibus.com"_s), QUrl(u"https://auth.sairibus.com/realms/sairibus"_s)});
        });
        DeviceSession::setDefaultEndpoints({QUrl(u"https://nc.example"_s), identity.issuer()});
        const auto server = clubServerFor(u"u723741i"_s);
        server->failingLookups = 1;
        const auto store = std::make_shared<QHash<QString, QByteArray>>();
        const auto account = Account::create();
        account->setUrl(QUrl(u"https://nc.example"_s));
        account->setDavUser(u"cjyet-yo"_s);
        account->setCredentials(new DeviceAccountCredentials(clubServer(server), u"u723741i"_s));
        account->deviceSession()->setCredentialStore([store](const QString &key, const std::optional<QByteArray> &data, DeviceSession::Completion done) {
            if (data) { data->isEmpty() ? void(store->remove(key)) : void(store->insert(key, *data)); }
            done(store->value(key), {});
        });
        identity.seed("refresh-own-offline");
        auto tokens = DeviceTokens();
        tokens.accessToken = OCC::Test::jwtFor(identity.subject, 1000);
        tokens.refreshToken = "refresh-own-offline";
        tokens.expiresAt = QDateTime::currentSecsSinceEpoch() + 300;
        tokens.scopes = {u"openid"_s, u"offline_access"_s};
        account->deviceSession()->adoptOffline(tokens);
        const auto state = AccountStatePtr(new AccountState(account));

        // The lookup failed: this attempt connects with the stored ID and reports its error.
        QTRY_COMPARE(state->state(), AccountState::NetworkError);
        QCOMPARE(server->lookups, 1);
        QCOMPARE(account->davUser(), u"cjyet-yo"_s);

        // The next connection check looks the user up again.
        QTest::qWait(50);
        state->checkConnectivity();
        QTRY_COMPARE(account->davUser(), u"u723741i"_s);
        QCOMPARE(server->lookups, 2);
    }

    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
    }

    // The account wizard sets capabilities before the account is added, so push can be ready first.
    void disconnectedAccountWithReadyPushChecksConnectivityOnCreation()
    {
        FakeWebSocketServer fakeServer(webSocketPort);
        const auto account = createPushAccount();
        QVERIFY(fakeServer.authenticateAccount(account));
        QVERIFY(account->pushNotifications()->isReady());

        ConnectivityCountingAccountState accountState(account);
        QCOMPARE(accountState.state(), AccountState::Disconnected);

        QTRY_COMPARE(accountState.checkConnectivityCount, 1);
    }

    void disconnectedAccountWithReadyPushChecksConnectivityOnPeriodicCheck()
    {
        FakeWebSocketServer fakeServer(webSocketPort);
        const auto account = createPushAccount();
        QVERIFY(fakeServer.authenticateAccount(account));

        ConnectivityCountingAccountState accountState(account);
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);
        const auto checksAfterCreation = accountState.checkConnectivityCount;

        // Queues slotCheckConnection(), the slot the periodic timer also drives.
        accountState.systemOnlineConfigurationChanged();
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);

        QCOMPARE(accountState.state(), AccountState::Disconnected);
        QCOMPARE(accountState.checkConnectivityCount, checksAfterCreation + 1);
    }

    void connectedAccountWithReadyPushSkipsPeriodicCheck()
    {
        FakeWebSocketServer fakeServer(webSocketPort);
        const auto account = createPushAccount();
        ConnectivityCountingAccountState accountState(account);

        // Push becoming ready after the account state exists marks it Connected.
        const auto socket = fakeServer.authenticateAccount(account);
        QVERIFY(socket);
        QCOMPARE(accountState.state(), AccountState::Connected);
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);
        const auto checksWhileConnected = accountState.checkConnectivityCount;

        accountState.systemOnlineConfigurationChanged();
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);
        QCOMPARE(accountState.checkConnectivityCount, checksWhileConnected);

        // Control: the same trigger checks again once push is lost.
        QSignalSpy pushDisabledSpy(account.data(), &Account::pushNotificationsDisabled);
        socket->abort();
        QVERIFY(pushDisabledSpy.wait());
        QVERIFY(!account->pushNotifications()->isReady());

        accountState.systemOnlineConfigurationChanged();
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);
        QCOMPARE(accountState.checkConnectivityCount, checksWhileConnected + 1);
    }

    void signedOutAccountWithReadyPushSkipsPeriodicCheck()
    {
        FakeWebSocketServer fakeServer(webSocketPort);
        const auto account = createPushAccount();
        ConnectivityCountingAccountState accountState(account);
        QVERIFY(fakeServer.authenticateAccount(account));
        QCOMPARE(accountState.state(), AccountState::Connected);
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);

        accountState.signOutByUi();
        QCOMPARE(accountState.state(), AccountState::SignedOut);
        const auto checksAfterSignOut = accountState.checkConnectivityCount;

        accountState.systemOnlineConfigurationChanged();
        QCoreApplication::sendPostedEvents(&accountState, QEvent::MetaCall);
        QCOMPARE(accountState.checkConnectivityCount, checksAfterSignOut);
    }
};

QTEST_MAIN(TestAccountState)
#include "testaccountstate.moc"
