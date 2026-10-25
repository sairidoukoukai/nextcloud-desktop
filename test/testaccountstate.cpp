/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accessmanager.h"
#include "cloudflarebrowsertestutils.h"
#include "account.h"
#include "accountstate.h"
#include "cloudflareaccess.h"
#include "cloudflareaccesstestserver.h"
#include "cloudflarenativecredentialstestutils.h"
#include "cmd/simplesslerrorhandler.h"
#include "configfile.h"
#include "networkjobs.h"
#include "pushnotifications.h"
#include "pushnotificationstestutils.h"
#include "syncenginetestutils.h"

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

}

class TestAccountState : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void cloudflareFailurePreservesNativeCredentials_data()
    {
        QTest::addColumn<bool>("browser");
        QTest::newRow("service-public-status") << false;
        QTest::newRow("browser-public-status") << true;
    }

    void cloudflareFailurePreservesNativeCredentials()
    {
        QFETCH(bool, browser);
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
        const auto firstToken = OCC::Test::browserToken();
        const auto renewedToken = OCC::Test::browserToken(QDateTime::currentSecsSinceEpoch() + 7200);
        if (browser) {
            access.saveBrowserToken(base, firstToken);
        } else {
            access.save(true, base, "client"_L1, "old-secret"_L1);
        }
        server.respond = [&](const QByteArray &request) {
            if (request.toLower().contains("cf-access-client-secret: new-secret")
                || (request.toLower().contains("cf-access-token:") && request.contains(renewedToken))) {
                return CloudflareAccessTestServer::response(200, "{\"installed\":true}");
            }
            if (!request.startsWith("GET /status.php ")) {
                return CloudflareAccessTestServer::response(401, "{}");
            }
            return CloudflareAccessTestServer::response(200, "{\"installed\":true}");
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
        QTRY_COMPARE_WITH_TIMEOUT(edgeFailure.count(), 1, 12000);
        QCOMPARE(invalid.count(), 0);
        QCOMPARE(credentials->forgotten, 0);
        QCOMPARE(credentials->password(), "native-device-secret"_L1);
        QVERIFY(!state.isSignedOut());
        const auto checks = state.checkConnectivityCount;
        if (browser) {
            access.saveBrowserToken(base, renewedToken);
        } else {
            access.save(true, base, "client"_L1, "new-secret"_L1);
        }
        QTRY_VERIFY(state.checkConnectivityCount > checks);
        const auto job = account->sendRequest("GET", QUrl(base + "/request"_L1), request);
        connect(job, &SimpleNetworkJob::finishedSignal, account.data(), [](QNetworkReply *reply) {
            QCOMPARE(reply->error(), QNetworkReply::NoError);
            QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 200);
        });
        QSignalSpy resumed(job, &SimpleNetworkJob::finishedSignal);
        QTRY_COMPARE(resumed.count(), 1);
        if (browser) {
            QVERIFY(server.requests.last().toLower().contains("cf-access-token:"));
            QVERIFY(server.requests.last().contains(renewedToken));
        } else {
            QVERIFY(server.requests.last().toLower().contains("cf-access-client-secret: new-secret"));
        }
        QCOMPARE(credentials->forgotten, 0);
        QCOMPARE(server.requests.size(), 2);
        QVERIFY(!server.requests.at(1).startsWith("GET /status.php "));
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
        QTRY_COMPARE(server.requests.size(), 1);
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
            QCOMPARE(server.requests.size(), 2);
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
        QCOMPARE(invalid.count(), 0);
        QCOMPARE(credentials->forgotten, change == "sign-out"_L1 ? 1 : 0);
        const auto requiresLogin = change == "sign-out"_L1;
        if (requiresLogin) {
            QVERIFY(state.isSignedOut() || state.state() == AccountState::AskingCredentials);
        } else {
            QVERIFY(!state.isSignedOut());
        }
        QCOMPARE(credentials->ready(), !requiresLogin);
        QCOMPARE(server.requests.size(), change == "coalesced"_L1 ? 2 : 1);
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
