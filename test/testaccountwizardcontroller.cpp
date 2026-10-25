/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "abstractnetworkjob.h"
#include "cloudflarebrowsertestutils.h"
#include "accessmanager.h"
#include "account.h"
#include "cloudflareaccess.h"
#include "cloudflareaccesssettingscontroller.h"
#include "cloudflareaccesstestserver.h"
#include "configfile.h"
#include "folder.h"
#include "gui/creds/flow2auth.h"
#include "gui/localnetworkpermission.h"
#include "gui/wizard/accountwizardcontroller.h"
#include "httplogger.h"
#include "managedsettingstestutils.h"
#include "networkjobs.h"
#include "syncenginetestutils.h"
#include "theme.h"

#ifdef BUILD_FILE_PROVIDER_MODULE
#include "gui/macOS/fileprovider.h"
#endif

#include <QDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickWindow>
#include <QScopeGuard>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTest>

using namespace OCC;
using namespace Qt::StringLiterals;

namespace OCC
{

class AccountWizardControllerTestAccess
{
public:
    static void connectServerCheck(AccountWizardController &controller, const AccountPtr &account, CheckServerJob &job)
    {
        controller._account = account;
        QObject::connect(&job, &CheckServerJob::instanceNotFound, &controller, &AccountWizardController::slotNoServerFound);
    }

    static void foundServer(AccountWizardController &controller, const QUrl &url)
    {
        controller.slotFoundServer(url, {});
    }
    static void setLocalNetworkPermissionDenied(AccountWizardController &controller, bool denied)
    {
        controller._localNetworkPermissionCheck = [denied](const QUrl &, QObject *, std::function<void(bool)> callback) {
            callback(denied);
        };
    }

    static void findServerBehindRedirect(AccountWizardController &controller, const AccountPtr &account)
    {
        controller._account = account;
        controller.slotFindServerBehindRedirect();
    }

    static void setAccountUrl(AccountWizardController &controller, const QUrl &url)
    {
        controller._account = Account::create();
        controller._account->setUrl(url);
    }

    static void setSyncMode(AccountWizardController &controller, AccountWizardController::SyncMode mode)
    {
        controller._syncMode = mode;
    }

    static void chooseSyncModeAfterCapabilities(AccountWizardController &controller)
    {
        controller.chooseSyncModeAfterCapabilities();
    }

    static void setLocalSyncFolderPicker(AccountWizardController &controller, AccountWizardController::LocalSyncFolderPicker picker)
    {
        controller._localSyncFolderPicker = std::move(picker);
    }

    static FolderDefinition syncFolderDefinition(const AccountWizardController &controller)
    {
        return controller.syncFolderDefinition();
    }

    static void openInitialLocalSyncFolderDialog(AccountWizardController &controller)
    {
        controller.openLocalSyncFolderDialog(true);
    }

    static void setLocalSyncFolderOverride(AccountWizardController &controller, bool localSyncFolderOverride)
    {
        controller._localSyncFolderOverride = localSyncFolderOverride;
    }

    static bool localSyncFolderOverride(const AccountWizardController &controller)
    {
        return controller._localSyncFolderOverride;
    }

    static void setCurrentStep(AccountWizardController &controller, AccountWizardController::Step step)
    {
        controller.setCurrentStep(step);
    }
};

}

class TestAccountWizardController : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void browserWizardStartsAndResumesAfterCentralLogin()
    {
        QTemporaryDir directory;
        const auto previous = ConfigFile().configPath();
        const auto restore = qScopeGuard([&] {
            ConfigFile::setConfDir(previous);
        });
        ConfigFile::setConfDir(directory.path());
        CloudflareAccess session(nullptr, [](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            done({}, {});
        });
        OCC::Test::BrowserLogin helper;
        AccountWizardController wizard(nullptr, nullptr, &session, &helper);
        wizard.setServerUrl(u"https://nc.sairibus.com"_s);
        wizard.submitServerUrl();
        QVERIFY(wizard.busy());
        QCOMPARE(helper.requested, QUrl(u"https://nc.sairibus.com"_s));
        QVERIFY(!session.enabled());
        helper.succeed();
        QVERIFY(session.enabled());
        QVERIFY(session.ready());
        QVERIFY(wizard.busy()); // Server discovery follows the saved Access session.
        QCOMPARE(wizard.currentStep(), AccountWizardController::ServerStep);
        // Destruction removes the queued discovery before any production I/O.
    }

    void browserWizardCancellationStopsTheHelper()
    {
        QTemporaryDir directory;
        const auto previous = ConfigFile().configPath();
        const auto restore = qScopeGuard([&] {
            ConfigFile::setConfDir(previous);
        });
        ConfigFile::setConfDir(directory.path());
        CloudflareAccess session(nullptr, [](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            done({}, {});
        });
        OCC::Test::BrowserLogin helper;
        AccountWizardController wizard(nullptr, nullptr, &session, &helper);
        wizard.setServerUrl(u"https://nc.sairibus.com"_s);
        wizard.submitServerUrl();
        wizard.cancel();
        QVERIFY(helper.cancelled);
        QVERIFY(!session.enabled());
    }

    void cloudflareDiscoveryResponses_data()
    {
        QTest::addColumn<bool>("enabled");
        QTest::addColumn<QString>("outcome");
        for (const auto enabled : {false, true}) {
            for (const auto &outcome : {u"redirect"_s, u"html"_s, u"denied"_s, u"server-error"_s, u"success"_s}) {
                const auto name = (enabled ? u"token-"_s : u"no-token-"_s) + outcome;
                QTest::newRow(qPrintable(name)) << enabled << outcome;
            }
        }
    }

    void cloudflareDiscoveryResponses()
    {
        QFETCH(bool, enabled);
        QFETCH(QString, outcome);
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
        CloudflareAccessTestServer login;
        QVERIFY(server.isListening() && login.isListening());
        const auto base = server.baseUrl();
        if (enabled) {
            access.save(true, base, u"client.access"_s, u"secret"_s);
        }
        login.respond = [](const QByteArray &) {
            return CloudflareAccessTestServer::response(200, "<html>Cloudflare Access</html>");
        };
        server.respond = [&](const QByteArray &) {
            if (outcome == "redirect"_L1) {
                return CloudflareAccessTestServer::response(302, {}, (login.baseUrl() + u"/cdn-cgi/access/login/server?meta=private"_s).toUtf8());
            }
            if (outcome == "html"_L1) {
                return CloudflareAccessTestServer::response(200, "<html>Sign in</html>");
            }
            if (outcome == "denied"_L1 || outcome == "server-error"_L1) {
                return CloudflareAccessTestServer::response(outcome == "denied"_L1 ? 403 : 503, "{}");
            }
            return CloudflareAccessTestServer::response(200, R"({"installed":true,"version":"33.0.0","versionstring":"33.0.0"})");
        };
        const auto account = Account::create();
        account->setUrl(QUrl(base));
        const auto manager = new AccessManager(nullptr, &access);
        account->setCredentials(new FakeCredentials(manager));
        disconnect(manager, &QNetworkAccessManager::sslErrors, account.data(), &Account::slotHandleSslErrors);
        connect(manager, &QNetworkAccessManager::sslErrors, manager, [](QNetworkReply *reply) {
            reply->ignoreSslErrors();
        });
        AccountWizardController controller(nullptr, &access);
        AccountWizardControllerTestAccess::setLocalNetworkPermissionDenied(controller, false);
        const auto job = new CheckServerJob(account, &controller);
        AccountWizardControllerTestAccess::connectServerCheck(controller, account, *job);
        QSignalSpy found(job, &CheckServerJob::instanceFound);
        QSignalSpy failed(job, &CheckServerJob::instanceNotFound);
        QSignalSpy secureFailure(&controller, &AccountWizardController::secureConnectionFailed);
        job->start();
        QTRY_COMPARE(found.count() + failed.count(), 1);
        QCOMPARE(found.count(), outcome == "success"_L1 ? 1 : 0);
        QCOMPARE(secureFailure.count(), 0);
        QVERIFY(!controller.busy());
        QCOMPARE(server.requests.size(), 1);
        QVERIFY(server.requests.first().startsWith("GET /status.php "));
        const auto headers = server.requests.first().toLower();
        QCOMPARE(headers.contains("cf-access-client-id: client.access\r\n"), enabled);
        QCOMPARE(headers.contains("cf-access-client-secret: secret\r\n"), enabled);
        if (outcome == "redirect"_L1) {
            QCOMPARE(login.requests.size(), 1);
            QVERIFY(!login.requests.first().toLower().contains("cf-access-client-"));
            QVERIFY(controller.errorText().contains("Cloudflare Access"_L1));
            QVERIFY(controller.errorText().contains("Service Auth"_L1));
            QVERIFY(!controller.errorText().contains("private"_L1));
        }
        if (outcome == "success"_L1) {
            QVERIFY(controller.errorText().isEmpty());
        } else {
            QVERIFY(!controller.errorText().isEmpty());
        }
        QCOMPARE(access.enabled(), enabled);
        if (enabled) {
            QCOMPARE(access.clientSecret(), u"secret"_s);
        }
    }

    void cloudflareLoginFlow_data()
    {
        QTest::addColumn<bool>("poll");
        QTest::addColumn<QString>("outcome");
        QTest::addColumn<int>("requestTimeoutMilliseconds");
        QTest::addColumn<int>("expectedRequestTimeoutMilliseconds");
        QTest::newRow("success") << false << u"success"_s << 1000 << 1000;
        QTest::newRow("success-short-timeout") << false << u"success"_s << 5000 << 5000;
        QTest::newRow("success-capped-timeout") << false << u"success"_s << 300000 << 30000;
        QTest::newRow("success-default-timeout") << false << u"success"_s << 0 << 30000;
        for (const auto poll : {false, true}) {
            for (const auto &outcome : {u"malformed"_s, u"denied"_s, u"server-error"_s, u"timeout"_s, u"cancel"_s}) {
                const auto name = QString((poll ? u"poll-"_s : u"initiate-"_s) + outcome);
                QTest::newRow(qPrintable(name)) << poll << outcome << 1000 << 1000;
            }
        }
    }

    void cloudflareLoginFlow()
    {
        QFETCH(bool, poll);
        QFETCH(QString, outcome);
        QFETCH(int, requestTimeoutMilliseconds);
        QFETCH(int, expectedRequestTimeoutMilliseconds);
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto previous = ConfigFile().configPath();
        const auto previousTimeout = AbstractNetworkJob::httpTimeout;
        const auto restore = qScopeGuard([&] {
            ConfigFile::setConfDir(previous);
            AbstractNetworkJob::httpTimeout = previousTimeout;
        });
        ConfigFile::setConfDir(directory.path());
        AbstractNetworkJob::httpTimeout = requestTimeoutMilliseconds;
        CloudflareAccess access(nullptr, [](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            done({}, {});
        });
        CloudflareAccessTestServer server;
        QVERIFY(server.isListening());
        const auto base = server.baseUrl();
        access.save(true, base, u"client"_s, u"secret"_s);
        QVERIFY(access.ready());
        const auto initiation = QJsonDocument(QJsonObject{{u"poll"_s, QJsonObject{{u"token"_s, u"poll-token"_s}, {u"endpoint"_s, QString(base + u"/poll"_s)}}},
                                                          {u"login"_s, QString(base + u"/browser"_s)}})
                                    .toJson(QJsonDocument::Compact);
        const auto loggedIn =
            QJsonDocument(QJsonObject{{u"server"_s, base}, {u"loginName"_s, u"alice"_s}, {u"appPassword"_s, u"app-password"_s}}).toJson(QJsonDocument::Compact);
        server.respond = [&](const QByteArray &request) {
            const auto isPoll = request.startsWith("POST /poll ");
            if (isPoll == poll) {
                if (outcome == "malformed"_L1) {
                    return CloudflareAccessTestServer::response(200, "<html>Access</html>");
                }
                if (outcome == "denied"_L1 || outcome == "server-error"_L1) {
                    return CloudflareAccessTestServer::response(outcome == "denied"_L1 ? 403 : 503, "{}");
                }
                if (outcome == "timeout"_L1 || outcome == "cancel"_L1) {
                    return QByteArray{};
                }
            }
            return CloudflareAccessTestServer::response(200, isPoll ? loggedIn : initiation);
        };
        const auto account = Account::create();
        account->setUrl(QUrl(base));
        const auto manager = new AccessManager(nullptr, &access);
        account->setCredentials(new FakeCredentials(manager));
        // The fixture uses an intentionally untrusted local certificate.
        disconnect(manager, &QNetworkAccessManager::sslErrors, account.data(), &Account::slotHandleSslErrors);
        connect(manager, &QNetworkAccessManager::sslErrors, manager, [](QNetworkReply *reply) {
            reply->ignoreSslErrors();
        });
        QSignalSpy finished(manager, &QNetworkAccessManager::finished);
        connect(manager, &QNetworkAccessManager::finished, &access, [expectedRequestTimeoutMilliseconds](QNetworkReply *reply) {
            QCOMPARE(reply->request().transferTimeout(), expectedRequestTimeoutMilliseconds);
            QVERIFY(reply->request().attribute(HttpLogger::SensitiveBodyAttribute).toBool());
            QVERIFY(!HttpLogger::bodyLoggingAllowed(reply->request()));
        });
        auto flow = std::make_unique<Flow2Auth>(account.data(), nullptr);
        QSignalSpy result(flow.get(), &Flow2Auth::result);
        flow->copyLinkToClipboard();
        QTRY_COMPARE(server.requests.size(), 1);
        if (poll || outcome == "success"_L1) {
            QTRY_VERIFY(!flow->authorisationLink().isEmpty());
            QCOMPARE(flow->authorisationLink(), QUrl(base + u"/browser"_s));
            flow->slotPollNow();
            QTRY_COMPARE(server.requests.size(), 2);
            QVERIFY(server.requests.last().endsWith("token=poll-token"));
        }
        if (outcome == "cancel"_L1) {
            flow.reset();
            for (const auto socket : server.findChildren<QSslSocket *>()) {
                socket->write(CloudflareAccessTestServer::response(200, poll ? loggedIn : initiation));
                socket->disconnectFromHost();
            }
            QTRY_COMPARE(finished.count(), poll ? 2 : 1);
            QCOMPARE(result.count(), 0);
        } else {
            QTRY_COMPARE(result.count(), 1);
            QCOMPARE(result.first().first().value<Flow2Auth::Result>(), outcome == "success"_L1 ? Flow2Auth::LoggedIn : Flow2Auth::Error);
            if (outcome == "success"_L1) {
                QCOMPARE(result.first().at(2).toString(), u"alice"_s);
                QCOMPARE(result.first().at(3).toString(), u"app-password"_s);
            }
        }
        for (const auto &request : server.requests) {
            const auto headers = request.toLower();
            QVERIFY(headers.contains("cf-access-client-id: client\r\n"));
            QVERIFY(headers.contains("cf-access-client-secret: secret\r\n"));
        }
        QVERIFY(access.enabled());
        QCOMPARE(access.clientSecret(), u"secret"_s);
    }

    void authenticationProbeTimeouts_data()
    {
        QTest::addColumn<bool>("redirectProbe");
        QTest::addColumn<int>("configuredTimeoutMilliseconds");
        QTest::addColumn<int>("expectedTimeoutMilliseconds");
        QTest::newRow("auth-detection") << false << 300000 << 30000;
        QTest::newRow("redirect") << true << 300000 << 2000;
        QTest::newRow("short-redirect") << true << 500 << 500;
    }

    void authenticationProbeTimeouts()
    {
        QFETCH(bool, redirectProbe);
        QFETCH(int, configuredTimeoutMilliseconds);
        QFETCH(int, expectedTimeoutMilliseconds);
        const auto previousTimeout = AbstractNetworkJob::httpTimeout;
        const auto restore = qScopeGuard([&] {
            AbstractNetworkJob::httpTimeout = previousTimeout;
        });
        AbstractNetworkJob::httpTimeout = configuredTimeoutMilliseconds;
        FakeFolder folder{{}, {}, {}, false};
        QList<QNetworkRequest> requests;
        folder.setServerOverride([&](QNetworkAccessManager::Operation operation, const QNetworkRequest &request, QIODevice *) -> QNetworkReply * {
            requests.append(request);
            return new FakeErrorReply(operation, request, folder.account()->networkAccessManager(), 404);
        });
        if (redirectProbe) {
            AccountWizardController controller;
            AccountWizardControllerTestAccess::findServerBehindRedirect(controller, folder.account());
            QVERIFY(!requests.isEmpty());
            QCOMPARE(requests.first().transferTimeout(), expectedTimeoutMilliseconds);
        } else {
            const auto job = new DetermineAuthTypeJob(folder.account());
            QSignalSpy determined(job, &DetermineAuthTypeJob::authType);
            job->start();
            QTRY_COMPARE(determined.count(), 1);
            QCOMPARE(requests.size(), 2);
            for (const auto &request : requests) {
                QCOMPARE(request.transferTimeout(), expectedTimeoutMilliseconds);
            }
        }
    }

    void cloudflareDialogUsesProductionController()
    {
        Q_INIT_RESOURCE(resources);
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
        AccountWizardController controller(nullptr, &access);
        controller.setServerUrl(u"cloud.example/nextcloud"_s);
        QQmlEngine engine;
        engine.addImportPath(QFINDTESTDATA("qml/imports"));
        engine.addImportPath(QFINDTESTDATA("../theme"));
        QQmlComponent component(&engine, QUrl(u"qrc:/qml/src/gui/wizard/qml/AccountWizardWindow.qml"_s));
        QTRY_VERIFY2(component.isReady(), qPrintable(component.errorString()));
        auto window = std::unique_ptr<QQuickWindow>(
            qobject_cast<QQuickWindow *>(component.createWithInitialProperties({{u"controller"_s, QVariant::fromValue(static_cast<QObject *>(&controller))}})));
        QVERIFY2(window, qPrintable(component.errorString()));
        window->show();
        const auto dialog = window->findChild<QObject *>(u"cloudflareAccessDialog"_s);
        QVERIFY(dialog);
        QVERIFY(QMetaObject::invokeMethod(dialog, "open"));
        QTRY_VERIFY(dialog->property("visible").toBool());
        QVERIFY(!dialog->findChild<QObject *>(u"cloudflareAccessServerUrl"_s));
        const auto server = dialog->findChild<QObject *>(u"cloudflareAccessServer"_s);
        QVERIFY(server);
        QCOMPARE(server->property("text").toString(), u"https://cloud.example/nextcloud"_s);
        const auto toggle = dialog->findChild<QQuickItem *>(u"cloudflareAccessEnabled"_s);
        QVERIFY(toggle);
        const auto point = toggle->mapToScene(QPointF(toggle->width() / 2, toggle->height() / 2)).toPoint();
        QTest::mouseClick(window.get(), Qt::LeftButton, Qt::NoModifier, point);
        QTRY_VERIFY(toggle->property("checked").toBool());
        const auto apply = dialog->findChild<QObject *>(u"cloudflareAccessApply"_s);
        QVERIFY(apply);
        QVERIFY(QMetaObject::invokeMethod(apply, "clicked"));
        QVERIFY(dialog->property("visible").toBool());
        const auto error = dialog->findChild<QObject *>(u"cloudflareAccessError"_s);
        QVERIFY(error);
        QVERIFY(!error->property("text").toString().isEmpty());
        dialog->findChild<QObject *>(u"cloudflareAccessClientId"_s)->setProperty("text", u"client"_s);
        dialog->findChild<QObject *>(u"cloudflareAccessClientSecret"_s)->setProperty("text", u"secret"_s);
        QVERIFY(QMetaObject::invokeMethod(apply, "clicked"));
        QTRY_VERIFY(!dialog->property("visible").toBool());
        QVERIFY(access.enabled());
        QCOMPARE(access.serverUrl(), QUrl(u"https://cloud.example"_s));
        QCOMPARE(access.clientSecret(), "secret"_L1);

        controller.setServerUrl(u"https://cloud.example:443/another-path"_s);
        QVERIFY(QMetaObject::invokeMethod(dialog, "open"));
        QTRY_VERIFY(dialog->property("visible").toBool());
        QVERIFY(toggle->property("checked").toBool());
        QCOMPARE(dialog->findChild<QObject *>(u"cloudflareAccessClientSecret"_s)->property("text").toString(), u"secret"_s);
        controller.setServerUrl(u"https://other.example"_s);
        QCOMPARE(server->property("text").toString(), u"https://other.example"_s);
        QVERIFY(!toggle->property("checked").toBool());
        QVERIFY(dialog->findChild<QObject *>(u"cloudflareAccessClientSecret"_s)->property("text").toString().isEmpty());
        QVERIFY(!apply->property("enabled").toBool());
        QVERIFY(QMetaObject::invokeMethod(dialog, "close"));
        QVERIFY(access.enabled());
        QCOMPARE(access.serverUrl(), QUrl(u"https://cloud.example"_s));
    }

    void cloudflareUsesMainServerAddress_data()
    {
        QTest::addColumn<QString>("input");
        QTest::addColumn<QString>("normalized");
        QTest::addColumn<bool>("configured");
        QTest::addColumn<bool>("accepted");
        QTest::newRow("no-scheme") << u" cloud.example/nextcloud "_s << u"https://cloud.example/nextcloud"_s << true << true;
        QTest::newRow("default-port") << u"https://CLOUD.example:443/path"_s << u"https://CLOUD.example:443/path"_s << true << true;
        QTest::newRow("other-server") << u"https://other.example"_s << u"https://other.example"_s << false << false;
        QTest::newRow("other-port") << u"https://cloud.example:8443"_s << u"https://cloud.example:8443"_s << false << false;
        QTest::newRow("http") << u"http://cloud.example"_s << u"http://cloud.example"_s << false << false;
        QTest::newRow("empty") << QString{} << QString{} << false << false;
        QTest::newRow("embedded-credentials") << u"https://user:password@cloud.example"_s << u"https://user:password@cloud.example"_s << true << false;
        QTest::newRow("query") << u"https://cloud.example?key=value"_s << u"https://cloud.example?key=value"_s << true << false;
        QTest::newRow("fragment") << u"https://cloud.example#fragment"_s << u"https://cloud.example#fragment"_s << true << false;
    }

    void cloudflareUsesMainServerAddress()
    {
        QFETCH(QString, input);
        QFETCH(QString, normalized);
        QFETCH(bool, configured);
        QFETCH(bool, accepted);
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
        access.save(true, u"https://cloud.example"_s, u"client"_s, u"secret"_s);
        AccountWizardController wizard(nullptr, &access);
        QSignalSpy changed(&wizard, &AccountWizardController::serverUrlChanged);
        wizard.setServerUrl(input);
        QCOMPARE(changed.count(), input.isEmpty() ? 0 : 1);
        QCOMPARE(wizard.cloudflareServerUrl(), normalized);
        const auto settings = qobject_cast<CloudflareAccessSettingsController *>(wizard.cloudflareAccess());
        QVERIFY(settings);
        QCOMPARE(settings->isConfiguredForServer(wizard.cloudflareServerUrl()), configured);
        QSignalSpy saved(settings, &CloudflareAccessSettingsController::saved);
        settings->save(true, wizard.cloudflareServerUrl(), u"client"_s, u"secret"_s);
        QCOMPARE(saved.count(), 1);
        QCOMPARE(saved.first().first().toBool(), accepted);
        QCOMPARE(settings->error().isEmpty(), accepted);
        QCOMPARE(access.serverUrl(), accepted ? CloudflareAccess::origin(QUrl(normalized)) : QUrl(u"https://cloud.example"_s));
    }

    void cloudflareConfigurationOutlivesWizardCancellation()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto previous = ConfigFile().configPath();
        const auto restore = qScopeGuard([&] {
            ConfigFile::setConfDir(previous);
        });
        ConfigFile::setConfDir(directory.path());
        auto entries = QHash<QString, QByteArray>();
        auto finishSave = std::function<void()>();
        CloudflareAccess access(nullptr, [&](const QString &key, const std::optional<QByteArray> &data, CloudflareAccess::Completion done) {
            if (data && !data->isEmpty()) {
                finishSave = [&, key, data, done] {
                    entries.insert(key, *data);
                    done({}, {});
                };
            } else {
                done(entries.value(key), {});
            }
        });
        {
            AccountWizardController wizard(nullptr, &access);
            const auto controller = qobject_cast<CloudflareAccessSettingsController *>(wizard.cloudflareAccess());
            QVERIFY(controller);
            controller->save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
            QVERIFY(access.busy());
            QSignalSpy finished(&wizard, &AccountWizardController::finished);
            wizard.cancel();
            QCOMPARE(finished.count(), 1);
        }
        QVERIFY(finishSave);
        finishSave();
        QVERIFY(access.enabled());
        CloudflareAccess restored(nullptr, [&](const QString &key, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            done(entries.value(key), {});
        });
        QVERIFY(restored.enabled());
        QCOMPARE(restored.clientSecret(), "secret"_L1);
    }

    void cloudflareUnavailableCredentialsPreventServerDiscovery()
    {
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
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        CloudflareAccess unavailable(nullptr, [](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion) { });
        AccountWizardController wizard(nullptr, &unavailable);
        wizard.setServerUrl("https://cloud.example"_L1);
        wizard.submitServerUrl();
        QVERIFY(!wizard.busy());
        QVERIFY(!wizard.errorText().isEmpty());
        QCOMPARE(wizard.currentStep(), AccountWizardController::ServerStep);
        AccountWizardController redirected(nullptr, &unavailable);
        AccountWizardControllerTestAccess::setAccountUrl(redirected, QUrl("http://cloud.example"_L1));
        AccountWizardControllerTestAccess::foundServer(redirected, QUrl("https://cloud.example"_L1));
        QVERIFY(!redirected.busy());
        QVERIFY(!redirected.errorText().isEmpty());
        QVERIFY(redirected.authStatusText().isEmpty());
        QSignalSpy finished(&redirected, &AccountWizardController::finished);
        redirected.finish();
        QCOMPARE(finished.count(), 0);
    }

    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
    }

    // Keeps tests off the device policy of the machine running them.
    void init()
    {
        ConfigFile::setDeviceSourcesFactory([] {
            return std::vector<std::unique_ptr<SettingSource>>{};
        });
    }

    void cleanup()
    {
        ConfigFile::setDeviceSourcesFactory({});
    }

    void choosingLocalSyncFolderKeepsItsBookmarkForTheSyncFolder()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto bookmarkData = "bookmark"_ba;

        AccountWizardController controller;
        AccountWizardControllerTestAccess::setLocalSyncFolderPicker(controller, [&](const QString &, const QString &, const auto &completion) {
            completion(dir.path(), bookmarkData);
        });
        controller.chooseLocalSyncFolder();

        QCOMPARE(controller.localSyncFolder(), QDir::fromNativeSeparators(dir.path()));
        const auto definition = AccountWizardControllerTestAccess::syncFolderDefinition(controller);
        QCOMPARE(definition.localPath, FolderDefinition::prepareLocalPath(dir.path()));
        QCOMPARE(definition.securityScopedBookmarkData, bookmarkData);
    }

    void cancellingLocalSyncFolderPickerKeepsTheChosenFolder()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        const auto bookmarkData = "bookmark"_ba;
        auto cancel = false;

        AccountWizardController controller;
        AccountWizardControllerTestAccess::setLocalSyncFolderPicker(controller, [&](const QString &, const QString &, const auto &completion) {
            completion(cancel ? QString{} : dir.path(), cancel ? QByteArray{} : bookmarkData);
        });
        controller.chooseLocalSyncFolder();
        cancel = true;
        controller.chooseLocalSyncFolder();

        QCOMPARE(controller.localSyncFolder(), QDir::fromNativeSeparators(dir.path()));
        QCOMPARE(AccountWizardControllerTestAccess::syncFolderDefinition(controller).securityScopedBookmarkData, bookmarkData);
    }

    void choosingLocalSyncFolderWithoutBookmarkDropsThePreviousBookmark()
    {
        QTemporaryDir firstDir;
        QTemporaryDir secondDir;
        QVERIFY(firstDir.isValid());
        QVERIFY(secondDir.isValid());
        auto chosenDir = firstDir.path();
        auto chosenBookmarkData = "bookmark"_ba;

        AccountWizardController controller;
        AccountWizardControllerTestAccess::setLocalSyncFolderPicker(controller, [&](const QString &, const QString &, const auto &completion) {
            completion(chosenDir, chosenBookmarkData);
        });
        controller.chooseLocalSyncFolder();
        chosenDir = secondDir.path();
        chosenBookmarkData.clear();
        controller.chooseLocalSyncFolder();

        QCOMPARE(controller.localSyncFolder(), QDir::fromNativeSeparators(secondDir.path()));
        QVERIFY(AccountWizardControllerTestAccess::syncFolderDefinition(controller).securityScopedBookmarkData.isEmpty());
    }

    void closingReportsAcceptedOnlyAfterSetupCompleted()
    {
        AccountWizardController controller;
        QCOMPARE(controller.resultOnClose(), static_cast<int>(QDialog::Rejected));

        AccountWizardControllerTestAccess::setCurrentStep(controller, AccountWizardController::SyncOptionsStep);
        QCOMPARE(controller.resultOnClose(), static_cast<int>(QDialog::Rejected));

        AccountWizardControllerTestAccess::setCurrentStep(controller, AccountWizardController::CompletedStep);
        QCOMPARE(controller.resultOnClose(), static_cast<int>(QDialog::Accepted));
    }

    void localSyncFolderPickerOpensOnceWhilePending()
    {
        auto pickerCalls = 0;
        std::function<void(const QString &, const QByteArray &)> pendingCompletion;

        AccountWizardController controller;
        AccountWizardControllerTestAccess::setLocalSyncFolderPicker(controller, [&](const QString &, const QString &, const auto &completion) {
            ++pickerCalls;
            pendingCompletion = completion;
        });
        controller.chooseLocalSyncFolder();
        controller.chooseLocalSyncFolder();
        QCOMPARE(pickerCalls, 1);

        pendingCompletion({}, {});
        controller.chooseLocalSyncFolder();
        QCOMPARE(pickerCalls, 2);
    }

    void localSyncFolderPickerCompletionAfterControllerIsGoneIsIgnored()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());
        std::function<void(const QString &, const QByteArray &)> pendingCompletion;

        {
            AccountWizardController controller;
            AccountWizardControllerTestAccess::setLocalSyncFolderPicker(controller, [&](const QString &, const QString &, const auto &completion) {
                pendingCompletion = completion;
            });
            controller.chooseLocalSyncFolder();
        }

        QVERIFY(pendingCompletion);
        pendingCompletion(dir.path(), "bookmark"_ba);
    }

    void initialLocalSyncFolderSelectionKeepsTheOverride()
    {
        QTemporaryDir dir;
        QVERIFY(dir.isValid());

        AccountWizardController controller;
        AccountWizardControllerTestAccess::setLocalSyncFolderPicker(controller, [&](const QString &, const QString &, const auto &completion) {
            completion(dir.path(), {});
        });
        AccountWizardControllerTestAccess::setLocalSyncFolderOverride(controller, true);
        AccountWizardControllerTestAccess::openInitialLocalSyncFolderDialog(controller);
        QVERIFY(AccountWizardControllerTestAccess::localSyncFolderOverride(controller));

        controller.chooseLocalSyncFolder();
        QVERIFY(!AccountWizardControllerTestAccess::localSyncFolderOverride(controller));
    }

    void switchesAwayFromVirtualFilesWhenEnforcedOff()
    {
        ConfigFile::setDeviceSourcesFactory([] {
            std::vector<std::unique_ptr<SettingSource>> sources;
            sources.push_back(std::make_unique<MapSource>(SettingSourceType::PlatformPolicy,
                                                          EnforcementState::Enforced,
                                                          200,
                                                          QVariantMap{{QStringLiteral("virtualFilesMode"), QStringLiteral("off")}}));
            return sources;
        });

        AccountWizardController controller;
        AccountWizardControllerTestAccess::setAccountUrl(controller, QUrl(QStringLiteral("https://cloud.example")));
        AccountWizardControllerTestAccess::setSyncMode(controller, AccountWizardController::VirtualFiles);
        QCOMPARE(controller.syncMode(), AccountWizardController::VirtualFiles);

        AccountWizardControllerTestAccess::chooseSyncModeAfterCapabilities(controller);

        QVERIFY(controller.syncMode() != AccountWizardController::VirtualFiles);
        QVERIFY(controller.needsSyncOptions());
        QVERIFY(controller.localSyncFolderRequired());
    }

    void normalizesCommonServerUrlSuffixes()
    {
        QCOMPARE(AccountWizardController::normalizeServerUrlInput(QStringLiteral(" https://cloud.example/index.php ")),
                 QStringLiteral("https://cloud.example/"));
        QCOMPARE(AccountWizardController::normalizeServerUrlInput(QStringLiteral("https://cloud.example/remote.php/dav/"), QStringLiteral("remote.php/dav/")),
                 QStringLiteral("https://cloud.example/"));
    }

    void defaultsToHttpsWhenSchemeIsMissing()
    {
        QCOMPARE(AccountWizardController::normalizeServerUrlInput(QString()), QString());
        QCOMPARE(AccountWizardController::normalizeServerUrlInput(QStringLiteral("cloud.example")), QStringLiteral("https://cloud.example"));
        QCOMPARE(AccountWizardController::normalizeServerUrlInput(QStringLiteral("cloud.example:8080")), QStringLiteral("https://cloud.example:8080"));
        QCOMPARE(AccountWizardController::normalizeServerUrlInput(QStringLiteral("http://cloud.example")), QStringLiteral("http://cloud.example"));
    }

    void localNetworkPermissionCheckIgnoresInvalidUrls()
    {
        auto callbackCalled = false;
        auto denied = true;

        LocalNetworkPermission::checkDeniedForConnection({}, this, [&callbackCalled, &denied](bool result) {
            callbackCalled = true;
            denied = result;
        });

        QTRY_VERIFY(callbackCalled);
        QVERIFY(!denied);
    }

    void localNetworkPermissionFailureSkipsSecureConnectionRecovery()
    {
        AccountWizardController controller;
        AccountWizardControllerTestAccess::setLocalNetworkPermissionDenied(controller, true);
        QSignalSpy recoverySpy(&controller, &AccountWizardController::secureConnectionFailed);

        QVERIFY(QMetaObject::invokeMethod(&controller,
                                          "slotNoServerFoundTimeout",
                                          Qt::DirectConnection,
                                          Q_ARG(QUrl, QUrl(QStringLiteral("https://cloud.example")))));

        QCOMPARE(recoverySpy.count(), 0);
        QCOMPARE(controller.errorText(), LocalNetworkPermission::deniedError());
    }

    void serverTimeoutDoesNotOfferSecureConnectionRecovery()
    {
        AccountWizardController controller;
        const auto serverUrl = QUrl(QStringLiteral("https://cloud.example"));
        AccountWizardControllerTestAccess::setLocalNetworkPermissionDenied(controller, false);
        AccountWizardControllerTestAccess::setAccountUrl(controller, serverUrl);
        QSignalSpy recoverySpy(&controller, &AccountWizardController::secureConnectionFailed);

        QVERIFY(QMetaObject::invokeMethod(&controller, "slotNoServerFoundTimeout", Qt::DirectConnection, Q_ARG(QUrl, serverUrl)));

        QCOMPARE(recoverySpy.count(), 0);
        QVERIFY(!controller.errorText().isEmpty());
    }

    void secureConnectionRecoveryRequiresTlsFailure_data()
    {
        QTest::addColumn<QNetworkReply::NetworkError>("error");
        QTest::addColumn<bool>("protectedServer");
        QTest::addColumn<bool>("hsts");
        QTest::newRow("tls") << QNetworkReply::SslHandshakeFailedError << false << false;
        QTest::newRow("tls-hsts") << QNetworkReply::SslHandshakeFailedError << false << true;
        QTest::newRow("tls-protected") << QNetworkReply::SslHandshakeFailedError << true << false;
        QTest::newRow("dns") << QNetworkReply::HostNotFoundError << false << false;
        QTest::newRow("connection") << QNetworkReply::ConnectionRefusedError << false << false;
        QTest::newRow("timeout") << QNetworkReply::TimeoutError << false << false;
        QTest::newRow("http") << QNetworkReply::ContentAccessDenied << false << false;
    }

    void secureConnectionRecoveryRequiresTlsFailure()
    {
        QFETCH(QNetworkReply::NetworkError, error);
        QFETCH(bool, protectedServer);
        QFETCH(bool, hsts);
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
        const auto server = QUrl(u"https://cloud.example"_s);
        if (protectedServer) {
            access.save(true, server.toString(), u"client.access"_s, u"secret"_s);
        }
        AccountWizardController controller(nullptr, &access);
        AccountWizardControllerTestAccess::setAccountUrl(controller, server);
        AccountWizardControllerTestAccess::setLocalNetworkPermissionDenied(controller, false);
        FakeErrorReply reply(QNetworkAccessManager::GetOperation, QNetworkRequest(server), nullptr, 0);
        reply.setError(error, u"Test connection error"_s);
        if (hsts) {
            reply.setRawHeader("Strict-Transport-Security", "max-age=31536000");
        }
        QSignalSpy recovery(&controller, &AccountWizardController::secureConnectionFailed);
        QVERIFY(QMetaObject::invokeMethod(&controller, "slotNoServerFound", Qt::DirectConnection, Q_ARG(QNetworkReply *, &reply)));
        QCOMPARE(recovery.count(), error == QNetworkReply::SslHandshakeFailedError ? 1 : 0);
        if (!recovery.isEmpty()) {
            QCOMPARE(recovery.first().first().toString(), server.host());
            QCOMPARE(recovery.first().at(1).toBool(), !hsts && !protectedServer);
        }
    }
    void invalidServerUrlStaysOnServerStep()
    {
        QFETCH(QString, serverUrl);

        AccountWizardController controller;
        QSignalSpy errorSpy(&controller, &AccountWizardController::errorTextChanged);

        controller.setServerUrl(serverUrl);
        controller.submitServerUrl();

        QCOMPARE(controller.currentStep(), AccountWizardController::ServerStep);
        QVERIFY(!controller.errorText().isEmpty());
        QCOMPARE(errorSpy.count(), 1);
    }

    void invalidServerUrlStaysOnServerStep_data()
    {
        QTest::addColumn<QString>("serverUrl");

        QTest::newRow("empty") << QString();
        QTest::newRow("plain text with spaces") << QStringLiteral("not a url");
        QTest::newRow("missing host") << QStringLiteral("https://");
        QTest::newRow("missing host with path") << QStringLiteral("https:///remote.php/dav");
        QTest::newRow("invalid scheme marker") << QStringLiteral("://cloud.example");
    }

    void rejectsIncompleteManualProxyBeforeServerCheck()
    {
        AccountWizardController controller;
        QSignalSpy errorSpy(&controller, &AccountWizardController::errorTextChanged);

        controller.setServerUrl(QStringLiteral("https://cloud.example"));
        controller.setProxyMode(2);
        controller.submitServerUrl();

        QCOMPARE(controller.currentStep(), AccountWizardController::ServerStep);
        QCOMPARE(controller.errorText(), QStringLiteral("Proxy settings are incomplete."));
        QCOMPARE(errorSpy.count(), 1);
    }

    void validatesManualProxyConfiguration()
    {
        AccountWizardController controller;
        QSignalSpy proxySpy(&controller, &AccountWizardController::proxySettingsChanged);

        QVERIFY(controller.proxySettingsValid());
        QCOMPARE(controller.proxyMode(), 0);

        controller.setProxyMode(2);
        QCOMPARE(controller.proxyMode(), 2);
        QCOMPARE(controller.manualProxyType(), 0);
        QVERIFY(!controller.proxySettingsValid());

        controller.setProxyHost(QStringLiteral("proxy.example"));
        QVERIFY(controller.proxySettingsValid());

        controller.setProxyAuthenticationRequired(true);
        QVERIFY(!controller.proxySettingsValid());

        controller.setProxyUser(QStringLiteral("alice"));
        QVERIFY(!controller.proxySettingsValid());

        controller.setProxyPassword(QStringLiteral("secret"));
        QVERIFY(controller.proxySettingsValid());

        controller.setManualProxyType(1);
        QCOMPARE(controller.manualProxyType(), 1);
        QCOMPARE(controller.proxyMode(), 2);
        QVERIFY(controller.proxySettingsValid());

        QVERIFY(proxySpy.count() >= 6);
    }

    void boundsManualProxyPort()
    {
        AccountWizardController controller;

        controller.setProxyPort(0);
        QCOMPARE(controller.proxyPort(), 1);

        controller.setProxyPort(70000);
        QCOMPARE(controller.proxyPort(), 65535);

        controller.setProxyPort(3128);
        QCOMPARE(controller.proxyPort(), 3128);
    }

    void seedsProxySettingsFromManagedDefault()
    {
        ConfigFile::setDeviceSourcesFactory([] {
            std::vector<std::unique_ptr<SettingSource>> sources;
            sources.push_back(std::make_unique<MapSource>(
                SettingSourceType::PlatformDefault,
                EnforcementState::NotEnforced,
                20,
                QVariantMap{{u"proxyType"_s, int(QNetworkProxy::HttpProxy)}, {u"proxyHost"_s, u"proxy.example.com"_s}, {u"proxyPort"_s, 8080}}));
            return sources;
        });

        AccountWizardController controller;

        QCOMPARE(controller.proxyMode(), 2);
        QCOMPARE(controller.manualProxyType(), 0);
        QCOMPARE(controller.proxyHost(), u"proxy.example.com"_s);
        QCOMPARE(controller.proxyPort(), 8080);
    }

    void warnsWhenManualProxyTargetsLocalhost_data()
    {
        QTest::addColumn<QString>("serverUrl");
        QTest::addColumn<bool>("warns");

        QTest::newRow("localhost") << QStringLiteral("http://localhost") << true;
        QTest::newRow("localhost without scheme") << QStringLiteral("localhost") << true;
        QTest::newRow("ipv4 loopback") << QStringLiteral("http://127.0.0.1") << true;
        QTest::newRow("ipv4 loopback subnet") << QStringLiteral("http://127.12.34.56") << true;
        QTest::newRow("ipv6 loopback") << QStringLiteral("http://[::1]") << true;
        QTest::newRow("remote host") << QStringLiteral("https://cloud.example") << false;
    }

    void warnsWhenManualProxyTargetsLocalhost()
    {
        QFETCH(QString, serverUrl);
        QFETCH(bool, warns);

        AccountWizardController controller;

        controller.setServerUrl(serverUrl);
        QVERIFY(!controller.showProxyLocalhostWarning());

        controller.setProxyMode(2);
        controller.setProxyHost(QStringLiteral("proxy.example"));

        QCOMPARE(controller.showProxyLocalhostWarning(), warns);
    }

    void systemProxyAndNoProxyDoNotRequireManualSettings()
    {
        AccountWizardController controller;

        controller.setProxyMode(2);
        QVERIFY(!controller.proxySettingsValid());

        controller.setProxyMode(1);
        QCOMPARE(controller.proxyMode(), 1);
        QVERIFY(controller.proxySettingsValid());
        QVERIFY(!controller.showProxyLocalhostWarning());

        controller.setProxyMode(0);
        QCOMPARE(controller.proxyMode(), 0);
        QVERIFY(controller.proxySettingsValid());
    }

    void manualProxyTypeDoesNotSelectManualProxy()
    {
        AccountWizardController controller;

        controller.setProxyMode(0);
        controller.setManualProxyType(0);
        QCOMPARE(controller.proxyMode(), 0);
        QVERIFY(controller.proxySettingsValid());

        controller.setProxyMode(1);
        controller.setManualProxyType(1);
        QCOMPARE(controller.proxyMode(), 1);
        QVERIFY(controller.proxySettingsValid());
    }

    void advancedSafeguardsEmitChanges()
    {
        AccountWizardController controller;
        QSignalSpy askLargeSpy(&controller, &AccountWizardController::askBeforeLargeFoldersChanged);
        QSignalSpy thresholdSpy(&controller, &AccountWizardController::largeFolderThresholdMbChanged);
        QSignalSpy externalSpy(&controller, &AccountWizardController::askBeforeExternalStorageChanged);

        controller.setAskBeforeLargeFolders(!controller.askBeforeLargeFolders());
        controller.setLargeFolderThresholdMb(controller.largeFolderThresholdMb() + 1);
        controller.setAskBeforeExternalStorage(!controller.askBeforeExternalStorage());

        QCOMPARE(askLargeSpy.count(), 1);
        QCOMPARE(thresholdSpy.count(), 1);
        QCOMPARE(externalSpy.count(), 1);
    }

    void exposesProxySettingsAvailability()
    {
        AccountWizardController controller;

        QCOMPARE(controller.proxySettingsAvailable(), !Theme::instance()->doNotUseProxy());
    }

    void preservesForcedOverrideServerChoices()
    {
        auto theme = Theme::instance();
        const auto previousOverrideServerUrl = theme->overrideServerUrl();
        const auto previousForceOverrideServerUrl = theme->forceOverrideServerUrl();
        const auto restoreTheme = qScopeGuard([theme, previousOverrideServerUrl, previousForceOverrideServerUrl] {
            theme->setOverrideServerUrl(previousOverrideServerUrl);
            theme->setForceOverrideServerUrl(previousForceOverrideServerUrl);
        });

        theme->setOverrideServerUrl(
            QStringLiteral("["
                           R"({"name": "Primary", "url": "https://primary.example"},)"
                           R"({"name": "Secondary", "url": "https://secondary.example"})"
                           "]"));
        theme->setForceOverrideServerUrl(true);

        AccountWizardController controller;

        QCOMPARE(controller.overrideServerNames(), QStringList({QStringLiteral("Primary"), QStringLiteral("Secondary")}));
        QVERIFY(controller.overrideServerSelectionRequired());
        QCOMPARE(controller.overrideServerIndex(), 0);
        QCOMPARE(controller.serverUrl(), QStringLiteral("https://primary.example"));
        QVERIFY(!controller.serverUrlEditable());

        controller.setOverrideServerIndex(1);

        QCOMPARE(controller.overrideServerIndex(), 1);
        QCOMPARE(controller.serverUrl(), QStringLiteral("https://secondary.example"));
    }

    void startsLoginFlowAutomaticallyForPersistedOverrideServerUrl()
    {
        ConfigFile cfg;
        const auto previousConfiguredOverrideServerUrl = cfg.overrideServerUrl();
        auto theme = Theme::instance();
        const auto previousOverrideServerUrl = theme->overrideServerUrl();
        const auto previousForceOverrideServerUrl = theme->forceOverrideServerUrl();
        const auto previousStartLoginFlowAutomatically = theme->startLoginFlowAutomatically();
        const auto restoreConfiguration = qScopeGuard(
            [&cfg, theme, previousConfiguredOverrideServerUrl, previousOverrideServerUrl, previousForceOverrideServerUrl, previousStartLoginFlowAutomatically] {
                cfg.setOverrideServerUrl(previousConfiguredOverrideServerUrl);
                theme->setOverrideServerUrl(previousOverrideServerUrl);
                theme->setForceOverrideServerUrl(previousForceOverrideServerUrl);
                theme->setStartLoginFlowAutomatically(previousStartLoginFlowAutomatically);
            });

        cfg.setOverrideServerUrl(QStringLiteral("https://cloud.example"));
        theme->setOverrideServerUrl({});
        theme->setForceOverrideServerUrl(false);
        theme->setStartLoginFlowAutomatically(false);

        AccountWizardController controller;

        QCOMPARE(controller.serverUrl(), QStringLiteral("https://cloud.example"));
        QVERIFY(!controller.serverUrlEditable());
        QVERIFY(controller.startLoginFlowAutomatically());
    }

#ifdef Q_OS_LINUX
    void defaultSyncModeIsNotVirtualFilesOnLinux()
    {
        AccountWizardController controller;

        if (controller.canUseVirtualFiles()) {
            QCOMPARE(controller.syncMode(), AccountWizardController::SyncEverything);
        }
    }
#endif

#ifdef BUILD_FILE_PROVIDER_MODULE
    // Keep this test last: it redirects the configuration directory.
    void followsAppLevelFileProviderMode()
    {
        QTemporaryDir dir;
        ConfigFile::setConfDir(dir.path());
        QVERIFY(dir.isValid());

        ConfigFile cfg;
        cfg.setMacFileProviderModeEnabled(false);

        {
            AccountWizardController controller;
            QVERIFY(!controller.canUseVirtualFiles());
            QVERIFY(!controller.isUsingFileProvider());
            QVERIFY(controller.canUseClassicSync());
            QVERIFY(controller.localSyncFolderRequired());
        }

        cfg.setMacFileProviderModeEnabled(true);

        {
            AccountWizardController controller;
            QCOMPARE(controller.canUseVirtualFiles(), Mac::FileProvider::available());
            QCOMPARE(controller.isUsingFileProvider(), Mac::FileProvider::available());
            QCOMPARE(controller.localSyncFolderRequired(), !Mac::FileProvider::available());
        }
    }
#endif
};

QTEST_MAIN(TestAccountWizardController)
#include "testaccountwizardcontroller.moc"
