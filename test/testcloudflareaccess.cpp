/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accessmanager.h"
#include "cloudflarebrowserlogin.h"
#include "cloudflarebrowsertestutils.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonArray>
#include "cloudflareaccess.h"
#include "cloudflareaccesstestserver.h"
#include "configfile.h"
#include "cookiejar.h"
#include "creds/keychainchunk.h"
#include "httplogger.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QScopeGuard>
#include <QSettings>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTest>

#include <atomic>
#include <thread>

using namespace OCC;
using namespace Qt::StringLiterals;
using OCC::Test::browserToken;

class TestCloudflareAccess : public QObject
{
    Q_OBJECT

    std::unique_ptr<QTemporaryDir> _directory;
    QHash<QString, QByteArray> _entries;

    CloudflareAccess::CredentialStore storage()
    {
        return [this](const QString &key, const std::optional<QByteArray> &data, CloudflareAccess::Completion done) {
            if (data) {
                if (data->isEmpty()) {
                    _entries.remove(key);
                } else {
                    _entries.insert(key, *data);
                }
            }
            done(_entries.value(key), {});
        };
    }

private Q_SLOTS:
    void initTestCase()
    {
        QStandardPaths::setTestModeEnabled(true);
    }

    void init()
    {
        _directory = std::make_unique<QTemporaryDir>();
        QVERIFY(_directory->isValid());
        ConfigFile::setConfDir(_directory->path());
        _entries.clear();
    }

    void browserSessionsAreAccountAndOriginBound()
    {
        CloudflareAccess first(nullptr, storage(), std::chrono::seconds(1), "account-one"_L1);
        CloudflareAccess other(nullptr, storage(), std::chrono::seconds(1), "account-two"_L1);
        const auto token = browserToken();
        first.saveBrowserToken("https://cloud.example"_L1, token);
        QVERIFY(first.ready());
        QVERIFY(first.browserMode());
        QVERIFY(!other.enabled());
        CloudflareAccess restored(nullptr, storage(), std::chrono::seconds(1), "account-one"_L1);
        QVERIFY(restored.enabled());
        QVERIFY(restored.ready());
        auto request = QNetworkRequest(QUrl("https://cloud.example/remote.php/dav"_L1));
        request.setRawHeader("CF-Access-Client-Id", "stale-service-id");
        request.setRawHeader("CF-Access-Client-Secret", "stale-service-secret");
        QVERIFY(restored.prepareRequest(request).isEmpty());
        QCOMPARE(request.rawHeader("cf-access-token"), token);
        QVERIFY(!request.hasRawHeader("CF-Access-Client-Id"));
        QVERIFY(!request.hasRawHeader("CF-Access-Client-Secret"));
        QVERIFY(CloudflareAccess::hasCredentials(request));
        request.setUrl(QUrl("https://elsewhere.example/"_L1));
        QVERIFY(restored.prepareRequest(request).isEmpty());
        QVERIFY(!request.hasRawHeader("cf-access-token"));
        QFile config(ConfigFile().configFile());
        QVERIFY(config.open(QIODevice::ReadOnly));
        QVERIFY(!config.readAll().contains(token));
        first.saveBrowserToken("https://cloud.example"_L1, browserToken(QDateTime::currentSecsSinceEpoch() + 3600, "eeeeeeee-1111-4444-9999-111111111111"_L1));
        QVERIFY(!first.error().isEmpty());
        first.clear();
        CloudflareAccess removed(nullptr, storage(), std::chrono::seconds(1), "account-one"_L1);
        QVERIFY(!removed.enabled());
    }

    void staleServiceChallengeCannotMatchBrowserSession()
    {
        CloudflareAccess service(nullptr, storage());
        CloudflareAccess browser(nullptr, storage(), std::chrono::seconds(1), "account-one"_L1);
        service.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        auto request = QNetworkRequest(QUrl("https://cloud.example/remote.php/dav"_L1));
        QVERIFY(service.prepareRequest(request).isEmpty());
        browser.saveBrowserToken("https://cloud.example"_L1, browserToken());
        QVERIFY(service.matchesCurrentRequest(request));
        QVERIFY(!browser.matchesCurrentRequest(request));
        QVERIFY(browser.prepareRequest(request).isEmpty());
        QVERIFY(browser.matchesCurrentRequest(request));
        QVERIFY(!service.matchesCurrentRequest(request));
    }

    void browserExpiryAndMalformedTokensAreRejected()
    {
        CloudflareAccess access(nullptr, storage(), std::chrono::seconds(1), "account-one"_L1);
        for (const auto &token : {QByteArray("not-a-jwt"), browserToken(QDateTime::currentSecsSinceEpoch() - 1), QByteArray(20000, 'x')}) {
            access.saveBrowserToken("https://cloud.example"_L1, token);
            QVERIFY(!access.error().isEmpty());
            QVERIFY(!access.enabled());
        }
        access.saveBrowserToken("https://cloud.example"_L1, browserToken(QDateTime::currentSecsSinceEpoch() + 1));
        QVERIFY(access.ready());
        QTRY_VERIFY(!access.ready());
        auto request = QNetworkRequest(QUrl("https://cloud.example/remote.php/dav"_L1));
        QVERIFY(!access.prepareRequest(request).isEmpty());
        QVERIFY(!request.hasRawHeader("cf-access-token"));
    }

    void browserHelperSuccessAndPrivateCacheCleanup()
    {
        const auto helper = QString::fromUtf8(CLOUDFLARE_TEST_HELPER);
        QFile executable(helper);
        QVERIFY(executable.open(QIODevice::ReadOnly));
        const auto digest = QCryptographicHash::hash(executable.readAll(), QCryptographicHash::Sha256).toHex();
        const auto report = _directory->filePath("helper-report.json"_L1);
        qputenv("NEXTCLOUD_TEST_HELPER_REPORT", report.toUtf8());
        qputenv("NEXTCLOUD_TEST_HELPER_MODE", "success");
        const auto token = browserToken();
        qputenv("NEXTCLOUD_TEST_HELPER_TOKEN", token);
        const auto environment = qgetenv("HOME");
        CloudflareBrowserLogin login(nullptr, helper, digest);
        QSignalSpy finished(&login, &CloudflareBrowserLogin::finished);
        login.start(QUrl("https://cloud.example/a-path"_L1));
        QTRY_COMPARE(finished.size(), 1);
        QCOMPARE(finished[0][0].toByteArray(), token);
        QVERIFY(finished[0][1].toString().isEmpty());
        QVERIFY(!login.busy());
        QFile captured(report);
        QVERIFY(captured.open(QIODevice::ReadOnly));
        const auto info = QJsonDocument::fromJson(captured.readAll()).object();
        QVERIFY(!QFileInfo::exists(info.value("cache"_L1).toString()));
        QCOMPARE(info.value("arguments"_L1).toArray().last().toString(), "https://cloud.example"_L1);
        QCOMPARE(qgetenv("HOME"), environment);
        qunsetenv("NEXTCLOUD_TEST_HELPER_REPORT");
        qunsetenv("NEXTCLOUD_TEST_HELPER_MODE");
        qunsetenv("NEXTCLOUD_TEST_HELPER_TOKEN");
    }

    void browserHelperFailures_data()
    {
        QTest::addColumn<QString>("mode");
        QTest::addColumn<bool>("cancel");
        QTest::newRow("process error") << "failure" << false;
        QTest::newRow("malformed response") << "success" << false;
        QTest::newRow("timeout") << "wait" << false;
        QTest::newRow("cancel") << "wait" << true;
    }

    void browserHelperFailures()
    {
        QFETCH(QString, mode);
        QFETCH(bool, cancel);
        const auto helper = QString::fromUtf8(CLOUDFLARE_TEST_HELPER);
        QFile executable(helper);
        QVERIFY(executable.open(QIODevice::ReadOnly));
        const auto digest = QCryptographicHash::hash(executable.readAll(), QCryptographicHash::Sha256).toHex();
        const auto report = _directory->filePath("helper-report.json"_L1);
        qputenv("NEXTCLOUD_TEST_HELPER_REPORT", report.toUtf8());
        qputenv("NEXTCLOUD_TEST_HELPER_MODE", mode.toUtf8());
        qputenv("NEXTCLOUD_TEST_HELPER_TOKEN", "synthetic invalid token");
        CloudflareBrowserLogin login(nullptr, helper, digest, std::chrono::milliseconds(1000));
        QSignalSpy finished(&login, &CloudflareBrowserLogin::finished);
        login.start(QUrl("https://cloud.example"_L1));
        QTRY_VERIFY(QFileInfo::exists(report));
        if (cancel) {
            login.cancel();
        }
        QTRY_COMPARE(finished.size(), 1);
        QVERIFY(finished[0][0].toByteArray().isEmpty());
        QVERIFY(!finished[0][1].toString().isEmpty());
        QVERIFY(!login.busy());
        QFile captured(report);
        QVERIFY(captured.open(QIODevice::ReadOnly));
        QVERIFY(!QFileInfo::exists(QJsonDocument::fromJson(captured.readAll()).object().value("cache"_L1).toString()));
        qunsetenv("NEXTCLOUD_TEST_HELPER_REPORT");
        qunsetenv("NEXTCLOUD_TEST_HELPER_MODE");
        qunsetenv("NEXTCLOUD_TEST_HELPER_TOKEN");
    }

    void browserHelperRejectsUnverifiedBinary()
    {
        CloudflareBrowserLogin login(nullptr, QString::fromUtf8(CLOUDFLARE_TEST_HELPER), QByteArray(64, '0'));
        QSignalSpy finished(&login, &CloudflareBrowserLogin::finished);
        login.start(QUrl("https://cloud.example"_L1));
        QCOMPARE(finished.size(), 1);
        QVERIFY(finished[0][0].toByteArray().isEmpty());
        QVERIFY(!login.busy());
    }

    void validation_data()
    {
        QTest::addColumn<QString>("url");
        QTest::addColumn<QString>("id");
        QTest::addColumn<QString>("secret");
        QTest::addColumn<bool>("valid");
        QTest::newRow("https") << "https://cloud.example/nextcloud" << "client.access" << "secret" << true;
        QTest::newRow("ipv6") << "https://[::1]:8443" << "client" << "secret" << true;
        QTest::newRow("http") << "http://cloud.example" << "client" << "secret" << false;
        QTest::newRow("missing host") << "https://" << "client" << "secret" << false;
        QTest::newRow("userinfo") << "https://user:password@cloud.example" << "client" << "secret" << false;
        QTest::newRow("empty userinfo") << "https://@cloud.example" << "client" << "secret" << false;
        QTest::newRow("query") << "https://cloud.example?token=secret" << "client" << "secret" << false;
        QTest::newRow("fragment") << "https://cloud.example#secret" << "client" << "secret" << false;
        QTest::newRow("empty id") << "https://cloud.example" << "" << "secret" << false;
        QTest::newRow("empty secret") << "https://cloud.example" << "client" << "" << false;
        QTest::newRow("newline") << "https://cloud.example" << "client" << "secret\r\nInjected: yes" << false;
        QTest::newRow("null") << "https://cloud.example" << "client" << QString::fromLatin1("secret\0value", 12) << false;
        QTest::newRow("unicode") << "https://cloud.example" << "client" << QString(QChar(0x100)) << false;
    }

    void validation()
    {
        QFETCH(QString, url);
        QFETCH(QString, id);
        QFETCH(QString, secret);
        QFETCH(bool, valid);
        QCOMPARE(CloudflareAccess::validate(true, url, id, secret).isEmpty(), valid);
        QVERIFY(CloudflareAccess::validate(false, url, id, secret).isEmpty());
    }

    void savesRestoresAndDisables()
    {
        CloudflareAccess access(nullptr, storage());
        QVERIFY(!access.enabled());
        QVERIFY(access.ready());
        access.save(true, "https://CLOUD.example:443/nextcloud/"_L1, "client.access"_L1, "secret"_L1);
        QVERIFY(access.error().isEmpty());
        QCOMPARE(access.serverUrl(), QUrl("https://cloud.example"_L1));
        QVERIFY(access.protects(QUrl("wss://cloud.example:443/push"_L1)));
        QVERIFY(!access.protects(QUrl("https://cloud.example:8443"_L1)));
        QVERIFY(!access.protects(QUrl("http://cloud.example"_L1)));
        QVERIFY(!access.protects(QUrl("https://other.example"_L1)));

        QFile config(ConfigFile().configFile());
        QVERIFY(config.open(QIODevice::ReadOnly));
        const auto contents = config.readAll();
        config.close();
        QVERIFY(!contents.contains("secret"));
        QVERIFY(!contents.contains("client.access"));

        CloudflareAccess restored(nullptr, storage());
        QVERIFY(restored.ready());
        QCOMPARE(restored.clientId(), "client.access"_L1);
        QCOMPARE(restored.clientSecret(), "secret"_L1);
        restored.save(false, {}, {}, {});
        QVERIFY(!restored.enabled());
        CloudflareAccess disabled(nullptr, storage());
        QVERIFY(!disabled.enabled());
        QCOMPARE(disabled.clientSecret(), "secret"_L1);
        disabled.save(true, disabled.serverUrl().toString(), "new-client"_L1, "rotated-secret"_L1);
        QCOMPARE(_entries.size(), 1);
        QCOMPARE(disabled.clientSecret(), "rotated-secret"_L1);
    }

    void removesStaleHeadersAndPreservesAuthorization()
    {
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        auto request = QNetworkRequest(QUrl("https://cloud.example/status.php"_L1));
        request.setRawHeader("Authorization", "Basic nextcloud-credentials");
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        QVERIFY(access.prepareRequest(request).isEmpty());
        QCOMPARE(request.rawHeader("CF-Access-Client-Secret"), "secret");
        QCOMPARE(request.rawHeader("Authorization"), "Basic nextcloud-credentials");
        QCOMPARE(request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(), int(QNetworkRequest::SameOriginRedirectPolicy));
        request.setUrl(QUrl("https://other.example"_L1));
        QVERIFY(access.prepareRequest(request).isEmpty());
        QVERIFY(!request.hasRawHeader("CF-Access-Client-Secret"));
        request.setUrl(QUrl("https://cloud.example"_L1));
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QVERIFY(access.prepareRequest(request).isEmpty());
        QCOMPARE(request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(), int(QNetworkRequest::ManualRedirectPolicy));
        access.save(false, {}, {}, {});
        QVERIFY(access.prepareRequest(request).isEmpty());
        QVERIFY(!request.hasRawHeader("CF-Access-Client-Id"));
    }

    void failedSaveKeepsWorkingCredentials()
    {
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        CloudflareAccess failing(nullptr, [this](const QString &key, const std::optional<QByteArray> &data, CloudflareAccess::Completion done) {
            done(data ? QByteArray{} : _entries.value(key), data ? "Storage unavailable"_L1 : QString{});
        });
        failing.save(true, "https://cloud.example"_L1, "new-client"_L1, "new-secret"_L1);
        QVERIFY(!failing.busy());
        QVERIFY(!failing.error().isEmpty());
        QVERIFY(failing.protects(QUrl("https://cloud.example"_L1)));
        QCOMPARE(failing.clientSecret(), "secret"_L1);
    }

    void delayedLoadAndStaleCompletion()
    {
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        auto pending = QList<CloudflareAccess::Completion>();
        auto values = QList<QByteArray>();
        CloudflareAccess delayed(nullptr, [&](const QString &key, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            pending.append(std::move(done));
            values.append(_entries.value(key));
        });
        QVERIFY(delayed.busy());
        QVERIFY(!delayed.ready());
        auto request = QNetworkRequest(QUrl("https://cloud.example"_L1));
        QVERIFY(!delayed.prepareRequest(request).isEmpty());
        AccessManager manager(nullptr, &delayed);
        const auto reply = manager.get(request);
        QSignalSpy finished(reply, &QNetworkReply::finished);
        QTRY_COMPARE(finished.count(), 1);
        QCOMPARE(reply->error(), QNetworkReply::ContentAccessDenied);
        delayed.load();
        pending[0](values[0], {});
        QVERIFY(delayed.busy());
        pending[1](values[1], {});
        QVERIFY(delayed.ready());
        QVERIFY(delayed.prepareRequest(request).isEmpty());
        QCOMPARE(request.rawHeader("CF-Access-Client-Secret"), "secret");
    }

    void changingOriginsRequiresExplicitDisable()
    {
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://first.example"_L1, "first-id"_L1, "first-secret"_L1);
        const auto entries = _entries;
        access.save(true, "https://second.example"_L1, "second-id"_L1, "second-secret"_L1);
        QVERIFY(!access.error().isEmpty());
        QVERIFY(!access.busy());
        QCOMPARE(access.serverUrl(), QUrl("https://first.example"_L1));
        QCOMPARE(access.clientSecret(), "first-secret"_L1);
        QCOMPARE(_entries, entries);
        access.save(false, {}, {}, {});
        access.save(true, "https://second.example"_L1, "second-id"_L1, "second-secret"_L1);
        QVERIFY(access.error().isEmpty());
        QCOMPARE(access.serverUrl(), QUrl("https://second.example"_L1));
        QCOMPARE(_entries.size(), 1);
    }

    void timeoutAndDestroyedOwner()
    {
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        auto pending = CloudflareAccess::Completion();
        auto timed = std::make_unique<CloudflareAccess>(
            nullptr,
            [&](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
                pending = std::move(done);
            },
            std::chrono::milliseconds(1));
        QTRY_VERIFY(!timed->busy());
        QVERIFY(!timed->ready());
        QVERIFY(!timed->error().isEmpty());
        timed.reset();
        pending("{}", {});
    }

    void malformedOrUnavailableCredential_data()
    {
        QTest::addColumn<QByteArray>("payload");
        QTest::addColumn<QString>("storageError");
        QTest::newRow("bad JSON") << QByteArray("{broken") << QString{};
        QTest::newRow("missing secret") << QByteArray("{\"id\":\"client\"}") << QString{};
        QTest::newRow("wrong server") << QByteArray("{\"origin\":\"https://other.example\",\"id\":\"client\",\"secret\":\"secret\"}") << QString{};
        QTest::newRow("locked store") << QByteArray{} << QString("Credential store is locked");
    }

    void malformedOrUnavailableCredential()
    {
        QFETCH(QByteArray, payload);
        QFETCH(QString, storageError);
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1);
        CloudflareAccess restored(nullptr, [&](const QString &, const std::optional<QByteArray> &, CloudflareAccess::Completion done) {
            done(payload, storageError);
        });
        QVERIFY(!restored.ready());
        QVERIFY(!restored.busy());
        QVERIFY(!restored.error().isEmpty());
        QVERIFY(restored.clientSecret().isEmpty());
    }

    void headerRedaction()
    {
        for (const auto name : {"CF-Access-Client-Id",
                                "cf-access-client-secret",
                                "CF-ACCESS-CLIENT-SECRET",
                                "cf-access-token",
                                "CF-ACCESS-TOKEN",
                                "Cookie",
                                "cOoKiE",
                                "Set-Cookie",
                                "SET-COOKIE",
                                "Cf-Access-Jwt-Assertion",
                                "Proxy-Authorization"}) {
            QCOMPARE(HttpLogger::redactedHeaderValue(name, "sensitive"), "[redacted]");
        }
        QCOMPARE(HttpLogger::redactedHeaderValue("authorization", "Basic sensitive"), "Basic [redacted]");
        QCOMPARE(HttpLogger::redactedHeaderValue("Content-Type", "application/json"), "application/json");
    }

    void credentialExchangeBodiesArePrivate()
    {
        auto request = QNetworkRequest(QUrl("https://cloud.example/arbitrary-poll-endpoint"_L1));
        QVERIFY(HttpLogger::bodyLoggingAllowed(request));
        request.setAttribute(HttpLogger::SensitiveBodyAttribute, true);
        QVERIFY(!HttpLogger::bodyLoggingAllowed(request));
        request.setAttribute(HttpLogger::SensitiveBodyAttribute, false);
        for (const auto name : {"CF-Access-Client-Id", "cf-access-client-secret", "cf-access-token"}) {
            request.setRawHeader(name, "synthetic-credential");
            QVERIFY(!HttpLogger::bodyLoggingAllowed(request));
            request.setRawHeader(name, QByteArray{});
        }
    }

    void accessCookiesCannotSurviveTokenChanges()
    {
        CloudflareAccessTestServer server;
        QVERIFY(server.isListening());
        server.respond = [](const QByteArray &) {
            auto response = CloudflareAccessTestServer::response(200, "{}");
            response.replace(
                "Connection: close\r\n",
                "Connection: close\r\nSet-Cookie: CF_Authorization=reusable-cookie; Secure; Path=/\r\nSet-Cookie: nc_session=session; Secure; Path=/\r\n");
            return response;
        };
        CloudflareAccess access(nullptr, storage());
        access.save(true, server.baseUrl(), "client"_L1, "old-secret"_L1);
        AccessManager manager(nullptr, &access);
        connect(&manager, &QNetworkAccessManager::sslErrors, &manager, [](QNetworkReply *reply) {
            reply->ignoreSslErrors();
        });
        const auto request = QNetworkRequest(QUrl(server.baseUrl() + "/request"_L1));
        for (const auto stage : {0, 1, 2}) {
            if (stage == 1) {
                access.save(true, server.baseUrl(), "client"_L1, "new-secret"_L1);
            } else if (stage == 2) {
                access.save(false, {}, {}, {});
            }
            const auto reply = manager.get(request);
            QSignalSpy finished(reply, &QNetworkReply::finished);
            QTRY_COMPARE(finished.count(), 1);
            QCOMPARE(reply->error(), QNetworkReply::NoError);
            QVERIFY(!server.requests.last().contains("CF_Authorization"));
            if (stage > 0) {
                QVERIFY(server.requests.last().contains("nc_session=session"));
            }
            QCOMPARE(reply->request().rawHeader("CF-Access-Client-Secret"), stage == 2 ? QByteArray{} : QByteArray(stage == 0 ? "old-secret" : "new-secret"));
            reply->deleteLater();
        }
    }

    void oversizedCredentialsAreNotSaved()
    {
        CloudflareAccess access(nullptr, storage());
        const auto oversized = QString(KeychainChunk::ChunkSize * KeychainChunk::MaxChunks, u'x');
        access.save(true, "https://cloud.example"_L1, "client"_L1, oversized);
        QVERIFY(!access.enabled());
        QVERIFY(!access.error().isEmpty());
        QVERIFY(_entries.isEmpty());
    }

    void staleWriteCannotReplaceNewerCredentials()
    {
        auto pending = QList<std::function<void()>>();
        auto backend = storage();
        CloudflareAccess access(nullptr, [&](const QString &key, const std::optional<QByteArray> &data, CloudflareAccess::Completion done) {
            if (data && !data->isEmpty()) {
                pending.append([=] {
                    backend(key, data, done);
                });
            } else {
                backend(key, data, done);
            }
        });
        access.save(true, "https://cloud.example"_L1, "old-client"_L1, "old-secret"_L1);
        access.save(true, "https://cloud.example"_L1, "new-client"_L1, "new-secret"_L1);
        QCOMPARE(pending.size(), 2);
        pending[1]();
        pending[0]();
        QCOMPARE(access.clientSecret(), "new-secret"_L1);
        QCOMPARE(_entries.size(), 1);
        CloudflareAccess restored(nullptr, backend);
        QCOMPARE(restored.clientSecret(), "new-secret"_L1);
    }

    void compatibilityIsCheckedAgainBeforeCommit()
    {
        auto pending = CloudflareAccess::Completion();
        CloudflareAccess access(nullptr, [&](const QString &, const std::optional<QByteArray> &data, CloudflareAccess::Completion done) {
            if (data && !data->isEmpty()) {
                pending = std::move(done);
            }
        });
        auto incompatible = false;
        access.save(true, "https://cloud.example"_L1, "client"_L1, "secret"_L1, [&](const QUrl &) {
            return incompatible ? "Incompatible account"_L1 : QString{};
        });
        QVERIFY(access.busy());
        incompatible = true;
        pending({}, {});
        QVERIFY(!access.enabled());
        QVERIFY(!access.busy());
        QCOMPARE(access.error(), "Incompatible account"_L1);
    }

    void concurrentRequestsObserveACompleteConfiguration()
    {
        CloudflareAccess access(nullptr, storage());
        access.save(true, "https://first.example"_L1, "first-id"_L1, "first-secret"_L1);
        auto stop = std::atomic_bool(false);
        auto inconsistent = std::atomic_bool(false);
        auto requests = std::atomic_int(0);
        auto worker = std::thread([&] {
            while (!stop.load()) {
                for (const auto first : {true, false}) {
                    auto request = QNetworkRequest(QUrl(first ? "https://first.example"_L1 : "https://second.example"_L1));
                    const auto error = access.prepareRequest(request);
                    const auto id = request.rawHeader("CF-Access-Client-Id");
                    const auto secret = request.rawHeader("CF-Access-Client-Secret");
                    if (error.isEmpty() && !id.isEmpty()
                        && (id != (first ? "first-id" : "second-id") || secret != (first ? "first-secret" : "second-secret"))) {
                        inconsistent.store(true);
                    }
                    ++requests;
                }
            }
        });
        const auto join = qScopeGuard([&] {
            stop.store(true);
            if (worker.joinable()) {
                worker.join();
            }
        });
        QTRY_VERIFY(requests.load() > 0);
        constexpr auto rotations = 100;
        for (auto index = 0; index < rotations; ++index) {
            const auto first = index % 2 == 0;
            access.save(false, {}, {}, {});
            access.save(true,
                        first ? "https://first.example"_L1 : "https://second.example"_L1,
                        first ? "first-id"_L1 : "second-id"_L1,
                        first ? "first-secret"_L1 : "second-secret"_L1);
            std::this_thread::yield();
        }
        stop.store(true);
        worker.join();
        QVERIFY(!inconsistent.load());
    }

    void outgoingRequestsAndRedirects()
    {
        CloudflareAccessTestServer tls;
        QVERIFY(tls.isListening());
        const auto base = tls.baseUrl();
        auto requests = QList<QByteArray>();
        tls.respond = [&](const QByteArray &data) {
            if (data.startsWith("GET /redirect ")) {
                return CloudflareAccessTestServer::response(302, {}, base.toUtf8() + "/request");
            }
            if (data.startsWith("GET /external ")) {
                return CloudflareAccessTestServer::response(302, {}, "https://127.0.0.1:" + QByteArray::number(tls.serverPort()) + "/request");
            }
            requests.append(data.toLower());
            if (data.startsWith("GET /denied ") || data.startsWith("GET /expired ")) {
                return CloudflareAccessTestServer::response(data.startsWith("GET /denied ") ? 403 : 401, {});
            }
            return CloudflareAccessTestServer::response(200, "{\"ok\":true}");
        };
        CloudflareAccess access(nullptr, storage());
        access.save(true, base, "client"_L1, "secret"_L1);
        AccessManager manager(nullptr, &access);
        connect(&manager, &QNetworkAccessManager::sslErrors, &manager, [](QNetworkReply *reply) {
            reply->ignoreSslErrors();
        });
        for (const auto verb : {"GET", "POST", "PROPFIND", "PUT", "DELETE"}) {
            auto request = QNetworkRequest(QUrl(base + "/request"_L1));
            QVERIFY2(request.url().isValid(), qPrintable(request.url().errorString()));
            request.setRawHeader("Authorization", "Basic nextcloud-credentials");
            const auto reply = manager.sendCustomRequest(request, verb);
            QSignalSpy finished(reply, &QNetworkReply::finished);
            QTRY_COMPARE(finished.count(), 1);
            QCOMPARE(reply->error(), QNetworkReply::NoError);
            QVERIFY(requests.last().contains("cf-access-client-id: client\r\n"));
            QVERIFY(requests.last().contains("cf-access-client-secret: secret\r\n"));
            QVERIFY(requests.last().contains("authorization: basic nextcloud-credentials\r\n"));
            reply->deleteLater();
        }
        auto request = QNetworkRequest(QUrl(base + "/redirect"_L1));
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        auto reply = manager.get(request);
        QSignalSpy sameOrigin(reply, &QNetworkReply::finished);
        QTRY_COMPARE(sameOrigin.count(), 1);
        QCOMPARE(reply->error(), QNetworkReply::NoError);
        QVERIFY(requests.last().contains("cf-access-client-secret: secret\r\n"));
        const auto count = requests.size();
        request.setUrl(QUrl(base + "/external"_L1));
        reply = manager.get(request);
        QSignalSpy crossOrigin(reply, &QNetworkReply::finished);
        QTRY_COMPARE(crossOrigin.count(), 1);
        QCOMPARE(reply->error(), QNetworkReply::InsecureRedirectError);
        QCOMPARE(requests.size(), count);
        for (const auto path : {"/redirect"_L1, "/external"_L1}) {
            request.setUrl(QUrl(base + path));
            request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
            reply = manager.get(request);
            QSignalSpy redirect(reply, &QNetworkReply::finished);
            QTRY_COMPARE(redirect.count(), 1);
            QCOMPARE(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(), 302);
            auto follow = reply->request();
            follow.setUrl(reply->url().resolved(reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl()));
            reply = manager.get(follow);
            QSignalSpy followed(reply, &QNetworkReply::finished);
            QTRY_COMPARE(followed.count(), 1);
            QCOMPARE(reply->error(), QNetworkReply::NoError);
            QCOMPARE(requests.last().contains("cf-access-client-secret: secret\r\n"), path == "/redirect"_L1);
        }
        for (const auto path : {"/denied"_L1, "/expired"_L1}) {
            request.setUrl(QUrl(base + path));
            reply = manager.get(request);
            QSignalSpy denied(reply, &QNetworkReply::finished);
            QTRY_COMPARE(denied.count(), 1);
            QVERIFY(reply->error() != QNetworkReply::NoError);
            QCOMPARE(access.clientSecret(), "secret"_L1);
            QVERIFY(access.ready());
        }
        request = reply->request();
        QVERIFY(request.hasRawHeader("CF-Access-Client-Secret"));
        access.save(false, {}, {}, {});
        request.setUrl(QUrl(base + "/request"_L1));
        reply = manager.get(request);
        QSignalSpy disabled(reply, &QNetworkReply::finished);
        QTRY_COMPARE(disabled.count(), 1);
        QVERIFY(!requests.last().contains("cf-access-client-secret"));
    }
};

QTEST_GUILESS_MAIN(TestCloudflareAccess)
#include "testcloudflareaccess.moc"
