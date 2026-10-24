/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accessmanager.h"
#include "cloudflareaccess.h"
#include "cloudflareaccesstestserver.h"
#include "configfile.h"
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
        failing.save(true, "https://other.example"_L1, "new-client"_L1, "new-secret"_L1);
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
        for (const auto name : {"CF-Access-Client-Id", "cf-access-client-secret", "CF-ACCESS-CLIENT-SECRET"}) {
            QCOMPARE(HttpLogger::redactedHeaderValue(name, "sensitive"), "[redacted]");
        }
        QCOMPARE(HttpLogger::redactedHeaderValue("authorization", "Basic sensitive"), "Basic [redacted]");
        QCOMPARE(HttpLogger::redactedHeaderValue("Content-Type", "application/json"), "application/json");
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
