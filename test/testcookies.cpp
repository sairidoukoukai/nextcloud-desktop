/*
 * SPDX-FileCopyrightText: 2021 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2020 ownCloud GmbH
 * SPDX-License-Identifier: CC0-1.0
 *
 * This software is in the public domain, furnished "as is", without technical
 * support, and with no warranty, express or implied, as to its usefulness for
 * any purpose.
 */

#include <QtTest>

#include "libsync/cookiejar.h"

using namespace OCC;
using namespace Qt::StringLiterals;

class TestCookies : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void serviceTokensDoNotRetainAccessCookies()
    {
        const auto url = QUrl("https://cloud.example/"_L1);
        auto authorization = QNetworkCookie("CF_Authorization", "reusable-access-cookie");
        authorization.setDomain("."_L1 + url.host());
        authorization.setPath("/"_L1);
        authorization.setSecure(true);
        const auto expiration = QDateTime::currentDateTimeUtc().addDays(1);
        authorization.setExpirationDate(QDateTime::fromSecsSinceEpoch(expiration.toSecsSinceEpoch()));
        auto session = authorization;
        session.setName("nextcloud-session");
        session.setValue("nextcloud-cookie");

        CookieJar jar(nullptr, false);
        QVERIFY(jar.setCookiesFromUrl({authorization, session}, url));
        QCOMPARE(jar.cookiesForUrl(url), QList<QNetworkCookie>{session});
        QCOMPARE(jar.allCookies(), QList<QNetworkCookie>{session});

        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const auto path = directory.filePath("cookies.db"_L1);
        CookieJar legacy;
        legacy.setAllCookies({authorization, session});
        QVERIFY(legacy.save(path));
        CookieJar restored(nullptr, false);
        QVERIFY(restored.restore(path));
        QCOMPARE(restored.allCookies(), QList<QNetworkCookie>{session});

        jar.setAllCookies({authorization, session});
        QCOMPARE(jar.cookiesForUrl(url), QList<QNetworkCookie>{session});
        QVERIFY(jar.save(path));
        QVERIFY(legacy.restore(path));
        QCOMPARE(legacy.allCookies(), QList<QNetworkCookie>{session});
    }

    void unmanagedAccessCookiesRemainAvailable()
    {
        const auto url = QUrl("https://cloud.example/"_L1);
        auto cookie = QNetworkCookie("CF_Authorization", "legacy-cookie");
        cookie.setPath("/"_L1);
        cookie.setSecure(true);
        cookie.setExpirationDate(QDateTime::currentDateTimeUtc().addDays(1));
        CookieJar jar;
        QVERIFY(jar.setCookiesFromUrl({cookie}, url));
        QCOMPARE(jar.cookiesForUrl(url).size(), 1);
        jar.setAllowCloudflareAccessCookies(false);
        QVERIFY(jar.cookiesForUrl(url).isEmpty());
        QVERIFY(jar.allCookies().isEmpty());
        jar.setAllowCloudflareAccessCookies(true);
        QVERIFY(jar.setCookiesFromUrl({cookie}, url));
        QCOMPARE(jar.cookiesForUrl(url).size(), 1);
    }

    void testCookies()
    {
        QTemporaryDir tmp;
        const QString nonexistingPath = tmp.filePath("someNonexistingDir/test.db");
        QNetworkCookie cookieA = QNetworkCookie("foo", "bar");
        // tomorrow rounded
        cookieA.setExpirationDate(QDateTime::currentDateTimeUtc().addDays(1).date().startOfDay());
        const QList<QNetworkCookie> cookies = {cookieA, QNetworkCookie("foo2", "bar")};
        CookieJar jar;
        jar.setAllCookies(cookies);
        QCOMPARE(cookies, jar.allCookies());
        QVERIFY(jar.save(tmp.filePath("test.db")));
        // ensure we are able to create a cookie jar in a non exisitning folder (mkdir)
        QVERIFY(jar.save(nonexistingPath));

        CookieJar jar2;
        QVERIFY(jar2.restore(nonexistingPath));
        // here we should have  only cookieA as the second one was a session cookie
        QCOMPARE(QList<QNetworkCookie>{cookieA}, jar2.allCookies());

    }

};

QTEST_APPLESS_MAIN(TestCookies)
#include "testcookies.moc"
