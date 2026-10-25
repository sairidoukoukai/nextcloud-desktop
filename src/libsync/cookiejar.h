/*
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014 ownCloud GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MIRALL_COOKIEJAR_H
#define MIRALL_COOKIEJAR_H

#include <QNetworkCookieJar>

#include "owncloudlib.h"

namespace OCC {

/**
 * @brief The CookieJar class
 * @ingroup libsync
 */
class OWNCLOUDSYNC_EXPORT CookieJar : public QNetworkCookieJar
{
    Q_OBJECT
public:
    explicit CookieJar(QObject *parent = nullptr, bool allowCloudflareAccessCookies = true);
    ~CookieJar() override;
    bool setCookiesFromUrl(const QList<QNetworkCookie> &cookieList, const QUrl &url) override;
    [[nodiscard]] QList<QNetworkCookie> cookiesForUrl(const QUrl &url) const override;

    void clearSessionCookies();
    void setAllowCloudflareAccessCookies(bool allow);

    using QNetworkCookieJar::setAllCookies;
    using QNetworkCookieJar::allCookies;

    bool save(const QString &fileName);
    bool restore(const QString &fileName);

Q_SIGNALS:
    void newCookiesForUrl(const QList<QNetworkCookie> &cookieList, const QUrl &url);

private:
    [[nodiscard]] QList<QNetworkCookie> allowedCookies(const QList<QNetworkCookie> &cookies) const;
    QList<QNetworkCookie> removeExpired(const QList<QNetworkCookie> &cookies);
    bool _allowCloudflareAccessCookies;
};

} // namespace OCC

#endif // MIRALL_COOKIEJAR_H
