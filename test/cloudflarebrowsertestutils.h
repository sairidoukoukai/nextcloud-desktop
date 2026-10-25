/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#include "cloudflarebrowserlogin.h"
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace OCC::Test
{
using namespace Qt::StringLiterals;

inline QByteArray browserToken(qint64 expires = QDateTime::currentSecsSinceEpoch() + 3600, const QString &subject = u"7a13bcce-8c7e-4444-b935-f00d04665df9"_s)
{
    const auto claims = QJsonDocument(QJsonObject{{u"iss"_s, u"https://sairibus.cloudflareaccess.com"_s},
                                                  {u"type"_s, u"app"_s},
                                                  {u"sub"_s, u"synthetic-access-user"_s},
                                                  {u"aud"_s, QJsonArray{u"synthetic-audience"_s}},
                                                  {u"exp"_s, expires},
                                                  {u"custom"_s, QJsonObject{{u"sairibus_subject"_s, subject}}}})
                            .toJson(QJsonDocument::Compact);
    return QByteArray("{\"alg\":\"RS256\"}").toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) + '.'
        + claims.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) + ".synthetic-signature";
}

class BrowserLogin : public CloudflareBrowserLogin
{
public:
    bool running = false;
    bool cancelled = false;
    QUrl requested;
    [[nodiscard]] bool busy() const override
    {
        return running;
    }
    void start(const QUrl &server) override
    {
        requested = server;
        running = true;
    }
    void cancel() override
    {
        cancelled = true;
        running = false;
        Q_EMIT finished({}, u"Synthetic cancellation"_s);
    }
    void succeed()
    {
        running = false;
        Q_EMIT finished(browserToken(), {});
    }
};

}
