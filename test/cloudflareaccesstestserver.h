/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslServer>
#include <QSslSocket>

#include <functional>

namespace OCC
{

class CloudflareAccessTestServer : public QSslServer
{
public:
    std::function<QByteArray(const QByteArray &)> respond;
    QList<QByteArray> requests;

    CloudflareAccessTestServer()
    {
        using namespace Qt::StringLiterals;
        QFile certificate(u"e2etestsfakecert.pem"_s);
        QFile key(u"e2etestsfakecertprivatekey.pem"_s);
        if (!certificate.open(QIODevice::ReadOnly) || !key.open(QIODevice::ReadOnly)) {
            return;
        }
        auto ssl = QSslConfiguration::defaultConfiguration();
        ssl.setLocalCertificate(QSslCertificate(certificate.readAll()));
        ssl.setPrivateKey(QSslKey(key.readAll(), QSsl::Rsa));
        setSslConfiguration(ssl);
        connect(this, &QTcpServer::pendingConnectionAvailable, this, [this] {
            const auto socket = nextPendingConnection();
            connect(socket, &QIODevice::readyRead, socket, [this, socket] {
                auto data = socket->property("request").toByteArray();
                data += socket->readAll();
                socket->setProperty("request", data);
                constexpr auto separator = QByteArrayView("\r\n\r\n");
                const auto end = data.indexOf(separator);
                if (end < 0 || socket->property("complete").toBool()) {
                    return;
                }
                auto length = 0;
                for (const auto &header : data.first(end).split('\n')) {
                    if (header.toLower().startsWith("content-length:")) {
                        length = header.mid(header.indexOf(':') + 1).trimmed().toInt();
                    }
                }
                if (data.size() < end + separator.size() + length) {
                    return;
                }
                socket->setProperty("complete", true);
                requests.append(data);
                const auto response = respond ? respond(data) : QByteArray{};
                if (!response.isEmpty()) {
                    socket->write(response);
                    socket->disconnectFromHost();
                }
            });
            connect(socket, &QAbstractSocket::disconnected, socket, &QObject::deleteLater);
        });
        static_cast<void>(listen(QHostAddress::LocalHost));
    }

    [[nodiscard]] QString baseUrl() const
    {
        using namespace Qt::StringLiterals;
        return u"https://localhost:%1"_s.arg(serverPort());
    }

    [[nodiscard]] static QByteArray response(int status, const QByteArray &body, const QByteArray &location = {})
    {
        return "HTTP/1.1 " + QByteArray::number(status) + " Test\r\nContent-Type: application/json\r\nContent-Length: " + QByteArray::number(body.size())
            + "\r\nConnection: close\r\n" + (location.isEmpty() ? QByteArray{} : "Location: " + location + "\r\n") + "\r\n" + body;
    }
};

}
