/*
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014 ownCloud GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MIRALL_ACCESS_MANAGER_H
#define MIRALL_ACCESS_MANAGER_H

#include "owncloudlib.h"
#include <QPointer>
#include <QNetworkAccessManager>

class QByteArray;
class QUrl;

namespace OCC {

class CloudflareAccess;

/**
 * @brief The AccessManager class
 * @ingroup libsync
 */
class OWNCLOUDSYNC_EXPORT AccessManager : public QNetworkAccessManager
{
    Q_OBJECT

public:
    static constexpr auto NativeCredentialEpochAttribute = static_cast<QNetworkRequest::Attribute>(QNetworkRequest::User + 3);
    static QByteArray generateRequestId();

    AccessManager(QObject *parent = nullptr, CloudflareAccess *cloudflareAccess = nullptr);
    [[nodiscard]] CloudflareAccess *cloudflareAccess() const;
    void setBrowserAccess(CloudflareAccess *access);
    void setNativeCredentialEpoch(quint64 epoch)
    {
        _nativeCredentialEpoch = epoch;
    }

protected:
    QNetworkReply *createRequest(QNetworkAccessManager::Operation op, const QNetworkRequest &request, QIODevice *outgoingData = nullptr) override;

private:
    CloudflareAccess *_cloudflareAccess;
    QPointer<CloudflareAccess> _browserAccess;
    bool _browserAccessAttached = false;
    quint64 _nativeCredentialEpoch = 0;
};

} // namespace OCC

#endif
