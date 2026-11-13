/*
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014 ownCloud GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MIRALL_ACCESS_MANAGER_H
#define MIRALL_ACCESS_MANAGER_H

#include "owncloudlib.h"
#include <QNetworkAccessManager>
#include <QPointer>

class QByteArray;
class QUrl;

namespace OCC {

class CloudflareAccess;
class DeviceSession;

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
    [[nodiscard]] CloudflareAccess *cloudflareAccess() const
    {
        return _cloudflareAccess;
    }
    void setNativeCredentialEpoch(quint64 epoch)
    {
        _nativeCredentialEpoch = epoch;
    }
    /** Adds the account's device token to requests for the club's Nextcloud. */
    void setDeviceSession(DeviceSession *session);

protected:
    QNetworkReply *createRequest(QNetworkAccessManager::Operation op, const QNetworkRequest &request, QIODevice *outgoingData = nullptr) override;

private:
    CloudflareAccess *_cloudflareAccess;
    quint64 _nativeCredentialEpoch = 0;
    QPointer<DeviceSession> _deviceSession;
};

} // namespace OCC

#endif
