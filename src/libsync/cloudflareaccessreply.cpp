/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cloudflareaccessreply.h"

#include <QTimer>

namespace OCC
{

CloudflareAccessReply::CloudflareAccessReply(QNetworkAccessManager::Operation operation, const QNetworkRequest &request, const QString &error, QObject *parent)
    : QNetworkReply(parent)
{
    setOperation(operation);
    setRequest(request);
    setUrl(request.url());
    open(QIODevice::ReadOnly);
    setError(QNetworkReply::ContentAccessDenied, error);
    QTimer::singleShot(0, this, [this] {
        if (!isFinished()) {
            setFinished(true);
            Q_EMIT errorOccurred(this->error());
            Q_EMIT finished();
        }
    });
}

void CloudflareAccessReply::abort()
{
    if (!isFinished()) {
        setError(QNetworkReply::OperationCanceledError, tr("Operation cancelled."));
    }
}

qint64 CloudflareAccessReply::readData(char *, qint64)
{
    return -1;
}

}
