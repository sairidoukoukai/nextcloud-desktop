/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "owncloudlib.h"
#include <QObject>
#include <QProcess>
#include <QTemporaryDir>
#include <QTimer>
#include <QUrl>
#include <chrono>
#include <memory>

namespace OCC
{

class OWNCLOUDSYNC_EXPORT CloudflareBrowserLogin : public QObject
{
    Q_OBJECT
public:
    explicit CloudflareBrowserLogin(QObject *parent = nullptr,
                                    const QString &helper = {},
                                    const QByteArray &digest = {},
                                    std::chrono::milliseconds timeout = std::chrono::minutes(5));
    ~CloudflareBrowserLogin() override;
    [[nodiscard]] virtual bool busy() const;
    virtual void start(const QUrl &server);
    virtual void cancel();

Q_SIGNALS:
    void finished(const QByteArray &token, const QString &error);

private:
    void complete(const QByteArray &token, const QString &error);
    [[nodiscard]] static bool makePrivate(const QString &path);
    QProcess _process;
    QTimer _timer;
    std::unique_ptr<QTemporaryDir> _directory;
    QString _helper;
    QByteArray _digest;
    QByteArray _output;
    QString _processError;
    bool _busy = false;
};

}
