/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

using namespace Qt::StringLiterals;

int main(int argc, char **argv)
{
    const auto application = QCoreApplication(argc, argv);
#ifdef Q_OS_WIN
    const auto cache = qEnvironmentVariable("USERPROFILE");
#else
    const auto cache = qEnvironmentVariable("HOME");
#endif
    QDir().mkpath(cache + u"/.cloudflared"_s);
    auto token = QFile(cache + u"/.cloudflared/synthetic-token"_s);
    if (!token.open(QIODevice::WriteOnly)) {
        return 3;
    }
    token.write("synthetic cache");
    token.close();
    auto report = QFile(qEnvironmentVariable("NEXTCLOUD_TEST_HELPER_REPORT"));
    if (!report.open(QIODevice::WriteOnly)) {
        return 4;
    }
    report.write(QJsonDocument(QJsonObject{{u"cache"_s, cache}, {u"arguments"_s, QJsonArray::fromStringList(QCoreApplication::arguments())}}).toJson());
    report.close();
    const auto mode = qEnvironmentVariable("NEXTCLOUD_TEST_HELPER_MODE");
    if (mode == u"wait"_s) {
        return QCoreApplication::exec();
    }
    auto output = QFile();
    if (!output.open(stdout, QIODevice::WriteOnly)) {
        return 3;
    }
    output.write(qgetenv("NEXTCLOUD_TEST_HELPER_TOKEN"));
    output.flush();
    return mode == u"failure"_s ? 1 : 0;
}
