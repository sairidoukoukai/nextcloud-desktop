/*
 * SPDX-FileCopyrightText: 2026 Sairibus contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "devicesession.h"
#include "owncloudlib.h"

#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>

#include <chrono>
#include <functional>

namespace OCC
{

/**
 * One authorization code grant for the public desktop client in the system browser,
 * with PKCE (S256) and a loopback redirect to http://127.0.0.1:<port>/.
 */
class OWNCLOUDSYNC_EXPORT DeviceAuthorization : public QObject
{
    Q_OBJECT

public:
    enum class Grant {
        Online, ///< scope "openid"
        Offline, ///< scope "openid offline_access"
    };
    Q_ENUM(Grant)
    enum class Outcome {
        Succeeded,
        LoginRequired, ///< A silent request found no browser session.
        Failed,
    };
    Q_ENUM(Outcome)
    using BrowserOpener = std::function<bool(const QUrl &)>;

    explicit DeviceAuthorization(const QUrl &issuer, QObject *parent = nullptr, BrowserOpener opener = {});
    ~DeviceAuthorization() override;

    /** Opens the browser. A silent request adds prompt=none. */
    void start(Grant grant, bool silent);
    void cancel();
    [[nodiscard]] bool busy() const;
    [[nodiscard]] DeviceTokens tokens() const;
    [[nodiscard]] QString error() const;

Q_SIGNALS:
    void finished(OCC::DeviceAuthorization::Outcome outcome);

private:
    void readCallback(QTcpSocket *socket);
    void exchange(const QByteArray &code);
    void finish(Outcome outcome, const QString &error = {});
    static void respond(QTcpSocket *socket, int status, const QString &message);

    QUrl _issuer;
    BrowserOpener _opener;
    QNetworkAccessManager _network;
    QTcpServer _server;
    QTimer _timeout;
    QPointer<QNetworkReply> _exchange;
    Grant _grant = Grant::Online;
    QByteArray _verifier;
    QByteArray _state;
    QUrl _redirectUri;
    DeviceTokens _tokens;
    QString _error;
    bool _busy = false;
    bool _callbackReceived = false;
};

/**
 * Signs a desktop in for the club's Nextcloud and keeps the result in its DeviceSession.
 *
 * signInOnline() is step 1: an online grant whose token serves Login Flow V2 (step 2)
 * in the same browser session. completeOffline() is step 3: the offline grant, first
 * without a prompt and again interactively when the browser has no session. An offline
 * grant redeemed in a brand-new browser session ends that session, so step 3 must
 * follow the browser step of Login Flow V2.
 */
class OWNCLOUDSYNC_EXPORT DeviceEnrollment : public QObject
{
    Q_OBJECT

public:
    explicit DeviceEnrollment(DeviceSession *session, QObject *parent = nullptr, DeviceAuthorization::BrowserOpener opener = {});

    /** How step 3 may involve the member. */
    enum class Prompt {
        Never, ///< Only through the browser's existing session; fails when the member has to sign in.
        IfNeeded, ///< Without a prompt first, then with a sign-in page.
        Always, ///< With a sign-in page at once.
    };
    Q_ENUM(Prompt)

    void signInOnline();
    /** Step 3. */
    void completeOffline(Prompt prompt = Prompt::IfNeeded);
    void cancel();
    [[nodiscard]] bool busy() const;
    [[nodiscard]] DeviceSession *session() const;

Q_SIGNALS:
    void onlineSignedIn();
    void offlineReady();
    void failed(const QString &error);

private:
    void authorizationFinished(DeviceAuthorization::Outcome outcome);

    enum class Phase {
        Idle,
        Online,
        SilentOffline,
        InteractiveOffline,
        Storing,
    };

    QPointer<DeviceSession> _session;
    DeviceAuthorization *_authorization;
    Phase _phase = Phase::Idle;
    bool _promptIfNeeded = false;
};

}
