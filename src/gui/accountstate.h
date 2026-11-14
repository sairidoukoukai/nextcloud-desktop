/*
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014 ownCloud GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ACCOUNTINFO_H
#define ACCOUNTINFO_H

#include "connectionvalidator.h"
#include "creds/abstractcredentials.h"
#include "devicesession.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QPointer>
#include <QTimer>

#include <functional>
#include <memory>

class QSettings;
class FakeAccountState;

namespace OCC {

class AccountState;
class Account;
class AccountApp;
class RemoteWipe;
class DeviceEnrollment;

using AccountStatePtr = QExplicitlySharedDataPointer<AccountState>;
using AccountAppList = QList<AccountApp *>;

/**
 * @brief Extra info about an ownCloud server account.
 * @ingroup gui
 */
class AccountState : public QObject, public QSharedData
{
    Q_OBJECT
    Q_PROPERTY(AccountPtr account MEMBER _account)
    Q_PROPERTY(State state READ state NOTIFY stateChanged)

public:
    enum State {
        /// Not even attempting to connect, most likely because the
        /// user explicitly signed out or cancelled a credential dialog.
        SignedOut,

        /// Account would like to be connected but hasn't heard back yet.
        Disconnected,

        /// The account is successfully talking to the server.
        Connected,

        /// There's a temporary problem with talking to the server,
        /// don't bother the user too much and try again.
        ServiceUnavailable,

        /// Connection is being redirected (likely a captive portal is in effect)
        /// Do not proceed with connecting and check back later
        RedirectDetected,

        /// Similar to ServiceUnavailable, but we know the server is down
        /// for maintenance
        MaintenanceMode,

        /// Could not communicate with the server for some reason.
        /// We assume this may resolve itself over time and will try
        /// again automatically.
        NetworkError,

        /// Server configuration error. (For example: unsupported version)
        ConfigurationError,

        /// We are currently asking the user for credentials
        AskingCredentials,

        /// Need to sign terms of service by going to web UI
        NeedToSignTermsOfService,
    };

    /// The actual current connectivity status.
    using ConnectionStatus = ConnectionValidator::Status;

    /// Use the account as parent
    explicit AccountState(const AccountPtr &account);
    ~AccountState() override;

    AccountPtr account() const;

    ConnectionStatus connectionStatus() const;
    QStringList connectionErrors() const;

    State state() const;
    static QString stateString(State state);

    bool isSignedOut() const;

    AccountAppList appList() const;
    AccountApp* findApp(const QString &appId) const;

    /** A user-triggered sign out which disconnects, stops syncs
     * for the account and forgets the password. */
    void signOutByUi();

    /** Tries to connect from scratch.
     *
     * Does nothing for signed out accounts.
     * Connected accounts will be disconnected and try anew.
     * Disconnected accounts will go to checkConnectivity().
     *
     * Useful for when network settings (proxy) change.
     */
    void freshConnectionAttempt();

    /// Move from SignedOut state to Disconnected (attempting to connect)
    void signIn();

    /** The account's sign-in ended and waits for the member to sign in again. */
    [[nodiscard]] bool isSignInRequired() const;

    bool isConnected() const;

    bool needsToSignTermsOfService() const;

    /** Returns a new settings object for this account, already in the right groups. */
    std::unique_ptr<QSettings> settings();

    /** Mark the timestamp when the last successful ETag check happened for
     *  this account.
     *  The checkConnectivity() method uses the timestamp to save a call to
     *  the server to validate the connection if the last successful etag job
     *  was not so long ago.
     */
    void tagLastSuccessfullETagRequest(const QDateTime &tp);

    /** Saves the ETag Response header from the last Notifications api
     * request with statusCode 200.
    */
    QByteArray notificationsEtagResponseHeader() const;

    /** Returns the ETag Response header from the last Notifications api
     * request with statusCode 200.
    */
    void setNotificationsEtagResponseHeader(const QByteArray &value);

    /** Saves the ETag Response header from the last Navigation Apps api
     * request with statusCode 200.
    */
    QByteArray navigationAppsEtagResponseHeader() const;

    /** Returns the ETag Response header from the last Navigation Apps api
     * request with statusCode 200.
    */
    void setNavigationAppsEtagResponseHeader(const QByteArray &value);

    ///Asks for user credentials
    void handleInvalidCredentials();

    /** Returns the notifications status retrieved by the notifications endpoint
     *  https://github.com/nextcloud/desktop/issues/2318#issuecomment-680698429
    */
    bool isDesktopNotificationsAllowed() const;

    /** Set desktop notifications status retrieved by the notifications endpoint
    */
    void setDesktopNotificationsAllowed(bool isAllowed);

    ConnectionStatus lastConnectionStatus() const;

    /** Answers whether an account may keep its folders under a new Nextcloud user ID. */
    using UserChangeConfirmation = std::function<void(const QString &previousUser, const QString &user, const QString &displayName, std::function<void(bool)> done)>;
    /** Replaces the dialog that confirms a user change. Tests answer without a window. */
    static void setUserChangeConfirmation(UserChangeConfirmation confirmation);
    
    void trySignIn();

    void systemOnlineConfigurationChanged();

public Q_SLOTS:
    /// Triggers a ping to the server to update state and
    /// connection status and errors.
    virtual void checkConnectivity();

private:
    virtual void setState(State state);
    void fetchNavigationApps();
    /** Whether the device session can authenticate requests now; otherwise starts what it needs and reports false. */
    bool ensureDeviceSession();
    enum class DeviceSignIn {
        Online, ///< Step 1, in the browser.
        OfflineAfterSignIn, ///< Step 3 in the background after the member's sign-in connected, in the browser session of step 1.
        OfflineInBackground, ///< Step 3 in the background after a later connection, without a sign-in page.
        OfflineSilently, ///< A new offline grant from the browser's existing session, without asking the member.
        OfflineInteractive, ///< A new offline grant with a sign-in page.
    };
    /** Runs the device sign-in. A background run follows a connection and never signs the account out. */
    void startDeviceSignIn(DeviceSignIn signIn);
    /** Signs the account out with @p reason and tells the member, who signs in again from the account's menu. */
    void requireSignIn(const QString &reason);
    /**
     * Before connecting to the club's Nextcloud, adopts the user ID the server reports
     * for the app password when it differs from the stored one, then checks connectivity again.
     */
    void checkServerUser();

    int retryCount() const;
    void increaseRetryCount();
    void resetRetryCount();

Q_SIGNALS:
    void stateChanged(OCC::AccountState::State state);
    void isConnectedChanged();
    void hasFetchedNavigationApps();
    void statusChanged();
    void desktopNotificationsAllowedChanged();
    void termsOfServiceChanged(OCC::AccountPtr account, OCC::AccountState::State state);
    /** The account's sign-in ended; the member signs in again with signIn(). */
    void signInRequired(const QString &reason);

protected Q_SLOTS:
    void slotConnectionValidatorResult(OCC::ConnectionValidator::Status status, const QStringList &errors);

    /// When client gets a 401 or 403 checks if server requested remote wipe
    /// before asking for user credentials again
    void slotHandleRemoteWipeCheck();

    void slotCredentialsFetched(OCC::AbstractCredentials *creds);
    void slotCredentialsAsked(OCC::AbstractCredentials *creds);

    void slotNavigationAppsFetched(const QJsonDocument &reply, int statusCode);
    void slotEtagResponseHeaderReceived(const QByteArray &value, int statusCode);
    void slotOcsError(int statusCode, const QString &message);

private Q_SLOTS:

    void slotCheckConnection();
    void slotCheckServerAvailibility();
    void slotPushNotificationsReady();
    void slotServerUserStatusChanged();

private:
    AccountPtr _account;
    State _state;
    ConnectionStatus _connectionStatus;
    ConnectionStatus _lastConnectionValidatorStatus = ConnectionStatus::Undefined;
    QStringList _connectionErrors;
    bool _waitingForNewCredentials = false;
    QDateTime _timeOfLastETagCheck;
    QPointer<ConnectionValidator> _connectionValidator;
    TermsOfServiceChecker _termsOfServiceChecker;
    QByteArray _notificationsEtagResponseHeader;
    QByteArray _navigationAppsEtagResponseHeader;

    /**
     * Starts counting when the server starts being back up after 503 or
     * maintenance mode. The account will only become connected once this
     * timer exceeds the _maintenanceToConnectedDelay value.
     */
    QElapsedTimer _timeSinceMaintenanceOver;

    /**
     * Milliseconds for which to delay reconnection after 503/maintenance.
     */
    int _maintenanceToConnectedDelay = 0;

    /**
     * Connects remote wipe check with the account
     * the log out triggers the check (loads app password -> create request)
     */
    RemoteWipe *_remoteWipe = nullptr;

    DeviceEnrollment *_deviceEnrollment = nullptr;
    bool _waitingForDeviceToken = false;
    bool _waitingForDeviceSignIn = false;
    /** The member is signing in now, so the browser or Login Flow V2 may ask them. */
    bool _interactiveSignIn = false;
    DeviceSignIn _deviceSignIn = DeviceSignIn::Online;
    DeviceSession::Status _deviceStatus = DeviceSession::Status::Unloaded;
    /** The device session ended while the client ran, so a new one waits for the member. */
    bool _deviceSessionEnded = false;
    bool _signInRequired = false;
    /** The account signed in again without an earlier device session, so nothing ties the browser's member to this account yet. */
    bool _deviceMemberUnverified = false;
    /** The server reported the account's user ID for the current app password, or accepted a connection with it. */
    bool _serverUserChecked = false;
    /** The last check could not read the user ID; the next connection attempt goes ahead without it. */
    bool _serverUserCheckFailed = false;
    bool _checkingServerUser = false;
    /** Counts checks so that a check made for replaced credentials is ignored. */
    quint64 _serverUserCheck = 0;

    /**
     * Holds the App names and URLs available on the server
     */
    AccountAppList _apps;

    bool _isDesktopNotificationsAllowed = false;

    int _retryCount = 0;

    QTimer _checkConnectionTimer;
    QElapsedTimer _lastCheckConnectionTimer;

    QTimer _checkServerAvailibilityTimer;

    explicit AccountState() = default;

    friend class ::FakeAccountState;
};

class AccountApp : public QObject
{
    Q_OBJECT
public:
    AccountApp(const QString &name, const QUrl &url,
        const QString &id, const QUrl &iconUrl,
        QObject* parent = nullptr);

    [[nodiscard]] QString name() const;
    [[nodiscard]] QUrl url() const;
    [[nodiscard]] QString id() const;
    [[nodiscard]] QUrl iconUrl() const;

private:
    QString _name;
    QUrl _url;

    QString _id;
    QUrl _iconUrl;
};

}

Q_DECLARE_METATYPE(OCC::AccountState *)
Q_DECLARE_METATYPE(OCC::AccountStatePtr)

#endif //ACCOUNTINFO_H
