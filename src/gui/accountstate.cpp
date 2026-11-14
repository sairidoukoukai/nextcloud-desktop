/*
 * SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
 * SPDX-FileCopyrightText: 2014 ownCloud GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "accountstate.h"

#include "accessmanager.h"
#include "account.h"
#include "accountmanager.h"
#include "cloudflareaccess.h"
#include "configfile.h"
#include "creds/abstractcredentials.h"
#include "creds/httpcredentials.h"
#include "creds/webflowcredentials.h"
#include "deviceauthorization.h"
#include "devicesession.h"
#include "logger.h"
#include "networkjobs.h"
#include "ocsnavigationappsjob.h"
#include "ocsuserstatusconnector.h"
#include "pushnotifications.h"
#include "remotewipe.h"
#include "settings/migration.h"
#include "theme.h"

#include <QMessageBox>
#include <QSettings>
#include <QTimer>
#include <QFontMetrics>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QBuffer>
#include <QRandomGenerator>

#include <cmath>

using namespace Qt::StringLiterals;

namespace OCC {

Q_LOGGING_CATEGORY(lcAccountState, "nextcloud.gui.account.state", QtInfoMsg)

namespace
{
AccountState::UserChangeConfirmation &userChangeConfirmation()
{
    static auto confirmation = AccountState::UserChangeConfirmation([](const QString &previousUser, const QString &user, const QString &displayName, std::function<void(bool)> done) {
        const auto box = new QMessageBox(QMessageBox::Question,
                                         Theme::instance()->appNameGUI(),
                                         AccountState::tr("Keep syncing these folders as %1 (%2)?").arg(displayName, user),
                                         QMessageBox::Yes | QMessageBox::No);
        box->setInformativeText(AccountState::tr("This account was set up for %1.").arg(previousUser));
        box->setDefaultButton(QMessageBox::No);
        box->setAttribute(Qt::WA_DeleteOnClose);
        QObject::connect(box, &QMessageBox::finished, box, [done](int result) {
            done(result == QMessageBox::Yes);
        });
        box->open();
    });
    return confirmation;
}
}

void AccountState::setUserChangeConfirmation(UserChangeConfirmation confirmation)
{
    userChangeConfirmation() = std::move(confirmation);
}

AccountState::AccountState(const AccountPtr &account)
    : QObject()
    , _account(account)
    , _state(AccountState::Disconnected)
    , _connectionStatus(ConnectionValidator::Undefined)
    , _waitingForNewCredentials(false)
    , _termsOfServiceChecker(_account)
    , _maintenanceToConnectedDelay(60000 + (QRandomGenerator::global()->generate() % (4 * 60000))) // 1-5min delay
    , _remoteWipe(new RemoteWipe(_account))
    , _isDesktopNotificationsAllowed(true)
{
    qRegisterMetaType<AccountState *>("AccountState*");

    connect(account.data(), &Account::invalidCredentials,
        this, &AccountState::slotHandleRemoteWipeCheck);
    connect(account.data(), &Account::cloudflareAccessCheckFailed, this, [this] {
        if (!isSignedOut()) {
            _connectionErrors = {tr("Cloudflare Access could not be verified. Check the service token and server availability.")};
            setState(NetworkError);
        }
    });
    connect(account.data(), &Account::credentialsFetched,
        this, &AccountState::slotCredentialsFetched);
    connect(account.data(), &Account::credentialsAsked,
        this, &AccountState::slotCredentialsAsked);
    connect(account.data(), &Account::pushNotificationsReady,
            this, &AccountState::slotPushNotificationsReady);
    connect(account.data(), &Account::serverUserStatusChanged, this,
        &AccountState::slotServerUserStatusChanged);
    connect(&_termsOfServiceChecker, &TermsOfServiceChecker::done,
            this, [this] ()
            {
                if (_termsOfServiceChecker.needToSign()) {
                    slotConnectionValidatorResult(ConnectionValidator::NeedToSignTermsOfService, {});
                }
            });
    connect(account.data(), &Account::termsOfServiceNeedToBeChecked,
            this, [this] ()
            {
                _termsOfServiceChecker.start();
            });

    connect(this, &AccountState::isConnectedChanged, [=, this]{
        // Get the Apps available on the server if we're now connected.
        if (isConnected()) {
            fetchNavigationApps();
        }
    });

    connect(&_checkConnectionTimer, &QTimer::timeout, this, &AccountState::slotCheckConnection);
    _checkConnectionTimer.setInterval(ConnectionValidator::DefaultCallingIntervalMsec);
    _checkConnectionTimer.start();

    connect(&_checkServerAvailibilityTimer, &QTimer::timeout, this, &AccountState::slotCheckServerAvailibility);
    _checkServerAvailibilityTimer.setInterval(ConnectionValidator::DefaultCallingIntervalMsec);
    _checkServerAvailibilityTimer.start();

    QTimer::singleShot(0, this, &AccountState::slotCheckConnection);
    const auto accessManager = qobject_cast<AccessManager *>(account->networkAccessManager());
    const auto access = accessManager ? accessManager->cloudflareAccess() : CloudflareAccess::instance();
    connect(access, &CloudflareAccess::configurationChanged, this, [this] {
        if (!isSignedOut()) {
            checkConnectivity();
        }
    });

    const auto session = account->deviceSession();
    _deviceStatus = session->status();
    connect(session, &DeviceSession::statusChanged, this, [this] {
        const auto status = _account->deviceSession()->status();
        const auto previous = std::exchange(_deviceStatus, status);
        if ((previous == DeviceSession::Status::Online || previous == DeviceSession::Status::Offline)
            && (status == DeviceSession::Status::Absent || status == DeviceSession::Status::Lost)) {
            _deviceSessionEnded = true;
        }
        if (_waitingForDeviceToken && (status == DeviceSession::Status::Absent || status == DeviceSession::Status::Lost)) {
            _waitingForDeviceToken = false;
            checkConnectivity();
        }
    });
    connect(session, &DeviceSession::tokenRefreshed, this, [this] {
        if (_waitingForDeviceToken || _state == NetworkError) {
            _waitingForDeviceToken = false;
            checkConnectivity();
        }
    });
    connect(session, &DeviceSession::refreshFailed, this, [this] {
        if (_waitingForDeviceToken && !isSignedOut()) {
            _waitingForDeviceToken = false;
            _connectionErrors = {_account->deviceSession()->error()};
            setState(NetworkError);
        }
    });
    connect(session, &DeviceSession::sessionLost, this, [this] {
        if (!isSignedOut()) {
            checkConnectivity();
        }
    });
}

AccountState::~AccountState() = default;

AccountPtr AccountState::account() const
{
    return _account;
}

AccountState::ConnectionStatus AccountState::connectionStatus() const
{
    return _connectionStatus;
}

QStringList AccountState::connectionErrors() const
{
    return _connectionErrors;
}

AccountState::State AccountState::state() const
{
    return _state;
}

void AccountState::setState(State state)
{
    if (_state != state) {
        qCInfo(lcAccountState) << "AccountState state change: "
                               << stateString(_state) << "->" << stateString(state);
        State oldState = _state;
        _state = state;

        if (_state == SignedOut) {
            _connectionStatus = ConnectionValidator::Undefined;
            if (oldState != _state && oldState == Disconnected && !_signInRequired) {
                qCInfo(lcAccountState) << "Invalid credentials for" << _account->url().toString() << "login needed";
                setState(AskingCredentials);
            }
        } else if (oldState == SignedOut && _state == Disconnected) {
            // If we stop being voluntarily signed-out, try to connect and
            // auth right now!
            checkConnectivity();
        } else if (_state == ServiceUnavailable || _state == RedirectDetected) {
            // Check if we are actually down for maintenance/in a redirect state (captive portal?).
            // To do this we must clear the connection validator that just
            // produced the 503/302. It's finished anyway and will delete itself.
            _connectionValidator.clear();
            checkConnectivity();
        }
        if (oldState == Connected || _state == Connected) {
            Q_EMIT isConnectedChanged();
        }
        if (_state == Connected) {
            resetRetryCount();
        }
    }

    // might not have changed but the underlying _connectionErrors might have
    Q_EMIT stateChanged(_state);
}

QString AccountState::stateString(State state)
{
    switch (state) {
    case SignedOut:
        return tr("Signed out");
    case Disconnected:
        return tr("Disconnected");
    case Connected:
        return tr("Connected");
    case ServiceUnavailable:
        return tr("Service unavailable");
    case MaintenanceMode:
        return tr("Maintenance mode");
    case RedirectDetected:
        return tr("Redirect detected");
    case NetworkError:
        return tr("Network error");
    case ConfigurationError:
        return tr("Configuration error");
    case AskingCredentials:
        return tr("Asking Credentials");
    case NeedToSignTermsOfService:
        return tr("Need the user to accept the terms of service");
    }
    return tr("Unknown account state");
}

int AccountState::retryCount() const
{
    return _retryCount;
}

void AccountState::increaseRetryCount()
{
    ++_retryCount;
}

bool AccountState::isSignedOut() const
{
    return _state == SignedOut;
}

void AccountState::signOutByUi()
{
    account()->advanceCredentialEpoch();
    account()->credentials()->forgetSensitiveData();
    account()->clearCookieJar();
    setState(SignedOut);
}

void AccountState::freshConnectionAttempt()
{
    if (isConnected()) {
        setState(Disconnected);
    }

    checkConnectivity();
}

void AccountState::signIn()
{
    if (_state == SignedOut) {
        _waitingForNewCredentials = false;
        _signInRequired = false;
        _interactiveSignIn = true;
        setState(Disconnected);
    }
}

bool AccountState::isSignInRequired() const
{
    return _signInRequired && isSignedOut();
}

void AccountState::requireSignIn(const QString &reason)
{
    qCWarning(lcAccountState) << "The sign-in of" << _account->url().toString() << "ended:" << reason;
    _interactiveSignIn = false;
    _waitingForDeviceSignIn = false;
    _waitingForNewCredentials = false;
    if (_deviceEnrollment) {
        // A sign-in still running in the background must not open the browser later.
        _deviceEnrollment->cancel();
    }
    _connectionErrors = {reason};
    const auto notify = !isSignInRequired();
    _signInRequired = true;
    setState(SignedOut);
    if (notify) {
        Q_EMIT signInRequired(reason);
    }
}

bool AccountState::isConnected() const
{
    return _state == Connected;
}

bool AccountState::needsToSignTermsOfService() const
{
    return _state == NeedToSignTermsOfService;
}

void AccountState::tagLastSuccessfullETagRequest(const QDateTime &tp)
{
    _timeOfLastETagCheck = tp;
}

QByteArray AccountState::notificationsEtagResponseHeader() const
{
    return _notificationsEtagResponseHeader;
}

void AccountState::setNotificationsEtagResponseHeader(const QByteArray &value)
{
    _notificationsEtagResponseHeader = value;
}

QByteArray AccountState::navigationAppsEtagResponseHeader() const
{
    return _navigationAppsEtagResponseHeader;
}

void AccountState::setNavigationAppsEtagResponseHeader(const QByteArray &value)
{
    _navigationAppsEtagResponseHeader = value;
}

bool AccountState::isDesktopNotificationsAllowed() const
{
    return _isDesktopNotificationsAllowed;
}

void AccountState::setDesktopNotificationsAllowed(bool isAllowed)
{
    if (_isDesktopNotificationsAllowed == isAllowed) {
        return;
    }
    
    _isDesktopNotificationsAllowed = isAllowed;
    Q_EMIT desktopNotificationsAllowedChanged();
}

AccountState::ConnectionStatus AccountState::lastConnectionStatus() const
{
    return _lastConnectionValidatorStatus;
}

void AccountState::trySignIn()
{
    if (isSignedOut() && account()) {
        account()->resetRejectedCertificates();
        signIn();
    }
}

void AccountState::systemOnlineConfigurationChanged()
{
    if (_account->deviceSession()->appliesTo(_account->url())) {
        _account->deviceSession()->networkChanged();
    }
    QMetaObject::invokeMethod(this, "slotCheckConnection", Qt::QueuedConnection);
}

void AccountState::checkConnectivity()
{
    qCInfo(lcAccountState()) << "check connectivity";

    const auto access = CloudflareAccess::instance();
    if (access->protects(account()->url()) && access->busy()) {
        return;
    }

    if (isSignedOut() || _waitingForNewCredentials) {
        return;
    }

    if (_connectionValidator) {
        qCWarning(lcAccountState) << "ConnectionValidator already running, ignoring" << account()->displayName();
        return;
    }

    // If we never fetched credentials, do that now - otherwise connection attempts
    // make little sense, we might be missing client certs.
    if (!account()->credentials()->wasFetched()) {
        _waitingForNewCredentials = true;
        ConfigFile configFile;
        const auto shouldTryUnbrandedToBrandedMigration = Migration::shouldTryUnbrandedToBrandedMigration();
        qCDebug(lcAccountState) << "shouldTryUnbrandedToBrandedMigration?" << shouldTryUnbrandedToBrandedMigration;
        qCDebug(lcAccountState) << "migration Phase?" << Migration::phase();
        const auto appName = shouldTryUnbrandedToBrandedMigration ? configFile.unbrandedAppName : "";
        account()->credentials()->fetchFromKeychain(appName);
        return;
    }

    // IF the account is connected the connection check can be skipped
    // if the last successful etag check job is not so long ago.
    const auto polltime = std::chrono::duration_cast<std::chrono::seconds>(ConfigFile().remotePollInterval());
    const auto elapsed = _timeOfLastETagCheck.secsTo(QDateTime::currentDateTimeUtc());
    if (isConnected() && _timeOfLastETagCheck.isValid()
        && elapsed <= polltime.count()) {
        qCDebug(lcAccountState) << account()->displayName() << "The last ETag check succeeded within the last " << polltime.count() << "s (" << elapsed << "s). No connection check needed!";
        return;
    }

    if (!ensureDeviceSession()) {
        return;
    }

    // Login Flow V2 may have stored an app password for a user ID the account does not use yet.
    if (_account->deviceSession()->appliesTo(_account->url()) && !_serverUserChecked) {
        if (_checkingServerUser) {
            return;
        }
        // After a failed check this attempt goes ahead, so its errors show; the next attempt checks again.
        if (!std::exchange(_serverUserCheckFailed, false)) {
            checkServerUser();
            return;
        }
    }

    auto *conValidator = new ConnectionValidator(AccountStatePtr(this), _connectionErrors);
    _connectionValidator = conValidator;
    _connectionErrors.clear();
    connect(conValidator, &ConnectionValidator::connectionResult,
        this, &AccountState::slotConnectionValidatorResult);
    if (isConnected() || needsToSignTermsOfService()) {
        // Use a small authed propfind as a minimal ping when we're
        // already connected.
        conValidator->checkAuthentication();
    } else {
        // Check the server and then the auth.

        // Let's try this for all OS and see if it fixes the Qt issues we have on Linux  #4720 #3888 #4051
        //#ifdef Q_OS_WIN
        // There seems to be a bug in Qt on Windows where QNAM sometimes stops
        // working correctly after the computer woke up from sleep. See #2895 #2899
        // and #2973.
        // As an attempted workaround, reset the QNAM regularly if the account is
        // disconnected.
        account()->resetNetworkAccessManager();

        // If we don't reset the ssl config a second CheckServerJob can produce a
        // ssl config that does not have a sensible certificate chain.
        account()->setSslConfiguration(QSslConfiguration::defaultConfiguration());
        //#endif
        conValidator->checkServerAndAuth();
    }
}

void AccountState::slotConnectionValidatorResult(ConnectionValidator::Status status, const QStringList &errors)
{
    const auto updateRetryCount = [this]() {
        increaseRetryCount();
        qCInfo(lcAccountState()) << "connection retry count" << retryCount();
        _lastCheckConnectionTimer.invalidate();
        _lastCheckConnectionTimer.start();
    };

    const auto resetRetryConnection = [this]() {
        qCInfo(lcAccountState) << "reset retry count";
        resetRetryCount();
        _lastCheckConnectionTimer.invalidate();
        _lastCheckConnectionTimer.start();
    };

    if (isSignedOut()) {
        qCWarning(lcAccountState) << "Signed out, ignoring" << status << _account->url().toString();
        return;
    }

    const auto oldConnectionValidatorStatus = _lastConnectionValidatorStatus;
    _lastConnectionValidatorStatus = status;

    // Come online gradually from 503, captive portal(redirection) or maintenance mode
    if (status == ConnectionValidator::Connected
        && (_connectionStatus == ConnectionValidator::ServiceUnavailable
            || _connectionStatus == ConnectionValidator::MaintenanceMode
              || _connectionStatus == ConnectionValidator::StatusRedirect)) {
        if (!_timeSinceMaintenanceOver.isValid()) {
            qCInfo(lcAccountState) << "AccountState reconnection: delaying for"
                                   << _maintenanceToConnectedDelay << "ms";
            _timeSinceMaintenanceOver.start();
            QTimer::singleShot(_maintenanceToConnectedDelay + 100, this, &AccountState::checkConnectivity);
            return;
        } else if (_timeSinceMaintenanceOver.elapsed() < _maintenanceToConnectedDelay) {
            qCInfo(lcAccountState) << "AccountState reconnection: only"
                                   << _timeSinceMaintenanceOver.elapsed() << "ms have passed";
            return;
        }
    }

    if (_connectionStatus != status) {
        qCInfo(lcAccountState) << "AccountState connection status change: "
                               << _connectionStatus << "->"
                               << status;
        _connectionStatus = status;
        Q_EMIT stateChanged(_state);
    }
    _connectionErrors = errors;
    // A refused principal, or any other failure, checks the user ID again before the next attempt.
    _serverUserChecked = status == ConnectionValidator::Connected;
    // The member's sign-in ends with this result, unless it asks for a new app password.
    const auto memberSignedIn = _interactiveSignIn;
    if (status != ConnectionValidator::CredentialsWrong && status != ConnectionValidator::CredentialsNotReady) {
        _interactiveSignIn = false;
    }

    switch (status) {
    case ConnectionValidator::Connected:
        // The server accepted this account's app password with the device token: the member is the account's own.
        _deviceMemberUnverified = false;
        _deviceSessionEnded = false;
        if (_state != Connected) {
            setState(Connected);
            resetRetryConnection();

            // Get the Apps available on the server.
            fetchNavigationApps();

            // Setup push notifications after a successful connection
            account()->trySetupPushNotifications();

            // An account that signed in again syncs with its online grant until
            // its own offline session follows in the same browser session.
            if (_account->deviceSession()->appliesTo(_account->url()) && _account->deviceSession()->status() == DeviceSession::Status::Online) {
                startDeviceSignIn(memberSignedIn ? DeviceSignIn::OfflineAfterSignIn : DeviceSignIn::OfflineInBackground);
            }
        }
        break;
    case ConnectionValidator::Undefined:
    case ConnectionValidator::NotConfigured:
        setState(Disconnected);
        updateRetryCount();
        break;
    case ConnectionValidator::ServerVersionMismatch:
        setState(ConfigurationError);
        break;
    case ConnectionValidator::StatusNotFound:
        // This can happen either because the server does not exist
        // or because we are having network issues. The latter one is
        // much more likely, so keep trying to connect.
        setState(NetworkError);
        updateRetryCount();
        break;
    case ConnectionValidator::CredentialsWrong:
    case ConnectionValidator::CredentialsNotReady:
        handleInvalidCredentials();
        break;
    case ConnectionValidator::SslError:
        setState(SignedOut);
        break;
    case ConnectionValidator::ServiceUnavailable:
        _timeSinceMaintenanceOver.invalidate();
        setState(ServiceUnavailable);
        break;
    case ConnectionValidator::MaintenanceMode:
        _timeSinceMaintenanceOver.invalidate();
        setState(MaintenanceMode);
        break;
    case ConnectionValidator::StatusRedirect:
        _timeSinceMaintenanceOver.invalidate();
        setState(RedirectDetected);
        break;
    case ConnectionValidator::Timeout:
        setState(NetworkError);
        updateRetryCount();
        break;
    case ConnectionValidator::NeedToSignTermsOfService:
        setState(NeedToSignTermsOfService);
        break;
    }

    if ((oldConnectionValidatorStatus == ConnectionValidator::NeedToSignTermsOfService && status == ConnectionValidator::Connected) ||
        (status == ConnectionValidator::NeedToSignTermsOfService && oldConnectionValidatorStatus != status)) {

        Q_EMIT termsOfServiceChanged(_account, status == ConnectionValidator::NeedToSignTermsOfService ? AccountState::NeedToSignTermsOfService : AccountState::Connected);
    }
}

void AccountState::slotHandleRemoteWipeCheck()
{
    // The club's Nextcloud has no remote wipe. Its devices take a new app password with the current device token.
    if (_account->deviceSession()->appliesTo(_account->url())) {
        qCInfo(lcAccountState) << "The app password of" << _account->url().toString() << "was refused; asking for a new one";
        handleInvalidCredentials();
        return;
    }

    // make sure it changes account state and icons
    signOutByUi();

    qCInfo(lcAccountState) << "Invalid credentials for" << _account->url().toString()
                           << "checking for remote wipe request";
}


bool AccountState::ensureDeviceSession()
{
    const auto session = _account->deviceSession();
    if (!session->appliesTo(_account->url())) {
        return true;
    }
    if (_waitingForDeviceSignIn) {
        return false;
    }
    switch (session->status()) {
    case DeviceSession::Status::Unloaded:
        _waitingForDeviceToken = true;
        session->load();
        return false;
    case DeviceSession::Status::Loading:
        _waitingForDeviceToken = true;
        return false;
    case DeviceSession::Status::Absent:
        if (_deviceSessionEnded && !_interactiveSignIn) {
            requireSignIn(tr("This computer's sign-in has ended."));
            return false;
        }
        // Sign in from the start so the browser step of a new app password can reuse the browser session.
        _deviceMemberUnverified = true;
        startDeviceSignIn(DeviceSignIn::Online);
        return false;
    case DeviceSession::Status::Lost:
        // The browser may still be signed in; otherwise the member signs in again when they choose to.
        startDeviceSignIn(_interactiveSignIn ? DeviceSignIn::OfflineInteractive : DeviceSignIn::OfflineSilently);
        return false;
    case DeviceSession::Status::Online:
    case DeviceSession::Status::Offline:
        if (session->hasFreshToken()) {
            return true;
        }
        // A failed renewal waits for its backoff; the next renewal reconnects the account.
        _waitingForDeviceToken = true;
        if (!session->backingOff()) {
            session->refresh();
        }
        return false;
    }
    return false;
}

void AccountState::startDeviceSignIn(DeviceSignIn signIn)
{
    if (!_deviceEnrollment) {
        _deviceEnrollment = new DeviceEnrollment(_account->deviceSession(), this);
        connect(_deviceEnrollment, &DeviceEnrollment::onlineSignedIn, this, [this] {
            _waitingForDeviceSignIn = false;
            setState(Disconnected);
            checkConnectivity();
        });
        connect(_deviceEnrollment, &DeviceEnrollment::offlineReady, this, [this] {
            qCInfo(lcAccountState) << "Stored the offline session of" << _account->url().toString();
            if (std::exchange(_waitingForDeviceSignIn, false)) {
                setState(Disconnected);
                checkConnectivity();
            }
        });
        connect(_deviceEnrollment, &DeviceEnrollment::failed, this, [this](const QString &error) {
            qCWarning(lcAccountState) << "Device sign-in failed for" << _account->url().toString() << error;
            if (_waitingForDeviceSignIn) {
                requireSignIn(_deviceSignIn == DeviceSignIn::OfflineSilently ? tr("This computer's sign-in has ended.") : error);
            }
        });
    }
    if (_deviceEnrollment->busy()) {
        return;
    }
    _deviceSignIn = signIn;
    if (signIn != DeviceSignIn::OfflineAfterSignIn && signIn != DeviceSignIn::OfflineInBackground) {
        // Requests cannot authenticate until this finishes; a failure waits for the member to sign in again.
        _waitingForDeviceSignIn = true;
        setState(AskingCredentials);
    }
    switch (signIn) {
    case DeviceSignIn::Online:
        _interactiveSignIn = true;
        _deviceEnrollment->signInOnline();
        break;
    case DeviceSignIn::OfflineAfterSignIn:
        // After an online sign-in the browser session usually still exists.
        _deviceEnrollment->completeOffline(DeviceEnrollment::Prompt::IfNeeded);
        break;
    case DeviceSignIn::OfflineSilently:
    case DeviceSignIn::OfflineInBackground:
        _deviceEnrollment->completeOffline(DeviceEnrollment::Prompt::Never);
        break;
    case DeviceSignIn::OfflineInteractive:
        _interactiveSignIn = true;
        _deviceEnrollment->completeOffline(DeviceEnrollment::Prompt::Always);
        break;
    }
}

void AccountState::handleInvalidCredentials()
{
    if (isSignedOut() || _waitingForNewCredentials) {
        return;
    }

    // A refused or missing app password of the club's Nextcloud waits until the member signs in again.
    if (_account->deviceSession()->appliesTo(_account->url()) && !_interactiveSignIn) {
        requireSignIn(tr("This computer's app password no longer works."));
        return;
    }

    qCInfo(lcAccountState) << "Invalid credentials for" << _account->url().toString()
                           << "asking user";

    _waitingForNewCredentials = true;
    setState(AskingCredentials);

    if (account()->credentials()->ready()) {
        account()->credentials()->invalidateToken();
    }
    account()->credentials()->askFromUser();
}


void AccountState::slotCredentialsFetched(AbstractCredentials *)
{
    // Make a connection attempt, no matter whether the credentials are
    // ready or not - we want to check whether we can get an SSL connection
    // going before bothering the user for a password.
    qCInfo(lcAccountState) << "Fetched credentials for" << _account->url().toString()
                           << "attempting to connect";
    _waitingForNewCredentials = false;
    if (Migration::isInProgress()) {
        Migration::setPhase(Migration::Phase::Done);
    }
    checkConnectivity();
}

void AccountState::slotCredentialsAsked(AbstractCredentials *credentials)
{
    qCInfo(lcAccountState) << "Credentials asked for" << _account->url().toString()
                           << "are they ready?" << credentials->ready();

    _waitingForNewCredentials = false;

    if (!credentials->ready()) {
        // User canceled the connection or did not give a password
        setState(SignedOut);
        return;
    }

    if (_connectionValidator) {
        // When new credentials become available we always want to restart the
        // connection validation, even if it's currently running.
        _connectionValidator->deleteLater();
        _connectionValidator = nullptr;
    }

    // A new app password may belong to another user ID.
    ++_serverUserCheck;
    _checkingServerUser = false;
    _serverUserChecked = false;
    _serverUserCheckFailed = false;
    checkConnectivity();
}

void AccountState::checkServerUser()
{
    _checkingServerUser = true;
    const auto check = ++_serverUserCheck;
    const auto job = new JsonApiJob(_account, QStringLiteral("ocs/v1.php/cloud/user"), this);
    job->setTimeout(20 * 1000);
    // jsonReceived also reports network errors.
    connect(job, &JsonApiJob::jsonReceived, this, [this, check](const QJsonDocument &json, int statusCode) {
        // New credentials replaced the ones this check asked about.
        if (check != _serverUserCheck) {
            return;
        }
        const auto finish = [this] {
            _checkingServerUser = false;
            _serverUserChecked = true;
            checkConnectivity();
        };
        const auto data = json.object().value("ocs"_L1).toObject().value("data"_L1).toObject();
        const auto user = data.value("id"_L1).toString();
        if (statusCode != 100 || user.isEmpty()) {
            qCWarning(lcAccountState) << "Could not read the user ID of" << _account->url().toString() << "status" << statusCode
                                      << "; checking again before the next connection attempt";
            _checkingServerUser = false;
            _serverUserCheckFailed = true;
            checkConnectivity();
            return;
        }
        const auto previousUser = _account->davUser();
        if (user == previousUser) {
            finish();
            return;
        }
        const auto displayName = data.value("display-name"_L1).toString(user);
        const auto adopt = [this, finish, previousUser, user, displayName] {
            // Folder definitions hold paths relative to the user's files and their own
            // journal paths; credentials are keyed by the login name. Only the DAV
            // user changes, so the local folder setup stays as it is.
            qCInfo(lcAccountState) << "The server now identifies" << previousUser << "as" << user << "; keeping the folders";
            _deviceMemberUnverified = false;
            _account->setDavUser(user);
            _account->setDavDisplayName(displayName);
            Q_EMIT _account->wantsAccountSaved(_account);
            finish();
        };
        if (!_deviceMemberUnverified) {
            // The app password came through this account's own device session.
            adopt();
            return;
        }
        // Nothing ties the browser's member to this account: ask before syncing its folders as them.
        userChangeConfirmation()(previousUser, user, displayName, [self = QPointer<AccountState>(this), check, adopt, previousUser, user](bool accepted) {
            // The account may have been removed, or signed in again, while the question was open.
            if (!self || check != self->_serverUserCheck) {
                return;
            }
            const auto state = self.data();
            if (accepted) {
                adopt();
                return;
            }
            const auto account = state->_account;
            const auto credentials = account->credentials();
            qCWarning(lcAccountState) << "A different member signed in for" << account->url().toString() << "; signing out";
            state->_checkingServerUser = false;
            state->_deviceMemberUnverified = false;
            account->deviceSession()->retire(credentials->user(), credentials->password());
            // The login name belongs to the other member; the account keeps its own.
            if (const auto webFlow = qobject_cast<WebFlowCredentials *>(credentials)) {
                webFlow->forgetSignIn(previousUser);
            } else {
                credentials->forgetSensitiveData();
            }
            Q_EMIT account->wantsAccountSaved(account);
            state->requireSignIn(tr("Signed in as %1, which does not own this account. Sign in with the account's own member.").arg(user));
        });
    });
    job->start();
}

std::unique_ptr<QSettings> AccountState::settings()
{
    auto s = ConfigFile::settingsWithGroup(QLatin1String("Accounts"));
    s->beginGroup(_account->id());
    return s;
}

void AccountState::fetchNavigationApps(){
    auto *job = new OcsNavigationAppsJob(_account);
    job->addRawHeader("If-None-Match", navigationAppsEtagResponseHeader());
    connect(job, &OcsNavigationAppsJob::appsJobFinished, this, &AccountState::slotNavigationAppsFetched);
    connect(job, &OcsNavigationAppsJob::etagResponseHeaderReceived, this, &AccountState::slotEtagResponseHeaderReceived);
    connect(job, &OcsNavigationAppsJob::ocsError, this, &AccountState::slotOcsError);
    job->getNavigationApps();
}

void AccountState::resetRetryCount()
{
    _retryCount = 0;
}

void AccountState::slotEtagResponseHeaderReceived(const QByteArray &value, int statusCode){
    if(statusCode == 200){
        qCDebug(lcAccountState) << "New navigation apps ETag Response Header received " << value;
        setNavigationAppsEtagResponseHeader(value);
    }
}

void AccountState::slotOcsError(int statusCode, const QString &message)
{
    qCWarning(lcAccountState) << "Error " << statusCode << " while fetching new navigation apps: " << message;
}

void AccountState::slotCheckConnection()
{
    if (_lastCheckConnectionTimer.isValid()) {
        static constexpr auto DefaultCallingIntervalMaxMsec = static_cast<int>(ConnectionValidator::DefaultCallingIntervalMsec) * 8;

        const auto minDelay = std::max(retryCount() * ConnectionValidator::DefaultCallingIntervalMsec,
                                       static_cast<int>(ConnectionValidator::DefaultCallingIntervalMsec));
        const auto currentDelay = std::min(minDelay, DefaultCallingIntervalMaxMsec);

        if (!_lastCheckConnectionTimer.hasExpired(currentDelay - 1)) {
            qCInfo(lcAccountState()) << "timer has not expired: do not check now" << _lastCheckConnectionTimer.elapsed() << currentDelay;
            return;
        }
    }

    const auto currentState = state();

    // Don't check if we're manually signed out or
    // when the error is permanent.
    const auto pushNotifications = account()->pushNotifications();
    // Push only replaces the check for an account already validated as connected. The account
    // wizard sets capabilities early, so push can be ready before a new account ever connected.
    const auto pushKeepsAccountConnected = currentState == AccountState::Connected && pushNotifications && pushNotifications->isReady();
    if (currentState != AccountState::SignedOut && currentState != AccountState::ConfigurationError && currentState != AccountState::AskingCredentials
        && !pushKeepsAccountConnected) {
        checkConnectivity();
    } else if (currentState == AccountState::SignedOut && lastConnectionStatus() == AccountState::ConnectionStatus::SslError) {
        qCWarning(lcAccountState()) << "Account is signed out due to SSL Handshake error. Going to perform a sign-in attempt...";
        trySignIn();
    }
}

void AccountState::slotCheckServerAvailibility()
{
    if (state() == AccountState::Connected
        || state() == AccountState::SignedOut
        || state() == AccountState::MaintenanceMode
        || state() == AccountState::AskingCredentials) {
        qCInfo(lcAccountState) << "Skipping server availability check for account" << _account->davUser() << "with state" << state();
        return;
    }
    qCInfo(lcAccountState) << "Checking server availability for account" << _account->davUser();
    const auto serverAvailibilityUrl = Utility::concatUrlPath(_account->url(), QLatin1String("/index.php/204"));
    auto checkServerAvailibilityJob = _account->sendRequest(QByteArrayLiteral("GET"), serverAvailibilityUrl);
    connect(checkServerAvailibilityJob, &SimpleNetworkJob::finishedSignal, this, [this](QNetworkReply *reply) {
        if (reply->attribute(QNetworkRequest::HttpStatusCodeAttribute) == 204) {
            qCInfo(lcAccountState) << "Server is now available for account" << _account->davUser();
            _lastCheckConnectionTimer.invalidate();
            resetRetryCount();
            QMetaObject::invokeMethod(this, &AccountState::slotCheckConnection, Qt::QueuedConnection);
        }
    });
}

void AccountState::slotPushNotificationsReady()
{
    if (state() != AccountState::State::Connected) {
        setState(AccountState::State::Connected);
    }
}

void AccountState::slotServerUserStatusChanged()
{
    setDesktopNotificationsAllowed(_account->userStatusConnector()->userStatus().state() != UserStatus::OnlineStatus::DoNotDisturb);
}

void AccountState::slotNavigationAppsFetched(const QJsonDocument &reply, int statusCode)
{
    if(_account){
        if (statusCode == 304) {
            qCWarning(lcAccountState) << "Status code " << statusCode << " Not Modified - No new navigation apps.";
        } else {
            _apps.clear();

            if(!reply.isEmpty()){
                auto element = reply.object().value("ocs").toObject().value("data");
                const auto navLinks = element.toArray();

                if(navLinks.size() > 0){
                    for (const QJsonValue &value : navLinks) {
                        auto navLink = value.toObject();

                        auto *app = new AccountApp(navLink.value("name"_L1).toString(), QUrl(navLink.value("href"_L1).toString()),
                            navLink.value("id"_L1).toString(), QUrl(navLink.value("icon"_L1).toString()));

                        _apps << app;
                    }
                }
            }

            Q_EMIT hasFetchedNavigationApps();
        }
    }
}

AccountAppList AccountState::appList() const
{
    return _apps;
}

AccountApp* AccountState::findApp(const QString &appId) const
{
    if(!appId.isEmpty()) {
        const auto apps = appList();
        const auto it = std::find_if(apps.cbegin(), apps.cend(), [appId](const auto &app) {
            return app->id() == appId;
        });
        if (it != apps.cend()) {
            return *it;
        }
    }

    return nullptr;
}

/*-------------------------------------------------------------------------------------*/

AccountApp::AccountApp(const QString &name, const QUrl &url,
    const QString &id, const QUrl &iconUrl,
    QObject *parent)
    : QObject(parent)
    , _name(name)
    , _url(url)
    , _id(id)
    , _iconUrl(iconUrl)
{
}

QString AccountApp::name() const
{
    return _name;
}

QUrl AccountApp::url() const
{
    return _url;
}

QString AccountApp::id() const
{
    return _id;
}

QUrl AccountApp::iconUrl() const
{
    return _iconUrl;
}

/*-------------------------------------------------------------------------------------*/

} // namespace OCC
