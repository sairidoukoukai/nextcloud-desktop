/*
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "remotewipe.h"
#include "accessmanager.h"
#include "cloudflareaccess.h"
#include "folderman.h"
#include "httplogger.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrlQuery>

using namespace Qt::StringLiterals;

namespace OCC {

Q_LOGGING_CATEGORY(lcRemoteWipe, "nextcloud.gui.remotewipe", QtInfoMsg)

RemoteWipe::RemoteWipe(AccountPtr account, QObject *parent, CloudflareAccess *cloudflareAccess, PasswordReader reader)
    : QObject(parent)
    , _account(account)
    , _passwordReader(reader ? std::move(reader) : [this](PasswordCompletion completion) { _account->retrieveAppPassword(true, std::move(completion)); })
    , _accessOverride(cloudflareAccess)
    , _appPassword(QString())
    , _networkManager{new AccessManager{this}}
{
    QObject::connect(AccountManager::instance(), &AccountManager::accountRemoved,
                     this, [=, this](AccountState *accountState) {
        if (_account != accountState->account()) {
            return;
        }

        if (!_wipeAuthorized) {
            _cancelled = true;
            ++_passwordReadGeneration;
            _passwordReadPending = false;
            const auto reply = _networkReplyCheck;
            _networkReplyCheck = nullptr;
            if (reply) {
                reply->abort();
                reply->deleteLater();
            }
            clearAccessCredentials();
            return;
        }

        notifyServerSuccess();
    });

    if (FolderMan::instance()) {
        qCDebug(lcRemoteWipe) << "FolderMan instance is present, a remote wipe will clean up local data first";
        _canWipeLocalFiles = true;
        QObject::connect(this, &RemoteWipe::authorized, FolderMan::instance(),
                         &FolderMan::slotWipeFolderForAccount);
        QObject::connect(FolderMan::instance(), &FolderMan::wipeDone, this,
                         &RemoteWipe::slotWipeDone);
    }

    connect(_account.data(), &Account::cloudflareRemoteWipeCheckRequested, this, &RemoteWipe::readAccessPassword);
    QObject::connect(_account.data(), &Account::appPasswordRetrieved, this,
                     &RemoteWipe::startCheckJobWithAppPassword);
}

void RemoteWipe::readAccessPassword()
{
    if (_cancelled || _passwordReadPending || _networkReplyCheck || !_appPassword.isEmpty()) {
        return;
    }
    _passwordReadPending = true;
    const auto generation = ++_passwordReadGeneration;
    const auto guard = QPointer<RemoteWipe>(this);
    _passwordReader([guard, generation](QString password) {
        if (!guard || guard->_passwordReadGeneration != generation || !guard->_passwordReadPending) {
            return;
        }
        guard->_passwordReadPending = false;
        guard->startCheckJob(std::move(password), true);
    });
    QTimer::singleShot(std::chrono::seconds(30), this, [this, generation] {
        if (_passwordReadGeneration == generation && _passwordReadPending) {
            ++_passwordReadGeneration;
            _passwordReadPending = false;
        }
    });
}

AccountState *RemoteWipe::registeredAccount() const
{
    for (const auto &state : AccountManager::instance()->accounts()) {
        if (state->account() == _account) {
            return state.data();
        }
    }
    return nullptr;
}

void RemoteWipe::boundReply(QNetworkReply *reply)
{
    constexpr auto maximumResponseBytes = 65536;
    reply->setReadBufferSize(maximumResponseBytes + 1);
    connect(reply, &QIODevice::readyRead, reply, [reply] {
        if (reply->bytesAvailable() > maximumResponseBytes) {
            reply->abort();
        }
    });
    QTimer::singleShot(std::chrono::seconds(30), reply, [reply] {
        if (!reply->isFinished()) {
            reply->abort();
        }
    });
}

void RemoteWipe::clearAccessCredentials()
{
    if (const auto manager = qobject_cast<AccessManager *>(_networkManager)) {
        manager->setAccountAccess(nullptr);
    }
    delete _accessSnapshot;
    _accessSnapshot = nullptr;
    _appPassword.clear();
}

void RemoteWipe::startCheckJobWithAppPassword(QString pwd)
{
    ++_passwordReadGeneration;
    _passwordReadPending = false;
    if (_preserveCredentials && _networkReplyCheck && !_wipeAuthorized) {
        const auto reply = _networkReplyCheck;
        _networkReplyCheck = nullptr;
        reply->abort();
        reply->deleteLater();
        clearAccessCredentials();
    }
    startCheckJob(std::move(pwd), false);
}

void RemoteWipe::startCheckJob(QString pwd, bool preserveCredentials)
{
    if (_cancelled || _networkReplyCheck || _networkReplySuccess || _wipeAuthorized || !registeredAccount()) {
        return;
    }
    _preserveCredentials = preserveCredentials;
    if (pwd.isEmpty()) {
        _preserveCredentials = false;
        qCDebug(lcRemoteWipe) << "not checking remote wipe status: app password is empty";
        return;
    }

    clearAccessCredentials();
    const auto accountManager = qobject_cast<AccessManager *>(_account->networkAccessManager());
    const auto access = _accessOverride ? _accessOverride.data() : accountManager ? accountManager->cloudflareAccess() : nullptr;
    if (access && access->enabled()) {
        if (access->busy() || !access->ready() || !access->protects(_account->url())) {
            _preserveCredentials = false;
            Q_EMIT _account->cloudflareAccessCheckFailed();
            return;
        }
        _accessSnapshot = access->snapshot(this);
        const auto manager = qobject_cast<AccessManager *>(_networkManager);
        if (!manager) {
            clearAccessCredentials();
            return;
        }
        manager->setAccountAccess(_accessSnapshot);
    }
    _networkManager->setProxy(_account->networkAccessManager()->proxy());
    _requestUrl = _account->url();
    _requestEpoch = _account->nativeCredentialEpoch();
    _appPassword = pwd;
    QUrl requestUrl = Utility::concatUrlPath(_account->url().toString(),
                                             QLatin1String("/index.php/core/wipe/check"));
    QNetworkRequest request;
    request.setTransferTimeout(std::chrono::seconds(30));
    request.setAttribute(HttpLogger::SensitiveBodyAttribute, true);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      "application/x-www-form-urlencoded");
    request.setUrl(requestUrl);
    request.setSslConfiguration(_account->getOrCreateSslConfig());
    auto arguments = QUrlQuery();
    arguments.addQueryItem("token"_L1, _appPassword);
    _networkReplyCheck = _networkManager->post(request, arguments.query(QUrl::FullyEncoded).toUtf8().replace("+", "%2B"));
    boundReply(_networkReplyCheck);
    QObject::connect(_networkManager, &QNetworkAccessManager::sslErrors,
        _account.data(), &Account::slotHandleSslErrors);
    const auto reply = _networkReplyCheck;
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        if (_networkReplyCheck == reply) {
            slotCheckJob();
        }
    });
}

void RemoteWipe::slotCheckJob()
{
    const auto accountState = registeredAccount();
    if (_cancelled || !accountState || _account->url() != _requestUrl || (_preserveCredentials && _account->nativeCredentialEpoch() != _requestEpoch)) {
        _networkReplyCheck->deleteLater();
        _networkReplyCheck = nullptr;
        clearAccessCredentials();
        _preserveCredentials = false;
        return;
    }
    auto jsonData = _networkReplyCheck->readAll();
    QJsonParseError jsonParseError{};
    QJsonObject json = QJsonDocument::fromJson(jsonData, &jsonParseError).object();
    bool wipe = false;

    //check for errors
    if (_networkReplyCheck->error() != QNetworkReply::NoError ||
            jsonParseError.error != QJsonParseError::NoError) {
        QString errorFromJson = json["error"].toString();
        if (!errorFromJson.isEmpty()) {
            qCWarning(lcRemoteWipe) << QStringLiteral("Error returned from the server: <em>%1<em>")
                                       .arg(errorFromJson.toHtmlEscaped());
        } else if (_networkReplyCheck->error() != QNetworkReply::NoError) {
            qCWarning(lcRemoteWipe) << QStringLiteral("There was an error accessing the 'token' endpoint: <br><em>%1</em>")
                              .arg(_networkReplyCheck->errorString().toHtmlEscaped());
        } else if (jsonParseError.error != QJsonParseError::NoError) {
            qCWarning(lcRemoteWipe) << QStringLiteral("Could not parse the JSON returned from the server: <br><em>%1</em>")
                              .arg(jsonParseError.errorString());
        } else {
            qCWarning(lcRemoteWipe) <<  QStringLiteral("The reply from the server did not contain all expected fields");
        }

    // check for wipe request
    } else if (_networkReplyCheck->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200
               && _networkReplyCheck->url() == _networkReplyCheck->request().url() && json.value("wipe").isBool()) {
        wipe = json["wipe"].toBool();
    }

    auto manager = AccountManager::instance();

    if (wipe) {
        _wipeAuthorized = true;
        qCInfo(lcRemoteWipe) << "Starting remote wipe for" << _account->displayName();

        /* IMPORTANT - remove later - FIXME MS@2019-12-07 -->
         * TODO: For "Log out" & "Remove account": Remove client CA certs and KEY!
         *
         *       Disabled as long as selecting another cert is not supported by the UI.
         *
         *       Being able to specify a new certificate is important anyway: expiry etc.
         *
         *       We introduce this dirty hack here, to allow deleting them upon Remote Wipe.
         */
        _account->setRemoteWipeRequested_HACK();
        // <-- FIXME MS@2019-12-07

        // delete data
        Q_EMIT authorized(accountState);

        if (!_canWipeLocalFiles) {
            qCInfo(lcRemoteWipe) << "Deleting account" << _account->displayName();
            // delete account if there was nothing else to wipe
            manager->deleteAccount(accountState);
            manager->save();
        }
    } else {
        // ask user for his credentials again
        clearAccessCredentials();
        if (!_preserveCredentials) {
            accountState->handleInvalidCredentials();
        }
        _preserveCredentials = false;
    }

    _networkReplyCheck->deleteLater();
    _networkReplyCheck = nullptr;
}

void RemoteWipe::slotWipeDone(AccountState *accountState, bool dataWiped)
{
    if (!accountState || accountState->account() != _account) {
        return;
    }
    if (!dataWiped) {
        clearAccessCredentials();
        _preserveCredentials = false;
        _wipeAuthorized = false;
        return;
    }

    // delete account after wiping local data succeeded
    // sending the notification to the server will be done after the account got removed
    qCInfo(lcRemoteWipe) << "Deleting account" << _account->displayName();
    auto manager = AccountManager::instance();
    manager->deleteAccount(accountState);
    manager->save();
}

void RemoteWipe::notifyServerSuccess()
{
    if (!_wipeAuthorized || _networkReplySuccess || _appPassword.isEmpty()) {
        return;
    }
    qCInfo(lcRemoteWipe) << "Notifying server about successful remote wipe for" << _account->displayName();
    QUrl requestUrl = Utility::concatUrlPath(_requestUrl.toString(), QLatin1String("/index.php/core/wipe/success"));
    QNetworkRequest request;
    request.setTransferTimeout(std::chrono::seconds(30));
    request.setAttribute(HttpLogger::SensitiveBodyAttribute, true);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                        "application/x-www-form-urlencoded");
    request.setUrl(requestUrl);
    request.setSslConfiguration(_account->getOrCreateSslConfig());
    auto arguments = QUrlQuery();
    arguments.addQueryItem("token"_L1, _appPassword);
    _networkReplySuccess = _networkManager->post(request, arguments.query(QUrl::FullyEncoded).toUtf8().replace("+", "%2B"));
    boundReply(_networkReplySuccess);
    QObject::connect(_networkReplySuccess, &QNetworkReply::finished, this,
                        &RemoteWipe::slotNotifyServerSuccessFinished);
}

void RemoteWipe::slotNotifyServerSuccessFinished()
{
    auto jsonData = _networkReplySuccess->readAll();
    QJsonParseError jsonParseError{};
    QJsonObject json = QJsonDocument::fromJson(jsonData, &jsonParseError).object();
    if (_networkReplySuccess->error() != QNetworkReply::NoError ||
            jsonParseError.error != QJsonParseError::NoError) {
        QString errorFromJson = json["error"].toString();
        if (!errorFromJson.isEmpty()) {
            qCWarning(lcRemoteWipe) << QStringLiteral("Error returned from the server: <em>%1</em>")
                              .arg(errorFromJson.toHtmlEscaped());
        } else if (_networkReplySuccess->error() != QNetworkReply::NoError) {
            qCWarning(lcRemoteWipe) << QStringLiteral("There was an error accessing the 'success' endpoint: <br><em>%1</em>")
                              .arg(_networkReplySuccess->errorString().toHtmlEscaped());
        } else if (jsonParseError.error != QJsonParseError::NoError) {
            qCWarning(lcRemoteWipe) << QStringLiteral("Could not parse the JSON returned from the server: <br><em>%1</em>")
                              .arg(jsonParseError.errorString());
        } else {
            qCWarning(lcRemoteWipe) << QStringLiteral("The reply from the server did not contain all expected fields.");
        }
    }

    clearAccessCredentials();
    _preserveCredentials = false;
    _wipeAuthorized = false;
    _networkReplySuccess->deleteLater();
    _networkReplySuccess = nullptr;
}
}
