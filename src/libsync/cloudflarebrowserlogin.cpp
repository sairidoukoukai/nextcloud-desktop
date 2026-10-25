/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cloudflarebrowserlogin.h"
#include "cloudflareaccess.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QProcessEnvironment>
#include <QStandardPaths>

#ifdef Q_OS_WIN
#include <qt_windows.h>
#include <sddl.h>
#include <vector>
#endif

using namespace Qt::StringLiterals;

namespace OCC
{

CloudflareBrowserLogin::CloudflareBrowserLogin(QObject *parent, const QString &helper, const QByteArray &digest, std::chrono::milliseconds timeout)
    : QObject(parent)
    , _helper(helper.isEmpty() ? QCoreApplication::applicationDirPath() + "/nextcloud-cloudflared"_L1
#ifdef Q_OS_WIN
                      + ".exe"_L1
#endif
                               : helper)
    , _digest(digest.isEmpty() ? QByteArray(CLOUDFLARED_HELPER_SHA256) : digest)
{
    _timer.setSingleShot(true);
    _timer.setInterval(timeout);
    connect(&_timer, &QTimer::timeout, this, [this] {
        _processError = tr("Browser sign-in timed out. Try again when you are ready.");
        _process.kill();
    });
    connect(&_process, &QProcess::readyReadStandardOutput, this, [this] {
        constexpr auto maximumOutput = 32768;
        _output += _process.readAllStandardOutput();
        if (_output.size() > maximumOutput) {
            _processError = tr("Browser sign-in returned an invalid response.");
            _process.kill();
        }
    });
    connect(&_process, &QProcess::readyReadStandardError, this, [this] {
        // The helper prints authentication URLs here. Never retain or log them.
        _process.readAllStandardError();
    });
    connect(&_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            complete({}, tr("Could not start browser sign-in. Reinstall the Sairibus client and try again."));
        }
    });
    connect(&_process, &QProcess::finished, this, [this](int code, QProcess::ExitStatus status) {
        if (!_busy) {
            return;
        }
        _output += _process.readAllStandardOutput();
        if (!_processError.isEmpty()) {
            complete({}, _processError);
        } else if (code != 0 || status != QProcess::NormalExit) {
            complete({}, tr("Browser sign-in did not finish. Check your connection and try again."));
        } else {
            const auto token = _output.trimmed();
            const auto error = CloudflareAccess::browserTokenError(token);
            complete(error.isEmpty() ? token : QByteArray{}, error);
        }
    });
#ifdef Q_OS_WIN
    _process.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *arguments) {
        arguments->flags |= CREATE_NO_WINDOW;
    });
#endif
}

CloudflareBrowserLogin::~CloudflareBrowserLogin()
{
    disconnect(&_process, nullptr, this, nullptr);
    _process.kill();
    _process.waitForFinished(1000);
}

bool CloudflareBrowserLogin::busy() const
{
    return _busy;
}

bool CloudflareBrowserLogin::makePrivate(const QString &path)
{
#ifdef Q_OS_WIN
    auto processToken = HANDLE{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken)) {
        return false;
    }
    auto required = DWORD{};
    GetTokenInformation(processToken, TokenUser, nullptr, 0, &required);
    auto storage = std::vector<unsigned char>(required);
    const auto found = GetTokenInformation(processToken, TokenUser, storage.data(), required, &required);
    CloseHandle(processToken);
    if (!found) {
        return false;
    }
    auto sid = LPWSTR{};
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(storage.data())->User.Sid, &sid)) {
        return false;
    }
    const auto dacl = QString("D:P(A;OICI;FA;;;"_L1 + QString::fromWCharArray(sid) + ")(A;OICI;FA;;;SY)"_L1);
    LocalFree(sid);
    auto descriptor = PSECURITY_DESCRIPTOR{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(reinterpret_cast<LPCWSTR>(dacl.utf16()), SDDL_REVISION_1, &descriptor, nullptr)) {
        return false;
    }
    const auto applied = SetFileSecurityW(reinterpret_cast<LPCWSTR>(path.utf16()), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    return applied;
#else
    return QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
#endif
}

void CloudflareBrowserLogin::start(const QUrl &server)
{
    if (_busy) {
        return;
    }
    const auto origin = CloudflareAccess::origin(server);
    if (const auto error = CloudflareAccess::validate(true, server.toString(), "browser"_L1, "browser"_L1); !error.isEmpty()) {
        Q_EMIT finished({}, error);
        return;
    }
    auto helper = QFile(_helper);
    if (!helper.open(QIODevice::ReadOnly) || QCryptographicHash::hash(helper.readAll(), QCryptographicHash::Sha256).toHex() != _digest) {
        Q_EMIT finished({}, tr("The browser sign-in component is missing or damaged. Reinstall the Sairibus client."));
        return;
    }
    helper.close();
    _directory = std::make_unique<QTemporaryDir>(QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/nextcloud-access-XXXXXX"_L1);
    if (!_directory->isValid() || !makePrivate(_directory->path())) {
        _directory.reset();
        Q_EMIT finished({}, tr("Could not create private storage for browser sign-in."));
        return;
    }
    auto environment = QProcessEnvironment::systemEnvironment();
    // Isolate only this child's cache. Never read or delete the user's regular
    // cloudflared directory; persistent sessions belong in the account keychain.
#ifdef Q_OS_WIN
    environment.remove("HOME"_L1);
    environment.insert("USERPROFILE"_L1, _directory->path());
#else
    environment.insert("HOME"_L1, _directory->path());
#endif
    _process.setProcessEnvironment(environment);
    _process.setProgram(_helper);
    _process.setArguments({"access"_L1, "login"_L1, "--no-verbose"_L1, "--auto-close"_L1, origin.toString()});
    _process.setWorkingDirectory(_directory->path());
    _output.clear();
    _processError.clear();
    _busy = true;
    _timer.start();
    _process.start();
}

void CloudflareBrowserLogin::cancel()
{
    if (!_busy) {
        return;
    }
    _processError = tr("Browser sign-in was cancelled.");
    _process.kill();
}

void CloudflareBrowserLogin::complete(const QByteArray &token, const QString &error)
{
    _timer.stop();
    _busy = false;
    _output.clear();
    _directory.reset();
    Q_EMIT finished(token, error);
}

}
