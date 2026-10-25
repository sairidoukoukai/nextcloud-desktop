/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "syncenginetestutils.h"

class CloudflareNativeTestCredentials : public FakeCredentials
{
public:
    explicit CloudflareNativeTestCredentials(QNetworkAccessManager *manager)
        : FakeCredentials(manager)
    {
        using namespace Qt::StringLiterals;
        _password = "native-device-secret"_L1;
    }

    [[nodiscard]] QString password() const override
    {
        return _password;
    }
    [[nodiscard]] bool ready() const override
    {
        return !_password.isEmpty();
    }
    void forgetSensitiveData() override
    {
        ++forgotten;
        _password.clear();
    }

    void refreshPassword()
    {
        using namespace Qt::StringLiterals;
        _password = "refreshed-device-secret"_L1;
        Q_EMIT asked();
    }

    int forgotten = 0;

private:
    QString _password;
};
