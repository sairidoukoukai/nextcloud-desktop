/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QGroupBox>

class QLabel;
class QComboBox;
class QFormLayout;
class QLineEdit;
class QPushButton;

namespace OCC
{

class CloudflareAccessSettingsController;
class SettingsSwitch;

class CloudflareAccessSettings : public QGroupBox
{
    Q_OBJECT

public:
    explicit CloudflareAccessSettings(QWidget *parent = nullptr);

protected:
    void showEvent(QShowEvent *event) override;

private:
    void load();
    void loadAccounts();
    void updateEnabled();

    CloudflareAccessSettingsController *_controller;
    SettingsSwitch *_enabled;
    QComboBox *_accounts;
    QLineEdit *_clientId;
    QLineEdit *_clientSecret;
    QPushButton *_apply;
    QPushButton *_browserSignIn;
    QLabel *_error;
    QFormLayout *_form;
    bool _dirty = false;
};

}
