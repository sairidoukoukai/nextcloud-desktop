/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cloudflareaccesssettings.h"

#include "accountmanager.h"
#include "cloudflareaccesssettingscontroller.h"
#include "settingsswitch.h"

#include <QComboBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>

using namespace Qt::StringLiterals;

namespace OCC
{

CloudflareAccessSettings::CloudflareAccessSettings(QWidget *parent, CloudflareAccess *access)
    : QGroupBox(parent)
    , _controller(new CloudflareAccessSettingsController(this, access))
    , _enabled(new SettingsSwitch(this))
    , _accounts(new QComboBox(this))
    , _clientId(new QLineEdit(this))
    , _clientSecret(new QLineEdit(this))
    , _apply(new QPushButton(tr("Apply"), this))
    , _error(new QLabel(this))
    , _form(new QFormLayout)
{
    setObjectName("cloudflareAccessGroupBox"_L1);
    _enabled->setObjectName("cloudflareAccessEnabled"_L1);
    _enabled->setAccessibleName(tr("Enable Cloudflare Access"));
    _accounts->setObjectName("cloudflareAccessAccount"_L1);
    _accounts->setPlaceholderText(tr("Set up a Nextcloud account first"));
    _clientId->setObjectName("cloudflareAccessClientId"_L1);
    _clientSecret->setObjectName("cloudflareAccessClientSecret"_L1);
    _clientSecret->setEchoMode(QLineEdit::Password);
    _apply->setObjectName("cloudflareAccessApply"_L1);
    _error->setObjectName("cloudflareAccessError"_L1);
    _error->setWordWrap(true);

    const auto layout = new QHBoxLayout(this);
    const auto content = new QGridLayout;
    content->setContentsMargins(0, 0, 0, 0);
    content->setColumnStretch(0, 1);
    layout->addLayout(content);
    const auto label = new QLabel(tr("Enable Cloudflare Access"), this);
    label->setBuddy(_enabled);
    content->addWidget(label, 0, 0);
    content->addWidget(_enabled, 0, 1, Qt::AlignRight);
    _form->setContentsMargins(0, 0, 0, 0);
    _form->setLabelAlignment(Qt::AlignLeading | Qt::AlignVCenter);
    _form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    _form->addRow(tr("Account"), _accounts);
    _form->addRow(tr("Client ID"), _clientId);
    _form->addRow(tr("Client Secret"), _clientSecret);
    content->addLayout(_form, 1, 0, 1, 2);
    const auto hint = new QLabel(tr("Credentials are shared by all accounts on this HTTPS server and sent to every path on the same hostname and port. macOS "
                                    "File Provider is not supported."),
                                 this);
    hint->setWordWrap(true);
    hint->setObjectName("cloudflareAccessHint"_L1);
    content->addWidget(hint, 2, 0, 1, 2);
    content->addWidget(_error, 3, 0, 1, 2);
    content->addWidget(_apply, 4, 0, 1, 2, Qt::AlignRight);
    connect(_enabled, &QAbstractButton::toggled, this, [this] {
        _dirty = true;
        updateEnabled();
    });
    for (const auto field : {_clientId, _clientSecret}) {
        connect(field, &QLineEdit::textEdited, this, [this] {
            _dirty = true;
        });
    }
    connect(_apply, &QPushButton::clicked, this, [this] {
        _controller->save(_enabled->isChecked(), _accounts->currentData().toString(), _clientId->text(), _clientSecret->text());
    });
    connect(_controller, &CloudflareAccessSettingsController::changed, this, [this] {
        if (!_dirty) {
            load();
        }
        _error->setText(_controller->error());
        _error->setVisible(!_controller->error().isEmpty());
        updateEnabled();
    });
    connect(_controller, &CloudflareAccessSettingsController::saved, this, [this](bool success) {
        if (success) {
            _dirty = false;
            load();
        }
    });
    connect(_accounts, &QComboBox::currentIndexChanged, this, [this] {
        _dirty = false;
        _controller->resetError();
        load();
    });
    const auto manager = AccountManager::instance();
    connect(manager, &AccountManager::accountAdded, this, &CloudflareAccessSettings::loadAccounts);
    connect(manager, &AccountManager::accountRemoved, this, &CloudflareAccessSettings::loadAccounts);
    loadAccounts();
}

void CloudflareAccessSettings::loadAccounts()
{
    const auto previous = _accounts->currentData().toString();
    const auto blocker = QSignalBlocker(_accounts);
    _accounts->clear();
    const auto accounts = AccountManager::instance()->accounts();
    auto selected = -1;
    for (const auto &state : accounts) {
        const auto account = state->account();
        const auto url = account->url().toString();
        _accounts->addItem(account->displayName(), url);
        if (url == previous || (selected < 0 && _controller->isConfiguredForServer(url))) {
            selected = _accounts->count() - 1;
        }
    }
    _accounts->setCurrentIndex(selected >= 0 ? selected : (_accounts->count() > 0 ? 0 : -1));
    _dirty = false;
    _controller->resetError();
    load();
}

void CloudflareAccessSettings::load()
{
    const auto blocker = QSignalBlocker(_enabled);
    const auto configured = _controller->isConfiguredForServer(_accounts->currentData().toString());
    _enabled->setChecked(configured && _controller->enabled());
    _clientId->setText(configured ? _controller->clientId() : QString{});
    _clientSecret->setText(configured ? _controller->clientSecret() : QString{});
    _error->setText(_controller->error());
    _error->setVisible(!_controller->error().isEmpty());
    updateEnabled();
}

void CloudflareAccessSettings::showEvent(QShowEvent *event)
{
    _dirty = false;
    _controller->resetError();
    load();
    QGroupBox::showEvent(event);
}

void CloudflareAccessSettings::updateEnabled()
{
    _accounts->setEnabled(!_controller->busy());
    _enabled->setEnabled(!_controller->busy() && _accounts->currentIndex() >= 0);
    for (const auto field : {_clientId, _clientSecret}) {
        field->setEnabled(_enabled->isChecked() && !_controller->busy());
        _form->labelForField(field)->setEnabled(field->isEnabled());
    }
    _apply->setEnabled(!_controller->busy() && _accounts->currentIndex() >= 0
                       && (_enabled->isChecked() || _controller->isConfiguredForServer(_accounts->currentData().toString())));
}

}
