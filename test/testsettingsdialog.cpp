/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "settingsdialog.h"
#include "cloudflarebrowsertestutils.h"

#include "account.h"
#include "accountmanager.h"
#include "accountsettings.h"
#include "cloudflareaccess.h"
#include "cloudflareaccesssettings.h"
#include "cloudflareaccesssettingscontroller.h"
#include "configfile.h"
#include "settingsswitch.h"
#include "syncenginetestutils.h"
#include "systray.h"

#include <QAction>
#include <QApplication>
#include <QComboBox>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScopeGuard>
#include <QScrollArea>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTest>
#include <QToolBar>

using namespace Qt::StringLiterals;

class TestSettingsDialog : public QObject
{
    Q_OBJECT

    QTemporaryDir _configDir;
    QPalette _originalPalette;

private Q_SLOTS:
    void removingServiceAccountDuringSaveDoesNotChangeAnotherAccount()
    {
        const auto immediate = [](const QString &, const std::optional<QByteArray> &, OCC::CloudflareAccess::Completion done) {
            done({}, {});
        };
        OCC::CloudflareAccess fallback(nullptr, immediate, std::chrono::seconds(1), "fallback"_L1);
        OCC::CloudflareAccess second(nullptr, immediate, std::chrono::seconds(1), "second"_L1);
        OCC::CloudflareAccess::Completion pending;
        const auto first = new OCC::CloudflareAccess(
            nullptr,
            [&](const QString &, const std::optional<QByteArray> &value, OCC::CloudflareAccess::Completion done) {
                if (value && !value->isEmpty()) {
                    pending = std::move(done);
                } else {
                    done({}, {});
                }
            },
            std::chrono::seconds(1),
            "first"_L1);
        OCC::CloudflareAccessSettingsController controller(nullptr, &fallback);
        controller.setAccountAccess(first);
        controller.save(true, "https://first.example"_L1, "first-id"_L1, "first-secret"_L1);
        QVERIFY(controller.busy());
        QVERIFY(pending);
        delete first;
        QVERIFY(!controller.busy());
        controller.setAccountAccess(&second);
        controller.save(true, "https://second.example"_L1, "second-id"_L1, "second-secret"_L1);
        QVERIFY(second.enabled());
        QVERIFY(!fallback.enabled());
        pending({}, {});
        QCOMPARE(controller.clientId(), "second-id"_L1);
    }

    void browserRenewalWaitsForTheSavedAccountIdentity()
    {
        QByteArray stored;
        const auto original = OCC::Test::browserToken();
        {
            OCC::CloudflareAccess session(
                nullptr,
                [&](const QString &, const std::optional<QByteArray> &data, OCC::CloudflareAccess::Completion done) {
                    if (data) {
                        stored = *data;
                    }
                    done(stored, {});
                },
                std::chrono::seconds(1),
                u"loading-account"_s);
            session.saveBrowserToken(u"https://cloud.example"_s, original);
            QVERIFY(session.ready());
        }
        OCC::CloudflareAccess::Completion loaded;
        OCC::CloudflareAccess session(
            nullptr,
            [&](const QString &, const std::optional<QByteArray> &data, OCC::CloudflareAccess::Completion done) {
                if (!data) {
                    loaded = std::move(done);
                } else {
                    done({}, {});
                }
            },
            std::chrono::seconds(5),
            u"loading-account"_s);
        OCC::Test::BrowserLogin helper;
        OCC::CloudflareAccessSettingsController controller(nullptr, nullptr, &helper);
        controller.setAccountAccess(&session);
        QVERIFY(controller.busy());
        controller.signInBrowser(u"https://cloud.example"_s);
        QVERIFY(!helper.running);
        QVERIFY(loaded);
        loaded(stored, {});
        QVERIFY(!controller.busy());
        controller.signInBrowser(u"https://cloud.example"_s);
        QVERIFY(helper.running);
        helper.running = false;
        Q_EMIT helper.finished(OCC::Test::browserToken(QDateTime::currentSecsSinceEpoch() + 3600, u"eeeeeeee-1111-4444-9999-111111111111"_s), {});
        QVERIFY(!controller.busy());
        QVERIFY(!controller.error().isEmpty());
        auto request = QNetworkRequest(QUrl(u"https://cloud.example/status.php"_s));
        QVERIFY(session.prepareRequest(request).isEmpty());
        QCOMPARE(request.rawHeader("cf-access-token"), original);
    }

    void browserSignInRemovalDuringStorageDoesNotLockSettings()
    {
        OCC::CloudflareAccess::Completion pending;
        OCC::CloudflareAccess session(
            nullptr,
            [&](const QString &, const std::optional<QByteArray> &data, OCC::CloudflareAccess::Completion done) {
                if (data && !data->isEmpty()) {
                    pending = std::move(done);
                } else {
                    done({}, {});
                }
            },
            std::chrono::seconds(1),
            u"fixture-account"_s);
        OCC::Test::BrowserLogin helper;
        OCC::CloudflareAccessSettingsController controller(nullptr, nullptr, &helper);
        controller.setAccountAccess(&session);
        QSignalSpy finished(&controller, &OCC::CloudflareAccessSettingsController::browserFinished);
        controller.signInBrowser(u"https://cloud.example"_s);
        helper.succeed();
        QVERIFY(controller.busy());
        QVERIFY(pending);
        session.clear();
        QVERIFY(!controller.busy());
        QCOMPARE(finished.size(), 1);
        QVERIFY(!finished[0][0].toBool());
        pending({}, {});
        QVERIFY(!session.enabled());
        controller.signInBrowser(u"https://cloud.example"_s);
        QVERIFY(helper.running);
        controller.cancelBrowserSignIn();
        QVERIFY(helper.cancelled);
        QVERIFY(!controller.busy());
    }

    void browserAccountSelectionSurvivesSameOriginRefresh()
    {
        const auto manager = OCC::AccountManager::instance();
        QList<OCC::AccountState *> states;
        const auto remove = qScopeGuard([&] {
            for (const auto state : states) {
                manager->removeAccountState(state);
            }
        });
        const auto makeAccount = [&] {
            const auto account = OCC::Account::create();
            account->setUrl(QUrl(u"https://cloud.example"_s));
            account->setCredentials(new FakeCredentials(new FakeQNAM({})));
            states.append(manager->addAccount(account));
            return account;
        };
        const auto personal = makeAccount();
        const auto administrator = makeAccount();
        OCC::CloudflareAccessSettings widget;
        const auto accounts = widget.findChild<QComboBox *>(u"cloudflareAccessAccount"_s);
        QVERIFY(accounts);
        accounts->setCurrentIndex(0);
        const auto selected = accounts->currentData(Qt::UserRole + 1).toString();
        QCOMPARE(selected, personal->uuid().toString());
        makeAccount();
        QCOMPARE(accounts->currentData(Qt::UserRole + 1).toString(), selected);
        QVERIFY(!widget.findChild<QLineEdit *>(u"cloudflareAccessClientSecret"_s)->isHidden());
        QVERIFY(!widget.findChild<QPushButton *>(u"cloudflareBrowserSignIn"_s)->isHidden());
        Q_UNUSED(administrator)
    }

    void cloudflarePanelMargins_data()
    {
        QTest::addColumn<bool>("dark");
        QTest::newRow("light") << false;
        QTest::newRow("dark") << true;
    }

    void cloudflarePanelMargins()
    {
        Q_INIT_RESOURCE(theme);
        QFETCH(bool, dark);
        auto palette = QApplication::palette();
        palette.setColor(QPalette::Window, dark ? QColor(u"#202020"_s) : QColor(Qt::white));
        palette.setColor(QPalette::WindowText, dark ? Qt::white : Qt::black);
        QApplication::setPalette(palette);
        OCC::SettingsDialog dialog(nullptr);
        for (const auto action : dialog.findChildren<QAction *>()) {
            if (action->text() == OCC::SettingsDialog::tr("Advanced")) {
                action->trigger();
            }
        }
        dialog.show();
        const auto panel = dialog.findChild<OCC::CloudflareAccessSettings *>();
        const auto referencePanel = dialog.findChild<QGroupBox *>(u"advancedGroupBox"_s);
        const auto referenceLabel = dialog.findChild<QLabel *>(u"newFolderLimitLabel"_s);
        QVERIFY(panel && referencePanel && referenceLabel);
        QTRY_VERIFY(panel->isVisible());
        const auto accounts = panel->findChild<QComboBox *>(u"cloudflareAccessAccount"_s);
        const auto id = panel->findChild<QLineEdit *>(u"cloudflareAccessClientId"_s);
        const auto secret = panel->findChild<QLineEdit *>(u"cloudflareAccessClientSecret"_s);
        const auto apply = panel->findChild<QPushButton *>(u"cloudflareAccessApply"_s);
        const auto toggle = panel->findChild<OCC::SettingsSwitch *>(u"cloudflareAccessEnabled"_s);
        auto form = static_cast<QFormLayout *>(nullptr);
        for (const auto candidate : panel->findChildren<QFormLayout *>()) {
            if (candidate->labelForField(accounts)) {
                form = candidate;
                break;
            }
        }
        QVERIFY(accounts && id && secret && apply && toggle && form);
        const auto margin = referenceLabel->mapTo(referencePanel, QPoint{}).x();
        QVERIFY(margin > 0);
        const auto accountLabel = form->labelForField(accounts);
        QVERIFY(accountLabel);
        QCOMPARE(accountLabel->mapTo(panel, QPoint{}).x(), margin);
        for (const auto field : {static_cast<QWidget *>(id), static_cast<QWidget *>(secret)}) {
            const auto label = form->labelForField(field);
            QVERIFY(label);
            QCOMPARE(label->mapTo(panel, QPoint{}).x(), margin);
            QCOMPARE(field->mapTo(panel, QPoint{}).x(), accounts->mapTo(panel, QPoint{}).x());
        }
        QCOMPARE(panel->width() - apply->mapTo(panel, apply->rect().topRight()).x() - 1, margin);
        QCOMPARE(panel->width() - toggle->mapTo(panel, toggle->rect().topRight()).x() - 1, margin);
        QVERIFY(apply->width() < secret->width());
        const auto hint = panel->findChild<QLabel *>(u"cloudflareAccessHint"_s);
        QVERIFY(hint);
        QCOMPARE(hint->mapTo(panel, QPoint{}).x(), margin);
        QVERIFY(hint->mapTo(panel, QPoint{}).y() > secret->mapTo(panel, secret->rect().bottomLeft()).y());
        QVERIFY(apply->mapTo(panel, QPoint{}).y() > hint->mapTo(panel, hint->rect().bottomLeft()).y());
        const auto controller = panel->findChild<OCC::CloudflareAccessSettingsController *>();
        const auto error = panel->findChild<QLabel *>(u"cloudflareAccessError"_s);
        QVERIFY(controller && error);
        controller->save(true, u"https://cloud.example"_s, {}, {});
        QTRY_VERIFY(error->isVisible());
        QCOMPARE(error->mapTo(panel, QPoint{}).x(), margin);
        QTRY_VERIFY(apply->mapTo(panel, QPoint{}).y() > error->mapTo(panel, error->rect().bottomLeft()).y());
        controller->resetError();
        QTRY_VERIFY(!error->isVisible());
    }

    void cloudflareControlsAreAccountScoped()
    {
        auto entries = QHash<QString, QByteArray>();
        auto failWrites = false;
        auto account = OCC::Account::create();
        auto &access =
            *new OCC::CloudflareAccess(account.data(), [&](const QString &key, const std::optional<QByteArray> &data, OCC::CloudflareAccess::Completion done) {
                if (data && failWrites) {
                    done({}, u"Store is locked"_s);
                    return;
                }
                if (data) {
                    entries.insert(key, *data);
                }
                done(entries.value(key), {});
            });
        account->_accountAccess = &access;
        OCC::CloudflareAccessSettings widget;
        const auto toggle = widget.findChild<OCC::SettingsSwitch *>(u"cloudflareAccessEnabled"_s);
        QVERIFY(!widget.findChild<QLineEdit *>(u"cloudflareAccessServerUrl"_s));
        const auto accounts = widget.findChild<QComboBox *>(u"cloudflareAccessAccount"_s);
        const auto id = widget.findChild<QLineEdit *>(u"cloudflareAccessClientId"_s);
        const auto secret = widget.findChild<QLineEdit *>(u"cloudflareAccessClientSecret"_s);
        const auto apply = widget.findChild<QPushButton *>(u"cloudflareAccessApply"_s);
        const auto error = widget.findChild<QLabel *>(u"cloudflareAccessError"_s);
        QVERIFY(toggle && accounts && id && secret && apply && error);
        QVERIFY(!accounts->isEditable());
        QVERIFY(!toggle->isEnabled());
        QVERIFY(!apply->isEnabled());
        const auto manager = OCC::AccountManager::instance();
        account->setUrl(QUrl(u"https://cloud.example/nextcloud"_s));
        account->setCredentials(new FakeCredentials(new FakeQNAM({})));
        const auto state = manager->addAccount(account);
        const auto remove = qScopeGuard([&] {
            manager->removeAccountState(state);
        });
        QCOMPARE(accounts->currentData().toString(), account->url().toString());
        QVERIFY(!toggle->isChecked());
        QVERIFY(!secret->isEnabled());
        const auto form = widget.findChild<QFormLayout *>();
        QVERIFY(form);
        QVERIFY(!form->labelForField(secret)->isEnabled());
        QCOMPARE(secret->echoMode(), QLineEdit::Password);
        toggle->click();
        QVERIFY(secret->isEnabled());
        QVERIFY(form->labelForField(secret)->isEnabled());
        apply->click();
        QVERIFY(!error->text().isEmpty());
        QVERIFY(apply->isEnabled());
        QTest::keyClicks(id, "client");
        QTest::keyClicks(secret, "secret");
        apply->click();
        QVERIFY2(access.enabled(), qPrintable(error->text()));
        QVERIFY(error->text().isEmpty());
        QCOMPARE(access.clientSecret(), u"secret"_s);
        QCOMPARE(access.serverUrl(), QUrl(u"https://cloud.example"_s));

        auto sharedAccount = OCC::Account::create();
        sharedAccount->setUrl(QUrl(u"https://cloud.example:443/another-path"_s));
        sharedAccount->setCredentials(new FakeCredentials(new FakeQNAM({})));
        const auto sharedState = manager->addAccount(sharedAccount);
        const auto removeShared = qScopeGuard([&] {
            manager->removeAccountState(sharedState);
        });
        accounts->setCurrentIndex(1);
        QVERIFY(!toggle->isChecked());
        QVERIFY(secret->text().isEmpty());

        auto otherAccount = OCC::Account::create();
        otherAccount->setUrl(QUrl(u"https://other.example"_s));
        otherAccount->setCredentials(new FakeCredentials(new FakeQNAM({})));
        const auto otherState = manager->addAccount(otherAccount);
        const auto removeOther = qScopeGuard([&] {
            manager->removeAccountState(otherState);
        });
        accounts->setCurrentIndex(2);
        QVERIFY(!toggle->isChecked());
        QVERIFY(secret->text().isEmpty());
        QVERIFY(!apply->isEnabled());
        toggle->click();
        QTest::keyClicks(secret, "unsaved-draft");
        accounts->setCurrentIndex(0);
        QVERIFY(toggle->isChecked());
        QCOMPARE(secret->text(), u"secret"_s);
        QVERIFY(access.enabled());

        OCC::CloudflareAccessSettings reopened;
        QCOMPARE(reopened.findChild<QComboBox *>(u"cloudflareAccessAccount"_s)->currentData().toString(), account->url().toString());
        QVERIFY(reopened.findChild<OCC::SettingsSwitch *>(u"cloudflareAccessEnabled"_s)->isChecked());
        failWrites = true;
        QTest::keyClicks(secret, "-changed");
        apply->click();
        QVERIFY(!error->text().isEmpty());
        QCOMPARE(access.clientSecret(), u"secret"_s);
        widget.show();
        QCOMPARE(secret->text(), u"secret"_s);
        QVERIFY(error->text().isEmpty());
        toggle->click();
        apply->click();
        QVERIFY(!access.enabled());
        QVERIFY(!secret->isEnabled());
        QCOMPARE(access.clientSecret(), u"secret"_s);

        manager->removeAccountState(state);
        manager->removeAccountState(sharedState);
        manager->removeAccountState(otherState);
        QCOMPARE(accounts->count(), 0);
        QVERIFY(secret->text().isEmpty());
        QVERIFY(!toggle->isEnabled());
        QVERIFY(!apply->isEnabled());

        auto settings = OCC::ConfigFile::settingsWithGroup(u"CloudflareAccess"_s);
        settings->remove(QString{});
    }

#ifdef BUILD_FILE_PROVIDER_MODULE
    void cloudflareRejectsExistingFileProviderAccount()
    {
        auto account = OCC::Account::create();
        account->setUrl(QUrl(u"https://cloud.example"_s));
        account->setFileProviderDomainIdentifier(u"file-provider-domain"_s);
        account->setCredentials(new FakeCredentials(new FakeQNAM({})));
        const auto manager = OCC::AccountManager::instance();
        const auto state = manager->addAccount(account);
        const auto remove = qScopeGuard([&] {
            manager->removeAccountState(state);
        });
        OCC::CloudflareAccess access(nullptr, [](const QString &, const std::optional<QByteArray> &, OCC::CloudflareAccess::Completion done) {
            done({}, {});
        });
        OCC::CloudflareAccessSettingsController controller(nullptr, &access);
        QSignalSpy saved(&controller, &OCC::CloudflareAccessSettingsController::saved);
        controller.save(true, u"https://cloud.example"_s, u"client"_s, u"secret"_s);
        QCOMPARE(saved.count(), 1);
        QCOMPARE(saved.takeFirst().first().toBool(), false);
        QVERIFY(!controller.error().isEmpty());
        QVERIFY(!access.enabled());
    }
#endif

    void initTestCase()
    {
        Q_INIT_RESOURCE(resources);
        QStandardPaths::setTestModeEnabled(true);
        QVERIFY(_configDir.isValid());
        OCC::ConfigFile::setConfDir(_configDir.path());
    }

    void init()
    {
        _originalPalette = QApplication::palette();
    }

    void cleanup()
    {
        QApplication::setPalette(_originalPalette);
    }

    void panelColors_data()
    {
        QTest::addColumn<QColor>("window");
        QTest::addColumn<QColor>("foreground");
        QTest::addColumn<QColor>("candidate");
        QTest::addColumn<QColor>("expected");

#ifdef Q_OS_WIN
        QTest::newRow("light") << QColor(Qt::white) << QColor(Qt::black) << QColor("#f7f7f7") << QColor("#f7f7f7");
        QTest::newRow("dark") << QColor("#202020") << QColor(Qt::white) << QColor("#404040") << QColor("#404040");
#else
        QTest::newRow("white") << QColor(Qt::white) << QColor(Qt::black) << QColor(Qt::white) << QColor("#f7f7f7");
        QTest::newRow("almost-white") << QColor(Qt::white) << QColor(Qt::black) << QColor("#fdfdfd") << QColor("#f7f7f7");
        QTest::newRow("black") << QColor(Qt::black) << QColor(Qt::white) << QColor(Qt::black) << QColor("#0f0f0f");
        QTest::newRow("dark") << QColor("#202020") << QColor(Qt::white) << QColor("#202020") << QColor("#2d2d2d");
        QTest::newRow("preserve-light") << QColor(Qt::white) << QColor(Qt::black) << QColor("#f7f7f7") << QColor("#f7f7f7");
        QTest::newRow("preserve-dark") << QColor("#202020") << QColor(Qt::white) << QColor("#404040") << QColor("#404040");
#endif
    }

    void panelColors()
    {
        QFETCH(QColor, window);
        QFETCH(QColor, foreground);
        QFETCH(QColor, candidate);
        QFETCH(QColor, expected);

        auto palette = _originalPalette;
        palette.setColor(QPalette::Window, window);
        palette.setColor(QPalette::WindowText, foreground);
        palette.setColor(QPalette::Light, candidate);
        palette.setColor(QPalette::AlternateBase, candidate);
        QApplication::setPalette(palette);

        OCC::SettingsDialog dialog(nullptr);
        dialog.ensurePolished();
        const auto panel = dialog.findChild<QGroupBox *>(QStringLiteral("generalGroupBox"));
        const auto navigation = dialog.findChild<QScrollArea *>(QStringLiteral("settings_navigation_scroll"));
        QVERIFY(panel);
        QVERIFY(navigation);
        QCOMPARE(dialog.palette().color(QPalette::Window), window);
        QCOMPARE(panel->palette().color(QPalette::Window), expected);
        QCOMPARE(navigation->palette().color(QPalette::Window), expected);
    }

    void panelColorsFollowApplicationPalette()
    {
        OCC::SettingsDialog dialog(nullptr);
        dialog.ensurePolished();
        const auto panel = dialog.findChild<QGroupBox *>(QStringLiteral("generalGroupBox"));
        QVERIFY(panel);

        for (const auto dark : {false, true, false}) {
            const auto background = QColor(dark ? "#202020" : "#ffffff");
#ifdef Q_OS_WIN
            const auto expected = background;
#else
            const auto expected = QColor(dark ? "#2d2d2d" : "#f7f7f7");
#endif
            auto palette = _originalPalette;
            palette.setColor(QPalette::Window, background);
            palette.setColor(QPalette::WindowText, dark ? Qt::white : Qt::black);
            palette.setColor(QPalette::Light, background);
            palette.setColor(QPalette::AlternateBase, background);
            QApplication::setPalette(palette);

            QTRY_COMPARE(dialog.palette().color(QPalette::Window), background);
            QTRY_COMPARE(panel->palette().color(QPalette::Window), expected);
            QCOMPARE(panel->palette().color(QPalette::Inactive, QPalette::Window), expected);

            QEvent themeChange(QEvent::ThemeChange);
            QCoreApplication::sendEvent(&dialog, &themeChange);
            QCOMPARE(panel->palette().color(QPalette::Window), expected);

            OCC::SettingsDialog reopened(nullptr);
            reopened.ensurePolished();
            const auto reopenedPanel = reopened.findChild<QGroupBox *>(QStringLiteral("generalGroupBox"));
            QVERIFY(reopenedPanel);
            QCOMPARE(reopenedPanel->palette().color(QPalette::Window), expected);
        }
    }

    void addAccountActionFollowsAccountsAndOpensWizard()
    {
        auto *const accountManager = OCC::AccountManager::instance();
        QVERIFY(accountManager->accounts().isEmpty());

        auto account = OCC::Account::create();
        account->setUrl(QUrl(QStringLiteral("https://cloud.example.com")));
        account->setDavUser(QStringLiteral("alice"));
        const auto accountState = accountManager->addAccount(account);
        const auto removeAccount = qScopeGuard([accountManager, accountState] {
            accountManager->removeAccountState(accountState);
        });

        OCC::SettingsDialog dialog(nullptr);
        const auto addAccountAction = dialog.findChild<QAction *>(QStringLiteral("settingsdialog_add_account"));
        const auto toolbar = dialog.findChild<QToolBar *>();
        QVERIFY(addAccountAction);
        QVERIFY(toolbar);
        QCOMPARE(toolbar->actions().indexOf(addAccountAction), 1);
        QVERIFY(!addAccountAction->isCheckable());
        QVERIFY(!addAccountAction->icon().isNull());
        QCOMPARE(addAccountAction->text(), OCC::Systray::tr("Add account"));

        const auto systray = OCC::Systray::instance();
        QCOMPARE(addAccountAction->isVisible(), systray->enableAddAccount());
        if (addAccountAction->isVisible()) {
            const auto wizardRequest = QSignalSpy(systray, &OCC::Systray::openAccountWizard);
            addAccountAction->trigger();
            QCOMPARE_EQ(wizardRequest.size(), 1);
        }

        dialog.ensurePolished();
        const auto shortcutsPanel = dialog.findChild<QFrame *>(QStringLiteral("accountShortcutsPanel"));
        const auto statusPanel = dialog.findChild<QFrame *>(QStringLiteral("accountStatusPanel"));
        QVERIFY(shortcutsPanel);
        QVERIFY(statusPanel);
        shortcutsPanel->ensurePolished();
        statusPanel->ensurePolished();
        QCOMPARE(shortcutsPanel->palette().color(QPalette::Window), statusPanel->palette().color(QPalette::Window));
    }
};

QTEST_MAIN(TestSettingsDialog)
#include "testsettingsdialog.moc"
