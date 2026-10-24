# SPDX-FileCopyrightText: 2026 Sairibus contributors
# SPDX-License-Identifier: GPL-2.0-or-later
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = (Get-Location).Path
$target = 'windows-msvc2022_64-cl'
$scratch = Join-Path $env:RUNNER_TEMP 'sairibus-craft'
$master = Join-Path $scratch 'CraftMaster'
$config = Join-Path $scratch 'craftmaster.ini'
$root = Join-Path $scratch $target
$suffix = $env:RELEASE_TAG -replace '^v35\.0\.0-', ''
if ($suffix -notmatch '^sairibus\.[1-9][0-9]*$') { throw 'Invalid release suffix.' }
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$configuration = Get-Content (Join-Path $workspace 'admin/club/craftmaster.ini') -Raw
$pythonDirectory = Split-Path (Get-Command python).Source
$configuration = $configuration.Replace('Paths/Python = C:\Python312-x64', "Paths/Python = $pythonDirectory")
Set-Content -Path $config -Value $configuration -Encoding utf8

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE" }
}

function Invoke-Craft {
    & python (Join-Path $master 'CraftMaster.py') --config $config --target $target -c @args
    if ($LASTEXITCODE -ne 0) { throw "Craft failed with exit code $LASTEXITCODE" }
}

function Assert-Source {
    $head = & git -C $workspace rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $env:GITHUB_SHA) { throw 'Source commit does not match the release commit.' }
    Invoke-Checked git @('-C', $workspace, 'diff', '--exit-code', 'HEAD', '--')
}

Assert-Source
Invoke-Checked choco @('install', 'inkscape', '--version=1.4.2', '--yes', '--no-progress')
Push-Location $scratch
try {
    Invoke-Checked git @('init', '--quiet', $master)
    Invoke-Checked git @('-C', $master, 'remote', 'add', 'origin', 'https://invent.kde.org/packaging/craftmaster.git')
    Invoke-Checked git @('-C', $master, 'fetch', '--depth=1', 'origin', '8a19d8fcab223b8b27126d98a46ed824b5948665')
    Invoke-Checked git @('-C', $master, 'checkout', '--detach', 'FETCH_HEAD')
    Invoke-Craft --add-blueprint-repository 'https://github.com/nextcloud/craft-blueprints-kde.git||d09c61abb67d3a1b219010d64f9139fea68694fe'
    Invoke-Craft --add-blueprint-repository 'https://github.com/nextcloud/craft-blueprints-nextcloud.git||d9829275a569d3cf83e42ad9c50140074d01dd9f'
    Invoke-Craft craft
    foreach ($pin in @(
        @('craft', 'a35a7cc53b3a06609081c1227156d4d59963927f'),
        @('etc/blueprints/locations/craft-blueprints-kde', 'd09c61abb67d3a1b219010d64f9139fea68694fe'),
        @('etc/blueprints/locations/craft-blueprints-nextcloud', 'd9829275a569d3cf83e42ad9c50140074d01dd9f')
    )) {
        $actual = & git -C (Join-Path $root $pin[0]) rev-parse HEAD
        if ($LASTEXITCODE -ne 0 -or $actual -ne $pin[1]) { throw "Build dependency pin changed: $($pin[0])." }
    }
    Invoke-Craft --install-deps nextcloud-client
    Invoke-Craft --src-dir $workspace --options "nextcloud-client.versionSuffix=$suffix" nextcloud-client
    $build = Join-Path $root 'build/nextcloud-client/work/build'
    $cache = Get-Content (Join-Path $build 'CMakeCache.txt') -Raw
    if ($cache -notmatch '(?m)^BUILD_UPDATER:BOOL=OFF\r?$') { throw 'The official updater must be disabled.' }
    $sourceEntry = [regex]::Match($cache, '(?m)^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)\r?$')
    if (!$sourceEntry.Success -or [IO.Path]::GetFullPath($sourceEntry.Groups[1].Value.Trim()) -ne [IO.Path]::GetFullPath($workspace)) {
        throw 'CMake did not build the checked-out release source.'
    }
    $versionHeader = Get-Content (Join-Path $build 'version.h') -Raw
    if ($versionHeader -notmatch ('MIRALL_VERSION_SUFFIX = "' + [regex]::Escape($suffix) + '"')) { throw 'Release version suffix is missing.' }
    $env:PATH = "$(Join-Path $root 'bin');$(Join-Path $root 'dev-utils/bin');$env:PATH"
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_QUICK_BACKEND = 'software'
    $tests = '^(CloudflareAccess|Cookies|AccountWizardController|AccountWizardWindowQml|SettingsDialog|PushNotifications|RemoteWipe|AccountState|ConnectionValidator)Test$'
    $inventory = & ctest --test-dir $build --show-only=json-v1 -R $tests
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate the client test suites.' }
    $inventoryPath = Join-Path $scratch 'test-inventory.json'
    $inventory | Set-Content -Path $inventoryPath -Encoding utf8
    Invoke-Checked python @((Join-Path $workspace 'admin/club/release.py'), 'test-list', $inventoryPath)
    Invoke-Checked ctest @('--test-dir', $build, '--output-on-failure', '--no-tests=error', '--timeout', '180', '-R', $tests)
    Invoke-Craft --options "nextcloud-client.versionSuffix=$suffix" --package nextcloud-client
    $installers = @(Get-ChildItem (Join-Path $root 'tmp') -Recurse -File -Filter '*nextcloud*.exe' | Where-Object { $_.Name -ne 'nextcloud.exe' })
    if ($installers.Count -ne 1) { throw "Expected one packaged installer; found $($installers.Count)." }
    $smoke = Join-Path $env:RUNNER_TEMP 'nextcloud-install-smoke'
    $installation = Start-Process -FilePath $installers[0].FullName -ArgumentList @('/S', "/D=$smoke") -PassThru -Wait
    if ($installation.ExitCode -ne 0) { throw "Installer failed with exit code $($installation.ExitCode)." }
    $application = Join-Path $smoke 'bin/nextcloud.exe'
    if (!(Test-Path $application)) { throw 'Installed application is missing.' }
    if ((Get-Item $application).VersionInfo.FileVersion -notmatch '^35\.0\.0\.') { throw 'Installed client version is incorrect.' }
    $builtApplication = Join-Path $build 'bin/nextcloud.exe'
    if ((Get-FileHash $application).Hash -ne (Get-FileHash $builtApplication).Hash) { throw 'Installed application differs from the tested build.' }
    Assert-Source
    $artifacts = Join-Path $workspace 'artifacts'
    New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
    Copy-Item $installers[0].FullName (Join-Path $artifacts "Nextcloud-$($env:RELEASE_TAG.Substring(1))-windows-x64.exe")
} finally {
    Pop-Location
}
