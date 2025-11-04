<#
.SYNOPSIS
    Applies system-wide and user-specific registry settings for Windows optimization and UI tweaking.
.DESCRIPTION
    This script performs the following actions:
    1. Applies machine-wide settings (e.g., disables Edge first run, enables long paths).
    2. Applies a consistent set of UI tweaks to:
        - The current interactive user.
        - All other currently logged-in (active) users.
        - All existing but currently logged-out (offline) user profiles.
        - The Default User profile, ensuring all future new users inherit the settings.
    The script uses a hybrid approach: native PowerShell cmdlets for standard registry hives and
    the robust reg.exe for dynamically loaded hives to overcome provider limitations.
.NOTES
    Author: Gemini Assistant (Final Hybrid Version)
    Requires: Administrative privileges.
#>

#requires -RunAsAdministrator

$MachineSettings = @(
    [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'HideFirstRunExperience'; Value = 1; Type = 'DWord'; Note = 'Microsoft Edge First Run Experience - Hidden' },
    [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; Name = 'AllowNewsAndInterests'; Value = 0; Type = 'DWord'; Note = 'Widgets (News and Interests) - Disabled' },
    [PSCustomObject]@{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'; Name = 'LongPathsEnabled'; Value = 1; Type = 'DWord'; Note = 'Long path support - Enabled' },
    [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended'; Name = 'StartupBoostEnabled'; Value = 0; Type = 'DWord'; Note = 'Microsoft Edge Startup Boost - Disabled' },
    [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended'; Name = 'AllowRunningInBackground'; Value = 0; Type = 'DWord'; Note = 'Microsoft Edge Background Mode - Disabled' }
)

$UserSettings = @(
    [PSCustomObject]@{ Path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'LaunchTo'; Value = 1; Type = 'REG_DWORD' },
    [PSCustomObject]@{ Path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'; Name = 'TaskbarEndTask'; Value = 1; Type = 'REG_DWORD' },
    [PSCustomObject]@{ Path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'ShowTaskViewButton'; Value = 0; Type = 'REG_DWORD' },
    [PSCustomObject]@{ Path = 'Software\Microsoft\Windows\CurrentVersion\Search'; Name = 'SearchboxTaskbarMode'; Value = 3; Type = 'REG_DWORD' },
    [PSCustomObject]@{ Path = 'Control Panel\Keyboard'; Name = 'InitialKeyboardIndicators'; Value = '2'; Type = 'REG_SZ' },
    [PSCustomObject]@{ Path = 'Software\Policies\Microsoft\Windows\Explorer'; Name = 'DisableSearchBoxSuggestions'; Value = 1; Type = 'REG_DWORD' }
)

function Apply-UserRegistrySettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryRoot
    )

    $useRegExe = $RegistryRoot.StartsWith("HKU\TempUser_") -or $RegistryRoot.StartsWith("HKU\DefaultUser")

    foreach ($setting in $UserSettings) {
        $fullPath = Join-Path -Path $RegistryRoot -ChildPath $setting.Path
        try {
            if ($useRegExe) {
                $regPath = $fullPath -replace "Microsoft.PowerShell.Core\\Registry::", ""
                reg.exe add $regPath /v $($setting.Name) /t $($setting.Type) /d $($setting.Value) /f | Out-Null
            }
            else {
                if (-not (Test-Path $fullPath)) {
                    New-Item -Path $fullPath -Force -ErrorAction Stop | Out-Null
                }
                $psType = if ($setting.Type -eq 'REG_DWORD') { 'DWord' } else { 'String' }
                New-ItemProperty -Path $fullPath -Name $setting.Name -Value $setting.Value -PropertyType $psType -Force -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Warning "Failed to apply setting '$($setting.Name)' to path '$fullPath': $($_.Exception.Message)"
        }
    }
}

Write-Host "`n[ -- ] Starting registry modification script..." -ForegroundColor Cyan

Write-Host "`n[ >> ] Applying machine-wide settings (HKLM)..." -ForegroundColor Yellow
foreach ($setting in $MachineSettings) {
    try {
        if (-not (Test-Path $setting.Path)) { New-Item -Path $setting.Path -Force | Out-Null }
        New-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
        Write-Host " [ ** ] $($setting.Note)" -ForegroundColor Green
    }
    catch { Write-Warning "Could not apply machine-wide setting '$($setting.Note)': $($_.Exception.Message)" }
}
Set-ItemProperty -LiteralPath 'Registry::HKU\.DEFAULT\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Type 'String' -Value 2 -Force
Write-Host ' [ ** ] NumLock on startup enabled for logon screen' -ForegroundColor Green

Write-Host "`n[ >> ] Applying UI tweaks for current user..." -ForegroundColor Yellow
if ($env:USERPROFILE) {
    Apply-UserRegistrySettings -RegistryRoot 'HKCU:'
    Write-Host ' [ ** ] Applied UI tweaks for current user' -ForegroundColor Green
} else {
    Write-Host " [ -- ] Script is not running in an interactive user context, skipping." -ForegroundColor Gray
}

$loadedProfilePaths = @{}
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ForEach-Object {
    try {
        $profilePath = $_.GetValue('ProfileImagePath', $null)
        if ($profilePath) { $loadedProfilePaths[$profilePath] = $true }
    } catch {}
}

Write-Host "`n[ >> ] Applying UI tweaks for other active user sessions..." -ForegroundColor Yellow
$currentUserSID = $null
if ($env:USERNAME) {
    try { $currentUserSID = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
}
$activeUserHives = Get-ChildItem "Registry::HKEY_USERS" | Where-Object { $_.Name -match "S-1-5-21-.*$" -and $_.Name -notlike "*_Classes" }

foreach ($hive in $activeUserHives) {
    if ($currentUserSID -and $hive.PSChildName -eq $currentUserSID) { continue }
    Apply-UserRegistrySettings -RegistryRoot $hive.PSPath
    Write-Host " [ ** ] Applied UI tweaks for loaded user profile $($hive.PSChildName)" -ForegroundColor Green
}

Write-Host "`n[ >> ] Applying UI tweaks for offline user profiles..." -ForegroundColor Yellow
$userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { 
    $_.Name -notin @('Public', 'Default', 'All Users', 'Default User') -and
    (Test-Path (Join-Path $_.FullName "NTUSER.DAT"))
}

foreach ($profile in $userProfiles) {
    if ($loadedProfilePaths.ContainsKey($profile.FullName)) {
        Write-Host " [ -- ] Profile $($profile.Name) is already loaded, skipping." -ForegroundColor Gray
        continue
    }
    $ntdatPath = Join-Path $profile.FullName "NTUSER.DAT"
    $tempHive = "HKU\TempUser_$($profile.Name)"
    $loaded = $false
    try {
        reg.exe load $tempHive $ntdatPath 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to load hive: $ntdatPath" }
        $loaded = $true
        Apply-UserRegistrySettings -RegistryRoot $tempHive
        Write-Host " [ ** ] Applied UI tweaks for offline user profile: $($profile.Name)" -ForegroundColor Green
    }
    catch { Write-Warning "Could not modify profile $($profile.Name): $($_.Exception.Message)" }
    finally {
        if ($loaded) {
            [GC]::Collect(); Start-Sleep -Milliseconds 200
            reg.exe unload $tempHive 2>&1 | Out-Null
        }
    }
}

Write-Host "`n[ >> ] Applying UI tweaks for future user profiles (Default User)..." -ForegroundColor Yellow
$defaultUserLoaded = $false
$defaultUserHive = "HKU\DefaultUser"
try {
    reg.exe load $defaultUserHive "C:\Users\Default\NTUSER.DAT" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to load Default User hive." }
    $defaultUserLoaded = $true
    Apply-UserRegistrySettings -RegistryRoot $defaultUserHive
    Write-Host ' [ ** ] Applied UI tweaks for future user profiles (Default User)' -ForegroundColor Green
}
catch { Write-Warning "Failed to modify the Default User profile: $($_.Exception.Message)" }
finally {
    if ($defaultUserLoaded) {
        [GC]::Collect(); Start-Sleep -Milliseconds 200
        reg.exe unload $defaultUserHive 2>&1 | Out-Null
    }
}

Write-Host "`n[ ** ] Registry modification completed!" -ForegroundColor Cyan