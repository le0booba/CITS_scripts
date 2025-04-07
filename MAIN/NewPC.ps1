Clear-Host

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning 'This script requires ADMIN permissions. Please, run it as Administrator'
    Write-Host 'Press any key to exit...'
    [void]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

if ($PSVersionTable.PSVersion.Major -ge 6) {
    Write-Warning 'This script is intended for PowerShell Classic (version 5.1 or lower). Attempting to execute in legacy mode...'
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Path
        exit
    }
    catch {
        Write-Error 'Failed to relaunch in classic PowerShell. Ensure PowerShell Classic is installed and accessible in PATH. Exiting...'
        exit 1
    }
}

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
Add-Type -AssemblyName System.Windows.Forms

try {
    $windowsVersion = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion
    Write-Host "`nDetected WIN. ver.: $windowsVersion" -ForegroundColor Cyan
}
catch {
    Write-Warning 'Failed to detect Windows version. Continuing with default settings (Win11)'
    $windowsVersion = "24H2"
}

$needRestart = $false
if ($windowsVersion -notlike '22*') {
    try {
        Import-Module Appx -ErrorAction Stop
    }
    catch {
        try {
            Import-Module Appx -UseWindowsPowerShell -ErrorAction Stop
        }
        catch {
            Import-Module Appx -SkipEditionCheck -ErrorAction SilentlyContinue
        }
    }
}

$appsToRemove = @{
    'Win11' = @(
        'Clipchamp.Clipchamp'
        'Microsoft.549981C3F5F10'
        'Microsoft.Todos'
        'Microsoft.BingNews'
        'MicrosoftOfficeHub'
        'Microsoft.OutlookForWindows'
        'Microsoft.PowerAutomateDesktop'
        'Microsoft.Xbox.TCUI'
        'Microsoft.XboxGameOverlay'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.XboxSpeechToTextOverlay'
        'Microsoft.GamingApp'
        'Microsoft.WindowsMaps'
        'Microsoft.ZuneVideo'
        'Microsoft.People'
        'Microsoft.ZuneMusic'
        'Microsoft.BingWeather'
        'microsoft.windowscommunicationsapps'
        'Microsoft.WindowsFeedbackHub'
        'A025C540.Yandex.Music'
        'Microsoft.GetHelp'
        'Microsoft.Getstarted'
        'Microsoft.Windows.DevHome'
        'MSTeams'
        'MicrosoftTeams'
        'Microsoft.BingSearch'
        'MicrosoftCorporationII.MicrosoftFamily'
        'C27EB4BA.DropboxOEM'
        '5A894077.McAfeeSecurity'
        '9E2F88E3.Twitter'
        '4DF9E0F8.Netflix'
        '7EE7776C.LinkedInforWindows'
        '2414FC7A.Viber'
        'Facebook.317180B0BB486'
        '4AE8B7C2.Booking.comPartnerEdition'
    )

    'Win10' = @(
        'Microsoft.549981C3F5F10'
        'Microsoft.Todos'
        'MicrosoftOfficeHub'
        'Microsoft.Office.OneNote'
        'MSPaint'
        'SkypeApp'
        'Microsoft.Xbox.TCUI'
        'Microsoft.XboxGameOverlay'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.XboxSpeechToTextOverlay'
        'Microsoft.XboxApp'
        'Microsoft.WindowsMaps'
        'Microsoft.ZuneVideo'
        'Microsoft.People'
        'Microsoft.ZuneMusic'
        'Microsoft.BingWeather'
        'microsoft.windowscommunicationsapps'
        'Microsoft.Microsoft3DViewer'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.MixedReality.Portal'
        'Microsoft.Getstarted'
        'Microsoft.GetHelp'
        'A025C540.Yandex.Music'
        'Microsoft.Wallet'
        'Microsoft.Windows.DevHome'
        'Microsoft.BingSearch'
        'Microsoft.OutlookForWindows'
    )
}

$questionRemoveApps = [System.Windows.Forms.MessageBox]::Show('Delete useless apps?', '', 'YesNo', [System.Windows.Forms.MessageBoxIcon]::Question)
if ($questionRemoveApps -eq 'Yes') {
    Write-Host "`n        ═════════════════════════════" -ForegroundColor DarkCyan
    Write-Host '        ║                      CITS ║' -ForegroundColor DarkGray
    Write-Host '        ║ ' -NoNewline -ForegroundColor DarkCyan
    Write-Host '  Removing useless apps  ' -NoNewline -ForegroundColor Green
    Write-Host ' ║' -ForegroundColor DarkCyan
    Write-Host '        ║                           ║' -ForegroundColor DarkCyan
    Write-Host '        ║  ' -NoNewline -ForegroundColor DarkCyan
    Write-Host '     please wait...' -NoNewline -ForegroundColor Magenta
    Write-Host '      ║' -ForegroundColor DarkCyan
    Write-Host '        ║                           ║' -ForegroundColor DarkCyan
    Write-Host "        ═════════════════════════════`n" -ForegroundColor DarkCyan

    $osKey = if ($windowsVersion -like '22*') { 'Win10' } else { 'Win11' }
    $operationSuccess = $true

    foreach ($appName in $appsToRemove[$osKey]) {
        try {
            Get-AppxPackage "*$appName*" | Remove-AppxPackage
            Get-AppxPackage -AllUsers "*$appName*" | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$appName*" } | Remove-AppxProvisionedPackage -Online
        }
        catch {
            Write-Warning "Failed to remove app '$appName': $($_.Exception.Message)"
            $operationSuccess = $false
        }
    }
    if ($operationSuccess) {
        Write-Host ' [ ** ] Useless apps were successfully removed' -ForegroundColor Green
        $needRestart = $true
    }

    $registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'

    try {
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Type Directory -Force | Out-Null
        }

        $registryValues = @{
            'ContentDeliveryAllowed'           = 0
            'FeatureManagementEnabled'         = 0
            'OemPreInstalledAppsEnabled'       = 0
            'PreInstalledAppsEnabled'          = 0
            'PreInstalledAppsEverEnabled'      = 0
            'RotatingLockScreenEnabled'        = 0
            'RotatingLockScreenOverlayEnabled' = 0
            'SilentInstalledAppsEnabled'       = 0
            'SoftLandingEnabled'               = 0
            'SubscribedContentEnabled'         = 0
            'SubscribedContent-310093Enabled'  = 0
            'SubscribedContent-314563Enabled'  = 0
            'SubscribedContent-338388Enabled'  = 0
            'SubscribedContent-338389Enabled'  = 0
            'SubscribedContent-338393Enabled'  = 0
            'SubscribedContent-353694Enabled'  = 0
            'SubscribedContent-353696Enabled'  = 0
            'SubscribedContent-353698Enabled'  = 0
            'SystemPaneSuggestionsEnabled'     = 0
        }

        foreach ($key in $registryValues.Keys) {
            Set-ItemProperty -Path $registryPath -Name $key -Value $registryValues[$key] -Type DWord -Force
        }

        $subkeysToRemove = @(
            "$registryPath\Subscriptions"
            "$registryPath\SuggestedApps"
        )

        foreach ($subkeyToRemove in $subkeysToRemove) {
            if (Test-Path $subkeyToRemove) {
                Remove-Item -Path $subkeyToRemove -Recurse -Force
            }
        }

        Write-Host ' [ ** ] ContentDeliveryManager Suggested Content - Disabled' -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to modify registry settings for ContentDeliveryManager: $($_.Exception.Message)"
    }
}

$questionRemoveOneDrive = [System.Windows.Forms.MessageBox]::Show('Delete OneDrive?', '', 'YesNo', [System.Windows.Forms.MessageBoxIcon]::Question)
if ($questionRemoveOneDrive -eq 'Yes') {
    Write-Host "`n        ═════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host '        ║                                                   ║' -ForegroundColor DarkCyan
    Write-Host '        ║  ' -NoNewline -ForegroundColor DarkCyan
    Write-Host 'Removing OneDrive ... [ ' -NoNewline -ForegroundColor Magenta
    Write-Host 'UninstallOneDrive.ps1' -NoNewline -ForegroundColor Blue
    Write-Host ' ]' -NoNewline -ForegroundColor Magenta
    Write-Host '  ║' -NoNewline -ForegroundColor DarkCyan
    Write-Host "`n        ║  " -NoNewline -ForegroundColor DarkCyan
    Write-Host '                                                 ║' -ForegroundColor DarkCyan
    Write-Host "        ═════════════════════════════════════════════════════`n" -ForegroundColor DarkCyan

    $oneDriveScriptFile = 'UninstallOneDrive.ps1'
    $oneDriveScriptPath = Join-Path $PSScriptRoot $oneDriveScriptFile
    if (Test-Path -Path $oneDriveScriptPath -PathType Leaf) {
        & powershell.exe -ExecutionPolicy Bypass -File $oneDriveScriptPath
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Script '$oneDriveScriptFile' may have encountered errors during execution (Exit Code: $LASTEXITCODE)."
        }
    }
    else {
        Write-Warning "Skipping OneDrive removal: Script '$oneDriveScriptFile' not found in '$PSScriptRoot'"
    }
}

Write-Host "`n        ═════════════════════════" -ForegroundColor DarkCyan
Write-Host '        ║                  CITS ║' -ForegroundColor DarkGray
Write-Host '        ║  ' -NoNewline -ForegroundColor DarkCyan
Write-Host ' Setting-Up new PC ' -NoNewline -ForegroundColor Green
Write-Host '  ║' -ForegroundColor DarkCyan
Write-Host '        ║                       ║' -ForegroundColor DarkCyan
Write-Host '        ║  ' -NoNewline -ForegroundColor DarkCyan
Write-Host '  please wait... ' -NoNewline -ForegroundColor Magenta
Write-Host '    ║' -ForegroundColor DarkCyan
Write-Host '        ║                       ║' -ForegroundColor DarkCyan
Write-Host "        ═════════════════════════`n" -ForegroundColor DarkCyan

$currentDate = Get-Date -Format "dd/MM/yyyy"
$fileDate = Get-Date -Format "dd-MM-yyyy"

$currentComputerName = $env:COMPUTERNAME
$newComputerName = $null

do {
    $inputName = Read-Host -Prompt " [ >> ] Enter a new name for this PC (Current: $($currentComputerName), press Enter to keep)"
    if ([string]::IsNullOrWhiteSpace($inputName)) {
        $newComputerName = $currentComputerName
        Write-Host " [ *! ] Keeping current computer name: $($currentComputerName)" -ForegroundColor Yellow
        break
    }
    if ($inputName -match '[^a-zA-Z0-9\-]') {
        Write-Host ' [ !! ] Computer name contains invalid characters. Use only letters, numbers, and hyphens' -ForegroundColor Red
        continue
    }
    if ($inputName -match '^-|-$') {
        Write-Host ' [ !! ] Computer name cannot start or end with a hyphen' -ForegroundColor Red
        continue
    }
    if ($inputName -match '^\d+$') {
        Write-Host ' [ !! ] Computer name cannot consist only of numbers' -ForegroundColor Red
        continue
    }
    if ($inputName.Length -gt 15) {
        Write-Host ' [ !! ] Computer name is too long (maximum 15 characters)' -ForegroundColor Red
        continue
    }
    if ($inputName -eq $currentComputerName) {
        $newComputerName = $currentComputerName
        Write-Host ' [ *! ] The new computer name is the same as the current. No changes will be made to the name.' -ForegroundColor Yellow
        break
    }
    $newComputerName = $inputName
    break
} while ($true)

$fileNameBase = if (-not [string]::IsNullOrWhiteSpace($newComputerName)) { $newComputerName } else { $currentComputerName }
$fileNameBase = $fileNameBase -replace '[\\/:*?"<>|]', '_'

Add-Content -Path "$($PSScriptRoot)\$($fileNameBase)_$($fileDate).txt" -Value "[ $($currentDate) ] PC name: $($newComputerName)`n"

if ($newComputerName -ne $currentComputerName) {
    try {
        Rename-Computer -NewName $newComputerName -Force *> $null
        Write-Host " [ ** ] Computer renamed to $($newComputerName) successfully. A reboot is required" -ForegroundColor Green
        $needRestart = $true
    }
    catch {
        Write-Warning "Error renaming computer: $($_.Exception.Message)"
        $newComputerName = $currentComputerName
    }
}


function Generate-SecurePassword {
    $pwgen_CONSONANT = 1
    $pwgen_VOWEL = (1 -shl 1)
    $pwgen_DIPTHONG = (1 -shl 2)
    $pwgen_NOT_FIRST = (1 -shl 3)

    $genpas_spec_symbols = '!#$%&\()*+-/<=>?@\_'

    $pwgen_ELEMENTS = @(
        @("a" , ($pwgen_VOWEL))
        @("ae", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("ah", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("ai", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("b" , ($pwgen_CONSONANT)),
        @("c" , ($pwgen_CONSONANT)),
        @("ch", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG)),
        @("d" , ($pwgen_CONSONANT)),
        @("e" , ($pwgen_VOWEL)),
        @("ee", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("ei", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("f" , ($pwgen_CONSONANT)),
        @("g" , ($pwgen_CONSONANT)),
        @("gh", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG -bor $pwgen_NOT_FIRST)),
        @("h" , ($pwgen_CONSONANT)),
        @("i" , ($pwgen_VOWEL)),
        @("ie", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("j" , ($pwgen_CONSONANT)),
        @("k" , ($pwgen_CONSONANT)),
        @("m" , ($pwgen_CONSONANT)),
        @("n" , ($pwgen_CONSONANT)),
        @("ng", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG -bor $pwgen_NOT_FIRST)),
        @("p" , ($pwgen_CONSONANT)),
        @("ph", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG)),
        @("qu", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG)),
        @("r" , ($pwgen_CONSONANT)),
        @("s" , ($pwgen_CONSONANT)),
        @("sh", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG)),
        @("t" , ($pwgen_CONSONANT)),
        @("th", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG)),
        @("u" , ($pwgen_VOWEL)),
        @("v" , ($pwgen_CONSONANT)),
        @("w" , ($pwgen_CONSONANT)),
        @("x" , ($pwgen_CONSONANT)),
        @("y" , ($pwgen_CONSONANT)),
        @("z" , ($pwgen_CONSONAN))
    )

    function pwgen_generate ($pwlen, $inc_capital, $inc_number, $inc_spec) {
        $result = ""
        while (-not $result) {
            $result = pwgen_generate0 -pwlen $pwlen -inc_capital $inc_capital -inc_number $inc_number -inc_spec $inc_spec
        }
        return $result
    }

    function pwgen_generate0 ([int]$pwlen, [bool]$inc_capital, [bool]$inc_number, [bool]$inc_spec) {
        $result = ""
        $prev = 0;
        $isFirst = $true;
        if ((Get-Random -Maximum 1.0) -lt 0.5) {
            $shouldBe = $pwgen_VOWEL
        }
        else {
            $shouldBe = $pwgen_CONSONANT
        }
        while ($result.length -lt $pwlen) {
            $i = [math]::Truncate(($pwgen_ELEMENTS.count - 1) * (Get-Random -Maximum 1.0))
            $str = $pwgen_ELEMENTS[$i][0]
            $flags = $pwgen_ELEMENTS[$i][1]
            if (($flags -band $shouldBe) -eq 0) {
                continue
            }
            if ($isFirst -and ($flags -band $pwgen_NOT_FIRST)) {
                continue
            }
            if (($prev -band $pwgen_VOWEL) -and ($flags -band $pwgen_VOWEL) -and ($flags -band $pwgen_DIPTHONG)) {
                continue
            }
            if (($result.length + $str.length) -gt $pwlen) {
                continue
            }
            if ($inc_capital) {
                if (($isFirst -or ($flags -band $pwgen_CONSONANT)) -and ((Get-Random -Maximum 1.0) -gt 0.3)) {
                    $str = $str.substring(0, 1).toupper() + $str.substring(1)
                    $inc_capital = $false
                }
            }
            $result += $str
            if ($inc_number) {
                if ((-not $isFirst) -and ((Get-Random -Maximum 1.0) -lt 0.3)) {
                    if (($result.length + $str.length) -gt $pwlen) {
                        $result = $result.Substring(0, $result.Length - 1)
                    }
                    $result += [math]::Truncate(10 * (Get-Random -Maximum 1.0)).toString()
                    $inc_number = $false
                    $isFirst = $true
                    $prev = 0
                    if ((Get-Random -Maximum 1.0) -lt 0.5) {
                        $shouldBe = $pwgen_VOWEL
                    }
                    else {
                        $shouldBe = $pwgen_CONSONANT
                    }
                    continue
                }
            }
            if ($inc_spec) {
                if ((-not $isFirst) -and ((Get-Random -Maximum 1.0) -lt 0.3)) {
                    if (($result.length + $str.length) -gt $pwlen) {
                        $result = $result.Substring(0, $result.Length - 1)
                    }
                    $possible = $genpas_spec_symbols
                    $result += $possible.chars([math]::Truncate((Get-Random -Maximum 1.0) * $possible.length))
                    $inc_spec = $false
                    $isFirst = $true
                    $prev = 0
                    if ((Get-Random -Maximum 1.0) -lt 0.5) {
                        $shouldBe = $pwgen_VOWEL
                    }
                    else {
                        $shouldBe = $pwgen_CONSONANT
                    }
                    continue
                }
            }
            if ($shouldBe -eq $pwgen_CONSONANT) {
                $shouldBe = $pwgen_VOWEL;
            }
            else {
                if (($prev -band $pwgen_VOWEL) -or ($flags -band $pwgen_DIPTHONG) -or ((Get-Random -Maximum 1.0) -gt 0.3)) {
                    $shouldBe = $pwgen_CONSONANT;
                }
                else {
                    $shouldBe = $pwgen_VOWEL;
                }
            }
            $prev = $flags;
            $isFirst = $false;
        }
        if ($inc_capital -or $inc_number -or $inc_spec) {
            return $null
        }
        return $result
    }

pwgen_generate -pwlen 9 -inc_capital $true -inc_number $true -inc_spec $true
}

$password = Generate-SecurePassword
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$userName = 'helper'
$adminGroupName = (Get-LocalGroup | Where-Object { $_.SID -like 'S-1-5-32-544' }).Name
if (-not (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
    try {
        New-LocalUser -Name $userName -Password $securePassword -Description 'helper' *> $null
        try {
            Add-LocalGroupMember -Group $adminGroupName -Member $userName *> $null
        }
        catch {
            Write-Warning "Error adding 'helper' to group '$adminGroupName': $($_.Exception.Message)"
        }
        Add-Content -Path "$($PSScriptRoot)\$($fileNameBase)_$($fileDate).txt" -Value "helper password:`n$password`n"
        Write-Host " [ ** ] User 'helper' created" -ForegroundColor Green
    }
    catch {
        Write-Warning "Error creating user 'helper': $($_.Exception.Message)"
    }
}
else {
    Write-Host " [ *! ] User 'helper' already exists" -ForegroundColor Yellow
    try {
        Add-LocalGroupMember -Group $adminGroupName -Member $userName *> $null
    }
    catch {
        Write-Warning "Error adding user to group '$adminGroupName': $($_.Exception.Message)"
    }
}

Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object {
    try {
        Set-LocalUser -Name $_.Name -PasswordNeverExpires $true
    }
    catch {
        Write-Warning "Error setting Non-Expires passwords for Active Local user '$($_.Name)': $($_.Exception.Message)"
    }
}
Write-Host ' [ ** ] All Active Local users now have Non-Expires passwords' -ForegroundColor Green

powercfg.exe -h off
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -monitor-timeout-dc 5
powercfg.exe -change -monitor-timeout-ac 10
Start-Sleep -Seconds 5
powercfg.exe /SETACVALUEINDEX scheme_current sub_buttons LIDACTION 0
powercfg.exe /SETDCVALUEINDEX scheme_current sub_buttons LIDACTION 1
powercfg.exe /SETACVALUEINDEX scheme_current sub_buttons PBUTTONACTION 3
powercfg.exe /SETDCVALUEINDEX scheme_current sub_buttons PBUTTONACTION 3
powercfg.exe /SETACVALUEINDEX scheme_current sub_buttons SBUTTONACTION 0
powercfg.exe /SETDCVALUEINDEX scheme_current sub_buttons SBUTTONACTION 1
powercfg.exe /SETACVALUEINDEX scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
Write-Host ' [ ** ] PowerCfg complete' -ForegroundColor Green

if ((Get-Culture).Name -like 'ru-*') {
    Enable-NetFirewallRule -DisplayGroup 'Веб-доступ к удаленным рабочим столам (WebSocket)'
    Enable-NetFirewallRule -DisplayGroup 'Дистанционное управление рабочим столом'
} else {
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop (WebSocket)'
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}

Set-NetFirewallProfile -All -Enabled False
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name fAllowFullControl -Value 1 -PropertyType DWORD -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Write-Host ' [ ** ] RDP - Enabled, Firewall - Disabled' -ForegroundColor Green

$is7zInstalled = $false
$dist7z = Get-ChildItem -Path "$PSScriptRoot" -Filter '7z*.msi' -File
if ($dist7z) {
    try {
        Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i', "$($dist7z.FullName)", '/Qr', '/NoRestart' -Wait
        $is7zInstalled = $true
    }
    catch {
        Write-Warning "Error installing 7-Zip: $($_.Exception.Message)"
    }
}
else {
    $path7z = Get-ChildItem -Path 'C:\Program Files\7-Zip' -Include '7z.exe' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq '7z.exe' }
    if ($path7z) {
        Write-Host " [ *! ] 7-Zip installer NOT found BUT, it is already installed. '7z.exe' found at: '$($path7z)'" -ForegroundColor DarkGray
        $is7zInstalled = $true
    }
    else {
        Write-Host ' [ !! ] 7-Zip installer NOT found and NOT installed.' -ForegroundColor Red
    }
}

if ($is7zInstalled) {
    if ($windowsVersion -like '22*') {
        Write-Host " [ ** ] Windows 10 detected - running '7z_Assoc_OnlyWin10.bat'" -ForegroundColor DarkGray
        $assocBatFile = '7z_Assoc_OnlyWin10.bat'
        $assocBatPath = Join-Path $PSScriptRoot $assocBatFile
        if (Test-Path -Path $assocBatPath -PathType Leaf) {
            try {
                Start-Process -FilePath $assocBatPath -Wait
            }
            catch {
                Write-Warning "Error running '$assocBatFile': $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning "Skipping 7-Zip association: Script '$assocBatFile' not found in '$PSScriptRoot'"
        }
    }
    else {
        Write-Host ' [ *! ] Please, don`t forget to associate 7-Zip files manually (automatic association works only in Win10)' -ForegroundColor White
    }
}

$anyDeskExe = 'AnyDesk.exe'
$anyDeskPath = Join-Path $PSScriptRoot $anyDeskExe
if (Test-Path -Path $anyDeskPath -PathType Leaf) {
    Start-Process $anyDeskPath '--silent --remove' -Wait
    $pass = Generate-SecurePassword
    Remove-Item -Path "${env:ProgramFiles(x86)}\AnyDesk", 'C:\ProgramData\AnyDesk' -Recurse -Force -ErrorAction SilentlyContinue
    Add-Content -Path "$($PSScriptRoot)\$($fileNameBase)_$($fileDate).txt" -Value 'AnyDesk ID:'
    Start-Process $anyDeskPath '--install "C:\ProgramData\AnyDesk" --start-with-win --create-shortcuts --create-desktop-icon' -Wait
    $timeout = 30
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host " [ >> ] When AnyDesk is completely started and obtains an ID - Press Any Key (Timeout: $($timeout) seconds)" -ForegroundColor Cyan
    while ($timer.Elapsed.TotalSeconds -lt $timeout) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            Write-Host "`nKey pressed. Setting-up AnyDesk..."
            $timer.Stop()
            break
        }
        Write-Host (" [            Time remaining: {0:00} seconds" -f ($timeout - $timer.Elapsed.TotalSeconds)) -ForegroundColor Cyan -NoNewline
        Write-Host "`r" -NoNewline
        Start-Sleep -Milliseconds 100
    }
    Write-Host ''
    if ($timer.Elapsed.TotalSeconds -ge $timeout) {
        Write-Host "Timeout. Setting-up AnyDesk...`n" -ForegroundColor DarkGray
    }
    $timer.Stop()

    C:\ProgramData\AnyDesk\AnyDesk.exe --get-id | Out-File "$($PSScriptRoot)\$($fileNameBase)_$($fileDate).txt" -Append
    $pathAnyDeskRuntime = 'C:\ProgramData\AnyDesk\AnyDesk.exe' # Path after installation
    $pass | & $pathAnyDeskRuntime --set-password
    Add-Content -Path "$($PSScriptRoot)\$($fileNameBase)_$($fileDate).txt" -Value 'AnyDesk password:'
    Add-Content -Path "$($PSScriptRoot)\$($fileNameBase)_$($fileDate).txt" -Value "$pass`n`n"
}
else {
    Write-Warning "Skipping AnyDesk installation: Installer '$anyDeskExe' not found in '$PSScriptRoot'"
}

$result = [System.Windows.Forms.MessageBox]::Show('Collect info about this PC to file?', 'Confirm Collection', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    if ($PSScriptRoot) {
        $currentPath = $PSScriptRoot
    } else {
        $currentPath = Get-Location
    }

    $csvFile = Join-Path $currentPath "$($fileNameBase)_INVENT.csv"
    $htmlFile = Join-Path $currentPath "$($fileNameBase)_INVENT.html"

    Write-Host ' [ .. ] Collecting system information...' -ForegroundColor DarkGray

    $SystemInfoParams = @{ ClassName = 'Win32_OperatingSystem'; ErrorAction = 'SilentlyContinue' }
    $ProcessorInfoParams = @{ ClassName = 'Win32_Processor'; ErrorAction = 'SilentlyContinue' }
    $GraphicsAdapterParams = @{ ClassName = 'Win32_VideoController'; ErrorAction = 'SilentlyContinue' }
    $MemoryModulesParams = @{ ClassName = 'Win32_PhysicalMemory'; ErrorAction = 'SilentlyContinue' }
    $DiskInfosParams = @{ ClassName = 'Win32_LogicalDisk'; Filter = "DriveType = 3"; ErrorAction = 'SilentlyContinue' }
    $NetworkAdaptersParams = @{ ClassName = 'Win32_NetworkAdapter'; Filter = "NetConnectionStatus = 2"; ErrorAction = 'SilentlyContinue' }
    $NetworkAdapterConfigParams = @{ ClassName = 'Win32_NetworkAdapterConfiguration'; Filter = "IPEnabled = TRUE"; ErrorAction = 'SilentlyContinue' }
    $ComputerSystemParams = @{ ClassName = 'Win32_ComputerSystem'; ErrorAction = 'SilentlyContinue' }
    $MotherboardInfoParams = @{ ClassName = 'Win32_BaseBoard'; ErrorAction = 'SilentlyContinue' }
    $BiosInfoParams = @{ ClassName = 'Win32_BIOS'; ErrorAction = 'SilentlyContinue' }

    $systemInfo = Get-CimInstance @SystemInfoParams
    $processorInfo = Get-CimInstance @ProcessorInfoParams | Select-Object -First 1
    $graphicsAdapters = Get-CimInstance @GraphicsAdapterParams
    $memoryModules = Get-CimInstance @MemoryModulesParams
    $diskInfos = Get-CimInstance @DiskInfosParams
    $networkAdapters = Get-CimInstance @NetworkAdaptersParams
    $networkAdapterConfigs = Get-CimInstance @NetworkAdapterConfigParams
    $computerSystem = Get-CimInstance @ComputerSystemParams
    $motherboardInfo = Get-CimInstance @MotherboardInfoParams
    $biosInfo = Get-CimInstance @BiosInfoParams

    $csvOutput = @()

    $csvOutput += [PSCustomObject]@{ Property = 'Computer Name'; Value = $newComputerName }

    if ($systemInfo) {
        $csvOutput += [PSCustomObject]@{ Property = 'Operating System'; Value = "$($systemInfo.Caption) $($systemInfo.OSArchitecture)" }
        $csvOutput += [PSCustomObject]@{ Property = 'OS Version'; Value = $systemInfo.Version }
        Try { $InstallDate = $systemInfo.InstallDate } Catch { $InstallDate = 'N/A' }
        $csvOutput += [PSCustomObject]@{ Property = 'OS Installation Date'; Value = if ($InstallDate -is [datetime]) { $InstallDate.ToString('dd/MM/yyyy HH:mm:ss') } else { $InstallDate } }
        $csvOutput += [PSCustomObject]@{ Property = 'OS Serial Number'; Value = $systemInfo.SerialNumber }
        $csvOutput += [PSCustomObject]@{ Property = 'Registered User'; Value = $systemInfo.RegisteredUser }
    }

    if ($computerSystem) {
        $csvOutput += [PSCustomObject]@{ Property = 'PC Manufacturer'; Value = $computerSystem.Manufacturer }
        $csvOutput += [PSCustomObject]@{ Property = 'PC Model'; Value = $computerSystem.Model }
        if ($computerSystem.PartOfDomain) {
            $csvOutput += [PSCustomObject]@{ Property = 'Domain'; Value = $computerSystem.Domain }
        } else {
            $csvOutput += [PSCustomObject]@{ Property = 'Workgroup'; Value = $computerSystem.Workgroup }
        }
    }

    if ($motherboardInfo) {
        $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Manufacturer'; Value = $motherboardInfo.Manufacturer }
        $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Product'; Value = $motherboardInfo.Product }
        $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Version'; Value = $motherboardInfo.Version }
        $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Serial Number'; Value = $motherboardInfo.SerialNumber }
    }

    if ($biosInfo) {
        $csvOutput += [PSCustomObject]@{ Property = 'BIOS - Manufacturer'; Value = $biosInfo.Manufacturer }
        $csvOutput += [PSCustomObject]@{ Property = 'BIOS - Version'; Value = $biosInfo.SMBIOSBIOSVersion }
        $csvOutput += [PSCustomObject]@{ Property = 'BIOS - Serial Number'; Value = $biosInfo.SerialNumber }
    }

    if ($processorInfo) {
        $csvOutput += [PSCustomObject]@{ Property = 'Processor'; Value = $processorInfo.Name.Trim() }
        $csvOutput += [PSCustomObject]@{ Property = 'Processor - Number of Cores'; Value = $processorInfo.NumberOfCores }
        $csvOutput += [PSCustomObject]@{ Property = 'Processor - Number of Logical Processors'; Value = $processorInfo.NumberOfLogicalProcessors }
        $csvOutput += [PSCustomObject]@{ Property = 'Processor - Max Speed (MHz)'; Value = $processorInfo.MaxClockSpeed }
    }

    if ($graphicsAdapters) {
        $adapterIndex = 1
        foreach ($adapter in $graphicsAdapters) {
            $prefix = if ($graphicsAdapters.Count -gt 1) { "Graphics Card $adapterIndex" } else { "Graphics Card" }
            $csvOutput += [PSCustomObject]@{ Property = "$prefix - Name"; Value = $adapter.Name }
            $csvOutput += [PSCustomObject]@{ Property = "$prefix - Driver Version"; Value = $adapter.DriverVersion }
             if ($adapter.AdapterRAM -gt 0) {
                 $vramGB = [math]::Round($adapter.AdapterRAM / 1GB, 2)
                 $csvOutput += [PSCustomObject]@{ Property = "$prefix - Video RAM (GB)"; Value = $vramGB }
             } else {
                  $csvOutput += [PSCustomObject]@{ Property = "$prefix - Video RAM (GB)"; Value = "N/A" }
             }
            $adapterIndex++
        }
    }

    if ($memoryModules) {
        $totalRamBytes = ($memoryModules | Measure-Object -Property Capacity -Sum).Sum
        $totalRamGB = [math]::Round($totalRamBytes / 1GB, 2)
        $csvOutput += [PSCustomObject]@{ Property = 'Total RAM (GB)'; Value = $totalRamGB }

        foreach ($module in $memoryModules) {
            $capacityMB = [math]::Round($module.Capacity / 1MB, 0)
            $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Manufacturer"; Value = $module.Manufacturer }
            $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Part Number"; Value = $module.PartNumber }
            $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Capacity (MB)"; Value = $capacityMB }
            $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Speed (MHz)"; Value = $module.Speed }
             $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Serial Number"; Value = $module.SerialNumber }
        }
    }

    if ($diskInfos) {
        foreach ($disk in $diskInfos) {
            $capacityGB = [math]::Round($disk.Size / 1GB, 2)
            $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Volume Name"; Value = $disk.VolumeName }
            $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - File System"; Value = $disk.FileSystem }
            $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Capacity (GB)"; Value = $capacityGB }
            $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Free Space (GB)"; Value = $freeSpaceGB }
        }
    }

    if ($networkAdapters) {
        foreach ($adapter in $networkAdapters) {
            $adapterConfig = $networkAdapterConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } | Select-Object -First 1

            if ($adapterConfig) {
                 $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Description"; Value = $adapter.Description }
                 $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - MAC Address"; Value = $adapterConfig.MACAddress }

                 $ipAddress = ($adapterConfig.IPAddress | Where-Object {$_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'}) | Select-Object -First 1
                 if (-not $ipAddress) { $ipAddress = ($adapterConfig.IPAddress | Select-Object -First 1) }
                 $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - IP Address"; Value = if ($ipAddress) { $ipAddress } else { '-' } }

                 $subnetMask = '-'
                 if ($ipAddress) {
                     $ipIndex = [array]::IndexOf($adapterConfig.IPAddress, $ipAddress)
                     if ($ipIndex -ge 0 -and $ipIndex -lt $adapterConfig.IPSubnet.Count) {
                         $subnetMask = $adapterConfig.IPSubnet[$ipIndex]
                     }
                 }
                 $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Subnet Mask"; Value = $subnetMask }

                 $defaultGateway = ($adapterConfig.DefaultIPGateway | Select-Object -First 1)
                 $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Default Gateway"; Value = if ($defaultGateway) { $defaultGateway } else { '-' } }

                 $dnsServers = ($adapterConfig.DNSServerSearchOrder | Select-Object -First 2) -join ', '
                 $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - DNS Servers"; Value = if ($dnsServers) { $dnsServers } else { '-' } }

            }
        }
    }

    $csvOutput | Export-Csv -Path $csvFile -Encoding UTF8 -NoTypeInformation -Delimiter ','

    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Information for $($newComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 10pt; margin: 20px; }
        h1 { color: #336699; border-bottom: 2px solid #336699; padding-bottom: 5px; }
        table { width: 80%; border-collapse: collapse; margin-top: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { padding: 8px 12px; border: 1px solid #ccc; text-align: left; }
        th { background-color: #eef4f9; font-weight: 600; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        td:first-child { width: 35%; font-weight: 500; color: #555; }
    </style>
</head>
<body>
    <h1>System Information - $($newComputerName)</h1>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
"@

    foreach ($item in $csvOutput) {
        $escapedValue = [System.Web.HttpUtility]::HtmlEncode($item.Value)
        $htmlContent += "        <tr><td>$($item.Property)</td><td>$($escapedValue)</td></tr>`n"
    }

    $htmlContent += @'
    </table>
'@
    $htmlContent += "<p style='font-size: 8pt; color: #888; margin-top: 15px;'>Report generated on $currentDate</p>`n"

    $htmlContent += @'
</body>
</html>
'@
    $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
    Write-Host " [ ** ] System Inventorization saved in files: '$csvFile' & '$htmlFile'" -ForegroundColor Green
}

Write-Host "`n        ═════════════════════════" -ForegroundColor DarkCyan
Write-Host '        ║                       ║' -ForegroundColor DarkCyan
Write-Host '        ║  ' -NoNewline -ForegroundColor DarkCyan
Write-Host '       Done! ' -NoNewline -ForegroundColor Magenta
Write-Host '        ║' -ForegroundColor DarkCyan
Write-Host '        ║                       ║' -ForegroundColor DarkCyan
Write-Host "        ═════════════════════════`n" -ForegroundColor DarkCyan

if ($needRestart) {
    $questionRestartComputer = [System.Windows.Forms.MessageBox]::Show("A reboot is required to apply changes.`nReboot Now?", 'Restart Required', 'YesNo', [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($questionRestartComputer -eq 'Yes') {
        Restart-Computer -Force
    }
}
