Clear-Host

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Warning 'This script requires ADMIN permissions. Please, run it as Administrator'
    Write-Host 'Press any key to exit...'
    [void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
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
Add-Type -AssemblyName Microsoft.VisualBasic

$configLoaded = $false
$configFilePath = Join-Path $PSScriptRoot 'config.json'
if (Test-Path $configFilePath) {
    try {
        $config = Get-Content -Path $configFilePath | ConvertFrom-Json
        $appsToRemove = $config.appRemoval
        $registrySettings = $config.registrySettings
        $configLoaded = $true
    }
    catch {
        Write-Warning "Failed to read or parse 'config.json'. App removal will be skipped."
    }
}
else {
    Write-Warning "Configuration file 'config.json' not found. App removal will be skipped."
}

try {
    $windowsInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $windowsVersion = $windowsInfo.DisplayVersion
    $WindowsEdition = $windowsInfo.EditionID
    $WindowsLocale = (Get-Culture).Name
    Write-Host "`nWindows ver.: $windowsVersion ($($WindowsEdition) / $($WindowsLocale))" -ForegroundColor Cyan
}
catch {
    Write-Warning 'Failed to detect Windows version/edition/locale. Some features might not work as expected.'
    $windowsVersion = 'Unknown'
    $WindowsEdition = 'Unknown'
    $WindowsLocale = 'Unknown'
}

$needRestart = $false
if ($windowsVersion -notlike '22*' -and $windowsVersion -ne 'Unknown') {
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

function Generate-SecurePassword {
    
    function Get-SecureInt {
        param([int]$Maximum)
        
        if ($Maximum -le 0) { return 0 }
        
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 4
        
        while ($true) {
            $rng.GetBytes($bytes)
            $rand = [System.BitConverter]::ToUInt32($bytes, 0)
            
            $limit = [uint32]::MaxValue - ([uint32]::MaxValue % $Maximum)
            
            if ($rand -lt $limit) {
                return ($rand % $Maximum)
            }
        }
    }

    $consonants = @('b','c','d','f','g','h','k','m','n','p','r','s','t','v','w','x','z')
    $vowels     = @('a','e','o','u')
    
    $GetRandomChar = {
        param($List)
        $Index = Get-SecureInt -Maximum $List.Count
        return $List[$Index]
    }
    
    $char1 = (&$GetRandomChar $consonants).ToString().ToUpper()
    $char2 = (&$GetRandomChar $vowels)
    $char3 = (&$GetRandomChar $consonants)
    
    $sep = "-"
    
    $char4 = (&$GetRandomChar $consonants)
    $char5 = (&$GetRandomChar $vowels)
    $char6 = (&$GetRandomChar $consonants)
    $char7 = (&$GetRandomChar $consonants)
    
    $digit = (Get-SecureInt -Maximum 10).ToString()

    return "$char1$char2$char3$sep$char4$char5$char6$char7$digit"
}

if ($configLoaded) {
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
        if ($windowsVersion -eq 'Unknown') { $osKey = 'Win11' }
        $operationSuccess = $true

        if ($appsToRemove.$osKey) {
            foreach ($appName in $appsToRemove.$osKey) {
                if (Get-AppxPackage -AllUsers -Name "*$appName*" -ErrorAction SilentlyContinue) {
                    try {
                        Get-AppxPackage "*$appName*" | Remove-AppxPackage -ErrorAction SilentlyContinue
                        Get-AppxPackage -AllUsers "*$appName*" | Remove-AppxPackage -ErrorAction SilentlyContinue
                        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$appName*" } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Warning "Failed to remove app '$appName': $($_.Exception.Message)"
                        $operationSuccess = $false
                    }
                }
            }
            if ($operationSuccess) {
                Write-Host ' [ ** ] Useless apps were successfully removed' -ForegroundColor Green
                $needRestart = $true
            }
        }
        else {
            Write-Warning "Could not determine appropriate app list for Windows Version '$windowsVersion'. Skipping app removal."
        }

        $registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        
        try {
            New-Item -Path $registryPath -Type Directory -Force | Out-Null

            foreach ($property in $registrySettings.PSObject.Properties) {
                Set-ItemProperty -Path $registryPath -Name $property.Name -Value $property.Value -Type DWord -Force
            }

            $subkeysToRemove = @(
                "$registryPath\Subscriptions",
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
}

$oneDriveScriptFile = 'UninstallOneDrive.ps1'
$oneDriveScriptPath = Join-Path $PSScriptRoot $oneDriveScriptFile
if (Test-Path -Path $oneDriveScriptPath -PathType Leaf) {
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

        & powershell.exe -ExecutionPolicy Bypass -File $oneDriveScriptPath
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Script '$oneDriveScriptFile' may have encountered errors during execution (Exit Code: $LASTEXITCODE)."
        }
    }
}
else {
    Write-Warning "Skipping OneDrive removal: Script '$oneDriveScriptFile' not found in '$PSScriptRoot'"
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

$currentDate = Get-Date -Format 'dd/MM/yyyy'
$fileDate = Get-Date -Format 'dd-MM-yyyy'

$currentComputerName = $env:COMPUTERNAME
$newComputerName = $null

do {
    $inputName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a new name for this PC', 'Rename Computer', $currentComputerName)
    if ([string]::IsNullOrWhiteSpace($inputName)) {
        [System.Windows.Forms.MessageBox]::Show('Computer name cannot be empty.', 'Invalid Name', 'OK', 'Error')
        continue
    }
    if ($inputName -match '[^a-zA-Z0-9\-]') {
        [void][System.Windows.Forms.MessageBox]::Show('Computer name contains invalid characters. Use only letters, numbers and hyphens.', 'Invalid Name', 'OK', 'Error')
        continue
    }
    if ($inputName -match '^-|-$' -or $inputName -match '^_|_$') {
        [void][System.Windows.Forms.MessageBox]::Show('Computer name cannot start or end with a hyphen or underscore.', 'Invalid Name', 'OK', 'Error')
        continue
    }
    if ($inputName -match '^[_\-]+$' -or $inputName -match '^\d+$') {
        [void][System.Windows.Forms.MessageBox]::Show('Computer name cannot consist only of underscores, hyphens, or numbers.', 'Invalid Name', 'OK', 'Error')
        continue
    }
    if ($inputName.Length -gt 15) {
        [void][System.Windows.Forms.MessageBox]::Show('Computer name is too long (maximum 15 characters).', 'Invalid Name', 'OK', 'Error')
        continue
    }
    if ($inputName -eq $currentComputerName) {
        $newComputerName = $currentComputerName
        Write-Host ' [ *! ] The new computer name is the same as the current. No changes were made.' -ForegroundColor Yellow
        break
    }
    $newComputerName = $inputName
    break
} while ($true)

$fileNameBase = if (-not [string]::IsNullOrWhiteSpace($newComputerName)) { $newComputerName } else { $currentComputerName }
$fileNameBase = $fileNameBase -replace '[\\/:*?"<>|]', '_'

$logFilePath = Join-Path -Path $PSScriptRoot -ChildPath "$($fileNameBase)_$($fileDate).txt"
Add-Content -Path $logFilePath -Value "[ $($currentDate) ] PC name: $($newComputerName)`n"

if ($newComputerName -ne $currentComputerName) {
    try {
        Rename-Computer -NewName $newComputerName -Force -WarningAction SilentlyContinue | Out-Null
        Write-Host " [ ** ] Computer renamed to '$($newComputerName)' successfully. A reboot is required" -ForegroundColor Green
        $needRestart = $true
    }
    catch {
        Write-Warning "Error renaming computer: $($_.Exception.Message)"
        $newComputerName = $currentComputerName
    }
}

$userName = 'helper'
$user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
if (-not $user) {
    Write-Host " [ .. ] User 'helper' not found. Renaming built-in Administrator..."
    try {
        $adminCim = Get-CimInstance -ClassName Win32_UserAccount -Filter "SID LIKE '%-500'"
        $adminUser = Get-LocalUser -Name $adminCim.Name
        
        $password = Generate-SecurePassword
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        
        $adminUser | Set-LocalUser -Password $securePassword
        $adminUser | Rename-LocalUser -NewName $userName
        Get-LocalUser -Name $userName | Enable-LocalUser

        Add-Content -Path $logFilePath -Value "helper password (from renamed Admin):`n$password`n`n"
        Write-Host " [ ** ] Built-in Administrator renamed to 'helper', enabled, and password set." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to rename and configure built-in Administrator: $($_.Exception.Message)"
    }
}
else {
    Write-Host " [ *! ] User 'helper' already exists" -ForegroundColor Yellow
    if (-not $user.Enabled) {
        try {
            $user | Enable-LocalUser
        }
        catch {
            Write-Warning "Failed to enable user 'helper': $($_.Exception.Message)"
        }
    }
}

try {
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    if (-not (Get-LocalGroupMember -Group $adminGroup -Member $userName -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group $adminGroup -Member $userName
    }
    
    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    if (Get-LocalGroupMember -Group $usersGroup -Member $userName -ErrorAction SilentlyContinue) {
        Remove-LocalGroupMember -Group $usersGroup -Member $userName
    }
}
catch {
    Write-Warning "Could not manage 'helper' group memberships: $($_.Exception.Message)"
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

$hibernateEnabled = $true
try {
    if ((Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled') -eq 0) {
        $hibernateEnabled = $false
    }
} catch {
    $hibernateEnabled = $false
}

if ($hibernateEnabled) {
    powercfg.exe -h off
}

powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -disk-timeout-ac 0
powercfg.exe -change -disk-timeout-dc 0
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

try {
    if ((Get-NetFirewallProfile).Enabled -contains $true) {
        Set-NetFirewallProfile -All -Enabled 'False'
        Write-Host ' [ ** ] Firewall Profiles - Disabled' -ForegroundColor Green
    }
}
catch {
    Write-Warning "Failed to configure Firewall profiles: $($_.Exception.Message)"
}

try {
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name fAllowFullControl -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host ' [ ** ] Remote Assistance - Enabled' -ForegroundColor Green
}
catch {
    Write-Warning "Failed to enable Remote Assistance: $($_.Exception.Message)"
}


if ($WindowsEdition -ieq 'Professional' -or $WindowsEdition -ieq 'Enterprise' -or $WindowsEdition -ieq 'Education') {
    try {
        Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP', 'RemoteDesktop-Shadow-In-TCP', 'RemoteDesktop-UserMode-In-UDP', 'RemoteDesktop-In-TCP-WSS', 'RemoteDesktop-In-TCP-WS' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
        
        # $rdpWebSocketGroup = if ($WindowsLocale -like 'ru-*') { 'Веб-доступ к удаленным рабочим столам (WebSocket)' } else { 'Remote Desktop (WebSocket)' }
        
        # $rdpWebSocketGroup = if ($WindowsLocale = (Get-Culture).Name) { 'Веб-доступ к удаленным рабочим столам (WebSocket)' } else { 'Remote Desktop (WebSocket)' }
        # Enable-NetFirewallRule -DisplayGroup $rdpWebSocketGroup -ErrorAction SilentlyContinue
        
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
        
        Write-Host ' [ ** ] RDP Host - Enabled' -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to enable RDP Host: $($_.Exception.Message)"
    }
}
else {
    Write-Host " [ *! ] Windows Edition '$WindowsEdition' detected. Skipping RDP Host configuration." -ForegroundColor Yellow
}

$is7zInstalled = $false
$dist7z = Get-ChildItem -Path $PSScriptRoot -Filter '7z*.msi' -File

if ($dist7z) {
    try {
        $msiArgs = "/i `"$($dist7z.FullName)`" /qr /norestart"
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
        if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
            throw "7-Zip installation failed with exit code: $($process.ExitCode)"
        }

        # Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i', "$($dist7z.FullName)", '/Qr', '/NoRestart' -Wait

        $is7zInstalled = $true
    }
    catch {
        Write-Warning "Error installing 7-Zip from local file: $($_.Exception.Message)"
    }
}
else {
    $path7z = Get-ChildItem -Path 'C:\Program Files\7-Zip' -Include '7z.exe' -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq '7z.exe' }
    if ($path7z) {
        $is7zInstalled = $true
    }
    else {
        Write-Host ' [ !! ] 7-Zip installer NOT found and NOT installed.' -ForegroundColor Red
    }
}

if ($is7zInstalled) {
    Write-Host ' [ ** ] 7-Zip successfully installed or already present.' -ForegroundColor Green
    if ($windowsVersion -like '22*') {
        Write-Host " [ .. ] Windows 10 detected - running '7z_Assoc_OnlyWin10.bat'" -ForegroundColor DarkGray
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
        Write-Host ' [ *! ] Please, don`t forget to associate 7-Zip files manually. (Win11 detected - automatic association works only in Win10)' -ForegroundColor White
    }
}

function Find-AnyDeskID {
    $confPath = 'C:\ProgramData\AnyDesk\system.conf'
    if (-not (Test-Path $confPath)) { return $null }
    try {
        $content = Get-Content $confPath -ErrorAction Stop
        $idLine = $content | Select-String -Pattern 'ad.anynet.id='
        if ($idLine) {
            return ($idLine -split '=')[1].Trim()
        }
    }
    catch {
        Write-Verbose "Could not read config: $($_.Exception.Message)"
    }
    return $null
}

$anyDeskExe = 'AnyDesk.exe'
$anyDeskPath = Join-Path $PSScriptRoot $anyDeskExe

if (Test-Path -Path $anyDeskPath -PathType Leaf) {
    Start-Process $anyDeskPath '--silent --remove' -Wait
    Remove-Item -Path "${env:ProgramFiles(x86)}\AnyDesk", 'C:\ProgramData\AnyDesk' -Recurse -Force -ErrorAction SilentlyContinue
    Start-Process $anyDeskPath '--install "C:\ProgramData\AnyDesk" --start-with-win --create-shortcuts --create-desktop-icon' -Wait
    
    $pass = Generate-SecurePassword

    $timeout = 60
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $anydeskID = $null
    Write-Host "Waiting for AnyDesk to obtain a valid ID (Timeout: $timeout seconds)..." -ForegroundColor Cyan

    while ($stopwatch.Elapsed.TotalSeconds -lt $timeout) {
        $anydeskID = Find-AnyDeskID
        if ($anydeskID) {
            Write-Host "`nAnyDesk ID obtained: $anydeskID" -ForegroundColor Cyan
            break
        }
        $remaining = [math]::Round($timeout - $stopwatch.Elapsed.TotalSeconds)
        Write-Host "Waiting... ($remaining s remaining)   `r" -NoNewline
        Start-Sleep -Seconds 3
    }
    $stopwatch.Stop()

    if (-not $anydeskID) {
        $anydeskID = Find-AnyDeskID
        if (-not $anydeskID) {
            Write-Warning 'Timed out waiting for a valid AnyDesk ID. The script will continue, but the ID might not be logged correctly.'
            $anydeskID = 'ID not found'
        }
    }
    
    Add-Content -Path $logFilePath -Value "AnyDesk ID:`n$($anydeskID)"
    
    try {
        $adExePath = 'C:\ProgramData\AnyDesk\AnyDesk.exe'
        if (Test-Path $adExePath) {
            $pass | & $adExePath --set-password
            if ($LASTEXITCODE -ne 0) {
                throw "AnyDesk process returned a non-zero exit code: $LASTEXITCODE"
            }
            Add-Content -Path $logFilePath -Value "AnyDesk password:`n$pass`n`n"
        }
        else {
            Write-Warning "AnyDesk executable not found at '$adExePath'. Could not set password."
        }
    }
    catch {
        Write-Warning "Failed to set AnyDesk password: $($_.Exception.Message)"
        Add-Content -Path $logFilePath -Value "AnyDesk password: NOT SET (Error). Intended password was:`n$pass`n`n"
    }
    
    Remove-Item -Path (Join-Path $PSScriptRoot 'service.conf.lock'), (Join-Path $PSScriptRoot 'system.conf.lock') -Force -ErrorAction SilentlyContinue
}
else {
    Write-Warning 'Skipping AnyDesk installation: Installer not found.'
}

$uiTweaksScriptFile = 'ApplyUI-tweaks.ps1'
$uiTweaksScriptPath = Join-Path $PSScriptRoot $uiTweaksScriptFile

if (Test-Path -Path $uiTweaksScriptPath -PathType Leaf) {
    $questionApplyTweaks = [System.Windows.Forms.MessageBox]::Show('Apply UI tweaks?', 'Confirm UI Tweaks', 'YesNo', 'Question')
    if ($questionApplyTweaks -eq 'Yes') {
        & powershell.exe -ExecutionPolicy Bypass -File $uiTweaksScriptPath
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Script '$uiTweaksScriptFile' may have encountered errors during execution (Exit Code: $LASTEXITCODE)."
        }
        $needRestart = $true
    }
}
else {
    Write-Warning "Skipping UI tweaks: Script '$uiTweaksScriptFile' not found in '$PSScriptRoot'"
}

$inventoryScriptPath = Join-Path $PSScriptRoot 'Get-PCInventory.ps1'
if (Test-Path $inventoryScriptPath) {
    $result = [System.Windows.Forms.MessageBox]::Show('Collect info about this PC to file?', 'Confirm Collection', 'YesNo', 'Question')
    if ($result -eq 'Yes') {
        & $inventoryScriptPath -NewComputerName $newComputerName -FileNameBase $fileNameBase -ScriptRoot $PSScriptRoot
    }
}
else {
    Write-Warning "Inventory script 'Get-PCInventory.ps1' not found. Skipping information collection."
}

Write-Host "`n        ═════════════════════════" -ForegroundColor DarkCyan
Write-Host '        ║                       ║' -ForegroundColor DarkCyan
Write-Host '        ║  ' -NoNewline -ForegroundColor DarkCyan
Write-Host '       Done! ' -NoNewline -ForegroundColor Magenta
Write-Host '        ║' -ForegroundColor DarkCyan
Write-Host '        ║                       ║' -ForegroundColor DarkCyan
Write-Host "        ═════════════════════════`n" -ForegroundColor DarkCyan

if ($needRestart) {
    $questionRestartComputer = [System.Windows.Forms.MessageBox]::Show("A reboot is required to apply changes.`nReboot Now?", 'Restart Required', 'YesNo', 'Question')
    if ($questionRestartComputer -eq 'Yes') {
        Restart-Computer -Force
    }
}