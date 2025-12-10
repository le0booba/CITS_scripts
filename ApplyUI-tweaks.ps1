#requires -RunAsAdministrator

$MachineSettings = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                     Name = 'HideFirstRunExperience';       Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh';                      Name = 'AllowNewsAndInterests';        Value = 0; Type = 'DWord' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem';          Name = 'LongPathsEnabled';             Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended';        Name = 'StartupBoostEnabled';          Value = 0; Type = 'DWord' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended';        Name = 'AllowRunningInBackground';     Value = 0; Type = 'DWord' }
)

$UserSettings = @(
    @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';                                      Name = 'LaunchTo';                  Value = 1;          Type = 'REG_DWORD' }
    @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings';              Name = 'TaskbarEndTask';            Value = 1;          Type = 'REG_DWORD' }
    @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';                                      Name = 'ShowTaskViewButton';        Value = 0;          Type = 'REG_DWORD' }
    @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Search';                                                  Name = 'SearchboxTaskbarMode';      Value = 3;          Type = 'REG_DWORD' }
    @{ Path = 'Control Panel\Keyboard';                                                                            Name = 'InitialKeyboardIndicators'; Value = '2';        Type = 'REG_SZ'    }
    @{ Path = 'Software\Policies\Microsoft\Windows\Explorer';                                                     Name = 'DisableSearchBoxSuggestions'; Value = 1;       Type = 'REG_DWORD' }
)

function Apply-UserSettings {
    param([string]$HiveRoot)
    foreach ($s in $UserSettings) {
        $fullKey = "$HiveRoot\$($s.Path)"
        reg add "$fullKey" /v "$($s.Name)" /t $($s.Type) /d $($s.Value) /f | Out-Null
    }
}

Write-Host "`nApplying machine-wide settings (HKLM)..." -ForegroundColor Yellow
foreach ($s in $MachineSettings) {
    if (-not (Test-Path $s.Path)) { New-Item $s.Path -Force | Out-Null }
    New-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -PropertyType $s.Type -Force | Out-Null
}

reg add "HKU\.DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f | Out-Null

Write-Host "`nProcessing all user profiles (active + offline + default)..." -ForegroundColor Yellow

if (-not (Test-Path 'HKU:\')) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null }

$Profiles = @()
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ForEach-Object {
    $sid  = $_.PSChildName
    $path = $_.GetValue('ProfileImagePath')
    if (-not $path) { return }
    $path = [Environment]::ExpandEnvironmentVariables($path)
    $name = Split-Path $path -Leaf

    if ($name -match '^(Public|Default|systemprofile|LocalService|NetworkService|DefaultAppPool|DWM-|UMFD-)') { return }
    if ($sid -like '*_Classes') { return }

    $Profiles += [pscustomobject]@{ SID = $sid; Path = $path; Name = $name; Loaded = $false }
}

$loadedSIDs = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue |
              Where-Object { $_.PSChildName -match '^S-1-5-21-.+-\d+$' -and $_.PSChildName -notlike '*_Classes' } |
              Select-Object -ExpandProperty PSChildName

foreach ($p in $Profiles) { $p.Loaded = $loadedSIDs -contains $p.SID }

foreach ($p in $Profiles | Where-Object Loaded) {
    Apply-UserSettings -HiveRoot "HKU\$($p.SID)"
    Write-Host "  Applied to active user: $($p.Name)" -ForegroundColor Green
}

foreach ($p in $Profiles | Where-Object { -not $_.Loaded }) {
    $ntuser = Join-Path $p.Path "NTUSER.DAT"
    if (-not (Test-Path $ntuser)) { continue }

    $tempHive = "HKU\Temp_$($p.SID.Split('-')[-1])"
    $wasLoaded = $false

    try {
        reg load $tempHive "`"$ntuser`"" >$null 2>&1
        if ($LASTEXITCODE -eq 0) {
            $wasLoaded = $true
            Apply-UserSettings -HiveRoot $tempHive
            Write-Host "  Applied to offline user: $($p.Name)" -ForegroundColor Green
        }
    }
    finally {
        if ($wasLoaded) {
            Start-Sleep -Milliseconds 400
            reg unload $tempHive /f >$null 2>&1
        }
    }
}

$defHive = "HKU\TempDefault_$(Get-Random)"
$defPath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $defPath) {
    reg load $defHive "`"$defPath`"" >$null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Apply-UserSettings -HiveRoot $defHive
        Write-Host "  Applied to Default User profile (future users)" -ForegroundColor Green
        Start-Sleep -Milliseconds 400
        reg unload $defHive /f >$null 2>&1
    }
}

Write-Host "`nAll settings have been successfully applied to every existing and future user profile." -ForegroundColor Cyan

Write-Host "`nDo you want to restart Explorer to apply UI changes immediately?" -ForegroundColor Yellow
Write-Host "Press [ENTER] to restart Explorer" -NoNewline
Write-Host "  |  " -NoNewline
Write-Host "Press [ESC] to skip" -ForegroundColor Gray

do {
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").VirtualKeyCode
} until ($key -eq 13 -or $key -eq 27)

if ($key -eq 13) {
    Write-Host "`nRestarting explorer.exe (clean restart, no extra windows)..." -ForegroundColor Cyan
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    # Start-Sleep -Seconds 2
    Start-Process "$env:SystemRoot\explorer.exe" -ErrorAction SilentlyContinue
    Write-Host "Explorer restarted successfully." -ForegroundColor Green
} else {
    Write-Host "`nExplorer was not restarted. UI changes will appear after logoff/logon or manual restart." -ForegroundColor Gray
}