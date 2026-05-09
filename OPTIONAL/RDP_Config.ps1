#Requires -RunAsAdministrator

param(
    [switch]$Enable,
    [switch]$Disable,
    [switch]$EnableRA,
    [switch]$DisableRA,
    [switch]$EnableRDP,
    [switch]$DisableRDP,
    [switch]$Rollback,
    [switch]$Interactive,
    [switch]$Help
)

Clear-Host

$Script:ConfigBackup = @{
    Registry        = @{}
    FirewallRules   = @{}
    CreatedRules    = @()
    BackupTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}
function Backup-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $key = "$Path\$Name"
        if (Test-Path $Path) {
            $property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($property) {
                $Script:ConfigBackup.Registry[$key] = @{
                    Value   = $property.$Name
                    Type    = $property.PSObject.Properties[$Name].TypeName
                    Existed = $true
                }
            }
            else {
                $Script:ConfigBackup.Registry[$key] = @{
                    Existed = $false
                }
            }
        }
        else {
            $Script:ConfigBackup.Registry[$key] = @{
                PathExisted = $false
            }
        }
    }
    catch {
        Write-Warning "Failed to backup registry value '$Path\$Name': $($_.Exception.Message)"
    }
}
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$PropertyType = 'DWORD'
    )
    try {
        Backup-RegistryValue -Path $Path -Name $Name
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $PropertyType -Force
        return $true
    }
    catch {
        Write-Warning "Failed to set registry value '$Path\$Name': $($_.Exception.Message)"
        return $false
    }
}
function Get-WindowsEditionWMI {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = $os.Caption
        switch -Regex ($caption) {
            'Enterprise|Корпоративная|企业版' { return 'Enterprise' }
            'Education|Для образовательных учреждений|教育版' { return 'Education' }
            'Professional|Pro|Профессиональная|专业版' { return 'Professional' }
            'Home|Домашняя|家庭版' { return 'Home' }
            default { return 'Unknown' }
        }
    }
    catch {
        Write-Warning "Failed to determine Windows edition: $($_.Exception.Message)"
        return 'Unknown'
    }
}
function Get-RemoteAssistanceState {
    $raPath = 'HKLM:\System\CurrentControlSet\Control\Remote Assistance'
    if (Test-Path $raPath) {
        $properties = Get-ItemProperty -Path $raPath -Name 'fAllowToGetHelp', 'fAllowFullControl' -ErrorAction SilentlyContinue
        return $properties -and ($properties.fAllowToGetHelp -eq 1) -and ($properties.fAllowFullControl -eq 1)
    }
    return $false
}
function Get-RDPRegistryState {
    $tsPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $rdpTcpPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    if ((Test-Path $tsPath) -and (Test-Path $rdpTcpPath)) {
        $tsProps = Get-ItemProperty -Path $tsPath -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        $rdpTcpProps = Get-ItemProperty -Path $rdpTcpPath -Name 'UserAuthentication' -ErrorAction SilentlyContinue
        return $tsProps -and $rdpTcpProps -and ($tsProps.fDenyTSConnections -eq 0) -and ($rdpTcpProps.UserAuthentication -eq 1)
    }
    return $false
}
function Get-RDPFirewallState {
    try {
        $enabledRule = Get-NetFirewallRule | Where-Object { 
            ($_.Direction -eq "Inbound") -and 
            ($_.Enabled -eq 'True') -and 
            (($_.DisplayName -match "Remote Desktop|Удаленный рабочий стол") -or ($_.DisplayName -match "RDP-Custom-")) 
        } -ErrorAction SilentlyContinue
        return [bool]$enabledRule
    }
    catch {
        return $false
    }
}
function Enable-RDPFirewall {
    Write-Host "    Configuring firewall for RDP..." -ForegroundColor DarkYellow
    $success = $false
    $methods = @()
    $foundRules = Get-NetFirewallRule | Where-Object { 
        ($_.DisplayName -match "Remote Desktop|Удаленный рабочий стол") -and 
        ($_.Direction -eq "Inbound") 
    } -ErrorAction SilentlyContinue
    try {
        foreach ($rule in $foundRules) {
            $Script:ConfigBackup.FirewallRules[$rule.Name] = @{
                Enabled = $rule.Enabled
                Existed = $true
            }
        }
    }
    catch {
        Write-Warning "Failed to backup firewall rules state: $($_.Exception.Message)"
    }
    try {
        Write-Host "      Method 1: Enabling Remote Desktop group via netsh..." -ForegroundColor Gray
        $output = netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      ✓ Remote Desktop group enabled successfully" -ForegroundColor DarkGreen
            $success = $true
            $methods += "netsh group (English)"
        }
        else {
            $output = netsh advfirewall firewall set rule group="Удаленный рабочий стол" new enable=Yes 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "      ✓ Remote Desktop group enabled successfully" -ForegroundColor DarkGreen
                $success = $true
                $methods += "netsh group (Russian)"
            }
            else {
                Write-Host "      ✗ Method 1 failed: Could not find matching firewall rule group." -ForegroundColor DarkRed
            }
        }
    }
    catch {
        Write-Host "      ✗ Method 1 exception: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
    if (-not $success) {
        try {
            Write-Host "      Method 2: Finding RDP rules via PowerShell..." -ForegroundColor Gray
            if ($foundRules) {
                $enabledCount = 0
                foreach ($rule in $foundRules) {
                    if ($rule.Enabled -eq 'False') {
                        Enable-NetFirewallRule -InputObject $rule
                    }
                    $enabledCount++
                }
                if ($enabledCount -gt 0) {
                    Write-Host "      ✓ $enabledCount RDP firewall rules processed" -ForegroundColor DarkGreen
                    $success = $true
                    $methods += "PowerShell rules ($enabledCount)"
                }
            }
            else {
                Write-Host "      ✗ No RDP rules found via PowerShell" -ForegroundColor DarkRed
            }
        }
        catch {
            Write-Host "      ✗ Method 2 exception: $($_.Exception.Message)" -ForegroundColor DarkRed
        }
    }
    if (-not $success) {
        Write-Host "      ✗ Standard RDP firewall rules were not found." -ForegroundColor DarkRed
        $prompt = "Do you want to create new custom rules for RDP (TCP/UDP port 3389)?"
        $choice = Read-Host -Prompt "      ? $prompt [Y/N]"
        if ($choice -eq 'y') {
            try {
                Write-Host "      Method 3: Creating custom RDP firewall rules..." -ForegroundColor Gray
                $rule1 = New-NetFirewallRule -DisplayName "RDP-Custom-TCP-In" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction Stop
                $rule2 = New-NetFirewallRule -DisplayName "RDP-Custom-UDP-In" -Direction Inbound -Protocol UDP -LocalPort 3389 -Action Allow -Profile Any -ErrorAction Stop
                $Script:ConfigBackup.CreatedRules += @($rule1.Name, $rule2.Name)
                Write-Host "      ✓ Custom RDP firewall rules created" -ForegroundColor DarkGreen
                $success = $true
                $methods += "Custom rules"
            }
            catch {
                Write-Host "      ✗ Method 3 exception: $($_.Exception.Message)" -ForegroundColor DarkRed
            }
        }
        else {
            Write-Host "      ✓ Skipping custom rule creation as requested." -ForegroundColor DarkGreen
        }
    }
    return @{
        Success = $success
        Methods = ($methods -join ", ")
    }
}
function Disable-RDPFirewall {
    Write-Host "    Disabling firewall for RDP..." -ForegroundColor DarkYellow
    $success = $false
    $methods = @()
    try {
        Write-Host "      Method 1: Disabling Remote Desktop group via netsh..." -ForegroundColor Gray
        $output = netsh advfirewall firewall set rule group="Remote Desktop" new enable=No 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      ✓ Remote Desktop group disabled successfully" -ForegroundColor DarkGreen
            $success = $true
            $methods += "netsh group (English)"
        }
        else {
            $output = netsh advfirewall firewall set rule group="Удаленный рабочий стол" new enable=No 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "      ✓ Remote Desktop group disabled successfully" -ForegroundColor DarkGreen
                $success = $true
                $methods += "netsh group (Russian)"
            }
            else {
                Write-Host "      ✗ Method 1 failed: Could not find matching firewall rule group." -ForegroundColor DarkRed
            }
        }
    }
    catch {
        Write-Host "      ✗ Method 1 exception: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
    try {
        Write-Host "      Method 2: Finding and disabling RDP rules via PowerShell..." -ForegroundColor Gray
        $rdpRules = Get-NetFirewallRule | Where-Object { 
            ($_.DisplayName -match "Remote Desktop|Удаленный рабочий стол") -and 
            ($_.Direction -eq "Inbound") -and
            ($_.Enabled -eq 'True')
        }
        if ($rdpRules) {
            $disabledCount = 0
            foreach ($rule in $rdpRules) {
                Disable-NetFirewallRule -InputObject $rule
                $disabledCount++
            }
            if ($disabledCount -gt 0) {
                Write-Host "      ✓ $disabledCount RDP firewall rules disabled" -ForegroundColor DarkGreen
                $success = $true
                $methods += "PowerShell rules ($disabledCount)"
            }
        }
    }
    catch {
        Write-Host "      ✗ Method 2 exception: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
    try {
        $customRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -match "RDP-Custom-" }
        if ($customRules) {
            $removedCount = 0
            foreach ($rule in $customRules) {
                Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
                $removedCount++
            }
            Write-Host "      ✓ $removedCount custom RDP rules removed" -ForegroundColor DarkGreen
            $methods += "Custom rules removed ($removedCount)"
        }
    }
    catch {
        Write-Host "      ✗ Method 3 exception: $($_.Exception.Message)" -ForegroundColor DarkRed
    }
    return @{
        Success = $success
        Methods = ($methods -join ", ")
    }
}
function Enable-RemoteAssistance {
    Write-Host "Step 1: Enabling Remote Assistance..." -ForegroundColor Yellow
    $currentState = Get-RemoteAssistanceState
    if ($currentState) {
        Write-Host "  [i] Remote Assistance - Already Enabled" -ForegroundColor Cyan
        return $true
    }
    $raPath = 'HKLM:\System\CurrentControlSet\Control\Remote Assistance'
    $raResult1 = Set-RegistryValue -Path $raPath -Name 'fAllowToGetHelp' -Value 1
    $raResult2 = Set-RegistryValue -Path $raPath -Name 'fAllowFullControl' -Value 1
    $raSuccess = $raResult1 -and $raResult2
    if ($raSuccess) {
        Write-Host "  [✓] Remote Assistance - Enabled" -ForegroundColor Green
    }
    else {
        Write-Host "  [✗] Remote Assistance - Failed" -ForegroundColor Red
    }
    return $raSuccess
}
function Disable-RemoteAssistance {
    Write-Host "Step 1: Disabling Remote Assistance..." -ForegroundColor Yellow
    $currentState = Get-RemoteAssistanceState
    if (-not $currentState) {
        Write-Host "  [i] Remote Assistance - Already Disabled" -ForegroundColor Cyan
        return $true
    }
    $raPath = 'HKLM:\System\CurrentControlSet\Control\Remote Assistance'
    $raResult1 = Set-RegistryValue -Path $raPath -Name 'fAllowToGetHelp' -Value 0
    $raResult2 = Set-RegistryValue -Path $raPath -Name 'fAllowFullControl' -Value 0
    $raSuccess = $raResult1 -and $raResult2
    if ($raSuccess) {
        Write-Host "  [✓] Remote Assistance - Disabled" -ForegroundColor Green
    }
    else {
        Write-Host "  [✗] Remote Assistance - Failed to disable" -ForegroundColor Red
    }
    return $raSuccess
}
function Enable-RDPHost {
    param([string]$WindowsEdition)
    $supportedEditions = @('Professional', 'Enterprise', 'Education')
    if ($supportedEditions -contains $WindowsEdition) {
        Write-Host "Step 3: Enabling RDP Host..." -ForegroundColor Yellow
        $regState = Get-RDPRegistryState
        $fwState = Get-RDPFirewallState
        if ($regState -and $fwState) {
            Write-Host "  [i] RDP Host - Already Fully Enabled" -ForegroundColor Cyan
            return @{
                Success         = $true
                Partial         = $false
                RegistrySuccess = $true
                FirewallSuccess = $true
                FirewallMethods = "Already enabled"
            }
        }
        Write-Host "  Configuring RDP registry settings..." -ForegroundColor DarkYellow
        $tsPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $rdpTcpPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $regResult1 = Set-RegistryValue -Path $tsPath -Name 'fDenyTSConnections' -Value 0
        $regResult2 = Set-RegistryValue -Path $rdpTcpPath -Name 'UserAuthentication' -Value 1
        $registrySuccess = $regResult1 -and $regResult2
        if ($registrySuccess) {
            Write-Host "    ✓ Registry settings configured" -ForegroundColor DarkGreen
        }
        else {
            Write-Host "    ✗ Registry settings failed" -ForegroundColor DarkRed
        }
        $firewallResult = Enable-RDPFirewall
        if ($registrySuccess -and $firewallResult.Success) {
            Write-Host "  [✓] RDP Host - Fully Enabled" -ForegroundColor Green
            Write-Host "    └─ Registry: ✓ Configured" -ForegroundColor DarkGreen
            Write-Host "    └─ Firewall: ✓ Enabled ($($firewallResult.Methods))" -ForegroundColor DarkGreen
        }
        elseif ($registrySuccess -or $firewallResult.Success) {
            Write-Host "  [⚠] RDP Host - Partially Configured" -ForegroundColor Yellow
            Write-Host "    └─ Registry: $(if($registrySuccess){'✓ Configured'}else{'✗ Failed'})" -ForegroundColor $(if ($registrySuccess) { 'DarkGreen' }else { 'Red' })
            Write-Host "    └─ Firewall: $(if($firewallResult.Success){'✓ Enabled'}else{'✗ Failed'})" -ForegroundColor $(if ($firewallResult.Success) { 'DarkGreen' }else { 'Red' })
        }
        else {
            Write-Host "  [✗] RDP Host - Configuration Failed" -ForegroundColor Red
            Write-Host "    └─ Registry: ✗ Failed" -ForegroundColor Red
            Write-Host "    └─ Firewall: ✗ Failed" -ForegroundColor Red
        }
        return @{
            Success         = ($registrySuccess -and $firewallResult.Success)
            Partial         = ($registrySuccess -or $firewallResult.Success)
            RegistrySuccess = $registrySuccess
            FirewallSuccess = $firewallResult.Success
            FirewallMethods = $firewallResult.Methods
        }
    }
    else {
        Write-Host "Step 3: RDP Host Configuration Skipped" -ForegroundColor Yellow
        Write-Host "  [!] Windows Edition '$WindowsEdition' does not support RDP Host" -ForegroundColor Yellow
        Write-Host "      Supported editions: Professional, Enterprise, Education" -ForegroundColor DarkYellow
        return @{
            Success      = $false
            Partial      = $false
            NotSupported = $true
        }
    }
}
function Disable-RDPHost {
    param([string]$WindowsEdition)
    $supportedEditions = @('Professional', 'Enterprise', 'Education')
    if ($supportedEditions -contains $WindowsEdition) {
        Write-Host "Step 3: Disabling RDP Host..." -ForegroundColor Yellow
        $regState = Get-RDPRegistryState
        $fwState = Get-RDPFirewallState
        if (-not $regState -and -not $fwState) {
            Write-Host "  [i] RDP Host - Already Fully Disabled" -ForegroundColor Cyan
            return @{
                Success         = $true
                Partial         = $false
                RegistrySuccess = $true
                FirewallSuccess = $true
                FirewallMethods = "Already disabled"
            }
        }
        Write-Host "  Configuring RDP registry settings..." -ForegroundColor DarkYellow
        $tsPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $rdpTcpPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $regResult1 = Set-RegistryValue -Path $tsPath -Name 'fDenyTSConnections' -Value 1
        $regResult2 = Set-RegistryValue -Path $rdpTcpPath -Name 'UserAuthentication' -Value 0
        $registrySuccess = $regResult1 -and $regResult2
        if ($registrySuccess) {
            Write-Host "    ✓ Registry settings configured (disabled)" -ForegroundColor DarkGreen
        }
        else {
            Write-Host "    ✗ Registry settings failed" -ForegroundColor DarkRed
        }
        $firewallResult = Disable-RDPFirewall
        if ($registrySuccess -and $firewallResult.Success) {
            Write-Host "  [✓] RDP Host - Fully Disabled" -ForegroundColor Green
            Write-Host "    └─ Registry: ✓ Configured (disabled)" -ForegroundColor DarkGreen
            Write-Host "    └─ Firewall: ✓ Disabled ($($firewallResult.Methods))" -ForegroundColor DarkGreen
        }
        elseif ($registrySuccess -or $firewallResult.Success) {
            Write-Host "  [⚠] RDP Host - Partially Disabled" -ForegroundColor Yellow
            Write-Host "    └─ Registry: $(if($registrySuccess){'✓ Configured'}else{'✗ Failed'})" -ForegroundColor $(if ($registrySuccess) { 'DarkGreen' }else { 'Red' })
            Write-Host "    └─ Firewall: $(if($firewallResult.Success){'✓ Disabled'}else{'✗ Failed'})" -ForegroundColor $(if ($firewallResult.Success) { 'DarkGreen' }else { 'Red' })
        }
        else {
            Write-Host "  [✗] RDP Host - Disable Operation Failed" -ForegroundColor Red
            Write-Host "    └─ Registry: ✗ Failed" -ForegroundColor Red
            Write-Host "    └─ Firewall: ✗ Failed" -ForegroundColor Red
        }
        return @{
            Success         = ($registrySuccess -and $firewallResult.Success)
            Partial         = ($registrySuccess -or $firewallResult.Success)
            RegistrySuccess = $registrySuccess
            FirewallSuccess = $firewallResult.Success
            FirewallMethods = $firewallResult.Methods
        }
    }
    else {
        Write-Host "Step 3: RDP Host Disable Operation Skipped" -ForegroundColor Yellow
        Write-Host "  [!] Windows Edition '$WindowsEdition' does not support RDP Host" -ForegroundColor Yellow
        Write-Host "      Supported editions: Professional, Enterprise, Education" -ForegroundColor DarkYellow
        return @{
            Success      = $false
            Partial      = $false
            NotSupported = $true
        }
    }
}
function Restore-ConfigurationChanges {
    Write-Host "`nStarting configuration rollback..." -ForegroundColor Yellow
    Write-Host "Backup created: $($Script:ConfigBackup.BackupTimestamp)" -ForegroundColor Cyan
    $rollbackSuccess = $true
    Write-Host "`nStep 1: Restoring registry settings..." -ForegroundColor Yellow
    foreach ($regKey in $Script:ConfigBackup.Registry.Keys) {
        try {
            $name = Split-Path -Path $regKey -Leaf
            $path = Split-Path -Path $regKey -Parent
            $backupInfo = $Script:ConfigBackup.Registry[$regKey]
            if ($backupInfo.ContainsKey('PathExisted') -and -not $backupInfo.PathExisted) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                    Write-Host "  ✓ Removed registry path: $path" -ForegroundColor DarkGreen
                }
            }
            elseif ($backupInfo.Existed) {
                if (Test-Path $path) {
                    Set-ItemProperty -Path $path -Name $name -Value $backupInfo.Value -ErrorAction Stop
                    Write-Host "  ✓ Restored: $regKey = $($backupInfo.Value)" -ForegroundColor DarkGreen
                }
            }
            else {
                if (Test-Path $path) {
                    Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
                    Write-Host "  ✓ Removed: $regKey" -ForegroundColor DarkGreen
                }
            }
        }
        catch {
            Write-Host "  ✗ Failed to restore ${regKey}: $($_.Exception.Message)" -ForegroundColor Red
            $rollbackSuccess = $false
        }
    }
    Write-Host "`nStep 2: Restoring firewall rules..." -ForegroundColor Yellow
    foreach ($ruleName in $Script:ConfigBackup.CreatedRules) {
        try {
            $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            if ($rule) {
                Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
                Write-Host "  ✓ Removed custom rule: $($rule.DisplayName)" -ForegroundColor DarkGreen
            }
        }
        catch {
            Write-Host "  ✗ Failed to remove rule ${ruleName}: $($_.Exception.Message)" -ForegroundColor Red
            $rollbackSuccess = $false
        }
    }
    foreach ($ruleName in $Script:ConfigBackup.FirewallRules.Keys) {
        try {
            $backupInfo = $Script:ConfigBackup.FirewallRules[$ruleName]
            $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            if ($rule -and $backupInfo.Existed) {
                if ($backupInfo.Enabled -eq 'False') {
                    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop
                    Write-Host "  ✓ Disabled rule: $($rule.DisplayName)" -ForegroundColor DarkGreen
                }
                else {
                    Enable-NetFirewallRule -InputObject $rule -ErrorAction Stop
                    Write-Host "  ✓ Enabled rule: $($rule.DisplayName)" -ForegroundColor DarkGreen
                }
            }
        }
        catch {
            Write-Host "  ✗ Failed to restore rule ${ruleName}: $($_.Exception.Message)" -ForegroundColor Red
            $rollbackSuccess = $false
        }
    }
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "ROLLBACK SUMMARY" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    if ($rollbackSuccess) {
        Write-Host "✓ Configuration successfully restored to original state" -ForegroundColor Green
        Write-Host "  Registry entries: Restored" -ForegroundColor Green
        Write-Host "  Firewall rules: Restored" -ForegroundColor Green
        Write-Host "  Custom rules: Removed" -ForegroundColor Green
    }
    else {
        Write-Host "⚠ Rollback completed with some errors" -ForegroundColor Yellow
        Write-Host "  Some settings may not have been fully restored" -ForegroundColor Yellow
        Write-Host "  Check the output above for details" -ForegroundColor Yellow
    }
    Write-Host "================================================" -ForegroundColor Cyan
    $Script:ConfigBackup = @{
        Registry        = @{}
        FirewallRules   = @{}
        CreatedRules    = @()
        BackupTimestamp = $null
    }
}
function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "     RDP & Remote Assistance Configuration" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Windows Edition: $(Get-WindowsEditionWMI)" -ForegroundColor Yellow
        Write-Host "Current Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "Select an action:" -ForegroundColor White
        Write-Host ""
        Write-Host "  1. Enable RDP Host and Remote Assistance" -ForegroundColor Green
        Write-Host "  2. Disable RDP Host and Remote Assistance" -ForegroundColor Red
        Write-Host "  3. Enable Remote Assistance only" -ForegroundColor Yellow
        Write-Host "  4. Disable Remote Assistance only" -ForegroundColor Yellow
        Write-Host "  5. Enable RDP Host only" -ForegroundColor Yellow
        Write-Host "  6. Disable RDP Host only" -ForegroundColor Yellow
        Write-Host "  7. Rollback all changes" -ForegroundColor Magenta
        Write-Host "  0. Exit" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Cyan
        $choice = Read-Host "Enter your choice (0-7)"
        switch ($choice) {
            "1" { 
                Write-Host "`nEnabling RDP Host and Remote Assistance..." -ForegroundColor Cyan
                Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
                Write-Host ""
                $WindowsEdition = Get-WindowsEditionWMI
                Write-Host "Step 2: Windows Edition Detection" -ForegroundColor Yellow
                Write-Host "  Detected: $WindowsEdition" -ForegroundColor Cyan
                Write-Host ""
                $raSuccess = Enable-RemoteAssistance
                Write-Host ""
                $rdpResult = Enable-RDPHost -WindowsEdition $WindowsEdition
                Show-ConfigurationSummary -RASuccess $raSuccess -RDPResult $rdpResult -WindowsEdition $WindowsEdition
                Read-Host "`nPress Enter to continue..."
            }
            "2" { 
                Write-Host "`nDisabling RDP Host and Remote Assistance..." -ForegroundColor Cyan
                Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
                Write-Host ""
                $WindowsEdition = Get-WindowsEditionWMI
                Write-Host "Step 2: Windows Edition Detection" -ForegroundColor Yellow
                Write-Host "  Detected: $WindowsEdition" -ForegroundColor Cyan
                Write-Host ""
                $raSuccess = Disable-RemoteAssistance
                Write-Host ""
                $rdpResult = Disable-RDPHost -WindowsEdition $WindowsEdition
                Show-ConfigurationSummary -RASuccess $raSuccess -RDPResult $rdpResult -WindowsEdition $WindowsEdition -DisableMode
                Read-Host "`nPress Enter to continue..."
            }
            "3" { 
                Write-Host "`nEnabling Remote Assistance only..." -ForegroundColor Cyan
                $raSuccess = Enable-RemoteAssistance
                Write-Host "`n✓ Operation completed" -ForegroundColor Green
                Read-Host "`nPress Enter to continue..."
            }
            "4" { 
                Write-Host "`nDisabling Remote Assistance only..." -ForegroundColor Cyan
                $raSuccess = Disable-RemoteAssistance
                Write-Host "`n✓ Operation completed" -ForegroundColor Green
                Read-Host "`nPress Enter to continue..."
            }
            "5" { 
                Write-Host "`nEnabling RDP Host only..." -ForegroundColor Cyan
                $WindowsEdition = Get-WindowsEditionWMI
                Write-Host "Windows Edition: $WindowsEdition" -ForegroundColor Cyan
                Write-Host ""
                $rdpResult = Enable-RDPHost -WindowsEdition $WindowsEdition
                Write-Host "`n✓ Operation completed" -ForegroundColor Green
                Read-Host "`nPress Enter to continue..."
            }
            "6" { 
                Write-Host "`nDisabling RDP Host only..." -ForegroundColor Cyan
                $WindowsEdition = Get-WindowsEditionWMI
                Write-Host "Windows Edition: $WindowsEdition" -ForegroundColor Cyan
                Write-Host ""
                $rdpResult = Disable-RDPHost -WindowsEdition $WindowsEdition
                Write-Host "`n✓ Operation completed" -ForegroundColor Green
                Read-Host "`nPress Enter to continue..."
            }
            "7" { 
                Write-Host "`nRollback Configuration..." -ForegroundColor Magenta
                if ($Script:ConfigBackup.BackupTimestamp) {
                    Restore-ConfigurationChanges
                }
                else {
                    Write-Host "No backup found in memory." -ForegroundColor Red
                }
                Read-Host "`nPress Enter to continue..."
            }
            "0" { 
                Write-Host "`nExiting..." -ForegroundColor DarkGray
                return 
            }
            default { 
                Write-Host "`nInvalid choice. Please select a number from 0-7." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}
function Show-ConfigurationSummary {
    param(
        [bool]$RASuccess,
        [hashtable]$RDPResult,
        [string]$WindowsEdition,
        [switch]$DisableMode
    )
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "CONFIGURATION SUMMARY" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    $actionWord = if ($DisableMode) { "DISABLED" } else { "ENABLED" }
    Write-Host "Remote Assistance: $(if($RASuccess){"✓ $actionWord"}else{'✗ FAILED'})" -ForegroundColor $(if ($RASuccess) { 'Green' }else { 'Red' })
    if ($RDPResult.NotSupported) {
        Write-Host "RDP Host:          ⚠ NOT SUPPORTED" -ForegroundColor Yellow
    }
    else {
        if ($RDPResult.Success) {
            Write-Host "RDP Host:          ✓ $actionWord" -ForegroundColor Green
        }
        elseif ($RDPResult.Partial) {
            Write-Host "RDP Host:          ⚠ PARTIAL" -ForegroundColor Yellow
        }
        else {
            Write-Host "RDP Host:          ✗ FAILED" -ForegroundColor Red
        }
    }
    Write-Host "================================================" -ForegroundColor Cyan
}

if ($Help) {
    Write-Host @"
RDP and Remote Assistance Configuration Script
==============================================
Usage:
  .\$($MyInvocation.MyCommand.Name)                     # Show interactive menu
  .\$($MyInvocation.MyCommand.Name) -Interactive        # Show interactive menu
  .\$($MyInvocation.MyCommand.Name) -Enable             # Enable both RDP Host and Remote Assistance
  .\$($MyInvocation.MyCommand.Name) -Disable            # Disable both RDP Host and Remote Assistance
  .\$($MyInvocation.MyCommand.Name) -EnableRA           # Enable Remote Assistance only
  .\$($MyInvocation.MyCommand.Name) -DisableRA          # Disable Remote Assistance only
  .\$($MyInvocation.MyCommand.Name) -EnableRDP          # Enable RDP Host only
  .\$($MyInvocation.MyCommand.Name) -DisableRDP         # Disable RDP Host only
  .\$($MyInvocation.MyCommand.Name) -Rollback           # Rollback all changes made by this script
  .\$($MyInvocation.MyCommand.Name) -Help               # Show this help
Examples:
  .\$($MyInvocation.MyCommand.Name) -EnableRDP
  .\$($MyInvocation.MyCommand.Name) -DisableRA
"@ -ForegroundColor Cyan
    return
}
if ($Rollback) {
    if ($Script:ConfigBackup.BackupTimestamp) {
        Restore-ConfigurationChanges
    }
    else {
        Write-Host "No backup found in memory. Cannot perform rollback." -ForegroundColor Red
    }
    return
}
if (-not ($Enable -or $Disable -or $EnableRA -or $DisableRA -or $EnableRDP -or $DisableRDP) -or $Interactive) {
    Show-InteractiveMenu
    return
}
$WindowsEdition = Get-WindowsEditionWMI
if ($Enable) {
    Write-Host "Enabling RDP Host and Remote Assistance..." -ForegroundColor Cyan
    Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "Step 2: Windows Edition Detection" -ForegroundColor Yellow
    Write-Host "  Detected: $WindowsEdition" -ForegroundColor Cyan
    Write-Host ""
    $raSuccess = Enable-RemoteAssistance
    Write-Host ""
    $rdpResult = Enable-RDPHost -WindowsEdition $WindowsEdition
    Show-ConfigurationSummary -RASuccess $raSuccess -RDPResult $rdpResult -WindowsEdition $WindowsEdition
}
elseif ($Disable) {
    Write-Host "Disabling RDP Host and Remote Assistance..." -ForegroundColor Cyan
    Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "Step 2: Windows Edition Detection" -ForegroundColor Yellow
    Write-Host "  Detected: $WindowsEdition" -ForegroundColor Cyan
    Write-Host ""
    $raSuccess = Disable-RemoteAssistance
    Write-Host ""
    $rdpResult = Disable-RDPHost -WindowsEdition $WindowsEdition
    Show-ConfigurationSummary -RASuccess $raSuccess -RDPResult $rdpResult -WindowsEdition $WindowsEdition -DisableMode
}
elseif ($EnableRA) {
    Write-Host "Enabling Remote Assistance only..." -ForegroundColor Cyan
    Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
    Write-Host ""
    $raSuccess = Enable-RemoteAssistance
}
elseif ($DisableRA) {
    Write-Host "Disabling Remote Assistance only..." -ForegroundColor Cyan
    Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
    Write-Host ""
    $raSuccess = Disable-RemoteAssistance
}
elseif ($EnableRDP) {
    Write-Host "Enabling RDP Host only..." -ForegroundColor Cyan
    Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "Step 2: Windows Edition Detection" -ForegroundColor Yellow
    Write-Host "  Detected: $WindowsEdition" -ForegroundColor Cyan
    Write-Host ""
    $rdpResult = Enable-RDPHost -WindowsEdition $WindowsEdition
}
elseif ($DisableRDP) {
    Write-Host "Disabling RDP Host only..." -ForegroundColor Cyan
    Write-Host "Creating configuration backup..." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "Step 2: Windows Edition Detection" -ForegroundColor Yellow
    Write-Host "  Detected: $WindowsEdition" -ForegroundColor Cyan
    Write-Host ""
    $rdpResult = Disable-RDPHost -WindowsEdition $WindowsEdition
}
if ($Script:ConfigBackup.BackupTimestamp) {
    Write-Host ""
    Write-Host "To rollback all changes run:" -ForegroundColor Yellow  
    Write-Host "  .\$($MyInvocation.MyCommand.Name) -Rollback" -ForegroundColor Gray
}