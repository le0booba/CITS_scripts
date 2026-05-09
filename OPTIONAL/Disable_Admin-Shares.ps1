Clear-Host

function Write-Info {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

function Write-OK {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Host "✅  $Message" -ForegroundColor Green
}

function Write-Warn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Err {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Host "❌  $Message" -ForegroundColor Red
}

function Write-Section {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Text,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Color
    )
    Write-Host $Text -ForegroundColor $Color
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err -Message "The script must be run as administrator."
    exit 1
}

Write-Section -Text "`n===== START =====`n" -Color Blue
Write-OK -Message "Execution as administrator confirmed."

do {
    $action = Read-Host "Press [1] to Disable admin shares, [2] to Restore them"
    if ($action -notin @('1', '2')) {
        Write-Warn -Message "Invalid input. Please enter 1 or 2."
    }
} while ($action -notin @('1', '2'))

$isRestore = ($action -eq '2')

$adminShares = @('C$', 'D$', 'ADMIN$')
$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$regValueNames = @('AutoShareWks', 'AutoShareServer', 'NoAdminShares')
$svcName = 'lanmanserver'

function Set-RegValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$Value
    )

    try {
        $setParams = @{
            Path        = $Path
            Name        = $Name
            Value       = $Value
            Force       = $true
            ErrorAction = 'Stop'
        }
        Set-ItemProperty @setParams
        Write-OK -Message "$Name = $Value"
    }
    catch {
        Write-Warn -Message "Failed to set $Name (possibly already set or insufficient permissions)."
    }
}

function Remove-RegValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    try {
        $removeParams = @{
            Path        = $Path
            Name        = $Name
            ErrorAction = 'Stop'
        }
        Remove-ItemProperty @removeParams
        Write-OK -Message "$Name removed"
    }
    catch {
        Write-Warn -Message "Failed to remove $Name or it does not exist."
    }
}

$hasSmbShare = [bool](Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue)

if ($isRestore) {
    Write-Info -Message "Restoring automatic creation of administrative shares..."
    foreach ($name in $regValueNames) {
        Remove-RegValue -Path $regPath -Name $name
    }
}
else {
    Write-Info -Message "Disabling automatic creation of administrative shares..."
    $regSettings = [ordered]@{
        AutoShareWks    = 0
        AutoShareServer = 0
        NoAdminShares   = 1
    }

    foreach ($kvp in $regSettings.GetEnumerator()) {
        Set-RegValue -Path $regPath -Name $kvp.Key -Value $kvp.Value
    }

    foreach ($shareName in $adminShares) {
        Write-Info -Message "Processing potential share $shareName..."
        $shareObject = if ($hasSmbShare) {
            Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        }
        else {
            Get-CimInstance -ClassName Win32_Share -Filter "Name='$shareName'" -ErrorAction SilentlyContinue
        }

        if (-not $shareObject) {
            Write-OK -Message "Share $shareName already does not exist."
            continue
        }

        if ($hasSmbShare) {
            try {
                Remove-SmbShare -Name $shareName -Force -Confirm:$false -ErrorAction Stop
                Write-OK -Message "Share $shareName removed via Remove-SmbShare."
                continue
            }
            catch {
            }
        }

        net share $shareName /delete 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK -Message "Share $shareName removed via net share."
        }
        else {
            Write-Info -Message "System share $shareName will be automatically removed after LanmanServer service restart."
        }
    }
}

function Restart-LanManServer {
    [CmdletBinding()]
    param()

    Write-Info -Message "Restarting LanmanServer service..."
    $canUseRestartService = [bool](Get-Command -Name Restart-Service -ErrorAction SilentlyContinue)

    if ($canUseRestartService) {
        try {
            Restart-Service -Name $svcName -Force -ErrorAction Stop
            Write-OK -Message "Service $svcName successfully restarted (Restart-Service)."
            return
        }
        catch {
            Write-Warn -Message "Restart-Service failed to restart ${svcName}: ${_}"
        }
    }

    try {
        sc.exe stop $svcName | Out-Null
        Start-Sleep -Seconds 2
        sc.exe start $svcName | Out-Null
        Write-OK -Message "Service $svcName successfully restarted (sc.exe)."
    }
    catch {
        Write-Err -Message "Failed to restart service $svcName. A full system reboot is recommended."
    }
}

Restart-LanManServer

Write-Section -Text "`n===== REPORT =====" -Color Cyan
Write-Host "`n1. Registry state (auto-sharing parameters):"
try {
    Get-ItemProperty -Path $regPath -Name $regValueNames -ErrorAction Stop | Format-List | Out-Host
}
catch {
    Write-Warn -Message "Registry values not found (they may have been removed to restore defaults)."
}

Write-Host "2. Current SMB shares (after service restart):"
if ($hasSmbShare) {
    Get-SmbShare | Format-Table Name, ShareType, Path -AutoSize
}
else {
    cmd.exe /c "net share" | Out-Host
}

Write-Host "`n3. LanmanServer service status:"
Get-Service -Name $svcName | Format-Table Name, Status, StartType -AutoSize

if ($isRestore) {
    Write-Host "`n✅  Administrative shares restoration completed."
}
else {
    Write-Host "`n✅  Administrative shares disabling completed."
    Write-Host "`nIf administrative shares still appear after service restart (or full reboot), check:" -ForegroundColor DarkGray
    Write-Host "  • Group Policy setting *Enable administrative shares* (should be Not Configured/Disabled)." -ForegroundColor DarkGray
    Write-Host "  • Duplicate registry entries (policy might override them at boot)." -ForegroundColor DarkGray
}

Write-Section -Text "`n===== END =====`n" -Color Blue