Clear-Host

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warning 'This script requires ADMIN permissions. Please, run it as Administrator'
    Write-Host 'Press any key to exit...'
    [void]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

Add-Type -AssemblyName System.Windows.Forms

function Invoke-RobustDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$OutFile,
        [string]$DisplayName,
        [int]$TimeoutSeconds = 60
    )
    
    if (-not $DisplayName) {
        $DisplayName = (Split-Path $OutFile -Leaf)
    }

    try {
        Import-Module BitsTransfer -ErrorAction Stop
        
        Write-Host "Starting reliable download for '$DisplayName' using BITS..."
        $bitsJob = Start-BitsTransfer -Source $Uri -Destination $OutFile -DisplayName $DisplayName -Asynchronous
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds -and $bitsJob.JobState -in ('Connecting', 'Transferring', 'TransientError')) {
            $percentComplete = [math]::Round(($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100, 2)
            $status = "Downloading $DisplayName... $percentComplete %"
            if ($bitsJob.JobState -eq 'TransientError') {
                $status += ' (Network issue, retrying...)'
            }
            Write-Progress -Activity 'Downloading Files' -Status $status -PercentComplete $percentComplete
            Start-Sleep -Seconds 1
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity 'Downloading Files' -Completed

        if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds -and $bitsJob.JobState -in ('Connecting', 'Transferring', 'TransientError')) {
            Remove-BitsTransfer -BitsJob $bitsJob
            throw "Download timed out for '$DisplayName' after $TimeoutSeconds seconds."
        }

        switch ($bitsJob.JobState) {
            'Transferred' {
                Complete-BitsTransfer -BitsJob $bitsJob
                Write-Host "Download completed: $OutFile"
            }
            'Error' {
                $errorDetails = $bitsJob | Select-Object -ExpandProperty ErrorDescription
                Resume-BitsTransfer -BitsJob $bitsJob | Out-Null
                Remove-BitsTransfer -BitsJob $bitsJob
                throw "BITS download failed for '$DisplayName': $errorDetails"
            }
            default {
                Remove-BitsTransfer -BitsJob $bitsJob
                throw "BITS download for '$DisplayName' was cancelled or failed with state: $($bitsJob.JobState)"
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'module' -or $_.FullyQualifiedErrorId -match 'ModuleNotFound') {
            Write-Warning "BITS module not found or failed to load. System error: $($_.Exception.Message)"
        }
        else {
            Write-Warning "BITS download attempt failed. Reason: $($_.Exception.Message)"
        }
        
        Write-Host 'Falling back to robust Invoke-WebRequest method.' -ForegroundColor Gray

        try {
            Write-Host "Step 1: Getting file size for '$DisplayName'..."
            $response = Invoke-WebRequest -Uri $Uri -Method Head
            $expectedSize = $response.Headers['Content-Length']
            if (-not $expectedSize) {
                throw 'Could not determine file size from server.'
            }
            Write-Host "Expected file size: $expectedSize bytes."

            Write-Host 'Step 2: Starting download in a background job...'
            $job = Start-Job -ScriptBlock {
                param($Uri, $OutFile)
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile
            } -ArgumentList $Uri, $OutFile

            $job | Wait-Job -Timeout $TimeoutSeconds | Out-Null

            if ($job.State -eq 'Running') {
                $job | Stop-Job -PassThru | Remove-Job
                throw "Download timed out after $TimeoutSeconds seconds."
            }

            if ($job.State -ne 'Completed') {
                $errorRecord = ($job | Receive-Job)[-1]
                $job | Remove-Job
                throw "Download job failed: $($errorRecord.Exception.Message)"
            }
            
            $job | Receive-Job
            $job | Remove-Job

            Write-Host 'Step 3: Verifying file integrity...'
            $actualSize = (Get-Item -Path $OutFile).Length
            if ($actualSize -ne $expectedSize) {
                Remove-Item -Path $OutFile -Force
                throw "File integrity check failed. Expected size: $expectedSize bytes, Actual size: $actualSize bytes. The downloaded file has been deleted."
            }

            Write-Host "Download and verification successful for '$DisplayName'."
        }
        catch {
            throw "Robust download fallback failed: $($_.Exception.Message)"
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

function Repair-SystemTime {
    param([int]$Retries = 3)
    
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP" -ErrorAction SilentlyContinue
        Set-Service -Name "w32time" -StartupType Automatic -ErrorAction SilentlyContinue
        
        $svc = Get-Service -Name w32time
        if ($svc.Status -ne 'Running') {
            Start-Service -Name w32time
        }
    } catch {
        Write-Warning "Failed to configure Time Service registry/startup: $($_.Exception.Message)"
    }

    for ($i = 1; $i -le $Retries; $i++) {
        w32tm /resync /force 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host 'Time synchronization successful.'
            return $true
        }
        Start-Sleep -Seconds 1
    }
    
    Write-Warning "Time synchronization failed after $Retries attempts."
    return $false
}

$programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$appData = [Environment]::GetFolderPath('ApplicationData')

$processName = 'AnyDesk'
$pathAppDataRoaming = Join-Path -Path $appData -ChildPath 'AnyDesk'
$pathProgramData = Join-Path -Path $programData -ChildPath 'AnyDesk\AnyDesk.exe'
$distAD = Join-Path -Path $PSScriptRoot -ChildPath 'AnyDesk.exe'
$anyDeskUrl = 'https://download.anydesk.com/AnyDesk.exe'

function Stop-AnyDeskProcess {
    [CmdletBinding()]
    param()

    try {
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($processes) {
            $processes | Stop-Process -Force -ErrorAction SilentlyContinue
            $processes | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
            Write-Host "Process '$processName' terminated."
        }
    }
    catch {
        Write-Host "Process '$processName' could not be terminated: $($_.Exception.Message)"
    }
}

function Uninstall-App {
    param (
        [string]$Path,
        [string]$Description
    )
    if (Test-Path -Path $Path) {
        try {
            Start-Process -FilePath $Path -ArgumentList '--silent', '--remove' -PassThru -Wait | Out-Null
            Write-Host "AnyDesk uninstalled from '$Description'."
        } catch {
            Write-Warning "Error uninstalling AnyDesk from '$Description': $($_.Exception.Message)"
        }
    } else {
        Write-Host "AnyDesk not found for uninstallation in '$Description'."
    }
}

function Remove-Folder {
    param (
        [string]$Path,
        [string]$Description
    )
    if (Test-Path -Path $Path) {
        $maxRetries = 10
        for ($i = 0; $i -lt $maxRetries; $i++) {
            try {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Host "Folder '$Description' removed."
                return
            } catch {
                if ($i -eq $maxRetries - 1) {
                    Write-Warning "Error removing folder '$Description' after retries: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Install-AnyDesk {
    if (Test-Path -Path $distAD) {
        try {
            Start-Process -FilePath $distAD `
                          -WorkingDirectory $env:TEMP `
                          -ArgumentList '--install "C:\ProgramData\AnyDesk"', '--start-with-win', '--create-shortcuts', '--create-desktop-icon' `
                          -Wait
            
            Write-Host 'AnyDesk installed successfully.'
            return $true
        } catch {
            Write-Warning "Error installing AnyDesk: $($_.Exception.Message)"
            return $false
        }
    } else {
        return $false
    }
}

function Remove-AnyDeskFolders {
    $folders = @(
        Join-Path -Path $script:programData -ChildPath 'AnyDesk'
        Join-Path -Path $script:programFilesX86 -ChildPath 'AnyDesk'
        Join-Path -Path $script:programFiles -ChildPath 'AnyDesk'
        $script:pathAppDataRoaming
    )
    foreach ($folder in $folders) {
        Remove-Folder -Path $folder -Description $folder
    }
}

function Get-AnyDeskInfo {
    $pathsToCheck = @(
        Join-Path -Path $script:programData -ChildPath 'AnyDesk\AnyDesk.exe'
        Join-Path -Path $script:programFilesX86 -ChildPath 'AnyDesk\AnyDesk.exe'
        Join-Path -Path $script:programFiles -ChildPath 'AnyDesk\AnyDesk.exe'
    )

    $executablePath = $null
    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            $executablePath = $path
            break
        }
    }

    if (-not $executablePath) {
        Write-Warning 'AnyDesk executable not found.'
        return $null
    }

    $attemptDelay = 3
    $maxAttempts = 20 

    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $status = (& $executablePath --get-status 2>&1 | Out-String).Trim()
            $id = (& $executablePath --get-id 2>&1 | Out-String).Trim()

            if (-not [string]::IsNullOrWhiteSpace($id) -and $id -ne "0" -and $status -match 'online') {
                return @{ Status = $status; ID = $id; ExePath = $executablePath }
            } else {
                if ($status -ne 'online' -and -not [string]::IsNullOrWhiteSpace($id)) {
                    throw "AnyDesk has ID but status is '$status' (waiting for online)"
                }
                throw "AnyDesk service is not ready yet. ID: '$id', Status: '$status'"
            }
        }
        catch {
            if ($i -eq $maxAttempts) {
                Write-Warning "Failed to get AnyDesk info after 1 minute."
            } else {
                Write-Host "Waiting to obtain an ID... ($i/$maxAttempts)" -ForegroundColor Gray
                Start-Sleep -Seconds $attemptDelay
            }
        }
    }
    return $null
}

function Display-AnyDeskStatus {
    param (
        [Hashtable]$StatusInfo
    )
    if ($StatusInfo) {
        if ($StatusInfo.ID) {
            Write-Host "AnyDesk status: $($StatusInfo.Status)" -ForegroundColor Blue
            Write-Host "AnyDesk ID: $($StatusInfo.ID)" -ForegroundColor Blue
        }
    } else {
        Write-Host 'Failed to get AnyDesk status.' -ForegroundColor Red
    }
}

Stop-AnyDeskProcess

Remove-Folder -Path $pathAppDataRoaming -Description "AnyDesk in AppData\Roaming"

$pathPFX86_Exe = Join-Path -Path $programFilesX86 -ChildPath 'AnyDesk\AnyDesk.exe'
Uninstall-App -Path $pathPFX86_Exe -Description 'Program Files (x86)'

$pathPD_Exe = Join-Path -Path $programData -ChildPath 'AnyDesk\AnyDesk.exe'
Uninstall-App -Path $pathPD_Exe -Description 'ProgramData'

Remove-AnyDeskFolders

$null = Repair-SystemTime

Write-Host 'Starting AnyDesk installation...'

if (-not (Test-Path -Path $distAD)) {
    Write-Host "AnyDesk installer not found ($PSScriptRoot\). Trying to download..." -ForegroundColor Yellow
    try {
        Invoke-RobustDownload -Uri $anyDeskUrl -OutFile $distAD -DisplayName 'AnyDesk Installer'
    }
    catch {
        Write-Error "Failed to download AnyDesk: $($_.Exception.Message)"
    }
}

$isInstalled = Install-AnyDesk

if ($isInstalled) {
    $statusInfo = Get-AnyDeskInfo
    if ($statusInfo) {
        Display-AnyDeskStatus -StatusInfo $statusInfo
        "AnyDesk ID:" | Out-File -FilePath "$PSScriptRoot\fix_AD.txt" -Encoding UTF8
        $statusInfo.ID | Out-File -FilePath "$PSScriptRoot\fix_AD.txt" -Append -Encoding UTF8
        Write-Host "ID saved to file $PSScriptRoot\fix_AD.txt"
        
        if ([Environment]::UserInteractive) {
            $result = [System.Windows.Forms.MessageBox]::Show('Set password for AnyDesk?', '', 'YesNo', 'Question')
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                $pass = Generate-SecurePassword
                $pass | & $statusInfo.ExePath --set-password
                Add-Content -Path "$PSScriptRoot\fix_AD.txt" -Value 'AnyDesk password:'
                Add-Content -Path "$PSScriptRoot\fix_AD.txt" -Value "$pass" -NoNewline
                Write-Host 'AnyDesk password is:'
                Write-Host "$pass" -ForegroundColor DarkRed
                Write-Host "it is also saved here: '$PSScriptRoot\fix_AD.txt'"
            }
        } else {
            Write-Host "Non-interactive session detected. Skipping password dialog." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host 'AnyDesk installation failed. Skipping status retrieval.' -ForegroundColor DarkGray
}