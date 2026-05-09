function Get-WindowsProductKey {
    try {
        $wmi = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        if ($wmi) {
            $key = $wmi.OA3xOriginalProductKey
            if ($key) {
                Write-Host "Found Product Key (from WMI): $key" -ForegroundColor Green
                return $key
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve key via WMI: $($_.Exception.Message)"
    }

    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
        $regValue = Get-ItemProperty -Path $regPath -Name "BackupProductKeyDefault" -ErrorAction Stop
        if ($regValue.BackupProductKeyDefault) {
            Write-Host "Found Product Key (from registry): $($regValue.BackupProductKeyDefault)" -ForegroundColor Green
            return $regValue.BackupProductKeyDefault
        }
    }
    catch {
        Write-Warning "Failed to retrieve key from registry: $($_.Exception.Message)"
    }

    try {
        $regPath2 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DefaultProductKey"
        if (Test-Path $regPath2) {
            $regValue2 = Get-ItemProperty -Path $regPath2 -ErrorAction Stop
            if ($regValue2.DefaultProductKey) {
                Write-Host "Found alternative Product Key: $($regValue2.DefaultProductKey)" -ForegroundColor Yellow
                return $regValue2.DefaultProductKey
            }
        }
    }
    catch {
        Write-Warning "Alternative method did not yield results: $($_.Exception.Message)"
    }

    Write-Host "Product Key not found in the system." -ForegroundColor Red
    return $null
}

function Get-UniqueFilePath {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        return $FilePath
    }

    $directory = Split-Path $FilePath -Parent
    $fileNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $extension = [System.IO.Path]::GetExtension($FilePath)
    $counter = 1

    do {
        $newFilePath = Join-Path $directory "$fileNameWithoutExt`_$counter$extension"
        $counter++
    } while (Test-Path $newFilePath)

    return $newFilePath
}

function Get-ValidatedFilePath {
    while ($true) {
        Write-Host "Enter file path or name for saving." -ForegroundColor Gray
        Write-Host "Example: mykey  or  C:\Users\User\Desktop\mykey" -ForegroundColor Gray
        Write-Host "The .txt extension will be added automatically." -ForegroundColor Gray
        Write-Host ""
        $inputPath = Read-Host "File path (Press Enter for automatic name)"

        if ([string]::IsNullOrWhiteSpace($inputPath)) {
            $autoName = "Windows_Product_Key_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            return Join-Path (Get-Location) $autoName
        }

        if ($inputPath.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) {
            Write-Host "Error: The file path contains invalid characters. Please try again." -ForegroundColor Red
            Write-Host ""
            continue
        }

        $folderPath = Split-Path $inputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($folderPath) -and -not (Test-Path $folderPath)) {
            Write-Host "Error: The specified directory does not exist: $folderPath. Please try again." -ForegroundColor Red
            Write-Host ""
            continue
        }

        $fileNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($inputPath)

        if ([string]::IsNullOrWhiteSpace($fileNameWithoutExt)) {
            Write-Host "Error: The file name cannot be empty. Please try again." -ForegroundColor Red
            Write-Host ""
            continue
        }

        if ($fileNameWithoutExt.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            Write-Host "Error: The file name contains invalid characters. Please try again." -ForegroundColor Red
            Write-Host ""
            continue
        }

        if ([string]::IsNullOrWhiteSpace($folderPath)) {
            $folderPath = Get-Location
        }

        return Join-Path $folderPath "$fileNameWithoutExt.txt"
    }
}

function Export-ProductKeyToFile {
    $FilePath = Get-ValidatedFilePath
    $FilePath = Get-UniqueFilePath -FilePath $FilePath

    $productKey = Get-WindowsProductKey

    if ($productKey) {
        $content = @"
Windows Product Key Information
==============================
Export Date: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')
Computer: $env:COMPUTERNAME
User: $env:USERNAME
OS Type: $([System.Environment]::OSVersion.VersionString)
Product Key: $productKey

Note: This key may be an OEM key or digital license without a visible product key.
"@

        try {
            $content | Out-File -FilePath $FilePath -Encoding UTF8 -Force
            Write-Host "Product Key successfully exported to file: $FilePath" -ForegroundColor Green

            $folderPath = Split-Path $FilePath -Parent
            if ([string]::IsNullOrWhiteSpace($folderPath)) {
                $folderPath = Get-Location
            }
            Invoke-Item $folderPath
        }
        catch {
            Write-Host "Error saving file: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Cannot export - Product Key not found." -ForegroundColor Red
    }
}

do {
    Clear-Host
    Write-Host "=== Windows Product Key Viewer and Export Tool ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. View Product Key" -ForegroundColor White
    Write-Host "2. Export Product Key to File" -ForegroundColor White
    Write-Host "Q. Exit" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "Choose action (1-2, Q)"

    switch ($choice) {
        '1' {
            Clear-Host
            Write-Host "Searching for Product Key..." -ForegroundColor Yellow
            Get-WindowsProductKey | Out-Null
            Write-Host ""
            Read-Host "Press Enter to continue..."
        }
        '2' {
            Clear-Host
            Write-Host "Exporting Product Key..." -ForegroundColor Yellow
            Write-Host ""
            Export-ProductKeyToFile
            Write-Host ""
            Read-Host "Press Enter to continue..."
        }
        'q' {
            Write-Host "Exiting program." -ForegroundColor Green
            break
        }
        default {
            Write-Host "Invalid choice. Please select 1-2 or Q." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -ne 'q')