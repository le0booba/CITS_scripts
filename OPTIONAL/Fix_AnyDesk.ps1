Clear-Host

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warning 'This script requires ADMIN permissions. Please, run it as Administrator'
    Write-Host 'Press any key to exit...'
    [void]$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

Add-Type -AssemblyName System.Windows.Forms

function Generate-SecurePassword {
    param(
        [int]$PasswordLength = 9,
        [switch]$IncludeCapitalLetters,
        [switch]$IncludeNumbers,
        [switch]$IncludeSpecialCharacters
    )

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
        @("b" , ($pwgen_CONSONANT))
        @("c" , ($pwgen_CONSONANT))
        @("ch", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG)),
        @("d" , ($pwgen_CONSONANT))
        @("e" , ($pwgen_VOWEL))
        @("ee", ($pwgen_VOWEL -bor $pwgen_DIPTHONG))
        @("ei", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("f" , ($pwgen_CONSONANT))
        @("g" , ($pwgen_CONSONANT))
        @("gh", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG -bor $pwgen_NOT_FIRST)),
        @("h" , ($pwgen_CONSONANT))
        @("i" , ($pwgen_VOWEL))
        @("ie", ($pwgen_VOWEL -bor $pwgen_DIPTHONG))
        @("j" , ($pwgen_CONSONANT))
        @("k" , ($pwgen_CONSONANT))
        #@("l" , ($pwgen_CONSONANT)),
        @("m" , ($pwgen_CONSONANT))
        @("n" , ($pwgen_CONSONANT))
        @("ng", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG -bor $pwgen_NOT_FIRST))
        #@("o" , ($pwgen_VOWEL)),
        #@("oh", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        #@("oo", ($pwgen_VOWEL -bor $pwgen_DIPTHONG)),
        @("p" , ($pwgen_CONSONANT))
        @("ph", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG))
        @("qu", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG))
        @("r" , ($pwgen_CONSONANT))
        @("s" , ($pwgen_CONSONANT))
        @("sh", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG))
        @("t" , ($pwgen_CONSONANT))
        @("th", ($pwgen_CONSONANT -bor $pwgen_DIPTHONG))
        @("u" , ($pwgen_VOWEL))
        @("v" , ($pwgen_CONSONANT))
        @("w" , ($pwgen_CONSONANT))
        @("x" , ($pwgen_CONSONANT))
        @("y" , ($pwgen_CONSONANT))
        @("z" , ($pwgen_CONSONAN))
    )

    function pwgen_generate {
      param(
        [int]$pwlen,
        [bool]$inc_capital,
        [bool]$inc_number,
        [bool]$inc_spec
      )
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

  pwgen_generate -pwlen $PasswordLength -inc_capital:$IncludeCapitalLetters -inc_number:$IncludeNumbers -inc_spec:$IncludeSpecialCharacters
}

$processName = 'AnyDesk'
$pathAppData = Join-Path -Path $env:APPDATA -ChildPath 'AnyDesk'
$pathProgramFiles = Join-Path -Path "$env:ProgramFiles(x86)" -ChildPath 'AnyDesk\AnyDesk.exe'
$pathProgramData = Join-Path -Path $env:ProgramData -ChildPath 'AnyDesk\AnyDesk.exe'
$distAD = Join-Path -Path $PSScriptRoot -ChildPath 'AnyDesk.exe'
$pathAppDataRoaming = Join-Path -Path $env:APPDATA -ChildPath 'AnyDesk'

function Stop-AnyDeskProcess {
    [CmdletBinding()]
    param()

    try {
        Get-Process -Name $processName -ErrorAction Stop | Stop-Process -Force
        Write-Host "Process '$processName' terminated."
    }
    catch {
        Write-Host "Process '$processName' not found or could not be terminated."
    }
}

function Uninstall-App {
    param (
        [string]$Path,
        [string]$Description
    )
    if (Test-Path -Path $Path) {
        try {
            Start-Process -FilePath $Path -ArgumentList '--silent', '--remove' -Wait
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
        try {
            Remove-Item -Path $Path -Recurse -Force
            Write-Host "Folder '$Description' removed."
        } catch {
            Write-Warning "Error removing folder '$Description': $($_.Exception.Message)"
        }
    } else {
        Write-Host "Folder '$Description' not found."
    }
}

function Install-AnyDesk {
    if (Test-Path -Path $distAD) {
        try {
            Start-Process -FilePath $distAD -ArgumentList '--install "C:\ProgramData\AnyDesk"', '--start-with-win', '--create-shortcuts', '--create-desktop-icon' -Wait
            Write-Host 'AnyDesk installed successfully.'
            return $true
        } catch {
            Write-Warning "Error installing AnyDesk: $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Host 'AnyDesk installer not found in script folder.' -ForegroundColor DarkYellow
        return $false
    }
}

function Remove-AnyDeskFolders {
    $folders = @(
        Join-Path -Path $env:ProgramData -ChildPath 'AnyDesk'
        Join-Path -Path "$env:ProgramFiles(x86)" -ChildPath 'AnyDesk'
        Join-Path -Path $env:ProgramFiles -ChildPath 'AnyDesk'
        $pathAppDataRoaming
    )
    foreach ($folder in $folders) {
        Remove-Folder -Path $folder -Description $folder
    }
}

function Get-AnyDeskInfo {
    $executablePath = if (Test-Path $pathProgramData) {
        $pathProgramData
    } elseif (Test-Path $pathProgramFiles) {
        $pathProgramFiles
    } else {
        Write-Warning 'AnyDesk executable not found.'
        return $null
    }
    try {
        $status = (& $executablePath --get-status 2>&1 | Out-String).Trim()
        $id = (& $executablePath --get-id 2>&1 | Out-String).Trim()
    } catch {
        Write-Warning "Failed to get AnyDesk information. $($_.Exception.Message)"
        return $null
    }
    return @{ Status = $status; ID = $id }
}

function Display-AnyDeskStatus {
    param (
        [Hashtable]$StatusInfo
    )
    if ($StatusInfo) {
        if ($StatusInfo.ID) {
            Write-Host "AnyDesk ID: $($StatusInfo.ID)" -ForegroundColor Blue
            Write-Host "AnyDesk status: $($StatusInfo.Status)" -ForegroundColor Blue
        }
    } else {
        Write-Host 'Failed to get AnyDesk status.' -ForegroundColor Red
    }
}

Stop-AnyDeskProcess
Start-Sleep -Seconds 2
Remove-Folder -Path $pathAppData -Description "AnyDesk in AppData\Roaming"
Start-Sleep -Seconds 2
Uninstall-App -Path $pathProgramFiles -Description 'Program Files (x86)'
Start-Sleep -Seconds 3
Uninstall-App -Path $pathProgramData -Description 'ProgramData'
Start-Sleep -Seconds 3
Remove-AnyDeskFolders
Start-Sleep -Seconds 5
Write-Host 'Waiting a few seconds and starting AnyDesk installation...'
Start-Sleep -Seconds 5

$isInstalled = Install-AnyDesk

if ($isInstalled) {
    Write-Host 'Waiting a couple of seconds after AnyDesk installation...'
    Start-Sleep -Seconds 10
    $statusInfo = Get-AnyDeskInfo
    if ($statusInfo) {
        Display-AnyDeskStatus -StatusInfo $statusInfo
        "AnyDesk ID:" | Out-File -FilePath "$PSScriptRoot\fix_AD.txt" -Encoding UTF8
        $statusInfo.ID | Out-File -FilePath "$PSScriptRoot\fix_AD.txt" -Append -Encoding UTF8
        Write-Host "AnyDesk ID ($($statusInfo.ID)) has been written to $PSScriptRoot\fix_AD.txt"
        $result = [System.Windows.Forms.MessageBox]::Show('Set password for AnyDesk?', '', 'YesNo', 'Question')
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $pathAD = Join-Path -Path $env:ProgramData -ChildPath 'AnyDesk\AnyDesk.exe'
            $pass = Generate-SecurePassword  -IncludeCapitalLetters -IncludeNumbers -IncludeSpecialCharacters
            $pass | & $pathAD --set-password
            Add-Content -Path "$PSScriptRoot\fix_AD.txt" -Value 'AnyDesk password:'
            Add-Content -Path "$PSScriptRoot\fix_AD.txt" -Value "$pass" -NoNewline
            Write-Host "`nAnyDesk password is:`n"
            Write-Host "$pass" -ForegroundColor DarkRed
            Write-Host "`nit is also saved here: '$PSScriptRoot\fix_AD.txt'`n"
        }
    }
} else {
    Write-Host 'AnyDesk installation failed. Skipping status retrieval.' -ForegroundColor DarkGray
}