<#PSScriptInfo

.VERSION 1.1.1

.GUID a4aa6d94-fe9e-41c0-8d8e-112b0c195fcb

.AUTHOR asherto

.COMPANYNAME asheroto

.TAGS PowerShell Microsoft OneDrive remove uninstall delete erase

.PROJECTURI https://github.com/asheroto/UninstallOneDrive

.RELEASENOTES
[Version 0.0.1] - Initial release.
[Version 0.0.2] - Updated description.
[Version 0.0.3] - Added to GitHub.
[Version 0.0.4] - Fixed signature.
[Version 0.0.5] - Fixed various bugs.
[Version 1.0.0] - Major refactor. Added removal of OneDrive scheduled tasks. Added Help, Version, CheckForUpdate, and UpdateSelf.
[Version 1.0.1] - Add Uninstall Complete verbiage.
[Version 1.0.2] - Fix position on Uninstall Complete verbiage.
[Version 1.1.0] - Add per-user OneDrive removal (LOCALAPPDATA and HKCU). Fix version comparison in CheckForUpdate. Fix uninstall string parsing when no arguments present. Check uninstaller exit codes. Verify removal before reporting success. Fix CheckForUpdate verbiage. Add runtime elevation check so running via irm | iex without administrator rights fails with a clear message instead of partially running.
[Version 1.1.1] - Add upfront OneDrive detection with early exit when not installed. Fix exit statements closing the console when run via irm | iex. Add multi-user support: detect OneDrive in any user profile and remove the OneDrive app folder from every profile (user data in the OneDrive folder is never touched).

#>

<#
.SYNOPSIS
    Uninstalls Microsoft OneDrive. Usage: UninstallOneDrive
.DESCRIPTION
    Uninstalls Microsoft OneDrive. Usage: UninstallOneDrive
.EXAMPLE
    UninstallOneDrive.ps1
.NOTES
    Version      : 1.1.1
    Created by   : asheroto
.LINK
    https://github.com/asheroto/UninstallOneDrive
#>
[CmdletBinding()]
param (
    [switch]$CheckForUpdate,
    [switch]$UpdateSelf,
    [switch]$Version,
    [switch]$Help
)

#Requires -RunAsAdministrator

# Version
$CurrentVersion = '1.1.1'
$RepoOwner = 'asheroto'
$RepoName = 'UninstallOneDrive'
$PowerShellGalleryName = 'UninstallOneDrive'

# Display version if -Version is specified
if ($Version.IsPresent) {
    $CurrentVersion
    exit 0
}

# Display full help if -Help is specified
if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Source -Full
    exit 0
}

# Display $PSVersionTable and Get-Host if -Verbose is specified
if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $PSVersionTable
    Get-Host
}

function Get-GitHubRelease {
    <#
        .SYNOPSIS
        Fetches the latest release information of a GitHub repository.

        .DESCRIPTION
        This function uses the GitHub API to get information about the latest release of a specified repository, including its version and the date it was published.

        .PARAMETER Owner
        The GitHub username of the repository owner.

        .PARAMETER Repo
        The name of the repository.
    #>
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        $latestVersion = $response.tag_name
        $publishedAt = $response.published_at

        # Convert UTC time string to local time
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()

        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Unable to check for updates.`nError: $_"
        exit 1
    }
}

function CheckForUpdate {
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [version]$CurrentVersion,
        [string]$PowerShellGalleryName
    )

    $Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

    Write-Output ""
    Write-Output ("Repository:       {0,-40}" -f "https://github.com/$RepoOwner/$RepoName")
    Write-Output ("Current Version:  {0,-40}" -f $CurrentVersion)
    Write-Output ("Latest Version:   {0,-40}" -f $Data.LatestVersion)
    Write-Output ("Published at:     {0,-40}" -f $Data.PublishedDateTime)

    if ([version]($Data.LatestVersion.TrimStart('v')) -gt $CurrentVersion) {
        Write-Output ("Status:           {0,-40}" -f "A new version is available.")
        Write-Output "`nOptions to update:"
        Write-Output "- Download latest release: https://github.com/$RepoOwner/$RepoName/releases"
        if ($PowerShellGalleryName) {
            Write-Output "- Run: $RepoName -UpdateSelf"
            Write-Output "- Run: Install-Script $PowerShellGalleryName -Force"
        }
    } else {
        Write-Output ("Status:           {0,-40}" -f "Up to date.")
    }
    exit 0
}

function UpdateSelf {
    try {
        # Get PSGallery version of script
        $psGalleryScriptVersion = (Find-Script -Name $PowerShellGalleryName).Version

        # If the current version is less than the PSGallery version, update the script
        if ($CurrentVersion -lt $psGalleryScriptVersion) {
            Write-Output "Updating script to version $psGalleryScriptVersion..."

            # Install NuGet PackageProvider if not already installed
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name "NuGet" -Force
            }

            # Trust the PSGallery if not already trusted
            $repo = Get-PSRepository -Name 'PSGallery'
            if ($repo.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            }

            # Update the script
            Install-Script $PowerShellGalleryName -Force

            Write-Output "Script updated to version $psGalleryScriptVersion."
            exit 0
        } else {
            Write-Output "Script is already up to date."
            exit 0
        }
    } catch {
        Write-Output "An error occurred: $_"
        exit 1
    }
}

function Uninstall-OneDrive {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        Write-Output "Uninstalling OneDrive found in $Path"
        $proc = Start-Process $Path "/uninstall" -PassThru
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) {
            Write-Warning "Uninstaller at `"$Path`" exited with code $($proc.ExitCode)."
        }
    } else {
        Write-Output "Path `"$Path`" not found, skipping..."
    }
}

function Get-UninstallString {
    param (
        [string]$DisplayName
    )
    $uninstallPaths = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            $uninstallString = Get-ChildItem -Path $path |
            Get-ItemProperty |
            Where-Object { $_.DisplayName -eq $DisplayName } |
            Select-Object -ExpandProperty UninstallString -First 1
            if ($uninstallString) {
                return $uninstallString
            }
        }
    }
    return $null
}

function Test-OneDriveInstalled {
    # Setup exes ship with Windows, so only OneDrive.exe and the registry entry indicate an actual install
    $installPaths = @(
        "$ENV:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
        "$ENV:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
        "${ENV:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
    )
    foreach ($path in $installPaths) {
        if (Test-Path $path) {
            return $true
        }
    }

    # OneDrive in any user profile (wildcards are valid in Test-Path)
    if (Test-Path (Join-Path $env:SystemDrive "Users\*\AppData\Local\Microsoft\OneDrive\OneDrive.exe") -ErrorAction SilentlyContinue) {
        return $true
    }

    return [bool](Get-UninstallString -DisplayName "Microsoft OneDrive")
}

try {
    # First heading
    Write-Output "UninstallOneDrive $CurrentVersion"

    # Check for updates if -CheckForUpdate is specified
    if ($CheckForUpdate) { CheckForUpdate -RepoOwner $RepoOwner -RepoName $RepoName -CurrentVersion $CurrentVersion -PowerShellGalleryName $PowerShellGalleryName }

    # Update the script if -UpdateSelf is specified
    if ($UpdateSelf) { UpdateSelf }

    # Runtime elevation check - #Requires is ignored when run via irm | iex
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "This script must be run as administrator. Open an elevated PowerShell window and try again."
        # exit closes the whole console under irm | iex, so only exit when running as a file
        if ($PSCommandPath) { exit 1 } else { return }
    }

    # Heading
    Write-Output "To check for updates, run UninstallOneDrive -CheckForUpdate"

    # Exit early if OneDrive is not installed
    if (-not (Test-OneDriveInstalled)) {
        Write-Output "OneDrive not detected, nothing to uninstall."
        if ($PSCommandPath) { exit 0 } else { return }
    }

    $oneDrivePaths = @(
        "$ENV:SystemRoot\System32\OneDriveSetup.exe",
        "$ENV:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$ENV:ProgramFiles\Microsoft Office\root\Integration\Addons\OneDriveSetup.exe",
        "${ENV:ProgramFiles(x86)}\Microsoft Office\root\Integration\Addons\OneDriveSetup.exe"
    )

    # Per-user installs keep OneDriveSetup.exe in a versioned folder under LOCALAPPDATA
    $perUserSetup = Get-ChildItem -Path "$ENV:LOCALAPPDATA\Microsoft\OneDrive" -Filter "OneDriveSetup.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($perUserSetup) {
        $oneDrivePaths += $perUserSetup
    }

    Write-Output "Stopping OneDrive processes..."
    Stop-Process -Name OneDrive* -Force -ErrorAction SilentlyContinue

    # Uninstall from common locations
    foreach ($path in $oneDrivePaths) {
        Uninstall-OneDrive -Path $path
    }

    # Uninstall from Uninstall registry key UninstallString
    $uninstallString = Get-UninstallString -DisplayName "Microsoft OneDrive"
    if ($uninstallString) {
        Write-Output "Uninstalling OneDrive found in Uninstall registry key..."
        try {
            # Remove quotation marks from the uninstall string
            $uninstallString = $uninstallString.Replace('"', '')

            $exeIndex = $uninstallString.IndexOf(".exe", [System.StringComparison]::OrdinalIgnoreCase)
            if ($exeIndex -eq -1) {
                throw "Unrecognized uninstall string: $uninstallString"
            }
            $exePath = $uninstallString.Substring(0, $exeIndex + 4).Trim()
            $argz = $uninstallString.Substring($exeIndex + 4).Trim()

            # Write the path of the executable and the arguments to the console
            Write-Output "`t`"$exePath`""

            if ($argz) {
                $proc = Start-Process -FilePath $exePath -Args $argz -PassThru
            } else {
                $proc = Start-Process -FilePath $exePath -PassThru
            }
            $proc.WaitForExit()
            if ($proc.ExitCode -ne 0) {
                Write-Warning "Uninstaller exited with code $($proc.ExitCode)."
            }
        } catch {
            Write-Output "Uninstall failed with exception: $($_.Exception.Message)"
        }
    } else {
        Write-Output "No OneDrive uninstall string found in registry, skipping..."
    }

    # Remove OneDrive scheduled tasks
    Write-Output "Removing OneDrive scheduled tasks..."
    Get-ScheduledTask -TaskName "OneDrive*" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    # Remove the OneDrive app folder from every user profile (per-user installs only clean the
    # profile running the script). User data in %UserProfile%\OneDrive is never touched.
    Write-Output "Deleting OneDrive app folders from all user profiles..."
    $profileDirs = Get-ChildItem (Join-Path $env:SystemDrive "Users") -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notin @("Public", "Default", "Default User", "All Users")
    }
    foreach ($profileDir in $profileDirs) {
        $appPath = Join-Path $profileDir.FullName "AppData\Local\Microsoft\OneDrive"
        if (Test-Path $appPath) {
            Write-Output "Deleting `"$appPath`"..."
            Remove-Item -Path $appPath -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
    # ponytail: other users' HKCU Run keys and uninstall entries are left alone (their hives
    # aren't loaded); the entries point at files deleted above, so they fail silently

    # Verify removal before claiming success
    if (Test-OneDriveInstalled) {
        Write-Warning "OneDrive still appears to be installed. Removal may have failed or a reboot may be required."
        if ($PSCommandPath) { exit 1 }
    } else {
        Write-Output "Uninstall complete! OneDrive is no longer detected."
    }
} catch {
    Write-Warning "Uninstall failed with exception: $($_.Exception.Message)"
    if ($PSCommandPath) { exit 1 }
}
# SIG # Begin signature block
# MIIpagYJKoZIhvcNAQcCoIIpWzCCKVcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDLt70jNVqxZetl
# Q3Pg7+PvJp+tgxFRKnXZtaW8mTlBG6CCDh8wggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggdnMIIFT6ADAgECAhAKNMZR1UZgqS/qeQN0g3OKMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwMjA5MDAwMDAwWhcNMjcwMjA4
# MjM1OTU5WjBvMQswCQYDVQQGEwJVUzERMA8GA1UECBMIT2tsYWhvbWExETAPBgNV
# BAcTCE11c2tvZ2VlMRwwGgYDVQQKExNBc2hlciBTb2x1dGlvbnMgSW5jMRwwGgYD
# VQQDExNBc2hlciBTb2x1dGlvbnMgSW5jMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAsNcdHVM982mI1sSTuI2eOkKc4SoeDvPdZyoybYQWcOxzAYJsVzEI
# EoQcIjKU0KyOmPAEb/4U8VGrlATrm1BYwGLC9eymeBmUWc/VKECl6bPwos3B5K83
# qkNQshZvRtaN1S+surYIhW2vbHAtiIJnK4aY6emutJxB8TKuf68hTH13C9d0lwTG
# BSHTvLnYphdRg2z/VriH39GOP9d58YI/kztkS76v2itPjoO8fmoS7UicgpjfgV/D
# C6L09zg4pR9xhPWO0jpC4bDBw8pJyydSWyJNwiKYsDxSu9EoWWgYSuR3aP27seSj
# Soh6p+gcAHNkwD3TmwcDxgjLQJGQZCq81Wg6XD1wNRcQj3Co+aHM4bDnrEGr3Fr+
# KybVO4JzImTMAqqiNJsJfgZFkJpo8yWX91bmfyo/gCZdq8FM74BqabuCT0POxV2i
# hmj1IEujJlGXV7o1dl3HbOHfAbKBXZ56+sydA2TCANU6Tx72g6MMauaxq+HOOKng
# SYkpScbzng4XafT3Ik4AMutry4XwXvVvplnp7vvTuJC/udSGHicc2gTV9cvD4tH3
# 52J8niCbtlivKvCux+BkoFrZK8C7OTjbc08EWoD5UpMuEddx/L/kWsg65NExvY2a
# pHBsU4JnUe5h6ABqp70hvZJxpoX8b3n8uiWGUYzuC0UaTB+WoMgxMd0CAwEAAaOC
# AgMwggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQW
# BBQHFH7qQHiyfL6gvRyEHXMdJO+aJTA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcG
# CCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+G
# TWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVT
# aWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQw
# OTZTSEEzODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25p
# bmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0B
# AQsFAAOCAgEAutKpxJB9JYzuVnoBPTWJJYB0MhRrjbKY2lBq4V58at51H9A4PZjz
# KcLGenWuhgsWgzlgG6i+M/JjTZ2HG6ZXB+vGA5ZJxO5/InNIEcP2llytP6513Bre
# dJqEejqqgV2wmqFdiH272+ejnER+9EgydyD/zzIFLXpJ/5AK1Hr6tE7J37fgX+4e
# Kn9Lr/BOSda1FpSXprbC+mUtjMIm6NgO9c+hctEvl30osz2pzy8SzqliGeE/Nkn9
# MmcLw6KMpRRSLFDIAXgB4hFoWj8isPeNs4p3Sjb8ObrnZJdNQ8qDnWjT8kbrvAGp
# wW4Kp4c7o6VEBGwT2lQnSF/2HGDphCZNj/9sNbJ1wex2HBYkn/a26uFmvGjYHrZG
# SDDKXVBQEFM9BNNPHrXW2cOZyKpTftDsOK0SmX+y+kuHA2UT8HfB0LklyjUc15mz
# yzYn/n2WvVZt7fzTPJgsqRLRuoKOgQ5pIJY9XRq7i9oyFeUDZKsR5EblKB7Fbqcj
# txNcz7YmGLJvxDDx/qjeyvJLRKgBfm3yLRB/vL2xCTNKtmo0yK+Q5z5lrqMId+vm
# lrHx9C1K2KSqn8/JtAi0sOeoENEbD5Azl/ZmEtxQKgfS9fyul4Enh57IqJ9MILAP
# YOW63KIHwYscQAosM/PdjNy5DKDjwk+4jN7x9bEZJquPrl1y5XYE4j4xghqhMIIa
# nQIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFB
# MD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5
# NiBTSEEzODQgMjAyMSBDQTECEAo0xlHVRmCpL+p5A3SDc4owDQYJYIZIAWUDBAIB
# BQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# G3WIcveBCEW2XxcVTGLFRp7YoMK+xBQMrxevTqbL57YwDQYJKoZIhvcNAQEBBQAE
# ggIAbgoRTXpKOfRkCz8ganQcDzAioUkrUV36gESyKflrpOQa7lMtDSdgITSyM5Yi
# yU3mXSh3D84pN2r5jGCpWx5n0PCFTjmbtMBo+uyAxQR/Qv14xVurr6igNdDDqyyX
# 7n/ktVnkrRo1P4ss/ogTjd427V5Gq2S9tynTSwKxg0TfVzSjwTTtyUgH9OaNjtzX
# Wy1547/NhqOcDjbUzjs6fRLbLuYqsSsCRYUnFUESL3Mi7dy9OJEYGbD+vhVe4isM
# jiKfYIZ4+PKBAZZhU3BFhaTqValzOXPvphMRiKV49WM/NDqv8v6tGtktb0lJS4DO
# mrM6IrM2bjFHAmwd6pvgqzhc5YtD0+j+ml+t7QnjIs/oFJae6TFybtxheEA7avDM
# ktMbFWOwlT4Fi3Pp8ktqMZdiO72P0vV0tOKFjx9KlRytQUdyOUqVe7wEC1yWZAmb
# k0yAIZnHbzx1nPSNRYz2+FCmKyBMQURc4KJHLB1lDXaRYE5mSRkA6VNW1UJqvHVv
# qXaDsaFK/0w5V0kMR4k6HPum/cbEAhKCklJpIEVKBIYU2Gwm6rvfb/YtlYDjQ/Jk
# iVl5HSOrnVAUnrJXfBEgNOfwczIv2UPaUdIxd6dEKD+Mg8OnySw/A5DCPcRBJowX
# /ZfGLD2ZGHzxPaWBm2iGX7kmDCIGIsZV+FgdYY3VDQVXy6qhghd3MIIXcwYKKwYB
# BAGCNwMDATGCF2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEPMA0GCWCGSAFl
# AwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTANBglg
# hkgBZQMEAgEFAAQgPVDM7AB64mk1SQ4pv18iK1vnmVsqCtgBRj4Us1rvXeUCEQCA
# 5GW5w7yHWv02fgdLZ1VuGA8yMDI2MDgzMTIwMjg1MlqgghM6MIIG7TCCBNWgAwIB
# AgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4X
# DTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYg
# UlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlC
# MGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA
# 2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYO
# zDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0
# ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5
# KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLo
# ZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdo
# RORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUo
# HLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7r
# lRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V
# 1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8
# +3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39
# /dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUF
# BwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# XQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmww
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUA
# A4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gB
# q9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9l
# Ffim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUq
# W4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMn
# xYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZp
# qyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AW
# cIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJg
# ddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV
# 1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVcc
# AvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8a
# tufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCBrQwggScoAMC
# AQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUw
# NzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2U
# tZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWC
# WgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+
# gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DP
# fNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVV
# gtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifi
# nT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x
# 5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HH
# fIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQ
# yogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70Ew
# gWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7Zr
# IGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877
# FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI
# 9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3ess
# BS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qK
# tntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I
# +ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q1
# 7r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+Mt
# ucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9J
# GYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlH
# qhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7G
# ELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlar
# Evf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggWNMIIEdaADAgECAhAOmxiO
# +dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAi
# BgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAw
# MDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsb
# hA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iT
# cMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGb
# NOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclP
# XuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCr
# VYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFP
# ObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTv
# kpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWM
# cCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls
# 5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBR
# a2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6
# MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8E
# BAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCg
# v0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQT
# SnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh
# 65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSw
# uKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAO
# QGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjD
# TZ9ztwGpn1eqXijiuZQxggN8MIIDeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjA4MzEyMDI4NTJaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFN1iMKyGCi0wa9o4sWh5UjAH+0F+MC8GCSqGSIb3DQEJBDEi
# BCCcxqw/a9WZGgdrlOCsaYwMJ4aNkWUw1DhK9FyN/YKdnzA3BgsqhkiG9w0BCRAC
# LzEoMCYwJDAiBCBKoD+iLNdchMVck4+CjmdrnK7Ksz/jbSaaozTxRhEKMzANBgkq
# hkiG9w0BAQEFAASCAgBWOkCG6bjaAbATjAo2X5Dd4fKIpcRswojqJ+HJJy9d+bXN
# JpDQ0aSV/hF5N2XUydY/qO9ZARaHoFWGq1z7G9Kg9EXzgOXgJWQabaGTE82+k0A9
# dedQrd4Dtn6o612DLry4c2X1syg0Ab4FNneHMR/Rueamo1H31vf2e1/cb8bqbHzD
# 6RauXdXjwjb8EZ2gtExBnKBAmwDgIuWda2UO5EAsCxA3143+1UiG3zDgSPwkiETR
# GQRZdo+MszX5mAgA2Mk9ThX6MsuUESjquxZx2H3bGXKQ0C9wSMWgZCQyrgA4EAKN
# X91fYQcIUM62ty4ksP6pIXN7leGjEEvL8DZkFyQ/im6YF+JTr6CsucsCUZJzpbn0
# 12TJUuar+gXO26v9gsrfClEA/AzqcOaIIKL0wVPqOqBGFx4qizEVcT+xmG2DJYqI
# IVzfHp+/ynnK4JnNvdgxTlEGq+/plso/is7DOMxtc+Gp29iKNpCdxpC99ikxBmNK
# 4oV6Gj7ker7msMINhFPjlf/o/TjJ17yEc9of+OzgDfVf9SwzubDcO1qdmb+WcKWp
# /bC2QUlM0VYpo547EZkUDQlU0XoluG1GhVQzJZgPykGzcRwCPS0rFC7EJm4YKzY7
# 9Ewn8yu9jDpWLWf2FkEq6277sduDM3rFBZ5qq2wd9ORb52VEeCs4Lcgus2tOoA==
# SIG # End signature block
