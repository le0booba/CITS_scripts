Clear-Host

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "PowerShell 5.1 detected. Relaunching in PowerShell 7 for compatibility." -ForegroundColor Yellow
    
    try {
        $powerShell7Path = Get-Command pwsh.exe -ErrorAction Stop
        Write-Host "Relaunching the script..." -ForegroundColor Green
        
        $scriptPath = $MyInvocation.MyCommand.Path
        
        Start-Process -FilePath $powerShell7Path.Source -ArgumentList "-NoProfile -NoExit -Command `& '$scriptPath'"`
    }
    catch {
        Write-Host "ERROR: PowerShell 7 (pwsh.exe) was not found in your system's PATH." -ForegroundColor Red
        Write-Host "Please install the latest version of PowerShell and try again." -ForegroundColor Red
        Read-Host "Press Enter to exit"
    }
    
    exit
}

# $webhookUrl = "https://hook.eu1.make.com/n4klmle5d3xop69z7watt2j7c3dzqm5u"
$webhookUrl = "https://hook.eu1.make.com/a3tsyuepux2rl189yu1vzjim2lmesijb"

function Select-FileDialog {
    Add-Type -AssemblyName System.Windows.Forms
    
    $csharpCode = @"
    using System;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;

    public class Win32 {
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
    }
    public class WindowWrapper : System.Windows.Forms.IWin32Window {
        private IntPtr _hwnd;
        public WindowWrapper(IntPtr handle) { _hwnd = handle; }
        public IntPtr Handle { get { return _hwnd; } }
    }
"@
    Add-Type -TypeDefinition $csharpCode -Language CSharp -ReferencedAssemblies System.Windows.Forms

    $owner = New-Object WindowWrapper -ArgumentList ([Win32]::GetConsoleWindow())

    $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $fileDialog.Title = "Select a file to send (max 10 MB)"
    $fileDialog.Filter = "All files (*.*)|*.*"
    $fileDialog.Multiselect = $false
    
    $maxSizeBytes = 10MB

    while ($true) {
        if ($fileDialog.ShowDialog($owner) -eq "OK") {
            $filePath = $fileDialog.FileName
            $fileInfo = Get-Item -Path $filePath
            if ($fileInfo.Length -le $maxSizeBytes) {
                return $filePath
            }
            else {
                $fileSizeMB = [Math]::Round($fileInfo.Length / 1MB, 2)
                $message = "File is too large ($($fileSizeMB) MB). Please select a file smaller than 10 MB."
                [void][System.Windows.Forms.MessageBox]::Show($owner, $message, "File Size Error", "OK", "Error")
            }
        }
        else {
            return $null
        }
    }
}

function Send-FileToWebhook {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$filePath,
        [string]$url,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 5,
        [int]$RequestTimeoutSeconds = 60
    )

    if (-not (Test-Path $filePath -PathType Leaf)) {
        Write-Host "Error: File '$filePath' not found." -ForegroundColor Red
        return $false
    }

    $fileName = [System.IO.Path]::GetFileName($filePath)
    Write-Host "Preparing to send file: '$fileName'..." -ForegroundColor Yellow
    Write-Host "Calculating SHA256 checksum..." -ForegroundColor DarkGray
    $fileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
    Write-Host "Checksum: $fileHash" -ForegroundColor DarkGray
    
    $fileItem = Get-Item -Path $filePath

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $form = @{
                file      = $fileItem
                sha256sum = $fileHash
            }

            $restMethodParams = @{
                Uri        = $url
                Method     = 'Post'
                Form       = $form
                TimeoutSec = $RequestTimeoutSeconds
            }

            if ($PSCmdlet.ShouldProcess($fileName, "Send to Webhook")) {
                $response = Invoke-RestMethod @restMethodParams
                
                Write-Host "File '$fileName' sent successfully." -ForegroundColor Green
                Write-Host "Server response:" -ForegroundColor DarkGray
                $response | ConvertTo-Json -Depth 3 | Write-Host -ForegroundColor DarkGray
                return $true
            } else {
                return $false
            }
        }
        catch [System.Net.WebException] {
            Write-Host "Attempt $attempt of $MaxRetries failed." -ForegroundColor Yellow
            if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__
                Write-Host "A network error occurred. Status code: $statusCode" -ForegroundColor Red
            } else {
                Write-Host "A network error occurred: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            if ($attempt -ge $MaxRetries) {
                Write-Host "An error occurred while sending file '$fileName' after $MaxRetries attempts." -ForegroundColor Red
            } else {
                Write-Host "Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }
        catch {
            Write-Host "Attempt $attempt of $MaxRetries failed." -ForegroundColor Yellow
            
            if ($attempt -lt $MaxRetries) {
                Write-Host "Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $RetryDelaySeconds
            } else {
                Write-Host "An unexpected error occurred while sending file '$fileName' after $MaxRetries attempts." -ForegroundColor Red
                Write-Host "Final error message: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    return $false
}

$selectedFile = Select-FileDialog

if ($null -ne $selectedFile) {
    Write-Host "Selected file:" -ForegroundColor Cyan
    Write-Host "- $selectedFile"
    Write-Host "----------------------------------------"

    $operationSuccess = Send-FileToWebhook -filePath $selectedFile -url $webhookUrl
    Write-Host "----------------------------------------"
    
    if ($operationSuccess) {
        Write-Host "Operation completed." -ForegroundColor Green
    }
}
else {
    Write-Host "No file was selected. The script will now exit." -ForegroundColor Yellow
}