Add-Type -AssemblyName System.Windows.Forms

function Show-Menu {
    Write-Host "`n- Press [Space] to send another file`n- Press [Esc] to exit"
    
    while ($true) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        if ($key.VirtualKeyCode -eq 32) {
            return "Continue"
        }
        if ($key.VirtualKeyCode -eq 27) {
            return "Exit"
        }
    }
}

$makeWebhookUrl = "https://hook.eu1.make.com/n4klmle5d3xop69z7watt2j7c3dzqm5u"
$chatId = "668888602"
$maxFileSize = 49 * 1024 * 1024
$maxFileCount = 5
$uploadDelaySeconds = 2

Clear-Host

while ($true) {
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select up to 5 files to send"
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    $openFileDialog.Multiselect = $true

    if ($openFileDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "No files selected. Operation cancelled."
        if ((Show-Menu) -eq "Exit") { break }
        continue
    }

    $selectedFiles = $openFileDialog.FileNames

    if ($selectedFiles.Count -gt $maxFileCount) {
        Write-Warning "You selected $($selectedFiles.Count) files. Only the first $maxFileCount will be processed."
        $selectedFiles = $selectedFiles[0..($maxFileCount - 1)]
    }

    $validFiles = @()
    foreach ($filePath in $selectedFiles) {
        $fileInfo = Get-Item -Path $filePath
        if ($fileInfo.Length -gt $maxFileSize) {
            $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
            Write-Warning "SKIPPING: File '$($fileInfo.Name)' ($fileSizeMB MB) exceeds the 49 MB size limit."
        }
        else {
            $validFiles += $filePath
        }
    }
    
    if ($validFiles.Count -eq 0) {
        Write-Host "No valid files to upload."
        if ((Show-Menu) -eq "Exit") { break }
        continue
    }

    $fileCounter = 0
    foreach ($filePath in $validFiles) {
        $fileCounter++
        $fileName = [System.IO.Path]::GetFileName($filePath)
        
        Write-Host "[$fileCounter/$($validFiles.Count)] Processing file: $fileName"
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $crlf = "`r`n"

        $bodyLines = @()
        $bodyLines += "--$boundary"
        $bodyLines += "Content-Disposition: form-data; name=`"chat_id`"$crlf"
        $bodyLines += $chatId

        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)

        $bodyLines += "--$boundary"
        $bodyLines += "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`""
        $bodyLines += "Content-Type: application/octet-stream$crlf"
        $bodyLines += [System.Text.Encoding]::GetEncoding('UTF-8').GetString($fileBytes)

        $bodyLines += "--$boundary--"

        $body = ($bodyLines -join $crlf)
        $contentType = "multipart/form-data; boundary=`"$boundary`""

        try {
            Write-Host "Uploading '$fileName'..."
            $response = Invoke-RestMethod -Uri $makeWebhookUrl -Method Post -ContentType $contentType -Body $body
            Write-Host "Upload successful."
        }
        catch {
            Write-Error "An error occurred while uploading '$fileName': $_"
            if ($_.Exception.Response) {
                $errorResponseStream = $_.Exception.Response.GetResponseStream()
                $streamReader = New-Object System.IO.StreamReader($errorResponseStream)
                $errorBody = $streamReader.ReadToEnd()
                Write-Error "Error response body: $errorBody"
            }
        }
        
        if ($fileCounter -lt $validFiles.Count) {
            Write-Host "Waiting for $uploadDelaySeconds seconds..."
            Start-Sleep -Seconds $uploadDelaySeconds
        }
    }
    
    Write-Host "`nAll operations are complete."
    if ((Show-Menu) -eq "Exit") { break }
}

Write-Host "`nExiting script."