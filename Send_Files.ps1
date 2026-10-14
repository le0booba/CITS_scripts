Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Net.Http

function Show-MainMenu {
    Write-Host "`nChoose an action:"
    Write-Host "  [F] Send file(s)"
    Write-Host "  [T] Send text message"
    Write-Host "  [Esc] Exit"

    while ($true) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        switch ($key.VirtualKeyCode) {
            70 { return "File" }   # F
            84 { return "Text" }   # T
            27 { return "Exit" }   # Esc
        }
    }
}

function Show-TextInputDialog {
    param(
        [string]$Title = "Enter text",
        [string]$Prompt = "Type your message below:"
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(500, 350)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.KeyPreview = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.Size = New-Object System.Drawing.Size(460, 20)
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 35)
    $textBox.Size = New-Object System.Drawing.Size(460, 220)
    $textBox.Multiline = $true
    $textBox.ScrollBars = "Vertical"
    $textBox.AcceptsReturn = $true
    $textBox.AcceptsTab = $true
    $form.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(310, 270)
    $okButton.Size = New-Object System.Drawing.Size(75, 30)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(395, 270)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 30)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)

    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton

    $textBox.Add_KeyDown({
        param($sender, $e)
        if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Close()
        }
    })

    $form.Add_Shown({ $textBox.Focus() })

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $enteredText = $textBox.Text
    }
    else {
        $enteredText = $null
    }

    $form.Dispose()

    return $enteredText
}

function Send-TextMessage {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Http.HttpClient]$HttpClient,
        [Parameter(Mandatory = $true)]
        [string]$WebhookUrl,
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $multipartContent = $null
    $stringContent = $null
    $response = $null

    try {
        Write-Host "Sending text message..."

        $multipartContent = New-Object System.Net.Http.MultipartFormDataContent
        $stringContent = New-Object System.Net.Http.StringContent($Text, [System.Text.Encoding]::UTF8)
        $multipartContent.Add($stringContent, "text")

        $response = $HttpClient.PostAsync($WebhookUrl, $multipartContent).GetAwaiter().GetResult()

        if ($response.IsSuccessStatusCode) {
            Write-Host "Text sent successfully." -ForegroundColor Green
        }
        else {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Write-Error "Server returned error code: $($response.StatusCode). Body: $responseBody"
        }
    }
    catch {
        Write-Error "An error occurred while sending text: $_"
    }
    finally {
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $stringContent) { $stringContent.Dispose() }
        if ($null -ne $multipartContent) { $multipartContent.Dispose() }
    }
}

$makeWebhookUrl = "https://hook.eu1.make.com/msmorih35os2umdmntqge098vhho4ghy"
$maxFileSize = 49 * 1024 * 1024
$maxFileCount = 5
$uploadDelaySeconds = 2

Clear-Host

$httpClient = New-Object System.Net.Http.HttpClient

try {
    while ($true) {

        $action = Show-MainMenu

        if ($action -eq "Exit") { break }

        if ($action -eq "Text") {
            $textToSend = Show-TextInputDialog -Title "Send text message" -Prompt "Type your message below (Ctrl+Enter or click OK to send):"

            if ([string]::IsNullOrWhiteSpace($textToSend)) {
                Write-Host "No text entered. Operation cancelled."
                continue
            }

            Send-TextMessage -HttpClient $httpClient -WebhookUrl $makeWebhookUrl -Text $textToSend
            Write-Host "`nAll operations are complete."
            continue
        }

        # action -eq "File"
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

        try {
            $openFileDialog.Title = "Select up to 5 files to send"
            $openFileDialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
            $openFileDialog.Multiselect = $true

            if ($openFileDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
                Write-Host "No files selected. Operation cancelled."
                continue
            }

            $selectedFiles = $openFileDialog.FileNames
        }
        finally {
            $openFileDialog.Dispose()
        }

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
            continue
        }

        $fileCounter = 0

        foreach ($filePath in $validFiles) {
            $fileCounter++
            $fileName = [System.IO.Path]::GetFileName($filePath)

            Write-Host "[$fileCounter/$($validFiles.Count)] Processing file: $fileName"

            $multipartContent = $null
            $fileStream = $null
            $streamContent = $null
            $response = $null

            try {
                Write-Host "Uploading '$fileName'..."

                $multipartContent = New-Object System.Net.Http.MultipartFormDataContent

                $fileStream = [System.IO.File]::OpenRead($filePath)
                $streamContent = New-Object System.Net.Http.StreamContent($fileStream)

                $headerValue = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
                $streamContent.Headers.ContentType = $headerValue

                $multipartContent.Add($streamContent, "document", $fileName)

                $response = $httpClient.PostAsync($makeWebhookUrl, $multipartContent).GetAwaiter().GetResult()

                if ($response.IsSuccessStatusCode) {
                    Write-Host "Upload successful." -ForegroundColor Green
                }
                else {
                    $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    Write-Error "Server returned error code: $($response.StatusCode). Body: $responseBody"
                }
            }
            catch {
                Write-Error "An error occurred while uploading '$fileName': $_"
            }
            finally {
                if ($null -ne $response) { $response.Dispose() }
                if ($null -ne $streamContent) { $streamContent.Dispose() }
                if ($null -ne $fileStream) { $fileStream.Dispose() }
                if ($null -ne $multipartContent) { $multipartContent.Dispose() }
            }

            if ($fileCounter -lt $validFiles.Count) {
                Write-Host "Waiting for $uploadDelaySeconds seconds..."
                Start-Sleep -Seconds $uploadDelaySeconds
            }
        }

        Write-Host "`nAll operations are complete."
    }
}
finally {
    $httpClient.Dispose()
}

Write-Host "`nExiting script."