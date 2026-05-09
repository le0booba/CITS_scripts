# Clear-Host

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Out-Log {
    param([string]$Message, [string]$Type = 'Info')
    switch ($Type) {
        'Title' { Write-Host "`n :: $Message ::`n" -ForegroundColor Cyan }
        'Info' { Write-Host " [~] $Message" -ForegroundColor Cyan }
        'Success' { Write-Host " [+] $Message" -ForegroundColor Green }
        'Warn' { Write-Host " [!] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host " [x] $Message" -ForegroundColor Red }
        'Detail' { Write-Host "  -> $Message" -ForegroundColor Gray }
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Out-Log 'Для работы скрипта требуются права администратора. Пожалуйста, запустите его от имени администратора.' 'Error'
    exit
}

if ($PSVersionTable.PSVersion.Major -ge 6) {
    Out-Log 'Скрипт предназначен для классической версии PowerShell (5.1 или ниже). Выполняется попытка запуска в режиме совместимости...' 'Warn'
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Path
        exit
    }
    catch {
        Out-Log 'Не удалось перезапустить скрипт в классической версии PowerShell. Убедитесь, что она установлена и доступна в переменной PATH. Завершение работы...' 'Error'
        exit 1
    }
}

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

Add-Type -AssemblyName System.Windows.Forms, Microsoft.VisualBasic, System.Web

function Generate-SecurePassword {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(4)

    function Get-SecureInt {
        param([int]$Maximum)
        
        if ($Maximum -le 0) { return 0 }
        
        while ($true) {
            $rng.GetBytes($bytes)
            $rand = [System.BitConverter]::ToUInt32($bytes, 0)
            $limit = [uint32]::MaxValue - ([uint32]::MaxValue % $Maximum)
            if ($rand -lt $limit) {
                return ($rand % $Maximum)
            }
        }
    }
    
    $words = 'apple', 'river', 'stone', 'cloud', 'green', 'night', 'sun', 'mouse', 'table', 'forest', 'water', 'paper', 'glass', 'light', 'snow', 'fire', 'wind', 'tree', 'road', 'field'
    $letters = 'a', 'b', 'c', 'd', 'e', 'f', 'h', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    
    $word = $words[(Get-SecureInt -Maximum $words.Count)]
    $wordCap = $word.Substring(0, 1).ToUpper() + $word.Substring(1)
    
    $l1 = $letters[(Get-SecureInt -Maximum $letters.Count)]
    $l2 = $letters[(Get-SecureInt -Maximum $letters.Count)]
    
    $d1 = Get-SecureInt -Maximum 10
    $d2 = Get-SecureInt -Maximum 10
    
    return "$wordCap-$l1$l2$d1$d2"
}

function Invoke-RobustDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri, [Parameter(Mandatory = $true)][string]$OutFile,
        [string]$DisplayName,
        [int]$TimeoutSeconds = 60
    )
    
    if (-not $DisplayName) {
        $DisplayName = (Split-Path $OutFile -Leaf)
    }

    try {
        Import-Module BitsTransfer -ErrorAction Stop
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        Out-Log "Запуск надежной загрузки '$DisplayName' через BITS..." 'Info'
        $bitsJob = Start-BitsTransfer -Source $Uri -Destination $OutFile -DisplayName $DisplayName -Asynchronous -Priority Foreground
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds -and $bitsJob.JobState -in ('Connecting', 'Transferring', 'TransientError')) {
            $percentComplete = if ($bitsJob.BytesTotal -gt 0) { [math]::Round(($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100, 2) } else { 0 }
            $status = "Загрузка $DisplayName... $percentComplete %"
            if ($bitsJob.JobState -eq 'TransientError') {
                $status += ' (Проблема с сетью, повторная попытка...)'
            }
            Write-Progress -Activity 'Загрузка файлов' -Status $status -PercentComplete $percentComplete
            Start-Sleep -Seconds 1
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity 'Загрузка файлов' -Completed

        if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds -and $bitsJob.JobState -in ('Connecting', 'Transferring', 'TransientError')) {
            Remove-BitsTransfer -BitsJob $bitsJob
            throw "Превышено время ожидания загрузки '$DisplayName' ($TimeoutSeconds сек)."
        }

        switch ($bitsJob.JobState) {
            'Transferred' {
                Complete-BitsTransfer -BitsJob $bitsJob
                Out-Log "Загрузка завершена: $OutFile" 'Success'
            }
            'Error' {
                $errorDetails = $bitsJob | Select-Object -ExpandProperty ErrorDescription
                [void](Resume-BitsTransfer -BitsJob $bitsJob)
                Remove-BitsTransfer -BitsJob $bitsJob
                throw "Ошибка загрузки BITS для '$DisplayName': $errorDetails"
            }
            default {
                Remove-BitsTransfer -BitsJob $bitsJob
                throw "Загрузка BITS для '$DisplayName' отменена или завершилась со статусом: $($bitsJob.JobState)"
            }
        }
    }
    catch {
        if ($_.Exception.Message -match 'module' -or $_.FullyQualifiedErrorId -match 'ModuleNotFound') {
            Out-Log "Модуль BITS не найден или не загрузился. Системная ошибка: $($_.Exception.Message)" 'Warn'
        }
        else {
            Out-Log "Попытка загрузки через BITS не удалась. Причина: $($_.Exception.Message)" 'Warn'
        }
        
        Out-Log 'Использование резервного метода Invoke-WebRequest.' 'Detail'

        try {
            Out-Log "Шаг 1: Получение размера файла для '$DisplayName'..." 'Detail'
            $response = Invoke-WebRequest -Uri $Uri -Method Head
            $expectedSize = $response.Headers['Content-Length']
            if (-not $expectedSize) {
                throw 'Не удалось определить размер файла на сервере.'
            }
            Out-Log "Ожидаемый размер файла: $expectedSize байт." 'Detail'

            Out-Log 'Шаг 2: Запуск фоновой загрузки...' 'Detail'
            $job = Start-Job -ScriptBlock {
                param($Uri, $OutFile)
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile
            } -ArgumentList $Uri, $OutFile

            [void](Wait-Job -Job $job -Timeout $TimeoutSeconds)

            if ($job.State -eq 'Running') {
                $job | Stop-Job -PassThru | Remove-Job
                throw "Превышено время ожидания загрузки ($TimeoutSeconds сек)."
            }

            if ($job.State -ne 'Completed') {
                $errorRecord = ($job | Receive-Job)[-1]
                $job | Remove-Job
                throw "Ошибка фоновой загрузки: $($errorRecord.Exception.Message)"
            }
            
            [void](Receive-Job -Job $job)
            Remove-Job -Job $job

            Out-Log 'Шаг 3: Проверка целостности файла...' 'Detail'
            $actualSize = (Get-Item -Path $OutFile).Length
            if ($actualSize -ne $expectedSize) {
                Remove-Item -Path $OutFile -Force
                throw "Проверка целостности файла не пройдена. Ожидаемый размер: $expectedSize байт, фактический: $actualSize байт. Скачанный файл удален."
            }

            Out-Log "Загрузка и проверка для '$DisplayName' успешно завершены." 'Success'
        }
        catch {
            throw "Ошибка резервного метода загрузки: $($_.Exception.Message)"
        }
    }
}

Out-Log 'Установщик Rudesktop' 'Title'

$rudesktopInstalled = $false
$installPath = "${env:ProgramFiles}\Rudesktop\rudesktop.exe"

if (Test-Path $installPath) {
    $rudesktopInstalled = $true
    Out-Log 'Программа Rudesktop уже установлена в системе' 'Warn'
    $installedVersion = (Get-Item $installPath).VersionInfo.FileVersion -replace '\.@BUILD', ''
    Out-Log "Установленная версия: $installedVersion" 'Detail'
}

$rudesktopUrl = "https://storage.rudesktop.ru/download/rudesktop-2.9.927-x64.msi"
$downloadDir = [System.IO.Path]::Combine($env:TEMP, "RudesktopInstaller")
$fileName = [System.IO.Path]::GetFileName($rudesktopUrl)
$installerPath = [System.IO.Path]::Combine($downloadDir, $fileName)

try {
    if (-not (Test-Path $downloadDir)) {
        [void](New-Item -ItemType Directory -Path $downloadDir -Force)
    }

    if ($rudesktopInstalled) {
        $reinstallResult = [System.Windows.Forms.MessageBox]::Show(
            "Программа Rudesktop уже установлена (версия $installedVersion).`nХотите переустановить ее?",
            'Переустановка Rudesktop',
            'YesNo',
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        
        if ($reinstallResult -ne 'Yes') {
            Out-Log 'Переустановка отменена пользователем.' 'Warn'
            exit 0
        }
        
        Out-Log 'Удаление предыдущей версии Rudesktop...' 'Info'
        
        $uninstallString = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -Name "DisplayName", "UninstallString" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Rudesktop*" } |
        Select-Object -First 1 -ExpandProperty UninstallString
        
        if ($uninstallString) {
            Out-Log 'Найдена запись об установке Rudesktop, выполняется удаление...' 'Detail'
            try {
                if ($uninstallString -match "MsiExec\.exe") {
                    $msiProductCode = ($uninstallString -split '/I')[-1].Trim()
                    Start-Process "msiexec.exe" "/x $msiProductCode /qn /norestart" -Wait -NoNewWindow
                }
                else {
                    Start-Process "cmd.exe" "/c `"$uninstallString /SILENT /NORESTART`"" -Wait -NoNewWindow
                }
                Out-Log 'Предыдущая версия удалена.' 'Success'
            }
            catch {
                Out-Log "Не удалось автоматически удалить предыдущую версию: $($_.Exception.Message)" 'Warn'
                Out-Log 'Продолжение установки поверх существующей...' 'Detail'
            }
        }
    }

    Out-Log 'Загрузка Rudesktop...' 'Info'
    Out-Log "Источник: $rudesktopUrl" 'Detail'
    Out-Log "Назначение: $installerPath" 'Detail'
    
    Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
    
    Invoke-RobustDownload -Uri $rudesktopUrl -OutFile $installerPath -DisplayName "Установщик Rudesktop"
    
    Out-Log 'Загрузка успешно завершена!' 'Success'
    
    Out-Log 'Запуск установки Rudesktop...' 'Info'
    Out-Log 'Запуск установщика MSI...' 'Detail'
        
    $msiArgs = "/i", "`"$installerPath`"", "/qn", "/norestart"
        
    Out-Log "Параметры установки: $($msiArgs -join ' ')" 'Detail'
        
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
        
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        Out-Log 'Программа Rudesktop успешно установлена!' 'Success'
            
        $rudesktopPaths = "${env:ProgramFiles}\Rudesktop\rudesktop.exe", "${env:ProgramFiles(x86)}\Rudesktop\rudesktop.exe"
            
        $rudesktopExePath = $null
        foreach ($path in $rudesktopPaths) {
            if (Test-Path $path) {
                $rudesktopExePath = $path
                $newVersion = (Get-Item $path).VersionInfo.FileVersion -replace '\.@BUILD', ''
                Out-Log "Версия установленной программы Rudesktop: $newVersion" 'Detail'
                break
            }
        }
            
        if (-not $rudesktopExePath) {
            Out-Log 'Не удалось найти установленную программу Rudesktop. Возможно, установка не завершилась полностью.' 'Warn'
        }
        else {
            $rudesktopId = "Не определен"
            try {
                Out-Log 'Получение ID Rudesktop...' 'Info'
                $idOutput = & $rudesktopExePath --get-id
                if ($null -ne $idOutput) {
                    $rudesktopId = ($idOutput -join '').Trim()
                }
                if (-not [string]::IsNullOrWhiteSpace($rudesktopId) -and $rudesktopId -ne "Не определен") {
                    Out-Log "Полученный ID: $rudesktopId" 'Success'
                }
                else {
                    Out-Log 'Получен пустой ID.' 'Warn'
                    $rudesktopId = "Не определен"
                }
            }
            catch {
                Out-Log 'Не удалось получить ID.' 'Warn'
            }

            $passwordResult = [System.Windows.Forms.MessageBox]::Show(
                'Сгенерировать и установить пароль для Rudesktop?' + "`n`n" +
                'Это позволит настроить безопасный доступ к программе.',
                'Установка пароля Rudesktop',
                'YesNo',
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
                
            if ($passwordResult -eq 'Yes') {
                Out-Log 'Генерация пароля для Rudesktop...' 'Info'
                    
                $rudesktopPassword = Generate-SecurePassword
                Out-Log "Сгенерированный пароль: $rudesktopPassword" 'Detail'
                    
                Out-Log 'Установка пароля в Rudesktop...' 'Info'
                    
                try {
                    $passwordArgs = "--password $rudesktopPassword"
                    $passwordProcess = Start-Process -FilePath $rudesktopExePath -ArgumentList $passwordArgs -Wait -PassThru -NoNewWindow
                        
                    if ($passwordProcess.ExitCode -eq 0) {
                        Out-Log 'Пароль успешно установлен в Rudesktop!' 'Success'
                    }
                    else {
                        Out-Log "Команда установки пароля завершилась с кодом: $($passwordProcess.ExitCode)" 'Warn'
                        Out-Log 'Возможно, Rudesktop не поддерживает установку пароля через командную строку.' 'Detail'
                    }
                }
                catch {
                    Out-Log "Ошибка при установке пароля: $($_.Exception.Message)" 'Warn'
                    Out-Log 'Попробуйте установить пароль вручную через настройки Rudesktop.' 'Detail'
                }
                    
                $passwordFilePath = Join-Path $PSScriptRoot "${env:COMPUTERNAME}.txt"
                $passwordContent = @"

Данные Rudesktop
================
Дата создания: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')
Имя ПК: $env:COMPUTERNAME
ID: $rudesktopId
Пароль: $rudesktopPassword

Путь к исполняемому файлу: $rudesktopExePath
"@
                
                if (Test-Path -Path $passwordFilePath) {
                    Out-Log "Файл $passwordFilePath уже существует. Новые данные будут добавлены в конец файла." 'Warn'
                    $passwordContent | Out-File -FilePath $passwordFilePath -Encoding UTF8 -Append
                }
                else {
                    $passwordContent | Out-File -FilePath $passwordFilePath -Encoding UTF8
                    Out-Log "Данные сохранены в файл: $passwordFilePath" 'Success'
                }
                    
                $showPassword = [System.Windows.Forms.MessageBox]::Show(
                    "Данные для подключения Rudesktop:`n`nИмя ПК: $env:COMPUTERNAME`nID: $rudesktopId`nПароль: $rudesktopPassword`n`n" +
                    "Данные также сохранены в файл:`n$passwordFilePath`n`n" +
                    "Скопировать пароль в буфер обмена?",
                    'Данные Rudesktop',
                    'YesNo',
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
                    
                if ($showPassword -eq 'Yes') {
                    Set-Clipboard -Value $rudesktopPassword
                    Out-Log 'Пароль скопирован в буфер обмена.' 'Detail'
                }
            }
            else {
                Out-Log 'Установка пароля отменена пользователем.' 'Warn'
                Out-Log 'Для установки пароля в будущем используйте команду: rudesktop.exe --password ВашПароль' 'Detail'
            }
                
            Out-Log 'Запуск Rudesktop...' 'Info'
            Start-Process -FilePath $rudesktopExePath
        }
    }
    else {
        Out-Log "Установщик завершился с кодом: $($process.ExitCode)" 'Warn'
            
        if ($process.ExitCode -eq 1603) {
            Out-Log 'Ошибка 1603: Обычно означает недостаток прав или конфликт с другим ПО.' 'Error'
            Out-Log 'Попробуйте запустить установку вручную с правами администратора.' 'Detail'
        }
            
        Out-Log 'Проверьте установку вручную.' 'Warn'
    }
}
catch {
    Out-Log "Ошибка при загрузке или установке Rudesktop: $($_.Exception.Message)" 'Error'
    Out-Log "Попробуйте установить программу вручную по ссылке: $rudesktopUrl" 'Detail'
}

Out-Log 'Процесс завершен!' 'Title'