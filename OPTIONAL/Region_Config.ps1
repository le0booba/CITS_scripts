Clear-Host

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "⚠️  Для выполнения скрипта требуются права администратора. Перезапуск..." -ForegroundColor Yellow
    $startProcessParams = @{
        FilePath     = "powershell.exe"
        Verb         = "RunAs"
        ArgumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    }
    Start-Process @startProcessParams
    exit
}

Add-Type -AssemblyName System.Windows.Forms

function Write-Info($msg) { Write-Host "ℹ️  $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "✅  $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "⚠️  $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "❌  $msg" -ForegroundColor Red }

$Language = "ru-RU"
$LanguageToAdd = "en-US"
$GeoId = 203
$SystemLocaleId = "0419"
$rebootRequired = $false

$availableCommands = @{
    InstallLanguage = [bool](Get-Command -Name Install-Language -ErrorAction SilentlyContinue)
    SetSystemPreferredUILanguage = [bool](Get-Command -Name Set-SystemPreferredUILanguage -ErrorAction SilentlyContinue)
    SetWinHomeLocation = [bool](Get-Command -Name Set-WinHomeLocation -ErrorAction SilentlyContinue)
    GetSystemLocale = [bool](Get-Command -Name Get-SystemLocale -ErrorAction SilentlyContinue)
    CopyUserInternationalSettingsToSystem = [bool](Get-Command -Name Copy-UserInternationalSettingsToSystem -ErrorAction SilentlyContinue)
}

try {
    Write-Info "Начало выполнения скрипта локализации Windows"

    try {
        if ($availableCommands.InstallLanguage) {
            $InstalledLanguages = Get-InstalledLanguage
            if (-not ($InstalledLanguages.LanguageId -contains $Language)) {
                Write-Info "Русский языковой пакет не найден. Начинается установка..."
                Install-Language $Language -CopyToCurrentSystemAccount -CopyToCurrentUserLogoff -CopyToNewUser
                $rebootRequired = $true
                Write-OK "Установка русского языкового пакета завершена."
            } else {
                Write-OK "Русский языковой пакет уже установлен."
            }
        } else {
            Write-Warn "Командлет 'Install-Language' не найден. Автоматическая установка языкового пакета невозможна на этой ОС."
        }
    }
    catch {
        Write-Warn "Произошла ошибка при установке языкового пакета. Возможно, ваша версия Windows не поддерживает эту операцию."
        Write-Warn "Сообщение об ошибке: $($_.Exception.Message)"
    }

    if ($availableCommands.SetSystemPreferredUILanguage) {
        $CurrentUILanguage = Get-SystemPreferredUILanguage
        if ($CurrentUILanguage -ne $Language) {
            Write-Info "Устанавливается русский язык в качестве языка интерфейса..."
            Set-SystemPreferredUILanguage $Language
            $rebootRequired = $true
            Write-OK "Русский язык установлен как основной язык интерфейса."
        } else {
            Write-OK "Русский язык уже является основным языком интерфейса."
        }
    } else {
        Write-Warn "Командлет 'Set-SystemPreferredUILanguage' не найден. Смена языка интерфейса не может быть автоматизирована."
    }

    Write-Info "Проверка и настройка языков ввода..."
    $CurrentLanguageList = Get-WinUserLanguageList
    $CurrentLanguageTags = $CurrentLanguageList.LanguageTag
    if (($CurrentLanguageTags.Count -gt 0) -and ($CurrentLanguageTags[0] -eq $Language) -and ($LanguageToAdd -in $CurrentLanguageTags)) {
        Write-OK "Русский и английский языки для ввода уже настроены корректно."
    } else {
        Write-Info "Список языков ввода требует обновления. Устанавливается русский (основной) и английский."
        $NewList = New-WinUserLanguageList -Language $Language
        [void]$NewList.Add($LanguageToAdd)
        Set-WinUserLanguageList -LanguageList $NewList -Force
        Write-OK "Список языков ввода успешно обновлен."
    }

    if ($availableCommands.SetWinHomeLocation) {
        $CurrentHomeLocation = Get-WinHomeLocation
        if ($CurrentHomeLocation.GeoId -ne $GeoId) {
            Write-Info "Устанавливается страна/регион: Россия..."
            Set-WinHomeLocation -GeoId $GeoId
            Write-OK "Страна/регион успешно установлены."
        } else {
            Write-OK "Параметр 'Страна/регион' уже установлен на 'Россия'."
        }
    } else {
         Write-Warn "Командлет 'Set-WinHomeLocation' не найден. Смена страны/региона не может быть автоматизирована."
    }

    Write-Info "Проверка формата региона..."
    if ((Get-Culture).Name -ne $Language) {
        Write-Info "Устанавливается формат региона: Русский (Россия)..."
        Set-Culture $Language
        Write-OK "Формат региона успешно установлен."
    } else {
        Write-OK "Формат региона уже установлен на Русский (Россия)."
    }
    
    Write-Info "Проверка языка для не-Unicode программ..."
    if ($availableCommands.GetSystemLocale) {
        $CurrentSystemLocale = Get-SystemLocale
        if ($CurrentSystemLocale.Name -ne $Language) {
            Write-Info "Установка языка для не-Unicode программ (современный метод)..."
            Set-SystemLocale -SystemLocale $Language
            $rebootRequired = $true
            Write-OK "Системная локаль успешно изменена."
        } else {
            Write-OK "Язык для не-Unicode программ уже установлен на русский."
        }
    }
    else {
        Write-Info "Используется метод совместимости для старых ОС (реестр)."
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language"
        $currentLocaleId = (Get-ItemProperty -Path $regPath -Name Default).Default
        if ($currentLocaleId -ne $SystemLocaleId) {
            Write-Info "Установка языка для не-Unicode программ (метод совместимости)..."
            Set-ItemProperty -Path $regPath -Name Default -Value $SystemLocaleId
            $rebootRequired = $true
            Write-OK "Системная локаль успешно изменена в реестре."
        } else {
            Write-OK "Язык для не-Unicode программ уже установлен на русский."
        }
    }

    if ($availableCommands.CopyUserInternationalSettingsToSystem) {
        Write-Info "Копирование международных настроек (современный метод)..."
        Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True
        Write-OK "Настройки успешно скопированы."
    } else {
        $regPathIntl = "Registry::HKEY_USERS\.DEFAULT\Control Panel\International"
        if(Test-Path $regPathIntl){
            Write-Info "Проверка настроек для экрана приветствия..."
            $intlSettings = Get-ItemProperty -Path $regPathIntl
            if (($intlSettings.Locale -ne "0000$($SystemLocaleId)") -or ($intlSettings.LocaleName -ne $Language)) {
                Write-Info "Применение формата для экрана приветствия (метод совместимости)..."
                Set-ItemProperty -Path $regPathIntl -Name "Locale" -Value "0000$($SystemLocaleId)"
                Set-ItemProperty -Path $regPathIntl -Name "LocaleName" -Value $Language
                $rebootRequired = $true
                Write-OK "Настройки для экрана приветствия обновлены."
            }
             else {
                Write-OK "Настройки для экрана приветствия уже корректны."
            }
        }
    }

    Write-OK "Все операции успешно завершены."
    if ($rebootRequired) {
        $questionRestartComputer = [System.Windows.Forms.MessageBox]::Show("Для применения изменений требуется перезагрузка.`nПерезагрузить сейчас?", "Требуется перезагрузка", "YesNo", "Question")
        if ($questionRestartComputer -eq "Yes") {
            Restart-Computer -Force
        }
    }

}
catch {
    Write-Err "Произошла критическая ошибка при выполнении скрипта: $($_.Exception.Message)"
}