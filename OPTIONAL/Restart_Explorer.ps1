Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 0 -Type DWord -Force
Stop-Process -Name explorer -Force
Start-Sleep -Seconds 3.5
Start-Process -FilePath "$env:windir\explorer.exe"
Start-Sleep -Seconds 2.5
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 1 -Type DWord -Force