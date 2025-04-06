Clear-Host

if ($PSScriptRoot) {
    $currentPath = $PSScriptRoot
} else {
    $currentPath = Get-Location
}

$csvFile = Join-Path $currentPath "$($env:COMPUTERNAME)_INVENT.csv"
$htmlFile = Join-Path $currentPath "$($env:COMPUTERNAME)_INVENT.html"

Write-Host ' [ .. ] Collecting system information...' -ForegroundColor DarkGray

$SystemInfoParams = @{ ClassName = 'Win32_OperatingSystem'; ErrorAction = 'SilentlyContinue' }
$ProcessorInfoParams = @{ ClassName = 'Win32_Processor'; ErrorAction = 'SilentlyContinue' }
$GraphicsAdapterParams = @{ ClassName = 'Win32_VideoController'; ErrorAction = 'SilentlyContinue' }
$MemoryModulesParams = @{ ClassName = 'Win32_PhysicalMemory'; ErrorAction = 'SilentlyContinue' }
$DiskInfosParams = @{ ClassName = 'Win32_LogicalDisk'; Filter = "DriveType = 3"; ErrorAction = 'SilentlyContinue' }
$NetworkAdaptersParams = @{ ClassName = 'Win32_NetworkAdapter'; Filter = "NetConnectionStatus = 2"; ErrorAction = 'SilentlyContinue' }
$NetworkAdapterConfigParams = @{ ClassName = 'Win32_NetworkAdapterConfiguration'; Filter = "IPEnabled = TRUE"; ErrorAction = 'SilentlyContinue' }
$ComputerSystemParams = @{ ClassName = 'Win32_ComputerSystem'; ErrorAction = 'SilentlyContinue' }
$MotherboardInfoParams = @{ ClassName = 'Win32_BaseBoard'; ErrorAction = 'SilentlyContinue' }
$BiosInfoParams = @{ ClassName = 'Win32_BIOS'; ErrorAction = 'SilentlyContinue' }

$systemInfo = Get-CimInstance @SystemInfoParams
$processorInfo = Get-CimInstance @ProcessorInfoParams | Select-Object -First 1
$graphicsAdapters = Get-CimInstance @GraphicsAdapterParams
$memoryModules = Get-CimInstance @MemoryModulesParams
$diskInfos = Get-CimInstance @DiskInfosParams
$networkAdapters = Get-CimInstance @NetworkAdaptersParams
$networkAdapterConfigs = Get-CimInstance @NetworkAdapterConfigParams
$computerSystem = Get-CimInstance @ComputerSystemParams
$motherboardInfo = Get-CimInstance @MotherboardInfoParams
$biosInfo = Get-CimInstance @BiosInfoParams

$csvOutput = @()
$csvOutput += [PSCustomObject]@{ Property = 'Computer Name'; Value = $env:COMPUTERNAME }
if ($systemInfo) {
    $csvOutput += [PSCustomObject]@{ Property = 'Operating System'; Value = "$($systemInfo.Caption) $($systemInfo.OSArchitecture)" }
    $csvOutput += [PSCustomObject]@{ Property = 'OS Version'; Value = $systemInfo.Version }
    Try { $InstallDate = $systemInfo.InstallDate } Catch { $InstallDate = 'N/A' }
    $csvOutput += [PSCustomObject]@{ Property = 'OS Installation Date'; Value = if ($InstallDate -is [datetime]) { $InstallDate.ToString('yyyy-MM-dd HH:mm:ss') } else { $InstallDate } }
    $csvOutput += [PSCustomObject]@{ Property = 'OS Serial Number'; Value = $systemInfo.SerialNumber }
    $csvOutput += [PSCustomObject]@{ Property = 'Registered User'; Value = $systemInfo.RegisteredUser }
}
if ($computerSystem) {
    $csvOutput += [PSCustomObject]@{ Property = 'PC Manufacturer'; Value = $computerSystem.Manufacturer }
    $csvOutput += [PSCustomObject]@{ Property = 'PC Model'; Value = $computerSystem.Model }
    if ($computerSystem.PartOfDomain) {
        $csvOutput += [PSCustomObject]@{ Property = 'Domain'; Value = $computerSystem.Domain }
    } else {
        $csvOutput += [PSCustomObject]@{ Property = 'Workgroup'; Value = $computerSystem.Workgroup }
    }
}
if ($motherboardInfo) {
    $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Manufacturer'; Value = $motherboardInfo.Manufacturer }
    $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Product'; Value = $motherboardInfo.Product }
    $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Version'; Value = $motherboardInfo.Version }
    $csvOutput += [PSCustomObject]@{ Property = 'Motherboard - Serial Number'; Value = $motherboardInfo.SerialNumber }
}
if ($biosInfo) {
    $csvOutput += [PSCustomObject]@{ Property = 'BIOS - Manufacturer'; Value = $biosInfo.Manufacturer }
    $csvOutput += [PSCustomObject]@{ Property = 'BIOS - Version'; Value = $biosInfo.SMBIOSBIOSVersion }
    $csvOutput += [PSCustomObject]@{ Property = 'BIOS - Serial Number'; Value = $biosInfo.SerialNumber }
}
if ($processorInfo) {
    $csvOutput += [PSCustomObject]@{ Property = 'Processor'; Value = $processorInfo.Name.Trim() }
    $csvOutput += [PSCustomObject]@{ Property = 'Processor - Number of Cores'; Value = $processorInfo.NumberOfCores }
    $csvOutput += [PSCustomObject]@{ Property = 'Processor - Number of Logical Processors'; Value = $processorInfo.NumberOfLogicalProcessors }
    $csvOutput += [PSCustomObject]@{ Property = 'Processor - Max Speed (MHz)'; Value = $processorInfo.MaxClockSpeed }
}
if ($graphicsAdapters) {
    $adapterIndex = 1
    foreach ($adapter in $graphicsAdapters) {
        $prefix = if ($graphicsAdapters.Count -gt 1) { "Graphics Card $adapterIndex" } else { "Graphics Card" }
        $csvOutput += [PSCustomObject]@{ Property = "$prefix - Name"; Value = $adapter.Name }
        $csvOutput += [PSCustomObject]@{ Property = "$prefix - Driver Version"; Value = $adapter.DriverVersion }
         if ($adapter.AdapterRAM -gt 0) {
             $vramGB = [math]::Round($adapter.AdapterRAM / 1GB, 2)
             $csvOutput += [PSCustomObject]@{ Property = "$prefix - Video RAM (GB)"; Value = $vramGB }
         } else {
              $csvOutput += [PSCustomObject]@{ Property = "$prefix - Video RAM (GB)"; Value = "N/A" }
         }
        $adapterIndex++
    }
}
if ($memoryModules) {
    $totalRamBytes = ($memoryModules | Measure-Object -Property Capacity -Sum).Sum
    $totalRamGB = [math]::Round($totalRamBytes / 1GB, 2)
    $csvOutput += [PSCustomObject]@{ Property = 'Total RAM (GB)'; Value = $totalRamGB }
    foreach ($module in $memoryModules) {
        $capacityMB = [math]::Round($module.Capacity / 1MB, 0)
        $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Manufacturer"; Value = $module.Manufacturer }
        $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Part Number"; Value = $module.PartNumber }
        $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Capacity (MB)"; Value = $capacityMB }
        $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Speed (MHz)"; Value = $module.Speed }
         $csvOutput += [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Serial Number"; Value = $module.SerialNumber }
    }
}
if ($diskInfos) {
    foreach ($disk in $diskInfos) {
        $capacityGB = [math]::Round($disk.Size / 1GB, 2)
        $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Volume Name"; Value = $disk.VolumeName }
        $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - File System"; Value = $disk.FileSystem }
        $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Capacity (GB)"; Value = $capacityGB }
        $csvOutput += [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Free Space (GB)"; Value = $freeSpaceGB }
    }
}
if ($networkAdapters) {
    foreach ($adapter in $networkAdapters) {
        $adapterConfig = $networkAdapterConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } | Select-Object -First 1
        if ($adapterConfig) {
             $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Description"; Value = $adapter.Description }
             $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - MAC Address"; Value = $adapterConfig.MACAddress }
             $ipAddress = ($adapterConfig.IPAddress | Where-Object {$_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'}) | Select-Object -First 1
             if (-not $ipAddress) { $ipAddress = ($adapterConfig.IPAddress | Select-Object -First 1) }
             $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - IP Address"; Value = if ($ipAddress) { $ipAddress } else { '-' } }
             $subnetMask = '-'
             if ($ipAddress) {
                 $ipIndex = [array]::IndexOf($adapterConfig.IPAddress, $ipAddress)
                 if ($ipIndex -ge 0 -and $ipIndex -lt $adapterConfig.IPSubnet.Count) {
                     $subnetMask = $adapterConfig.IPSubnet[$ipIndex]
                 }
             }
             $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Subnet Mask"; Value = $subnetMask }
             $defaultGateway = ($adapterConfig.DefaultIPGateway | Select-Object -First 1)
             $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Default Gateway"; Value = if ($defaultGateway) { $defaultGateway } else { '-' } }
             $dnsServers = ($adapterConfig.DNSServerSearchOrder | Select-Object -First 2) -join ', '
             $csvOutput += [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - DNS Servers"; Value = if ($dnsServers) { $dnsServers } else { '-' } }
        }
    }
}

$csvEncoding = 'UTF8'
try {
    $windowsVersion = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion
    $productName = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName
    if ($productName -like '*Windows 10*') {
        $csvEncoding = 'UTF8BOM'
    }
}
catch {
    Write-Warning 'Failed to detect Windows version. Continuing with default settings (Win11/UTF8)'
    $windowsVersion = "24H2"
}

$csvOutput | Export-Csv -Path $csvFile -Encoding $csvEncoding -NoTypeInformation -Delimiter ','

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Information for $($env:COMPUTERNAME)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 10pt; margin: 20px; }
        h1 { color: #336699; border-bottom: 2px solid #336699; padding-bottom: 5px; }
        table { width: 80%; border-collapse: collapse; margin-top: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { padding: 8px 12px; border: 1px solid #ccc; text-align: left; }
        th { background-color: #eef4f9; font-weight: 600; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        td:first-child { width: 35%; font-weight: 500; color: #555; }
    </style>
</head>
<body>
    <h1>System Information - $($env:COMPUTERNAME)</h1>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
"@

$currentDate = Get-Date -Format 'dd/MM/yyyy'

foreach ($item in $csvOutput) {
    $escapedValue = [System.Web.HttpUtility]::HtmlEncode($item.Value)
    $htmlContent += "        <tr><td>$($item.Property)</td><td>$($escapedValue)</td></tr>`n"
}

$htmlContent += @'
</table>
'@
$htmlContent += "<p style='font-size: 8pt; color: #888; margin-top: 15px;'>Report generated on $currentDate</p>`n"

$htmlContent += @'
</body>
</html>
'@
$htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8

Write-Host " [ ** ] System Inventorization saved in files: '$csvFile' and '$htmlFile'" -ForegroundColor Green