param(
    [string]$NewComputerName,
    [string]$FileNameBase,
    [string]$ScriptRoot
)

if ([string]::IsNullOrWhiteSpace($ScriptRoot)) {
    $ScriptRoot = $PSScriptRoot
}

if ([string]::IsNullOrWhiteSpace($NewComputerName)) {
    $NewComputerName = $env:COMPUTERNAME
}

if ([string]::IsNullOrWhiteSpace($FileNameBase)) {
    $FileNameBase = $NewComputerName
}


$currentDate = Get-Date -Format 'dd/MM/yyyy'
$csvFile = Join-Path $ScriptRoot "$($FileNameBase)_INVENT.csv"
$htmlFile = Join-Path $ScriptRoot "$($FileNameBase)_INVENT.html"

Write-Host ' [ .. ] Collecting system information...' -ForegroundColor DarkGray

$SystemInfoParams = @{ ClassName = 'Win32_OperatingSystem'; ErrorAction = 'SilentlyContinue' }
$ProcessorInfoParams = @{ ClassName = 'Win32_Processor'; ErrorAction = 'SilentlyContinue' }
$GraphicsAdapterParams = @{ ClassName = 'Win32_VideoController'; ErrorAction = 'SilentlyContinue' }
$MemoryModulesParams = @{ ClassName = 'Win32_PhysicalMemory'; ErrorAction = 'SilentlyContinue' }
$DiskInfosParams = @{ ClassName = 'Win32_LogicalDisk'; Filter = 'DriveType = 3'; ErrorAction = 'SilentlyContinue' }
$NetworkAdaptersParams = @{ ClassName = 'Win32_NetworkAdapter'; Filter = 'NetConnectionStatus = 2'; ErrorAction = 'SilentlyContinue' }
$NetworkAdapterConfigParams = @{ ClassName = 'Win32_NetworkAdapterConfiguration'; Filter = 'IPEnabled = TRUE'; ErrorAction = 'SilentlyContinue' }
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
$localUsers = Get-LocalUser | Where-Object { $_.SID.Value -notmatch '-(500|501|503)$' -and $_.Name -notin 'WDAGUtilityAccount' }

$csvOutput = . {
    [PSCustomObject]@{ Property = 'Computer Name'; Value = $NewComputerName }

    if ($systemInfo) {
        [PSCustomObject]@{ Property = 'Operating System'; Value = "$($systemInfo.Caption) $($systemInfo.OSArchitecture)" }
        [PSCustomObject]@{ Property = 'OS Version'; Value = $systemInfo.Version }
        [PSCustomObject]@{ Property = 'OS Locale'; Value = $systemInfo.Locale }
        $InstallDate = try { $systemInfo.InstallDate }
        catch { 'N/A' }
        [PSCustomObject]@{ Property = 'OS Installation Date'; Value = if ($InstallDate -is [datetime]) { $InstallDate.ToString('dd/MM/yyyy HH:mm:ss') } else { $InstallDate } }
        [PSCustomObject]@{ Property = 'OS Serial Number'; Value = $systemInfo.SerialNumber }
    }

    if ($computerSystem) {
        [PSCustomObject]@{ Property = 'PC Manufacturer'; Value = $computerSystem.Manufacturer }
        [PSCustomObject]@{ Property = 'PC Model'; Value = $computerSystem.Model }
        if ($computerSystem.PartOfDomain) {
            [PSCustomObject]@{ Property = 'Domain'; Value = $computerSystem.Domain }
        }
        else {
            [PSCustomObject]@{ Property = 'Workgroup'; Value = $computerSystem.Workgroup }
        }
    }
    
    if ($localUsers) {
        foreach ($user in $localUsers | Where-Object { $_.Enabled }) {
            [PSCustomObject]@{ Property = 'Local User - Enabled'; Value = $user.Name }
        }
        foreach ($user in $localUsers | Where-Object { -not $_.Enabled }) {
            [PSCustomObject]@{ Property = 'Local User - Disabled'; Value = $user.Name }
        }
    }

    if ($motherboardInfo) {
        [PSCustomObject]@{ Property = 'Motherboard - Manufacturer'; Value = $motherboardInfo.Manufacturer }
        [PSCustomObject]@{ Property = 'Motherboard - Product'; Value = $motherboardInfo.Product }
        [PSCustomObject]@{ Property = 'Motherboard - Version'; Value = $motherboardInfo.Version }
        [PSCustomObject]@{ Property = 'Motherboard - Serial Number'; Value = $motherboardInfo.SerialNumber }
    }

    if ($biosInfo) {
        [PSCustomObject]@{ Property = 'BIOS - Manufacturer'; Value = $biosInfo.Manufacturer }
        [PSCustomObject]@{ Property = 'BIOS - Version'; Value = $biosInfo.SMBIOSBIOSVersion }
        [PSCustomObject]@{ Property = 'BIOS - Serial Number'; Value = $biosInfo.SerialNumber }
    }

    if ($processorInfo) {
        [PSCustomObject]@{ Property = 'Processor'; Value = $processorInfo.Name.Trim() }
        [PSCustomObject]@{ Property = 'Processor - Number of Cores'; Value = $processorInfo.NumberOfCores }
        [PSCustomObject]@{ Property = 'Processor - Number of Logical Processors'; Value = $processorInfo.NumberOfLogicalProcessors }
        [PSCustomObject]@{ Property = 'Processor - Max Speed (MHz)'; Value = $processorInfo.MaxClockSpeed }
    }

    if ($graphicsAdapters) {
        $adapterIndex = 1
        foreach ($adapter in $graphicsAdapters) {
            $prefix = if ($graphicsAdapters.Count -gt 1) { "Graphics Card $adapterIndex" } else { 'Graphics Card' }
            [PSCustomObject]@{ Property = "$prefix - Name"; Value = $adapter.Name }
            [PSCustomObject]@{ Property = "$prefix - Driver Version"; Value = $adapter.DriverVersion }
             if ($adapter.AdapterRAM -gt 0) {
                 $vramGB = [math]::Round($adapter.AdapterRAM / 1GB, 2)
                 [PSCustomObject]@{ Property = "$prefix - Video RAM (GB)"; Value = $vramGB }
             }
             else {
                  [PSCustomObject]@{ Property = "$prefix - Video RAM (GB)"; Value = 'N/A' }
             }
            $adapterIndex++
        }
    }

    if ($memoryModules) {
        $totalRamBytes = ($memoryModules | Measure-Object -Property Capacity -Sum).Sum
        $totalRamGB = [math]::Round($totalRamBytes / 1GB, 2)
        [PSCustomObject]@{ Property = 'Total RAM (GB)'; Value = $totalRamGB }

        foreach ($module in $memoryModules) {
            $capacityMB = [math]::Round($module.Capacity / 1MB, 0)
            [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Manufacturer"; Value = $module.Manufacturer }
            [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Part Number"; Value = $module.PartNumber }
            [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Capacity (MB)"; Value = $capacityMB }
            [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Speed (MHz)"; Value = $module.Speed }
            [PSCustomObject]@{ Property = "Memory Module $($module.DeviceLocator) - Serial Number"; Value = $module.SerialNumber }
        }
    }

    if ($diskInfos) {
        foreach ($disk in $diskInfos) {
            $capacityGB = [math]::Round($disk.Size / 1GB, 2)
            $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Volume Name"; Value = $disk.VolumeName }
            [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - File System"; Value = $disk.FileSystem }
            [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Capacity (GB)"; Value = $capacityGB }
            [PSCustomObject]@{ Property = "Disk $($disk.DeviceID) - Free Space (GB)"; Value = $freeSpaceGB }
        }
    }

    if ($networkAdapters) {
        foreach ($adapter in $networkAdapters) {
            $adapterConfig = $networkAdapterConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex } | Select-Object -First 1

            if ($adapterConfig) {
                 [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Description"; Value = $adapter.Description }
                 [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - MAC Address"; Value = $adapterConfig.MACAddress }

                 $ipAddress = ($adapterConfig.IPAddress | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }) | Select-Object -First 1
                 if (-not $ipAddress) { $ipAddress = ($adapterConfig.IPAddress | Select-Object -First 1) }
                 [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - IP Address"; Value = if ($ipAddress) { $ipAddress } else { '-' } }

                 $subnetMask = '-'
                 if ($ipAddress) {
                     $ipIndex = [array]::IndexOf($adapterConfig.IPAddress, $ipAddress)
                     if ($ipIndex -ge 0 -and $ipIndex -lt $adapterConfig.IPSubnet.Count) {
                         $subnetMask = $adapterConfig.IPSubnet[$ipIndex]
                     }
                 }
                 [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Subnet Mask"; Value = $subnetMask }

                 $defaultGateway = ($adapterConfig.DefaultIPGateway | Select-Object -First 1)
                 [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - Default Gateway"; Value = if ($defaultGateway) { $defaultGateway } else { '-' } }

                 $dnsServers = ($adapterConfig.DNSServerSearchOrder | Select-Object -First 2) -join ', '
                 [PSCustomObject]@{ Property = "Network Adapter [$($adapter.Name)] - DNS Servers"; Value = if ($dnsServers) { $dnsServers } else { '-' } }
            }
        }
    }
}

foreach ($item in $csvOutput) {
    if ([string]::IsNullOrWhiteSpace($item.Value)) {
        $item.Value = '-'
    }
}

$csvOutput | Export-Csv -Path $csvFile -Encoding UTF8 -NoTypeInformation

$htmlParams = @{
    Head = @"
<meta charset="UTF-8">
<title>System Information for $($NewComputerName)</title>
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 10pt; margin: 20px; }
    h1 { color: #336699; border-bottom: 2px solid #336699; padding-bottom: 5px; }
    table { width: 80%; border-collapse: collapse; margin-top: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    th, td { padding: 8px 12px; border: 1px solid #ccc; text-align: left; vertical-align: top; }
    th { background-color: #eef4f9; font-weight: 600; color: #333; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    tr:hover { background-color: #f1f1f1; }
    td:first-child { width: 35%; font-weight: 500; color: #555; }
</style>
"@
    Body        = "<h1>System Information - $($NewComputerName)</h1><br>"
    PostContent = "<br><p style='font-size: 8pt; color: #888; margin-top: 15px;'>Report generated on $currentDate</p>"
}

$csvOutput | Select-Object @{Name = 'Property'; Expression = { $_.Property } }, @{Name = 'Value'; Expression = { $_.Value } } | ConvertTo-Html @htmlParams | Out-File -FilePath $htmlFile -Encoding UTF8

Write-Host " [ ** ] System Inventorization saved in files: '$csvFile' & '$htmlFile'" -ForegroundColor Green