$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Get-InterfaceIndex {
    param([object]$Item)

    if ($null -ne $Item.ifIndex) {
        return [int]$Item.ifIndex
    }
    return [int]$Item.InterfaceIndex
}

function Add-IndexedValue {
    param(
        [hashtable]$Index,
        [int]$Key,
        [object]$Value
    )

    if ($Index.ContainsKey($Key)) {
        $Index[$Key] = @($Index[$Key]) + @($Value)
    } else {
        $Index[$Key] = @($Value)
    }
}

# Each provider is queried globally at most once. Provider failures are isolated so
# one slow or unavailable source cannot suppress otherwise valid inventory JSON.
$signedDrivers = @()
try {
    $signedDrivers = @(
        Get-CimInstance -ClassName Win32_PnPSignedDriver `
            -Property DeviceID, Manufacturer, DeviceName, DriverProviderName, DriverVersion `
            -OperationTimeoutSec 8 -ErrorAction Stop
    )
} catch {}

$netAdapters = @()
try {
    $netAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object -Property ifIndex)
} catch {}

$statisticsSourceAvailable = $false
$allStatistics = @()
try {
    $allStatistics = @(Get-NetAdapterStatistics -IncludeHidden -ErrorAction Stop)
    $statisticsSourceAvailable = $true
} catch {}

$ipConfigurationSourceAvailable = $false
$allIpConfigurations = @()
try {
    $allIpConfigurations = @(Get-NetIPConfiguration -ErrorAction Stop)
    $ipConfigurationSourceAvailable = $true
} catch {}

$addressesSourceAvailable = $false
$allAddresses = @()
try {
    $allAddresses = @(Get-NetIPAddress -ErrorAction Stop)
    $addressesSourceAvailable = $true
} catch {}

$routesSourceAvailable = $false
$allRoutes = @()
try {
    $allRoutes = @(Get-NetRoute -ErrorAction Stop)
    $routesSourceAvailable = $true
} catch {}

$dnsSourceAvailable = $false
$allDnsAddresses = @()
try {
    $allDnsAddresses = @(Get-DnsClientServerAddress -ErrorAction Stop)
    $dnsSourceAvailable = $true
} catch {}

$driversByDeviceId = @{}
foreach ($driver in $signedDrivers) {
    if ($null -ne $driver.DeviceID -and -not $driversByDeviceId.ContainsKey([string]$driver.DeviceID)) {
        $driversByDeviceId[[string]$driver.DeviceID] = $driver
    }
}

$statisticsByInterfaceIndex = @{}
foreach ($statistics in $allStatistics) {
    $interfaceIndex = Get-InterfaceIndex $statistics
    if (-not $statisticsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $statisticsByInterfaceIndex[$interfaceIndex] = $statistics
    }
}

$ipConfigurationsByInterfaceIndex = @{}
foreach ($ipConfiguration in $allIpConfigurations) {
    $interfaceIndex = Get-InterfaceIndex $ipConfiguration
    if (-not $ipConfigurationsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $ipConfigurationsByInterfaceIndex[$interfaceIndex] = $ipConfiguration
    }
}

$addressesByInterfaceIndex = @{}
foreach ($address in $allAddresses) {
    $interfaceIndex = Get-InterfaceIndex $address
    Add-IndexedValue $addressesByInterfaceIndex $interfaceIndex ([ordered]@{
        family = [string]$address.AddressFamily
        address = [string]$address.IPAddress
        prefix_length = [int]$address.PrefixLength
    })
}

$routesByInterfaceIndex = @{}
foreach ($route in $allRoutes) {
    $interfaceIndex = Get-InterfaceIndex $route
    Add-IndexedValue $routesByInterfaceIndex $interfaceIndex ([ordered]@{
        family = [string]$route.AddressFamily
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        route_metric = [int]$route.RouteMetric
    })
}

$dnsByInterfaceIndex = @{}
foreach ($dnsAddress in $allDnsAddresses) {
    $interfaceIndex = Get-InterfaceIndex $dnsAddress
    foreach ($serverAddress in @($dnsAddress.ServerAddresses)) {
        Add-IndexedValue $dnsByInterfaceIndex $interfaceIndex ([string]$serverAddress)
    }
}

$adapters = @($netAdapters | ForEach-Object {
    $adapter = $_
    $interfaceIndex = [int]$adapter.ifIndex
    $signedDriver = $null
    if ($null -ne $adapter.PnPDeviceID -and $driversByDeviceId.ContainsKey([string]$adapter.PnPDeviceID)) {
        $signedDriver = $driversByDeviceId[[string]$adapter.PnPDeviceID]
    }
    $statistics = $null
    if ($statisticsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $statistics = $statisticsByInterfaceIndex[$interfaceIndex]
    }
    $ipConfiguration = $null
    if ($ipConfigurationsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $ipConfiguration = $ipConfigurationsByInterfaceIndex[$interfaceIndex]
    }
    $addresses = @()
    if ($addressesByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $addresses = @($addressesByInterfaceIndex[$interfaceIndex])
    }
    $routes = @()
    if ($routesByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $routes = @($routesByInterfaceIndex[$interfaceIndex])
    }
    $dns = @()
    if ($dnsByInterfaceIndex.ContainsKey($interfaceIndex)) {
        $dns = @($dnsByInterfaceIndex[$interfaceIndex])
    }
    $gateways = @(
        @($ipConfiguration.IPv4DefaultGateway | ForEach-Object { [string]$_.NextHop })
        @($ipConfiguration.IPv6DefaultGateway | ForEach-Object { [string]$_.NextHop })
    )
    [ordered]@{
        interface_guid = if ($null -eq $adapter.InterfaceGuid) { $null } else { [string]$adapter.InterfaceGuid }
        interface_index = $interfaceIndex
        name = [string]$adapter.Name
        description = if ($null -eq $adapter.InterfaceDescription) { $null } else { [string]$adapter.InterfaceDescription }
        status = if ($null -eq $adapter.Status) { $null } else { [string]$adapter.Status }
        virtual = if ($null -eq $adapter.Virtual) { $null } else { [bool]$adapter.Virtual }
        hardware_interface = if ($null -eq $adapter.HardwareInterface) { $null } else { [bool]$adapter.HardwareInterface }
        manufacturer = if ($null -eq $signedDriver.Manufacturer) { $null } else { [string]$signedDriver.Manufacturer }
        model = if ($null -eq $signedDriver.DeviceName) { $null } else { [string]$signedDriver.DeviceName }
        driver_description = if ($null -eq $adapter.DriverDescription) { $null } else { [string]$adapter.DriverDescription }
        driver_provider = if ($null -eq $signedDriver.DriverProviderName) { $null } else { [string]$signedDriver.DriverProviderName }
        driver_version = if ($null -ne $signedDriver.DriverVersion) {
            [string]$signedDriver.DriverVersion
        } elseif ($null -ne $adapter.DriverVersion) {
            [string]$adapter.DriverVersion
        } else {
            $null
        }
        mac_address = if ($null -eq $adapter.MacAddress) { $null } else { [string]$adapter.MacAddress }
        link_speed = if ($null -eq $adapter.LinkSpeed) { $null } else { [string]$adapter.LinkSpeed }
        statistics_available = $statisticsSourceAvailable -and $null -ne $statistics
        ip_configuration_available = $ipConfigurationSourceAvailable -and $null -ne $ipConfiguration
        addresses_available = $addressesSourceAvailable
        routes_available = $routesSourceAvailable
        dns_available = $dnsSourceAvailable
        received_bytes = if ($null -eq $statistics) { $null } else { [long]$statistics.ReceivedBytes }
        sent_bytes = if ($null -eq $statistics) { $null } else { [long]$statistics.SentBytes }
        received_packets = if ($null -eq $statistics) { $null } else { [long]($statistics.ReceivedUnicastPackets + $statistics.ReceivedMulticastPackets + $statistics.ReceivedBroadcastPackets) }
        sent_packets = if ($null -eq $statistics) { $null } else { [long]($statistics.SentUnicastPackets + $statistics.SentMulticastPackets + $statistics.SentBroadcastPackets) }
        received_errors = if ($null -eq $statistics) { $null } else { [long]$statistics.ReceivedPacketErrors }
        sent_errors = if ($null -eq $statistics) { $null } else { [long]$statistics.OutboundPacketErrors }
        received_discards = if ($null -eq $statistics) { $null } else { [long]$statistics.ReceivedDiscardedPackets }
        sent_discards = if ($null -eq $statistics) { $null } else { [long]$statistics.OutboundDiscardedPackets }
        addresses = $addresses
        routes = $routes
        gateways = $gateways
        dns_servers = @($dns)
    }
})

[ordered]@{
    schema_version = '1.0.0'
    powershell_edition = [string]$PSVersionTable.PSEdition
    powershell_version = [string]$PSVersionTable.PSVersion
    adapters = $adapters
} | ConvertTo-Json -Compress -Depth 8
