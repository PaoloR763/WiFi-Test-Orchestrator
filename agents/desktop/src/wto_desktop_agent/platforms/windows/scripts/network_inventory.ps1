$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$signedDrivers = @()
try { $signedDrivers = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop) } catch {}
$netAdapters = @()
try { $netAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object -Property ifIndex) } catch {}
$adapters = @($netAdapters | ForEach-Object {
    $adapter = $_
    $signedDriver = $signedDrivers | Where-Object { $_.DeviceID -eq $adapter.PnPDeviceID } | Select-Object -First 1
    $statistics = $null
    $statisticsAvailable = $false
    try {
        $statistics = Get-NetAdapterStatistics -Name $adapter.Name -IncludeHidden -ErrorAction Stop
        $statisticsAvailable = $null -ne $statistics
    } catch {}
    $ipConfiguration = $null
    $ipConfigurationAvailable = $false
    try {
        $ipConfiguration = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
        $ipConfigurationAvailable = $null -ne $ipConfiguration
    } catch {}
    $addresses = @()
    $addressesAvailable = $false
    try {
        $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                family = [string]$_.AddressFamily
                address = [string]$_.IPAddress
                prefix_length = [int]$_.PrefixLength
            }
        })
        $addressesAvailable = $true
    } catch {}
    $routes = @()
    $routesAvailable = $false
    try {
        $routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                family = [string]$_.AddressFamily
                destination_prefix = [string]$_.DestinationPrefix
                next_hop = [string]$_.NextHop
                route_metric = [int]$_.RouteMetric
            }
        })
        $routesAvailable = $true
    } catch {}
    $dns = @()
    $dnsAvailable = $false
    try {
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | ForEach-Object {
            @($_.ServerAddresses | ForEach-Object { [string]$_ })
        })
        $dnsAvailable = $true
    } catch {}
    $gateways = @(
        @($ipConfiguration.IPv4DefaultGateway | ForEach-Object { [string]$_.NextHop })
        @($ipConfiguration.IPv6DefaultGateway | ForEach-Object { [string]$_.NextHop })
    )
    [ordered]@{
        interface_guid = if ($null -eq $adapter.InterfaceGuid) { $null } else { [string]$adapter.InterfaceGuid }
        interface_index = [int]$adapter.ifIndex
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
        statistics_available = $statisticsAvailable
        ip_configuration_available = $ipConfigurationAvailable
        addresses_available = $addressesAvailable
        routes_available = $routesAvailable
        dns_available = $dnsAvailable
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
