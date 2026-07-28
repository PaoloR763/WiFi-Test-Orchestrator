package com.wifitestorchestrator.agent.platform.connectivity

import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationReason
import com.wifitestorchestrator.agent.domain.connectivity.DefaultNetworkPresence
import com.wifitestorchestrator.agent.domain.connectivity.NetworkTransport
import com.wifitestorchestrator.agent.domain.connectivity.ObservationAvailability
import com.wifitestorchestrator.agent.domain.connectivity.ObservationConfidence
import com.wifitestorchestrator.agent.domain.connectivity.ObservationSource
import com.wifitestorchestrator.agent.domain.connectivity.WifiAssociationScope
import com.wifitestorchestrator.agent.domain.connectivity.WifiAssociationState
import com.wifitestorchestrator.agent.domain.connectivity.WifiBand
import com.wifitestorchestrator.agent.domain.connectivity.WifiSecurityType
import com.wifitestorchestrator.agent.domain.connectivity.WifiStandard
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidConnectivitySnapshotMapperTest {
    private val mapper = AndroidConnectivitySnapshotMapper()

    @Test
    fun `initial pending and confirmed absence remain distinct`() {
        val initial = mapper.initial(ConnectivityCollectionProfile.BASIC, stamp(0))
        val pending =
            mapper.capabilitiesPending(
                ConnectivityCollectionProfile.BASIC,
                stamp(1),
                blocked = false,
            )
        val absent = mapper.absent(ConnectivityCollectionProfile.BASIC, stamp(2))

        assertEquals(
            ConnectivityObservationReason.INITIAL_CALLBACK_PENDING,
            initial.defaultNetwork.presence.reason,
        )
        assertEquals(DefaultNetworkPresence.PRESENT, pending.defaultNetwork.presence.value)
        assertEquals(true, pending.defaultNetwork.capabilitiesPending.value)
        assertEquals(false, pending.defaultNetwork.blocked.value)
        assertEquals(
            ConnectivityObservationReason.CAPABILITIES_PENDING,
            pending.defaultNetwork.transports.reason,
        )
        assertEquals(DefaultNetworkPresence.ABSENT, absent.defaultNetwork.presence.value)
        assertEquals(
            ObservationAvailability.NOT_APPLICABLE,
            absent.defaultNetwork.isValidated.availability,
        )
        assertNull(absent.defaultNetwork.isValidated.value)
        assertEquals(
            ConnectivityObservationReason.NO_DEFAULT_NETWORK,
            absent.defaultNetwork.isValidated.reason,
        )
    }

    @Test
    fun `authorized network scoped wifi maps identity KPIs and derivations without leakage`() {
        val snapshot =
            mapper.available(
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                stamp = stamp(7),
                capabilities =
                    capabilities(
                        transports = setOf(NetworkTransport.WIFI),
                        wifiInfo =
                            wifiInfo(
                                ssid = value("\"  Lab Wi-Fi  \""),
                                bssid = value("AA:0B:CC:1D:EE:2F"),
                                rssi = value(-61),
                                frequency = value(5975),
                                linkSpeed = value(433),
                                rxLinkSpeed = value(390),
                                txLinkSpeed = value(351),
                                standard = value(ScanResult.WIFI_STANDARD_11AX),
                                security = value(WifiInfo.SECURITY_TYPE_SAE),
                            ),
                    ),
                blocked = true,
            )

        assertEquals(7, snapshot.sequence)
        assertEquals(DefaultNetworkPresence.PRESENT, snapshot.defaultNetwork.presence.value)
        assertEquals(setOf(NetworkTransport.WIFI), snapshot.defaultNetwork.transports.value?.values)
        assertEquals(true, snapshot.defaultNetwork.blocked.value)
        assertEquals(WifiAssociationState.ASSOCIATED, snapshot.wifiAssociation.association.value)
        assertEquals(WifiAssociationScope.DEFAULT_NETWORK, snapshot.wifiAssociation.scope)
        assertEquals(
            "\"  Lab Wi-Fi  \"",
            snapshot.wifiAssociation.ssid.value?.reportedValue,
        )
        assertEquals("  Lab Wi-Fi  ", snapshot.wifiAssociation.ssid.value?.displayValue)
        assertEquals(
            "aa:0b:cc:1d:ee:2f",
            snapshot.wifiAssociation.bssid.value?.canonicalValue,
        )
        assertEquals(-61, snapshot.wifiAssociation.rssiDbm.value)
        assertEquals(5975, snapshot.wifiAssociation.frequencyMhz.value)
        assertEquals(WifiBand.GHZ_6, snapshot.wifiAssociation.band.value)
        assertEquals(5, snapshot.wifiAssociation.primaryChannel.value)
        assertEquals(433, snapshot.wifiAssociation.linkSpeedMbps.value)
        assertEquals(390, snapshot.wifiAssociation.rxLinkSpeedMbps.value)
        assertEquals(351, snapshot.wifiAssociation.txLinkSpeedMbps.value)
        assertEquals(WifiStandard.IEEE_802_11AX, snapshot.wifiAssociation.standard.value)
        assertEquals(WifiSecurityType.SAE, snapshot.wifiAssociation.securityType.value)
        assertEquals(
            ConnectivityObservationReason.UNSUPPORTED_API,
            snapshot.wifiAssociation.channelWidthMhz.reason,
        )
        assertEquals(
            ObservationSource.DERIVED_FROM_FREQUENCY,
            snapshot.wifiAssociation.primaryChannel.source,
        )
        assertFalse(snapshot.toString().contains("Lab Wi-Fi"))
        assertFalse(snapshot.toString().contains("AA:0B:CC"))
        assertFalse(snapshot.toString().contains("aa:0b:cc"))
    }

    @Test
    fun `basic redacts identity by policy without discarding wifi KPIs`() {
        val snapshot =
            mapper.available(
                profile = ConnectivityCollectionProfile.BASIC,
                stamp = stamp(),
                capabilities =
                    capabilities(
                        transports = setOf(NetworkTransport.WIFI),
                        wifiInfo =
                            wifiInfo(
                                ssid = missing(ConnectivityObservationReason.POLICY_REDACTED),
                                bssid = missing(ConnectivityObservationReason.POLICY_REDACTED),
                                rssi = value(-55),
                                frequency = value(2412),
                                linkSpeed = value(0),
                            ),
                    ),
                blocked = null,
            )

        assertNull(snapshot.wifiAssociation.ssid.value)
        assertNull(snapshot.wifiAssociation.bssid.value)
        assertEquals(
            ConnectivityObservationReason.POLICY_REDACTED,
            snapshot.wifiAssociation.ssid.reason,
        )
        assertEquals(-55, snapshot.wifiAssociation.rssiDbm.value)
        assertEquals(0, snapshot.wifiAssociation.linkSpeedMbps.value)
        assertEquals(WifiBand.GHZ_2_4, snapshot.wifiAssociation.band.value)
        assertEquals(1, snapshot.wifiAssociation.primaryChannel.value)
    }

    @Test
    fun `transports preserve cellular ethernet vpn and simultaneous values`() {
        val cellular =
            available(setOf(NetworkTransport.CELLULAR))
        val ethernet =
            available(setOf(NetworkTransport.ETHERNET))
        val simultaneous =
            available(
                setOf(
                    NetworkTransport.WIFI,
                    NetworkTransport.CELLULAR,
                    NetworkTransport.ETHERNET,
                ),
                wifiInfo = wifiInfo(),
            )
        val vpn =
            available(
                setOf(NetworkTransport.VPN, NetworkTransport.WIFI),
                wifiInfo = wifiInfo(),
            )

        assertEquals(
            ConnectivityObservationReason.NON_WIFI_DEFAULT_NETWORK,
            cellular.wifiAssociation.association.reason,
        )
        assertEquals(
            ConnectivityObservationReason.NON_WIFI_DEFAULT_NETWORK,
            ethernet.wifiAssociation.association.reason,
        )
        assertEquals(
            setOf(
                NetworkTransport.WIFI,
                NetworkTransport.CELLULAR,
                NetworkTransport.ETHERNET,
            ),
            simultaneous.defaultNetwork.transports.value?.values,
        )
        assertEquals(
            ConnectivityObservationReason.VPN_UNDERLYING_NETWORK_NOT_OBSERVABLE,
            vpn.wifiAssociation.association.reason,
        )
        assertEquals(
            setOf(NetworkTransport.VPN, NetworkTransport.WIFI),
            vpn.defaultNetwork.transports.value?.values,
        )
    }

    @Test
    fun `capabilities retain literal booleans and derive metered only from not metered`() {
        val snapshot =
            mapper.available(
                ConnectivityCollectionProfile.BASIC,
                stamp(),
                capabilities(
                    transports = setOf(NetworkTransport.CELLULAR),
                    internet = true,
                    validated = false,
                    captivePortal = true,
                    notMetered = false,
                    notRoaming = false,
                    notSuspended = true,
                ),
                blocked = false,
            )

        assertEquals(true, snapshot.defaultNetwork.hasInternetCapability.value)
        assertEquals(false, snapshot.defaultNetwork.isValidated.value)
        assertEquals(true, snapshot.defaultNetwork.hasCaptivePortalCapability.value)
        assertEquals(false, snapshot.defaultNetwork.hasNotMeteredCapability.value)
        assertEquals(true, snapshot.defaultNetwork.isMetered.value)
        assertEquals(false, snapshot.defaultNetwork.hasNotRoamingCapability.value)
        assertEquals(true, snapshot.defaultNetwork.hasNotSuspendedCapability.value)
        assertEquals(false, snapshot.defaultNetwork.blocked.value)
    }

    @Test
    fun `legacy wifi remains non network scoped with reduced confidence`() {
        val snapshot =
            available(
                transports = setOf(NetworkTransport.WIFI),
                wifiInfo =
                    wifiInfo(
                        origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                        rssi = value(-70),
                        frequency = value(5180),
                    ),
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
            )

        assertEquals(
            WifiAssociationScope.DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT,
            snapshot.wifiAssociation.scope,
        )
        assertEquals(WifiAssociationState.ASSOCIATED, snapshot.wifiAssociation.association.value)
        assertEquals(
            ObservationSource.WIFI_MANAGER_LEGACY,
            snapshot.wifiAssociation.association.source,
        )
        assertEquals(
            ObservationConfidence.MEDIUM,
            snapshot.wifiAssociation.association.confidence,
        )
    }

    @Test
    fun `authorized legacy permission and location failures never become no association`() {
        listOf(
            ConnectivityObservationReason.PERMISSION_DENIED,
            ConnectivityObservationReason.LOCATION_SERVICES_DISABLED,
        ).forEach { reason ->
            val snapshot =
                available(
                    transports = setOf(NetworkTransport.WIFI),
                    wifiInfo =
                        wifiInfo(
                            origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                            allMissingReason = reason,
                        ),
                    profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                )

            assertNull(snapshot.wifiAssociation.association.value)
            assertEquals(ObservationAvailability.UNKNOWN, snapshot.wifiAssociation.association.availability)
            assertEquals(reason, snapshot.wifiAssociation.association.reason)
            assertEquals(reason, snapshot.wifiAssociation.ssid.reason)
            assertEquals(reason, snapshot.wifiAssociation.bssid.reason)
        }
    }

    @Test
    fun `legacy wifi with only sentinels never proves association`() {
        val snapshot =
            available(
                transports = setOf(NetworkTransport.WIFI),
                wifiInfo =
                    wifiInfo(
                        origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                        ssid = value(WifiManager.UNKNOWN_SSID),
                        bssid = value("02:00:00:00:00:00"),
                        rssi = value(-127),
                        frequency = value(-1),
                        linkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                        rxLinkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                        txLinkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                        standard = value(ScanResult.WIFI_STANDARD_UNKNOWN),
                        security = value(WifiInfo.SECURITY_TYPE_UNKNOWN),
                    ),
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
            )

        assertNull(snapshot.wifiAssociation.association.value)
        assertEquals(
            ObservationAvailability.UNKNOWN,
            snapshot.wifiAssociation.association.availability,
        )
        assertEquals(
            ConnectivityObservationReason.REDACTED_BY_PLATFORM,
            snapshot.wifiAssociation.association.reason,
        )
        assertEquals(
            WifiAssociationScope.DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT,
            snapshot.wifiAssociation.scope,
        )
        listOf(
            snapshot.wifiAssociation.ssid,
            snapshot.wifiAssociation.bssid,
            snapshot.wifiAssociation.rssiDbm,
            snapshot.wifiAssociation.frequencyMhz,
            snapshot.wifiAssociation.linkSpeedMbps,
            snapshot.wifiAssociation.rxLinkSpeedMbps,
            snapshot.wifiAssociation.txLinkSpeedMbps,
            snapshot.wifiAssociation.standard,
            snapshot.wifiAssociation.securityType,
        ).forEach { observed ->
            assertNull(observed.value)
            assertTrue(observed.reason != null)
        }
    }

    @Test
    fun `each invalid legacy field alone remains non evidence`() {
        val vectors =
            listOf(
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    ssid = value(""),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    bssid = value("not-a-bssid"),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    rssi = value(-127),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    frequency = value(-1),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    linkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    rxLinkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    txLinkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    standard = value(ScanResult.WIFI_STANDARD_UNKNOWN),
                ),
                wifiInfo(
                    origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                    security = value(WifiInfo.SECURITY_TYPE_UNKNOWN),
                ),
            )

        vectors.forEach { wifiInfo ->
            val snapshot =
                available(
                    transports = setOf(NetworkTransport.WIFI),
                    wifiInfo = wifiInfo,
                    profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                )

            assertNull(snapshot.wifiAssociation.association.value)
            assertEquals(
                ObservationAvailability.UNKNOWN,
                snapshot.wifiAssociation.association.availability,
            )
        }
    }

    @Test
    fun `legacy semantic evidence preserves legitimate zero link speed`() {
        val snapshot =
            available(
                transports = setOf(NetworkTransport.WIFI),
                wifiInfo =
                    wifiInfo(
                        origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                        linkSpeed = value(0),
                    ),
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
            )

        assertEquals(WifiAssociationState.ASSOCIATED, snapshot.wifiAssociation.association.value)
        assertEquals(0, snapshot.wifiAssociation.linkSpeedMbps.value)
    }

    @Test
    fun `API policy confines legacy and location aware access to authorized ranges`() {
        listOf(Build.VERSION_CODES.Q, Build.VERSION_CODES.R).forEach { sdkInt ->
            assertTrue(
                AndroidConnectivityApiPolicy.shouldReadLegacyWifiManager(
                    ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                    sdkInt,
                ),
            )
            assertFalse(
                AndroidConnectivityApiPolicy.shouldReadLegacyWifiManager(
                    ConnectivityCollectionProfile.BASIC,
                    sdkInt,
                ),
            )
        }
        listOf(31, 33, 35, 36).forEach { sdkInt ->
            assertFalse(
                AndroidConnectivityApiPolicy.shouldReadLegacyWifiManager(
                    ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                    sdkInt,
                ),
            )
            assertTrue(
                AndroidConnectivityApiPolicy.shouldIncludeLocationInformation(
                    ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                    sdkInt,
                    sensitiveAccessReason = null,
                ),
            )
            assertFalse(
                AndroidConnectivityApiPolicy.shouldIncludeLocationInformation(
                    ConnectivityCollectionProfile.BASIC,
                    sdkInt,
                    sensitiveAccessReason = null,
                ),
            )
            assertFalse(
                AndroidConnectivityApiPolicy.shouldIncludeLocationInformation(
                    ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                    sdkInt,
                    sensitiveAccessReason = ConnectivityObservationReason.PERMISSION_DENIED,
                ),
            )
        }
        assertFalse(
            AndroidConnectivityApiPolicy.shouldIncludeLocationInformation(
                ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                Build.VERSION_CODES.R,
                sensitiveAccessReason = null,
            ),
        )
    }

    @Test
    fun `sentinels and unsupported values stay null with explicit reasons`() {
        val snapshot =
            available(
                transports = setOf(NetworkTransport.WIFI),
                wifiInfo =
                    wifiInfo(
                        ssid = value(WifiManager.UNKNOWN_SSID),
                        bssid = value("02:00:00:00:00:00"),
                        rssi = value(-127),
                        frequency = value(-1),
                        linkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                        rxLinkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                        txLinkSpeed = value(WifiInfo.LINK_SPEED_UNKNOWN),
                        standard = value(ScanResult.WIFI_STANDARD_UNKNOWN),
                        security = value(-1),
                    ),
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
            )

        assertEquals(
            ConnectivityObservationReason.REDACTED_BY_PLATFORM,
            snapshot.wifiAssociation.ssid.reason,
        )
        assertNull(snapshot.wifiAssociation.ssid.value)
        assertEquals(
            ConnectivityObservationReason.REDACTED_BY_PLATFORM,
            snapshot.wifiAssociation.bssid.reason,
        )
        assertNull(snapshot.wifiAssociation.bssid.value)
        listOf(
            snapshot.wifiAssociation.rssiDbm,
            snapshot.wifiAssociation.frequencyMhz,
            snapshot.wifiAssociation.linkSpeedMbps,
            snapshot.wifiAssociation.rxLinkSpeedMbps,
            snapshot.wifiAssociation.txLinkSpeedMbps,
            snapshot.wifiAssociation.standard,
            snapshot.wifiAssociation.securityType,
        ).forEach { value ->
            assertNull(value.value)
            assertEquals(ConnectivityObservationReason.INVALID_PLATFORM_VALUE, value.reason)
        }
        assertNull(snapshot.wifiAssociation.band.value)
        assertNull(snapshot.wifiAssociation.primaryChannel.value)

        val unspecifiedSignal =
            mapper.available(
                ConnectivityCollectionProfile.BASIC,
                stamp(),
                capabilities(
                    transports = setOf(NetworkTransport.WIFI),
                    signalStrength = value(Int.MIN_VALUE),
                ),
                blocked = null,
            )
        assertNull(unspecifiedSignal.wifiAssociation.rssiDbm.value)
        assertEquals(
            ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            unspecifiedSignal.wifiAssociation.rssiDbm.reason,
        )

        val unmappedBand =
            available(
                transports = setOf(NetworkTransport.WIFI),
                wifiInfo = wifiInfo(frequency = value(9_000)),
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
            )
        assertEquals(9_000, unmappedBand.wifiAssociation.frequencyMhz.value)
        assertNull(unmappedBand.wifiAssociation.band.value)
        assertEquals(
            ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            unmappedBand.wifiAssociation.band.reason,
        )
    }

    @Test
    fun `missing wifi info maps signal fallback source mismatch and hardware inconsistency`() {
        val unexpected =
            mapper.available(
                ConnectivityCollectionProfile.BASIC,
                stamp(),
                capabilities(
                    transports = setOf(NetworkTransport.WIFI),
                    wifiInfo = null,
                    signalStrength = value(-72),
                    unexpectedTransportInfo = true,
                    wifiFeaturePresent = false,
                ),
                blocked = null,
            )

        assertEquals(-72, unexpected.wifiAssociation.rssiDbm.value)
        assertEquals(
            ObservationSource.NETWORK_CAPABILITIES,
            unexpected.wifiAssociation.rssiDbm.source,
        )
        assertEquals(
            ConnectivityObservationReason.SOURCE_MISMATCH,
            unexpected.wifiAssociation.association.reason,
        )
        assertEquals(1, unexpected.failures.size)
        assertEquals(
            ConnectivityObservationReason.SOURCE_MISMATCH,
            unexpected.failures.single().reason,
        )
    }

    private fun available(
        transports: Set<NetworkTransport>,
        wifiInfo: AndroidWifiInfoSnapshot? = null,
        profile: ConnectivityCollectionProfile = ConnectivityCollectionProfile.BASIC,
    ) =
        mapper.available(
            profile = profile,
            stamp = stamp(),
            capabilities = capabilities(transports = transports, wifiInfo = wifiInfo),
            blocked = null,
        )

    private fun capabilities(
        transports: Set<NetworkTransport>,
        wifiInfo: AndroidWifiInfoSnapshot? = null,
        internet: Boolean = true,
        validated: Boolean = true,
        captivePortal: Boolean = false,
        notMetered: Boolean = true,
        notRoaming: Boolean = true,
        notSuspended: Boolean = true,
        signalStrength: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        unexpectedTransportInfo: Boolean = false,
        wifiFeaturePresent: Boolean? = true,
    ) =
        AndroidNetworkCapabilitiesSnapshot(
            transports = transports,
            hasInternetCapability = internet,
            isValidated = validated,
            hasCaptivePortalCapability = captivePortal,
            hasNotMeteredCapability = notMetered,
            hasNotRoamingCapability = notRoaming,
            hasNotSuspendedCapability = notSuspended,
            signalStrength = signalStrength,
            wifiInfo = wifiInfo,
            wifiTransportInfoUnexpected = unexpectedTransportInfo,
            wifiFeaturePresent = wifiFeaturePresent,
        )

    private fun wifiInfo(
        origin: AndroidWifiInfoOrigin = AndroidWifiInfoOrigin.NETWORK_CALLBACK,
        ssid: AndroidPlatformValue<String> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        bssid: AndroidPlatformValue<String> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        rssi: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        frequency: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        linkSpeed: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        rxLinkSpeed: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        txLinkSpeed: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        standard: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        security: AndroidPlatformValue<Int> =
            missing(ConnectivityObservationReason.NOT_REPORTED),
        allMissingReason: ConnectivityObservationReason? = null,
    ): AndroidWifiInfoSnapshot {
        fun <T : Any> choose(field: AndroidPlatformValue<T>): AndroidPlatformValue<T> =
            allMissingReason?.let { missing(it) } ?: field
        return AndroidWifiInfoSnapshot(
            origin = origin,
            ssid = choose(ssid),
            bssid = choose(bssid),
            rssiDbm = choose(rssi),
            frequencyMhz = choose(frequency),
            linkSpeedMbps = choose(linkSpeed),
            rxLinkSpeedMbps = choose(rxLinkSpeed),
            txLinkSpeedMbps = choose(txLinkSpeed),
            wifiStandard = choose(standard),
            securityType = choose(security),
        )
    }

    private fun stamp(sequence: Long = 0) =
        AndroidObservationStamp(
            observedAtUtc = Instant.parse("2026-07-26T12:00:00Z"),
            elapsedRealtimeNanos = sequence + 100,
            sequence = sequence,
        )

    private fun <T : Any> value(value: T): AndroidPlatformValue<T> =
        AndroidPlatformValue.value(value)

    private fun <T : Any> missing(
        reason: ConnectivityObservationReason,
    ): AndroidPlatformValue<T> = AndroidPlatformValue.missing(reason)
}
