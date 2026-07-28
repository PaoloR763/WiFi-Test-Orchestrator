package com.wifitestorchestrator.agent.domain.connectivity

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ConnectivityObservationTest {
    @Test
    fun `observed null semantics preserve zero and false`() {
        val zero =
            ObservedValue.observed(
                value = 0,
                unit = ObservationUnit.MEGABITS_PER_SECOND,
                source = ObservationSource.WIFI_TRANSPORT_INFO,
                confidence = ObservationConfidence.HIGH,
            )
        val falseValue =
            ObservedValue.observed(
                value = false,
                unit = ObservationUnit.BOOLEAN,
                source = ObservationSource.NETWORK_CAPABILITIES,
                confidence = ObservationConfidence.HIGH,
            )
        val missing =
            ObservedValue.unavailable<Int>(
                unit = ObservationUnit.MEGABITS_PER_SECOND,
                source = ObservationSource.WIFI_TRANSPORT_INFO,
                reason = ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            )

        assertEquals(0, zero.value)
        assertEquals(false, falseValue.value)
        assertNotEquals(zero, missing)
        assertEquals(null, missing.value)
        assertEquals(
            ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            missing.reason,
        )
    }

    @Test
    fun `availability factories enforce reason and confidence invariants`() {
        val unknown =
            ObservedValue.unknown<Boolean>(
                ObservationUnit.BOOLEAN,
                ObservationSource.DEFAULT_NETWORK_CALLBACK,
                ConnectivityObservationReason.INITIAL_CALLBACK_PENDING,
            )
        val notApplicable =
            ObservedValue.notApplicable<Boolean>(ObservationUnit.BOOLEAN)

        assertEquals(ObservationAvailability.UNKNOWN, unknown.availability)
        assertEquals(ObservationConfidence.UNKNOWN, unknown.confidence)
        assertEquals(ObservationAvailability.NOT_APPLICABLE, notApplicable.availability)
        assertEquals(ObservationConfidence.NOT_APPLICABLE, notApplicable.confidence)
        assertFailsWith<IllegalArgumentException> {
            ObservedValue.observed(
                true,
                ObservationUnit.BOOLEAN,
                ObservationSource.NETWORK_CAPABILITIES,
                ObservationConfidence.UNKNOWN,
            )
        }
    }

    @Test
    fun `SSID preserves reported form and derives display without trimming`() {
        val quoted =
            assertIs<WifiIdentityValidation.Valid<WifiSsid>>(
                WifiSsid.fromPlatformValue("\"  Lab Wi-Fi  \""),
            ).value
        val unquoted =
            assertIs<WifiIdentityValidation.Valid<WifiSsid>>(
                WifiSsid.fromPlatformValue("  Lab Wi-Fi  "),
            ).value

        assertEquals("\"  Lab Wi-Fi  \"", quoted.reportedValue)
        assertEquals("  Lab Wi-Fi  ", quoted.displayValue)
        assertEquals(
            WifiSsidDisplayMethod.REMOVE_SINGLE_ANDROID_QUOTE_PAIR,
            quoted.displayMethod,
        )
        assertEquals("  Lab Wi-Fi  ", unquoted.reportedValue)
        assertEquals("  Lab Wi-Fi  ", unquoted.displayValue)
        assertEquals("WifiSsid(<redacted>)", quoted.toString())
        assertIs<WifiIdentityValidation.Invalid>(WifiSsid.fromPlatformValue(""))
        assertIs<WifiIdentityValidation.Invalid>(WifiSsid.fromPlatformValue("\"\""))
    }

    @Test
    fun `BSSID validates before identity preserving canonicalization`() {
        val value =
            assertIs<WifiIdentityValidation.Valid<WifiBssid>>(
                WifiBssid.fromPlatformValue("AA:0B:CC:1D:EE:2F"),
            ).value

        assertEquals("AA:0B:CC:1D:EE:2F", value.reportedValue)
        assertEquals("aa:0b:cc:1d:ee:2f", value.canonicalValue)
        assertEquals("WifiBssid(<redacted>)", value.toString())
        assertIs<WifiIdentityValidation.Invalid>(
            WifiBssid.fromPlatformValue(WifiBssid.PLATFORM_REDACTED_VALUE),
        )
        assertIs<WifiIdentityValidation.Invalid>(
            WifiBssid.fromPlatformValue("invalid"),
        )
    }

    @Test
    fun `channel policy follows Android frequency and channel boundaries`() {
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_2_4, 1), WifiChannelPolicy.fromFrequencyMhz(2412))
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_2_4, 14), WifiChannelPolicy.fromFrequencyMhz(2484))
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_5, 32), WifiChannelPolicy.fromFrequencyMhz(5160))
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_6, 2), WifiChannelPolicy.fromFrequencyMhz(5935))
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_6, 1), WifiChannelPolicy.fromFrequencyMhz(5955))
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_60, 1), WifiChannelPolicy.fromFrequencyMhz(58320))
        assertEquals(DerivedWifiChannel(WifiBand.UNKNOWN, null), WifiChannelPolicy.fromFrequencyMhz(0))
        assertEquals(DerivedWifiChannel(WifiBand.GHZ_2_4, null), WifiChannelPolicy.fromFrequencyMhz(2413))
    }

    @Test
    fun `transport and failure collections are defensive`() {
        val transports = mutableSetOf(NetworkTransport.WIFI)
        val transportValue = NetworkTransports.of(transports)
        transports += NetworkTransport.VPN

        assertEquals(setOf(NetworkTransport.WIFI), transportValue.values)
        assertFailsWith<IllegalArgumentException> { NetworkTransports.of(emptySet()) }

        val failures = mutableListOf<ConnectivityObservationFailure>()
        val snapshot = snapshot(failures)
        failures +=
            ConnectivityObservationFailure(
                ConnectivityFailureOperation.REGISTER_CALLBACK,
                ConnectivityObservationReason.REGISTRATION_FAILED,
                Instant.parse("2026-07-26T12:00:01Z"),
                2,
            )
        assertTrue(snapshot.failures.isEmpty())
    }

    @Test
    fun `snapshot validates UTC order fields independently of wall clock movement`() {
        val first = snapshot(emptyList(), utc = "2026-07-26T12:00:10Z", monotonic = 10, sequence = 0)
        val second = snapshot(emptyList(), utc = "2026-07-26T12:00:00Z", monotonic = 11, sequence = 1)

        assertTrue(second.observedAtUtc < first.observedAtUtc)
        assertTrue(second.elapsedRealtimeNanos > first.elapsedRealtimeNanos)
        assertTrue(second.sequence > first.sequence)
        assertFailsWith<IllegalArgumentException> {
            snapshot(emptyList(), monotonic = -1)
        }
        assertFailsWith<IllegalArgumentException> {
            snapshot(emptyList(), sequence = -1)
        }
    }

    @Test
    fun `profiles and association scope remain explicit`() {
        val basic = snapshot(emptyList(), profile = ConnectivityCollectionProfile.BASIC)
        val authorized =
            snapshot(
                emptyList(),
                profile = ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED,
                scope = WifiAssociationScope.DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT,
            )

        assertEquals(ConnectivityCollectionProfile.BASIC, basic.collectionProfile)
        assertEquals(
            WifiAssociationScope.DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT,
            authorized.wifiAssociation.scope,
        )
        assertFalse(basic.toString().contains("AA:0B:CC"))
    }

    @Test
    fun `observer lifecycle rejects terminal snapshots`() {
        assertFailsWith<IllegalArgumentException> {
            ConnectivityObserverState(
                lifecycle = ConnectivityObserverLifecycle.CLOSED,
                profile = ConnectivityCollectionProfile.BASIC,
                snapshot = snapshot(emptyList()),
                failure = null,
            )
        }
        assertEquals(ConnectivityObserverLifecycle.NEW, ConnectivityObserverState.new().lifecycle)
    }

    private fun snapshot(
        failures: List<ConnectivityObservationFailure>,
        utc: String = "2026-07-26T12:00:00Z",
        monotonic: Long = 1,
        sequence: Long = 0,
        profile: ConnectivityCollectionProfile = ConnectivityCollectionProfile.BASIC,
        scope: WifiAssociationScope = WifiAssociationScope.UNKNOWN,
    ): ConnectivitySnapshot {
        val booleanUnknown =
            ObservedValue.unknown<Boolean>(
                ObservationUnit.BOOLEAN,
                ObservationSource.NETWORK_CAPABILITIES,
                ConnectivityObservationReason.CAPABILITIES_PENDING,
            )
        val identityUnavailable =
            ObservedValue.unavailable<WifiSsid>(
                ObservationUnit.SSID,
                ObservationSource.PLATFORM_POLICY,
                ConnectivityObservationReason.POLICY_REDACTED,
            )
        return ConnectivitySnapshot(
            observedAtUtc = Instant.parse(utc),
            elapsedRealtimeNanos = monotonic,
            sequence = sequence,
            collectionProfile = profile,
            defaultNetwork =
                DefaultNetworkObservation(
                    presence =
                        ObservedValue.unknown(
                            ObservationUnit.NONE,
                            ObservationSource.DEFAULT_NETWORK_CALLBACK,
                            ConnectivityObservationReason.INITIAL_CALLBACK_PENDING,
                        ),
                    transports =
                        ObservedValue.unknown(
                            ObservationUnit.NONE,
                            ObservationSource.NETWORK_CAPABILITIES,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    capabilitiesPending = booleanUnknown,
                    blocked = booleanUnknown,
                    hasInternetCapability = booleanUnknown,
                    isValidated = booleanUnknown,
                    hasCaptivePortalCapability = booleanUnknown,
                    hasNotMeteredCapability = booleanUnknown,
                    isMetered = booleanUnknown,
                    hasNotRoamingCapability = booleanUnknown,
                    hasNotSuspendedCapability = booleanUnknown,
                ),
            wifiAssociation =
                WifiAssociationObservation(
                    association =
                        ObservedValue.unknown(
                            ObservationUnit.NONE,
                            ObservationSource.DEFAULT_NETWORK_CALLBACK,
                            ConnectivityObservationReason.TRANSPORT_UNKNOWN,
                        ),
                    scope = scope,
                    ssid = identityUnavailable,
                    bssid =
                        ObservedValue.unavailable(
                            ObservationUnit.BSSID,
                            ObservationSource.PLATFORM_POLICY,
                            ConnectivityObservationReason.POLICY_REDACTED,
                        ),
                    rssiDbm =
                        ObservedValue.unknown(
                            ObservationUnit.DBM,
                            ObservationSource.NETWORK_CAPABILITIES,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    frequencyMhz =
                        ObservedValue.unknown(
                            ObservationUnit.MEGAHERTZ,
                            ObservationSource.NETWORK_CAPABILITIES,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    band =
                        ObservedValue.unknown(
                            ObservationUnit.NONE,
                            ObservationSource.DERIVED_FROM_FREQUENCY,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    primaryChannel =
                        ObservedValue.unknown(
                            ObservationUnit.CHANNEL_NUMBER,
                            ObservationSource.DERIVED_FROM_FREQUENCY,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    linkSpeedMbps =
                        ObservedValue.unknown(
                            ObservationUnit.MEGABITS_PER_SECOND,
                            ObservationSource.WIFI_TRANSPORT_INFO,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    rxLinkSpeedMbps =
                        ObservedValue.unknown(
                            ObservationUnit.MEGABITS_PER_SECOND,
                            ObservationSource.WIFI_TRANSPORT_INFO,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    txLinkSpeedMbps =
                        ObservedValue.unknown(
                            ObservationUnit.MEGABITS_PER_SECOND,
                            ObservationSource.WIFI_TRANSPORT_INFO,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    standard =
                        ObservedValue.unknown(
                            ObservationUnit.WIFI_STANDARD,
                            ObservationSource.WIFI_TRANSPORT_INFO,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    securityType =
                        ObservedValue.unknown(
                            ObservationUnit.SECURITY_TYPE,
                            ObservationSource.WIFI_TRANSPORT_INFO,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    channelWidthMhz =
                        ObservedValue.unavailable(
                            ObservationUnit.MEGAHERTZ,
                            ObservationSource.WIFI_TRANSPORT_INFO,
                            ConnectivityObservationReason.UNSUPPORTED_API,
                        ),
                ),
            failures = failures,
        )
    }
}
