package com.wifitestorchestrator.agent.platform.connectivity

import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityFailureOperation
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationFailure
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationReason
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivitySnapshot
import com.wifitestorchestrator.agent.domain.connectivity.DefaultNetworkObservation
import com.wifitestorchestrator.agent.domain.connectivity.DefaultNetworkPresence
import com.wifitestorchestrator.agent.domain.connectivity.NetworkTransport
import com.wifitestorchestrator.agent.domain.connectivity.NetworkTransports
import com.wifitestorchestrator.agent.domain.connectivity.ObservationConfidence
import com.wifitestorchestrator.agent.domain.connectivity.ObservationSource
import com.wifitestorchestrator.agent.domain.connectivity.ObservationUnit
import com.wifitestorchestrator.agent.domain.connectivity.ObservedValue
import com.wifitestorchestrator.agent.domain.connectivity.WifiAssociationObservation
import com.wifitestorchestrator.agent.domain.connectivity.WifiAssociationScope
import com.wifitestorchestrator.agent.domain.connectivity.WifiAssociationState
import com.wifitestorchestrator.agent.domain.connectivity.WifiBand
import com.wifitestorchestrator.agent.domain.connectivity.WifiBssid
import com.wifitestorchestrator.agent.domain.connectivity.WifiChannelPolicy
import com.wifitestorchestrator.agent.domain.connectivity.WifiIdentityValidation
import com.wifitestorchestrator.agent.domain.connectivity.WifiSecurityType
import com.wifitestorchestrator.agent.domain.connectivity.WifiSsid
import com.wifitestorchestrator.agent.domain.connectivity.WifiStandard
import java.time.Instant

internal data class AndroidObservationStamp(
    val observedAtUtc: Instant,
    val elapsedRealtimeNanos: Long,
    val sequence: Long,
)

internal class AndroidConnectivitySnapshotMapper {
    fun initial(
        profile: ConnectivityCollectionProfile,
        stamp: AndroidObservationStamp,
    ): ConnectivitySnapshot =
        snapshot(
            profile = profile,
            stamp = stamp,
            defaultNetwork = pendingDefaultNetwork(initial = true),
            wifiAssociation = unknownWifi(ConnectivityObservationReason.INITIAL_CALLBACK_PENDING),
        )

    fun capabilitiesPending(
        profile: ConnectivityCollectionProfile,
        stamp: AndroidObservationStamp,
        blocked: Boolean?,
    ): ConnectivitySnapshot =
        snapshot(
            profile = profile,
            stamp = stamp,
            defaultNetwork =
                DefaultNetworkObservation(
                    presence = observed(DefaultNetworkPresence.PRESENT),
                    transports =
                        unknown(
                            ObservationUnit.NONE,
                            ObservationSource.NETWORK_CAPABILITIES,
                            ConnectivityObservationReason.CAPABILITIES_PENDING,
                        ),
                    capabilitiesPending = observedBoolean(true),
                    blocked = blockedValue(blocked),
                    hasInternetCapability = pendingBoolean(),
                    isValidated = pendingBoolean(),
                    hasCaptivePortalCapability = pendingBoolean(),
                    hasNotMeteredCapability = pendingBoolean(),
                    isMetered = pendingMetered(),
                    hasNotRoamingCapability = pendingBoolean(),
                    hasNotSuspendedCapability = pendingBoolean(),
                ),
            wifiAssociation = unknownWifi(ConnectivityObservationReason.CAPABILITIES_PENDING),
        )

    fun available(
        profile: ConnectivityCollectionProfile,
        stamp: AndroidObservationStamp,
        capabilities: AndroidNetworkCapabilitiesSnapshot,
        blocked: Boolean?,
    ): ConnectivitySnapshot {
        val failures =
            if (
                NetworkTransport.WIFI in capabilities.transports &&
                capabilities.wifiFeaturePresent == false
            ) {
                listOf(
                    ConnectivityObservationFailure(
                        operation = ConnectivityFailureOperation.MAP_PLATFORM_DATA,
                        reason = ConnectivityObservationReason.SOURCE_MISMATCH,
                        occurredAtUtc = stamp.observedAtUtc,
                        elapsedRealtimeNanos = stamp.elapsedRealtimeNanos,
                    ),
                )
            } else {
                emptyList()
            }
        val transportValue =
            if (capabilities.transports.isEmpty()) {
                unknown<NetworkTransports>(
                    ObservationUnit.NONE,
                    ObservationSource.NETWORK_CAPABILITIES,
                    ConnectivityObservationReason.TRANSPORT_UNKNOWN,
                )
            } else {
                ObservedValue.observed(
                    NetworkTransports.of(capabilities.transports),
                    ObservationUnit.NONE,
                    ObservationSource.NETWORK_CAPABILITIES,
                    ObservationConfidence.HIGH,
                )
            }
        return ConnectivitySnapshot(
            observedAtUtc = stamp.observedAtUtc,
            elapsedRealtimeNanos = stamp.elapsedRealtimeNanos,
            sequence = stamp.sequence,
            collectionProfile = profile,
            defaultNetwork =
                DefaultNetworkObservation(
                    presence = observed(DefaultNetworkPresence.PRESENT),
                    transports = transportValue,
                    capabilitiesPending = observedBoolean(false),
                    blocked = blockedValue(blocked),
                    hasInternetCapability = capability(capabilities.hasInternetCapability),
                    isValidated = capability(capabilities.isValidated),
                    hasCaptivePortalCapability =
                        capability(capabilities.hasCaptivePortalCapability),
                    hasNotMeteredCapability =
                        capability(capabilities.hasNotMeteredCapability),
                    isMetered =
                        ObservedValue.observed(
                            value = !capabilities.hasNotMeteredCapability,
                            unit = ObservationUnit.BOOLEAN,
                            source = ObservationSource.DERIVED_FROM_NOT_METERED_CAPABILITY,
                            confidence = ObservationConfidence.HIGH,
                        ),
                    hasNotRoamingCapability =
                        capability(capabilities.hasNotRoamingCapability),
                    hasNotSuspendedCapability =
                        capability(capabilities.hasNotSuspendedCapability),
                ),
            wifiAssociation = mapWifi(profile, capabilities),
            failures = failures,
        )
    }

    fun absent(
        profile: ConnectivityCollectionProfile,
        stamp: AndroidObservationStamp,
    ): ConnectivitySnapshot {
        val noNetworkBoolean =
            notApplicable<Boolean>(
                ObservationUnit.BOOLEAN,
                ConnectivityObservationReason.NO_DEFAULT_NETWORK,
            )
        return ConnectivitySnapshot(
            observedAtUtc = stamp.observedAtUtc,
            elapsedRealtimeNanos = stamp.elapsedRealtimeNanos,
            sequence = stamp.sequence,
            collectionProfile = profile,
            defaultNetwork =
                DefaultNetworkObservation(
                    presence = observed(DefaultNetworkPresence.ABSENT),
                    transports =
                        notApplicable(
                            ObservationUnit.NONE,
                            ConnectivityObservationReason.NO_DEFAULT_NETWORK,
                        ),
                    capabilitiesPending = noNetworkBoolean,
                    blocked = noNetworkBoolean,
                    hasInternetCapability = noNetworkBoolean,
                    isValidated = noNetworkBoolean,
                    hasCaptivePortalCapability = noNetworkBoolean,
                    hasNotMeteredCapability = noNetworkBoolean,
                    isMetered = noNetworkBoolean,
                    hasNotRoamingCapability = noNetworkBoolean,
                    hasNotSuspendedCapability = noNetworkBoolean,
                ),
            wifiAssociation = unknownWifi(ConnectivityObservationReason.NOT_REPORTED),
            failures = emptyList(),
        )
    }

    private fun mapWifi(
        profile: ConnectivityCollectionProfile,
        capabilities: AndroidNetworkCapabilitiesSnapshot,
    ): WifiAssociationObservation {
        if (NetworkTransport.VPN in capabilities.transports) {
            return unknownWifi(
                ConnectivityObservationReason.VPN_UNDERLYING_NETWORK_NOT_OBSERVABLE,
            )
        }
        if (NetworkTransport.WIFI !in capabilities.transports) {
            return unknownWifi(ConnectivityObservationReason.NON_WIFI_DEFAULT_NETWORK)
        }
        if (capabilities.wifiInfo == null) {
            val reason =
                if (capabilities.wifiTransportInfoUnexpected) {
                    ConnectivityObservationReason.SOURCE_MISMATCH
                } else {
                    ConnectivityObservationReason.WIFI_INFO_UNAVAILABLE
                }
            val signal = mapSignalStrength(capabilities.signalStrength)
            return unavailableWifi(reason, signal)
        }
        val info = capabilities.wifiInfo
        val source =
            when (info.origin) {
                AndroidWifiInfoOrigin.NETWORK_CALLBACK ->
                    ObservationSource.WIFI_TRANSPORT_INFO
                AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY ->
                    ObservationSource.WIFI_MANAGER_LEGACY
            }
        val confidence =
            when (info.origin) {
                AndroidWifiInfoOrigin.NETWORK_CALLBACK -> ObservationConfidence.HIGH
                AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY -> ObservationConfidence.MEDIUM
            }
        val scope =
            when (info.origin) {
                AndroidWifiInfoOrigin.NETWORK_CALLBACK -> WifiAssociationScope.DEFAULT_NETWORK
                AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY ->
                    WifiAssociationScope.DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT
            }
        val ssid = mapSsid(profile, info.ssid, source, confidence)
        val bssid = mapBssid(profile, info.bssid, source, confidence)
        val rssi = mapRssi(info.rssiDbm, source, confidence)
        val frequency = mapFrequency(info.frequencyMhz, source, confidence)
        val linkSpeed = mapLinkSpeed(info.linkSpeedMbps, source, confidence)
        val rxLinkSpeed = mapLinkSpeed(info.rxLinkSpeedMbps, source, confidence)
        val txLinkSpeed = mapLinkSpeed(info.txLinkSpeedMbps, source, confidence)
        val standard = mapStandard(info.wifiStandard, source, confidence)
        val securityType = mapSecurity(info.securityType, source, confidence)
        val semanticEvidence =
            listOf(
                ssid,
                bssid,
                rssi,
                frequency,
                linkSpeed,
                rxLinkSpeed,
                txLinkSpeed,
                standard,
                securityType,
            )
        val association =
            if (
                info.origin == AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY &&
                semanticEvidence.none { it.value != null }
            ) {
                unknown<WifiAssociationState>(
                    ObservationUnit.NONE,
                    source,
                    semanticEvidence.firstNotNullOfOrNull { it.reason }
                        ?: ConnectivityObservationReason.WIFI_INFO_UNAVAILABLE,
                )
            } else {
                ObservedValue.observed(
                    WifiAssociationState.ASSOCIATED,
                    ObservationUnit.NONE,
                    source,
                    confidence,
                )
            }
        val derived = frequency.value?.let(WifiChannelPolicy::fromFrequencyMhz)
        return WifiAssociationObservation(
            association = association,
            scope = scope,
            ssid = ssid,
            bssid = bssid,
            rssiDbm = rssi,
            frequencyMhz = frequency,
            band =
                derived
                    ?.takeIf { it.band != WifiBand.UNKNOWN }
                    ?.let {
                        ObservedValue.observed(
                            it.band,
                            ObservationUnit.NONE,
                            ObservationSource.DERIVED_FROM_FREQUENCY,
                            confidence,
                        )
                    } ?: unavailable(
                        ObservationUnit.NONE,
                        ObservationSource.DERIVED_FROM_FREQUENCY,
                        frequency.reason ?: ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
                    ),
            primaryChannel =
                derived?.primaryChannel?.let {
                    ObservedValue.observed(
                        it,
                        ObservationUnit.CHANNEL_NUMBER,
                        ObservationSource.DERIVED_FROM_FREQUENCY,
                        confidence,
                    )
                } ?: unavailable(
                    ObservationUnit.CHANNEL_NUMBER,
                    ObservationSource.DERIVED_FROM_FREQUENCY,
                    frequency.reason ?: ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
                ),
            linkSpeedMbps = linkSpeed,
            rxLinkSpeedMbps = rxLinkSpeed,
            txLinkSpeedMbps = txLinkSpeed,
            standard = standard,
            securityType = securityType,
            channelWidthMhz =
                unavailable(
                    ObservationUnit.MEGAHERTZ,
                    source,
                    ConnectivityObservationReason.UNSUPPORTED_API,
                ),
        )
    }

    private fun mapSsid(
        profile: ConnectivityCollectionProfile,
        field: AndroidPlatformValue<String>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<WifiSsid> {
        if (profile == ConnectivityCollectionProfile.BASIC) {
            return unavailable(
                ObservationUnit.SSID,
                ObservationSource.PLATFORM_POLICY,
                ConnectivityObservationReason.POLICY_REDACTED,
            )
        }
        val raw =
            field.value ?: return unavailable(
                ObservationUnit.SSID,
                source,
                field.requiredReason(),
            )
        if (raw == WifiManager.UNKNOWN_SSID) {
            return unavailable(
                ObservationUnit.SSID,
                source,
                ConnectivityObservationReason.REDACTED_BY_PLATFORM,
            )
        }
        return when (val parsed = WifiSsid.fromPlatformValue(raw)) {
            is WifiIdentityValidation.Valid ->
                ObservedValue.observed(parsed.value, ObservationUnit.SSID, source, confidence)
            is WifiIdentityValidation.Invalid ->
                unavailable(ObservationUnit.SSID, source, parsed.reason)
        }
    }

    private fun mapBssid(
        profile: ConnectivityCollectionProfile,
        field: AndroidPlatformValue<String>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<WifiBssid> {
        if (profile == ConnectivityCollectionProfile.BASIC) {
            return unavailable(
                ObservationUnit.BSSID,
                ObservationSource.PLATFORM_POLICY,
                ConnectivityObservationReason.POLICY_REDACTED,
            )
        }
        val raw =
            field.value ?: return unavailable(ObservationUnit.BSSID, source, field.requiredReason())
        if (raw.equals(WifiBssid.PLATFORM_REDACTED_VALUE, ignoreCase = true)) {
            return unavailable(
                ObservationUnit.BSSID,
                source,
                ConnectivityObservationReason.REDACTED_BY_PLATFORM,
            )
        }
        return when (val parsed = WifiBssid.fromPlatformValue(raw)) {
            is WifiIdentityValidation.Valid ->
                ObservedValue.observed(parsed.value, ObservationUnit.BSSID, source, confidence)
            is WifiIdentityValidation.Invalid ->
                unavailable(ObservationUnit.BSSID, source, parsed.reason)
        }
    }

    private fun mapRssi(
        field: AndroidPlatformValue<Int>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<Int> {
        val value = field.value ?: return unavailable(ObservationUnit.DBM, source, field.requiredReason())
        return if (value in MIN_WIFI_RSSI..MAX_WIFI_RSSI && value != INVALID_WIFI_RSSI) {
            ObservedValue.observed(value, ObservationUnit.DBM, source, confidence)
        } else {
            unavailable(
                ObservationUnit.DBM,
                source,
                ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            )
        }
    }

    private fun mapSignalStrength(field: AndroidPlatformValue<Int>): ObservedValue<Int> {
        val value =
            field.value ?: return unavailable(
                ObservationUnit.DBM,
                ObservationSource.NETWORK_CAPABILITIES,
                field.requiredReason(),
            )
        return if (
            value != NetworkCapabilities.SIGNAL_STRENGTH_UNSPECIFIED &&
            value in MIN_WIFI_RSSI..MAX_WIFI_RSSI
        ) {
            ObservedValue.observed(
                value,
                ObservationUnit.DBM,
                ObservationSource.NETWORK_CAPABILITIES,
                ObservationConfidence.MEDIUM,
            )
        } else {
            unavailable(
                ObservationUnit.DBM,
                ObservationSource.NETWORK_CAPABILITIES,
                ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            )
        }
    }

    private fun mapFrequency(
        field: AndroidPlatformValue<Int>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<Int> {
        val value =
            field.value ?: return unavailable(
                ObservationUnit.MEGAHERTZ,
                source,
                field.requiredReason(),
            )
        return if (value > 0) {
            ObservedValue.observed(value, ObservationUnit.MEGAHERTZ, source, confidence)
        } else {
            unavailable(
                ObservationUnit.MEGAHERTZ,
                source,
                ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            )
        }
    }

    private fun mapLinkSpeed(
        field: AndroidPlatformValue<Int>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<Int> {
        val value =
            field.value ?: return unavailable(
                ObservationUnit.MEGABITS_PER_SECOND,
                source,
                field.requiredReason(),
            )
        return if (value >= 0 && value != WifiInfo.LINK_SPEED_UNKNOWN) {
            ObservedValue.observed(
                value,
                ObservationUnit.MEGABITS_PER_SECOND,
                source,
                confidence,
            )
        } else {
            unavailable(
                ObservationUnit.MEGABITS_PER_SECOND,
                source,
                ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
            )
        }
    }

    private fun mapStandard(
        field: AndroidPlatformValue<Int>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<WifiStandard> {
        val value =
            field.value ?: return unavailable(
                ObservationUnit.WIFI_STANDARD,
                source,
                field.requiredReason(),
            )
        val mapped =
            when (value) {
                ScanResult.WIFI_STANDARD_LEGACY -> WifiStandard.LEGACY
                ScanResult.WIFI_STANDARD_11N -> WifiStandard.IEEE_802_11N
                ScanResult.WIFI_STANDARD_11AC -> WifiStandard.IEEE_802_11AC
                ScanResult.WIFI_STANDARD_11AX -> WifiStandard.IEEE_802_11AX
                ScanResult.WIFI_STANDARD_11AD -> WifiStandard.IEEE_802_11AD
                ScanResult.WIFI_STANDARD_11BE -> WifiStandard.IEEE_802_11BE
                else -> null
            }
        return mapped?.let {
            ObservedValue.observed(it, ObservationUnit.WIFI_STANDARD, source, confidence)
        } ?: unavailable(
            ObservationUnit.WIFI_STANDARD,
            source,
            ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
        )
    }

    private fun mapSecurity(
        field: AndroidPlatformValue<Int>,
        source: ObservationSource,
        confidence: ObservationConfidence,
    ): ObservedValue<WifiSecurityType> {
        val value =
            field.value ?: return unavailable(
                ObservationUnit.SECURITY_TYPE,
                source,
                field.requiredReason(),
            )
        val mapped =
            when (value) {
                WifiInfo.SECURITY_TYPE_OPEN -> WifiSecurityType.OPEN
                WifiInfo.SECURITY_TYPE_WEP -> WifiSecurityType.WEP
                WifiInfo.SECURITY_TYPE_PSK -> WifiSecurityType.PSK
                WifiInfo.SECURITY_TYPE_EAP -> WifiSecurityType.EAP
                WifiInfo.SECURITY_TYPE_SAE -> WifiSecurityType.SAE
                WifiInfo.SECURITY_TYPE_OWE -> WifiSecurityType.OWE
                WifiInfo.SECURITY_TYPE_WAPI_PSK -> WifiSecurityType.WAPI_PSK
                WifiInfo.SECURITY_TYPE_WAPI_CERT -> WifiSecurityType.WAPI_CERT
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE ->
                    WifiSecurityType.EAP_WPA3_ENTERPRISE
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT ->
                    WifiSecurityType.EAP_WPA3_ENTERPRISE_192_BIT
                WifiInfo.SECURITY_TYPE_OSEN -> WifiSecurityType.OSEN
                WifiInfo.SECURITY_TYPE_PASSPOINT_R1_R2 -> WifiSecurityType.PASSPOINT_R1_R2
                WifiInfo.SECURITY_TYPE_PASSPOINT_R3 -> WifiSecurityType.PASSPOINT_R3
                WifiInfo.SECURITY_TYPE_DPP -> WifiSecurityType.DPP
                else -> null
            }
        return mapped?.let {
            ObservedValue.observed(it, ObservationUnit.SECURITY_TYPE, source, confidence)
        } ?: unavailable(
            ObservationUnit.SECURITY_TYPE,
            source,
            ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
        )
    }

    private fun pendingDefaultNetwork(initial: Boolean): DefaultNetworkObservation {
        val reason =
            if (initial) {
                ConnectivityObservationReason.INITIAL_CALLBACK_PENDING
            } else {
                ConnectivityObservationReason.CAPABILITIES_PENDING
            }
        val pending = unknown<Boolean>(ObservationUnit.BOOLEAN, ObservationSource.DEFAULT_NETWORK_CALLBACK, reason)
        return DefaultNetworkObservation(
            presence =
                unknown(
                    ObservationUnit.NONE,
                    ObservationSource.DEFAULT_NETWORK_CALLBACK,
                    reason,
                ),
            transports =
                unknown(
                    ObservationUnit.NONE,
                    ObservationSource.NETWORK_CAPABILITIES,
                    reason,
                ),
            capabilitiesPending = pending,
            blocked = pending,
            hasInternetCapability = pending,
            isValidated = pending,
            hasCaptivePortalCapability = pending,
            hasNotMeteredCapability = pending,
            isMetered =
                unknown(
                    ObservationUnit.BOOLEAN,
                    ObservationSource.DERIVED_FROM_NOT_METERED_CAPABILITY,
                    reason,
                ),
            hasNotRoamingCapability = pending,
            hasNotSuspendedCapability = pending,
        )
    }

    private fun unknownWifi(reason: ConnectivityObservationReason): WifiAssociationObservation =
        WifiAssociationObservation(
            association = unknown(ObservationUnit.NONE, ObservationSource.PLATFORM_POLICY, reason),
            scope = WifiAssociationScope.UNKNOWN,
            ssid = unavailable(ObservationUnit.SSID, ObservationSource.PLATFORM_POLICY, reason),
            bssid = unavailable(ObservationUnit.BSSID, ObservationSource.PLATFORM_POLICY, reason),
            rssiDbm = unavailable(ObservationUnit.DBM, ObservationSource.PLATFORM_POLICY, reason),
            frequencyMhz =
                unavailable(ObservationUnit.MEGAHERTZ, ObservationSource.PLATFORM_POLICY, reason),
            band =
                unavailable(ObservationUnit.NONE, ObservationSource.DERIVED_FROM_FREQUENCY, reason),
            primaryChannel =
                unavailable(
                    ObservationUnit.CHANNEL_NUMBER,
                    ObservationSource.DERIVED_FROM_FREQUENCY,
                    reason,
                ),
            linkSpeedMbps =
                unavailable(
                    ObservationUnit.MEGABITS_PER_SECOND,
                    ObservationSource.PLATFORM_POLICY,
                    reason,
                ),
            rxLinkSpeedMbps =
                unavailable(
                    ObservationUnit.MEGABITS_PER_SECOND,
                    ObservationSource.PLATFORM_POLICY,
                    reason,
                ),
            txLinkSpeedMbps =
                unavailable(
                    ObservationUnit.MEGABITS_PER_SECOND,
                    ObservationSource.PLATFORM_POLICY,
                    reason,
                ),
            standard =
                unavailable(
                    ObservationUnit.WIFI_STANDARD,
                    ObservationSource.PLATFORM_POLICY,
                    reason,
                ),
            securityType =
                unavailable(
                    ObservationUnit.SECURITY_TYPE,
                    ObservationSource.PLATFORM_POLICY,
                    reason,
                ),
            channelWidthMhz =
                unavailable(
                    ObservationUnit.MEGAHERTZ,
                    ObservationSource.PLATFORM_POLICY,
                    ConnectivityObservationReason.UNSUPPORTED_API,
                ),
        )

    private fun unavailableWifi(
        reason: ConnectivityObservationReason,
        signalStrength: ObservedValue<Int>,
    ): WifiAssociationObservation =
        unknownWifi(reason).copy(rssiDbm = signalStrength)

    private fun snapshot(
        profile: ConnectivityCollectionProfile,
        stamp: AndroidObservationStamp,
        defaultNetwork: DefaultNetworkObservation,
        wifiAssociation: WifiAssociationObservation,
    ): ConnectivitySnapshot =
        ConnectivitySnapshot(
            observedAtUtc = stamp.observedAtUtc,
            elapsedRealtimeNanos = stamp.elapsedRealtimeNanos,
            sequence = stamp.sequence,
            collectionProfile = profile,
            defaultNetwork = defaultNetwork,
            wifiAssociation = wifiAssociation,
            failures = emptyList(),
        )

    private fun observed(value: DefaultNetworkPresence): ObservedValue<DefaultNetworkPresence> =
        ObservedValue.observed(
            value,
            ObservationUnit.NONE,
            ObservationSource.DEFAULT_NETWORK_CALLBACK,
            ObservationConfidence.HIGH,
        )

    private fun observedBoolean(value: Boolean): ObservedValue<Boolean> =
        ObservedValue.observed(
            value,
            ObservationUnit.BOOLEAN,
            ObservationSource.DEFAULT_NETWORK_CALLBACK,
            ObservationConfidence.HIGH,
        )

    private fun capability(value: Boolean): ObservedValue<Boolean> =
        ObservedValue.observed(
            value,
            ObservationUnit.BOOLEAN,
            ObservationSource.NETWORK_CAPABILITIES,
            ObservationConfidence.HIGH,
        )

    private fun blockedValue(blocked: Boolean?): ObservedValue<Boolean> =
        blocked?.let(::observedBoolean)
            ?: unknown(
                ObservationUnit.BOOLEAN,
                ObservationSource.DEFAULT_NETWORK_CALLBACK,
                ConnectivityObservationReason.NOT_REPORTED,
            )

    private fun pendingBoolean(): ObservedValue<Boolean> =
        unknown(
            ObservationUnit.BOOLEAN,
            ObservationSource.NETWORK_CAPABILITIES,
            ConnectivityObservationReason.CAPABILITIES_PENDING,
        )

    private fun pendingMetered(): ObservedValue<Boolean> =
        unknown(
            ObservationUnit.BOOLEAN,
            ObservationSource.DERIVED_FROM_NOT_METERED_CAPABILITY,
            ConnectivityObservationReason.CAPABILITIES_PENDING,
        )

    private fun <T : Any> unknown(
        unit: ObservationUnit,
        source: ObservationSource,
        reason: ConnectivityObservationReason,
    ): ObservedValue<T> = ObservedValue.unknown(unit, source, reason)

    private fun <T : Any> unavailable(
        unit: ObservationUnit,
        source: ObservationSource,
        reason: ConnectivityObservationReason,
    ): ObservedValue<T> = ObservedValue.unavailable(unit, source, reason)

    private fun <T : Any> notApplicable(
        unit: ObservationUnit,
        reason: ConnectivityObservationReason,
    ): ObservedValue<T> =
        ObservedValue.notApplicable(
            unit = unit,
            source = ObservationSource.DEFAULT_NETWORK_CALLBACK,
            reason = reason,
        )

    private fun AndroidPlatformValue<*>.requiredReason(): ConnectivityObservationReason =
        requireNotNull(reason) { "A missing platform value requires a reason." }

    private companion object {
        const val INVALID_WIFI_RSSI = -127
        const val MIN_WIFI_RSSI = -126
        const val MAX_WIFI_RSSI = 200
    }
}
