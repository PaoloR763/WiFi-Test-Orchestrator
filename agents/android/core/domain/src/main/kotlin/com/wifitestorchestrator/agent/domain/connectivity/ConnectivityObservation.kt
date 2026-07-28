package com.wifitestorchestrator.agent.domain.connectivity

import java.time.Instant
import java.util.Collections
import java.util.Locale

enum class ConnectivityCollectionProfile {
    BASIC,
    WIFI_TEST_AUTHORIZED,
}

enum class ObservationAvailability {
    OBSERVED,
    UNAVAILABLE,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class ObservationConfidence {
    HIGH,
    MEDIUM,
    LOW,
    UNKNOWN,
    NOT_APPLICABLE,
}

enum class ObservationUnit {
    NONE,
    BOOLEAN,
    DBM,
    MEGAHERTZ,
    MEGABITS_PER_SECOND,
    CHANNEL_NUMBER,
    SSID,
    BSSID,
    WIFI_STANDARD,
    SECURITY_TYPE,
}

enum class ObservationSource {
    DEFAULT_NETWORK_CALLBACK,
    NETWORK_CAPABILITIES,
    WIFI_TRANSPORT_INFO,
    WIFI_MANAGER_LEGACY,
    PACKAGE_MANAGER_FEATURE,
    PLATFORM_PERMISSION,
    LOCATION_MANAGER,
    DERIVED_FROM_FREQUENCY,
    DERIVED_FROM_NOT_METERED_CAPABILITY,
    PLATFORM_POLICY,
}

enum class ConnectivityObservationReason {
    POLICY_REDACTED,
    PERMISSION_NOT_DECLARED,
    PERMISSION_DENIED,
    LOCATION_SERVICES_DISABLED,
    REDACTED_BY_PLATFORM,
    UNSUPPORTED_API,
    NOT_REPORTED,
    INVALID_PLATFORM_VALUE,
    NOT_APPLICABLE,
    INITIAL_CALLBACK_PENDING,
    NO_DEFAULT_NETWORK,
    CAPABILITIES_PENDING,
    WIFI_HARDWARE_ABSENT,
    WIFI_INFO_UNAVAILABLE,
    NON_WIFI_DEFAULT_NETWORK,
    VPN_UNDERLYING_NETWORK_NOT_OBSERVABLE,
    TRANSPORT_UNKNOWN,
    SOURCE_MISMATCH,
    ACCESS_BLOCKED,
    REGISTRATION_FAILED,
    UNREGISTRATION_FAILED,
    THREAD_CLEANUP_FAILED,
    MODE_CHANGE_REQUIRES_RESTART,
    OBSERVER_STOPPED,
    OBSERVER_CLOSED,
    PLATFORM_ERROR,
}

class ObservedValue<out T : Any> private constructor(
    val value: T?,
    val unit: ObservationUnit,
    val source: ObservationSource,
    val availability: ObservationAvailability,
    val confidence: ObservationConfidence,
    val reason: ConnectivityObservationReason?,
) {
    init {
        if (availability == ObservationAvailability.OBSERVED) {
            require(value != null) { "Observed values cannot be null." }
            require(reason == null) { "Observed values cannot have a reason." }
            require(
                confidence == ObservationConfidence.HIGH ||
                    confidence == ObservationConfidence.MEDIUM ||
                    confidence == ObservationConfidence.LOW,
            ) {
                "Observed values require a measured confidence."
            }
        } else {
            require(value == null) { "Unavailable values must be null." }
            require(reason != null) { "Unavailable values require a reason." }
            when (availability) {
                ObservationAvailability.NOT_APPLICABLE ->
                    require(confidence == ObservationConfidence.NOT_APPLICABLE)
                ObservationAvailability.UNAVAILABLE,
                ObservationAvailability.UNKNOWN,
                -> require(confidence == ObservationConfidence.UNKNOWN)
                ObservationAvailability.OBSERVED -> error("Already handled.")
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is ObservedValue<*> &&
            value == other.value &&
            unit == other.unit &&
            source == other.source &&
            availability == other.availability &&
            confidence == other.confidence &&
            reason == other.reason

    override fun hashCode(): Int =
        listOf(value, unit, source, availability, confidence, reason).hashCode()

    override fun toString(): String =
        "ObservedValue(value=$value, unit=$unit, source=$source, " +
            "availability=$availability, confidence=$confidence, reason=$reason)"

    companion object {
        fun <T : Any> observed(
            value: T,
            unit: ObservationUnit,
            source: ObservationSource,
            confidence: ObservationConfidence,
        ): ObservedValue<T> =
            ObservedValue(
                value = value,
                unit = unit,
                source = source,
                availability = ObservationAvailability.OBSERVED,
                confidence = confidence,
                reason = null,
            )

        fun <T : Any> unavailable(
            unit: ObservationUnit,
            source: ObservationSource,
            reason: ConnectivityObservationReason,
        ): ObservedValue<T> =
            ObservedValue(
                value = null,
                unit = unit,
                source = source,
                availability = ObservationAvailability.UNAVAILABLE,
                confidence = ObservationConfidence.UNKNOWN,
                reason = reason,
            )

        fun <T : Any> unknown(
            unit: ObservationUnit,
            source: ObservationSource,
            reason: ConnectivityObservationReason,
        ): ObservedValue<T> =
            ObservedValue(
                value = null,
                unit = unit,
                source = source,
                availability = ObservationAvailability.UNKNOWN,
                confidence = ObservationConfidence.UNKNOWN,
                reason = reason,
            )

        fun <T : Any> notApplicable(
            unit: ObservationUnit,
            source: ObservationSource = ObservationSource.PLATFORM_POLICY,
            reason: ConnectivityObservationReason =
                ConnectivityObservationReason.NOT_APPLICABLE,
        ): ObservedValue<T> =
            ObservedValue(
                value = null,
                unit = unit,
                source = source,
                availability = ObservationAvailability.NOT_APPLICABLE,
                confidence = ObservationConfidence.NOT_APPLICABLE,
                reason = reason,
            )
    }
}

sealed interface WifiIdentityValidation<out T : Any> {
    data class Valid<out T : Any>(val value: T) : WifiIdentityValidation<T>

    data class Invalid(val reason: ConnectivityObservationReason) :
        WifiIdentityValidation<Nothing>
}

enum class WifiSsidDisplayMethod {
    REPORTED_VALUE,
    REMOVE_SINGLE_ANDROID_QUOTE_PAIR,
}

/**
 * Preserves the exact string reported by Android. [displayValue] is a separate presentation
 * derivative: it removes one surrounding quote pair, without unescaping, trimming, case folding,
 * or Unicode normalization.
 */
class WifiSsid private constructor(
    val reportedValue: String,
    val displayValue: String,
    val displayMethod: WifiSsidDisplayMethod,
) {
    override fun equals(other: Any?): Boolean =
        other is WifiSsid &&
            reportedValue == other.reportedValue &&
            displayValue == other.displayValue &&
            displayMethod == other.displayMethod

    override fun hashCode(): Int =
        listOf(reportedValue, displayValue, displayMethod).hashCode()

    override fun toString(): String = "WifiSsid(<redacted>)"

    companion object {
        private const val MAX_PLATFORM_CODE_POINTS = 256

        fun fromPlatformValue(value: String): WifiIdentityValidation<WifiSsid> {
            if (
                value.isEmpty() ||
                    value.hasUnpairedSurrogate() ||
                    value.codePointCount(0, value.length) > MAX_PLATFORM_CODE_POINTS
            ) {
                return WifiIdentityValidation.Invalid(
                    ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
                )
            }
            val quoted = value.length >= 2 && value.first() == '"' && value.last() == '"'
            val displayValue = if (quoted) value.substring(1, value.length - 1) else value
            if (displayValue.isEmpty()) {
                return WifiIdentityValidation.Invalid(
                    ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
                )
            }
            return WifiIdentityValidation.Valid(
                WifiSsid(
                    reportedValue = value,
                    displayValue = displayValue,
                    displayMethod =
                        if (quoted) {
                            WifiSsidDisplayMethod.REMOVE_SINGLE_ANDROID_QUOTE_PAIR
                        } else {
                            WifiSsidDisplayMethod.REPORTED_VALUE
                        },
                ),
            )
        }
    }
}

/**
 * Preserves the validated platform representation and exposes a lower-case canonical identity.
 * Hexadecimal case is identity-preserving for a MAC address. Both forms are redacted from
 * [toString].
 */
class WifiBssid private constructor(
    val reportedValue: String,
    val canonicalValue: String,
) {
    override fun equals(other: Any?): Boolean =
        other is WifiBssid && canonicalValue == other.canonicalValue

    override fun hashCode(): Int = canonicalValue.hashCode()

    override fun toString(): String = "WifiBssid(<redacted>)"

    companion object {
        const val PLATFORM_REDACTED_VALUE: String = "02:00:00:00:00:00"

        private val FORMAT = Regex("^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")

        fun fromPlatformValue(value: String): WifiIdentityValidation<WifiBssid> {
            if (
                value.equals(PLATFORM_REDACTED_VALUE, ignoreCase = true) ||
                    !FORMAT.matches(value)
            ) {
                return WifiIdentityValidation.Invalid(
                    ConnectivityObservationReason.INVALID_PLATFORM_VALUE,
                )
            }
            return WifiIdentityValidation.Valid(
                WifiBssid(
                    reportedValue = value,
                    canonicalValue = value.lowercase(Locale.ROOT),
                ),
            )
        }
    }
}

enum class NetworkTransport {
    WIFI,
    CELLULAR,
    ETHERNET,
    VPN,
    BLUETOOTH,
    WIFI_AWARE,
    LOWPAN,
    USB,
    THREAD,
    SATELLITE,
}

class NetworkTransports private constructor(values: Set<NetworkTransport>) {
    val values: Set<NetworkTransport> =
        Collections.unmodifiableSet(LinkedHashSet(values))

    override fun equals(other: Any?): Boolean =
        other is NetworkTransports && values == other.values

    override fun hashCode(): Int = values.hashCode()

    override fun toString(): String = "NetworkTransports(values=$values)"

    companion object {
        fun of(values: Set<NetworkTransport>): NetworkTransports {
            require(values.isNotEmpty()) { "An observed transport set cannot be empty." }
            return NetworkTransports(values)
        }
    }
}

enum class DefaultNetworkPresence {
    PRESENT,
    ABSENT,
}

data class DefaultNetworkObservation(
    val presence: ObservedValue<DefaultNetworkPresence>,
    val transports: ObservedValue<NetworkTransports>,
    val capabilitiesPending: ObservedValue<Boolean>,
    val blocked: ObservedValue<Boolean>,
    val hasInternetCapability: ObservedValue<Boolean>,
    val isValidated: ObservedValue<Boolean>,
    val hasCaptivePortalCapability: ObservedValue<Boolean>,
    val hasNotMeteredCapability: ObservedValue<Boolean>,
    val isMetered: ObservedValue<Boolean>,
    val hasNotRoamingCapability: ObservedValue<Boolean>,
    val hasNotSuspendedCapability: ObservedValue<Boolean>,
)

enum class WifiAssociationScope {
    DEFAULT_NETWORK,
    DEVICE_ASSOCIATION_NOT_PROVEN_AS_DEFAULT,
    UNKNOWN,
}

enum class WifiAssociationState {
    ASSOCIATED,
    NOT_ASSOCIATED,
}

enum class WifiBand {
    GHZ_2_4,
    GHZ_5,
    GHZ_6,
    GHZ_60,
    UNKNOWN,
}

enum class WifiStandard {
    LEGACY,
    IEEE_802_11N,
    IEEE_802_11AC,
    IEEE_802_11AX,
    IEEE_802_11AD,
    IEEE_802_11BE,
}

enum class WifiSecurityType {
    OPEN,
    WEP,
    PSK,
    EAP,
    SAE,
    OWE,
    WAPI_PSK,
    WAPI_CERT,
    EAP_WPA3_ENTERPRISE,
    EAP_WPA3_ENTERPRISE_192_BIT,
    OSEN,
    PASSPOINT_R1_R2,
    PASSPOINT_R3,
    DPP,
}

data class WifiAssociationObservation(
    val association: ObservedValue<WifiAssociationState>,
    val scope: WifiAssociationScope,
    val ssid: ObservedValue<WifiSsid>,
    val bssid: ObservedValue<WifiBssid>,
    val rssiDbm: ObservedValue<Int>,
    val frequencyMhz: ObservedValue<Int>,
    val band: ObservedValue<WifiBand>,
    val primaryChannel: ObservedValue<Int>,
    val linkSpeedMbps: ObservedValue<Int>,
    val rxLinkSpeedMbps: ObservedValue<Int>,
    val txLinkSpeedMbps: ObservedValue<Int>,
    val standard: ObservedValue<WifiStandard>,
    val securityType: ObservedValue<WifiSecurityType>,
    val channelWidthMhz: ObservedValue<Int>,
)

enum class ConnectivityFailureOperation {
    REGISTER_CALLBACK,
    UNREGISTER_CALLBACK,
    CLEANUP_THREAD,
    MAP_PLATFORM_DATA,
}

data class ConnectivityObservationFailure(
    val operation: ConnectivityFailureOperation,
    val reason: ConnectivityObservationReason,
    val occurredAtUtc: Instant,
    val elapsedRealtimeNanos: Long,
) {
    init {
        require(elapsedRealtimeNanos >= 0) {
            "Failure monotonic time cannot be negative."
        }
    }
}

class ConnectivitySnapshot(
    val observedAtUtc: Instant,
    val elapsedRealtimeNanos: Long,
    val sequence: Long,
    val collectionProfile: ConnectivityCollectionProfile,
    val defaultNetwork: DefaultNetworkObservation,
    val wifiAssociation: WifiAssociationObservation,
    failures: List<ConnectivityObservationFailure>,
) {
    val failures: List<ConnectivityObservationFailure> =
        Collections.unmodifiableList(ArrayList(failures))

    init {
        require(elapsedRealtimeNanos >= 0) {
            "Snapshot monotonic time cannot be negative."
        }
        require(sequence >= 0) {
            "Snapshot sequence cannot be negative."
        }
    }

    override fun equals(other: Any?): Boolean =
        other is ConnectivitySnapshot &&
            observedAtUtc == other.observedAtUtc &&
            elapsedRealtimeNanos == other.elapsedRealtimeNanos &&
            sequence == other.sequence &&
            collectionProfile == other.collectionProfile &&
            defaultNetwork == other.defaultNetwork &&
            wifiAssociation == other.wifiAssociation &&
            failures == other.failures

    override fun hashCode(): Int =
        listOf(
            observedAtUtc,
            elapsedRealtimeNanos,
            sequence,
            collectionProfile,
            defaultNetwork,
            wifiAssociation,
            failures,
        ).hashCode()

    override fun toString(): String =
        "ConnectivitySnapshot(observedAtUtc=$observedAtUtc, " +
            "elapsedRealtimeNanos=$elapsedRealtimeNanos, sequence=$sequence, " +
            "collectionProfile=$collectionProfile, defaultNetwork=$defaultNetwork, " +
            "wifiAssociation=$wifiAssociation, failures=$failures)"
}

data class DerivedWifiChannel(
    val band: WifiBand,
    val primaryChannel: Int?,
)

object WifiChannelPolicy {
    private const val BAND_24_START_MHZ = 2412
    private const val BAND_24_END_MHZ = 2484
    private const val BAND_5_START_MHZ = 5160
    private const val BAND_5_END_MHZ = 5885
    private const val BAND_6_CHANNEL_2_MHZ = 5935
    private const val BAND_6_START_MHZ = 5955
    private const val BAND_6_END_MHZ = 7115
    private const val BAND_60_START_MHZ = 58320
    private const val BAND_60_END_MHZ = 70200

    fun fromFrequencyMhz(frequencyMhz: Int): DerivedWifiChannel =
        when {
            frequencyMhz == 2484 -> DerivedWifiChannel(WifiBand.GHZ_2_4, 14)
            frequencyMhz in BAND_24_START_MHZ..2472 &&
                (frequencyMhz - BAND_24_START_MHZ) % 5 == 0 ->
                DerivedWifiChannel(
                    WifiBand.GHZ_2_4,
                    (frequencyMhz - BAND_24_START_MHZ) / 5 + 1,
                )
            frequencyMhz in BAND_24_START_MHZ..BAND_24_END_MHZ ->
                DerivedWifiChannel(WifiBand.GHZ_2_4, null)
            frequencyMhz in BAND_5_START_MHZ..BAND_5_END_MHZ ->
                DerivedWifiChannel(
                    WifiBand.GHZ_5,
                    if ((frequencyMhz - BAND_5_START_MHZ) % 5 == 0) {
                        (frequencyMhz - BAND_5_START_MHZ) / 5 + 32
                    } else {
                        null
                    },
                )
            frequencyMhz == BAND_6_CHANNEL_2_MHZ ->
                DerivedWifiChannel(WifiBand.GHZ_6, 2)
            frequencyMhz in BAND_6_START_MHZ..BAND_6_END_MHZ ->
                DerivedWifiChannel(
                    WifiBand.GHZ_6,
                    if ((frequencyMhz - BAND_6_START_MHZ) % 5 == 0) {
                        (frequencyMhz - BAND_6_START_MHZ) / 5 + 1
                    } else {
                        null
                    },
                )
            frequencyMhz in BAND_60_START_MHZ..BAND_60_END_MHZ ->
                DerivedWifiChannel(
                    WifiBand.GHZ_60,
                    if ((frequencyMhz - BAND_60_START_MHZ) % 2160 == 0) {
                        (frequencyMhz - BAND_60_START_MHZ) / 2160 + 1
                    } else {
                        null
                    },
                )
            else -> DerivedWifiChannel(WifiBand.UNKNOWN, null)
        }
}

private fun String.hasUnpairedSurrogate(): Boolean {
    var index = 0
    while (index < length) {
        val current = this[index]
        when {
            current.isHighSurrogate() -> {
                if (index + 1 >= length || !this[index + 1].isLowSurrogate()) return true
                index += 2
            }
            current.isLowSurrogate() -> return true
            else -> index += 1
        }
    }
    return false
}
