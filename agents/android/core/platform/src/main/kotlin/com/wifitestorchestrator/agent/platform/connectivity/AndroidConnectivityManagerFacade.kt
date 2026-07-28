package com.wifitestorchestrator.agent.platform.connectivity

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationReason
import com.wifitestorchestrator.agent.domain.connectivity.NetworkTransport
import java.util.concurrent.CancellationException

internal class AndroidNetworkIdentity(
    private val token: Any,
) {
    override fun equals(other: Any?): Boolean =
        other is AndroidNetworkIdentity && token == other.token

    override fun hashCode(): Int = token.hashCode()
}

internal interface AndroidDefaultNetworkEvents {
    fun onAvailable(network: AndroidNetworkIdentity)

    fun onCapabilitiesChanged(
        network: AndroidNetworkIdentity,
        capabilities: AndroidNetworkCapabilitiesSnapshot,
    )

    fun onControlFailure(failure: AndroidCallbackControlFailure)

    fun onBlockedStatusChanged(
        network: AndroidNetworkIdentity,
        blocked: Boolean,
    )

    fun onLost(network: AndroidNetworkIdentity)
}

internal sealed interface AndroidCallbackControlFailure {
    val throwable: Throwable

    data class Cancellation(
        val exception: CancellationException,
    ) : AndroidCallbackControlFailure {
        override val throwable: Throwable = exception
    }

    data class Fatal(
        val error: Error,
    ) : AndroidCallbackControlFailure {
        override val throwable: Throwable = error
    }
}

internal interface AndroidNetworkCallbackRegistration {
    val controlFailureDuringRegistration: AndroidCallbackControlFailure?
        get() = null
}

internal interface AndroidConnectivityManagerFacade {
    fun registerDefaultNetworkCallback(
        profile: ConnectivityCollectionProfile,
        handler: Handler,
        events: AndroidDefaultNetworkEvents,
    ): AndroidNetworkCallbackRegistration

    fun unregisterNetworkCallback(registration: AndroidNetworkCallbackRegistration)
}

internal interface AndroidConnectivityCallbackRegistrar {
    fun registerDefaultNetworkCallback(
        callback: ConnectivityManager.NetworkCallback,
        handler: Handler,
    ): AndroidCallbackRegistrationAttempt

    fun unregisterNetworkCallback(callback: ConnectivityManager.NetworkCallback)
}

internal fun interface AndroidLocationAwareCallbackFactory {
    fun create(delegate: ConnectivityManager.NetworkCallback): ConnectivityManager.NetworkCallback
}

internal sealed interface AndroidCallbackRegistrationAttempt {
    data object Registered : AndroidCallbackRegistrationAttempt

    data class FailedBeforeRegistration(
        val failure: Throwable,
    ) : AndroidCallbackRegistrationAttempt

    data class RegisteredThenControlFailure(
        val failure: AndroidCallbackControlFailure,
    ) : AndroidCallbackRegistrationAttempt
}

internal fun interface AndroidLegacyWifiInfoProvider {
    fun currentWifiInfo(): AndroidWifiInfoAccess?
}

internal fun interface AndroidWifiFeatureProvider {
    fun hasWifiFeature(): Boolean
}

internal fun interface AndroidSensitiveWifiAccess {
    fun sensitiveWifiAccessReason(): ConnectivityObservationReason?

    fun wifiAccessAssessment(): AndroidWifiAccessAssessment =
        AndroidWifiAccessAssessment(
            baseAccessReason = null,
            sensitiveAccessReason = sensitiveWifiAccessReason(),
        )
}

internal data class AndroidWifiAccessAssessment(
    val baseAccessReason: ConnectivityObservationReason?,
    val sensitiveAccessReason: ConnectivityObservationReason?,
)

internal interface AndroidWifiInfoAccess {
    val ssid: String?
    val bssid: String?
    val rssi: Int?
    val frequency: Int?
    val linkSpeed: Int?
    val rxLinkSpeedMbps: Int?
    val txLinkSpeedMbps: Int?
    val wifiStandard: Int?
    val currentSecurityType: Int?
}

internal enum class AndroidWifiInfoOrigin {
    NETWORK_CALLBACK,
    WIFI_MANAGER_LEGACY,
}

internal class AndroidPlatformValue<out T : Any> private constructor(
    val value: T?,
    val reason: ConnectivityObservationReason?,
) {
    init {
        require((value == null) != (reason == null)) {
            "A platform value must contain exactly one of value or reason."
        }
    }

    companion object {
        fun <T : Any> value(value: T): AndroidPlatformValue<T> =
            AndroidPlatformValue(value, null)

        fun <T : Any> missing(reason: ConnectivityObservationReason): AndroidPlatformValue<T> =
            AndroidPlatformValue(null, reason)
    }
}

internal data class AndroidWifiInfoSnapshot(
    val origin: AndroidWifiInfoOrigin,
    val ssid: AndroidPlatformValue<String>,
    val bssid: AndroidPlatformValue<String>,
    val rssiDbm: AndroidPlatformValue<Int>,
    val frequencyMhz: AndroidPlatformValue<Int>,
    val linkSpeedMbps: AndroidPlatformValue<Int>,
    val rxLinkSpeedMbps: AndroidPlatformValue<Int>,
    val txLinkSpeedMbps: AndroidPlatformValue<Int>,
    val wifiStandard: AndroidPlatformValue<Int>,
    val securityType: AndroidPlatformValue<Int>,
)

internal data class AndroidNetworkCapabilitiesSnapshot(
    val transports: Set<NetworkTransport>,
    val hasInternetCapability: Boolean,
    val isValidated: Boolean,
    val hasCaptivePortalCapability: Boolean,
    val hasNotMeteredCapability: Boolean,
    val hasNotRoamingCapability: Boolean,
    val hasNotSuspendedCapability: Boolean,
    val signalStrength: AndroidPlatformValue<Int>,
    val wifiInfo: AndroidWifiInfoSnapshot?,
    val wifiTransportInfoUnexpected: Boolean,
    val wifiFeaturePresent: Boolean?,
)

internal class FrameworkAndroidConnectivityManagerFacade internal constructor(
    private val callbackRegistrar: AndroidConnectivityCallbackRegistrar,
    private val legacyWifiInfoProvider: AndroidLegacyWifiInfoProvider?,
    private val sensitiveWifiAccess: AndroidSensitiveWifiAccess,
    private val wifiFeatureProvider: AndroidWifiFeatureProvider,
    private val sdkInt: Int,
    private val locationAwareCallbackFactory: AndroidLocationAwareCallbackFactory? = null,
) : AndroidConnectivityManagerFacade {
    constructor(context: Context) : this(
        callbackRegistrar =
            FrameworkAndroidConnectivityCallbackRegistrar(
                requireNotNull(context.getSystemService(ConnectivityManager::class.java)) {
                    "ConnectivityManager is required."
                },
            ),
        legacyWifiInfoProvider =
            context.getSystemService(WifiManager::class.java)?.let {
                FrameworkAndroidLegacyWifiInfoProvider(it)
            },
        sensitiveWifiAccess = AndroidPermissionAndLocation(context),
        wifiFeatureProvider = FrameworkAndroidWifiFeatureProvider(context.packageManager),
        sdkInt = Build.VERSION.SDK_INT,
    )

    override fun registerDefaultNetworkCallback(
        profile: ConnectivityCollectionProfile,
        handler: Handler,
        events: AndroidDefaultNetworkEvents,
    ): AndroidNetworkCallbackRegistration {
        val includeLocation =
            if (
                profile == ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED &&
                sdkInt >= Build.VERSION_CODES.S
            ) {
                AndroidConnectivityApiPolicy.shouldIncludeLocationInformation(
                    profile = profile,
                    sdkInt = sdkInt,
                    sensitiveAccessReason =
                        sensitiveWifiAccess.sensitiveWifiAccessReason(),
                )
            } else {
                false
            }
        val callback =
            if (includeLocation) {
                createLocationAwareCallback(profile, events)
            } else {
                createBasicCallback(profile, events)
            }
        return when (
            val attempt = callbackRegistrar.registerDefaultNetworkCallback(callback, handler)
        ) {
            AndroidCallbackRegistrationAttempt.Registered ->
                FrameworkCallbackRegistration(callback)
            is AndroidCallbackRegistrationAttempt.FailedBeforeRegistration ->
                throw attempt.failure
            is AndroidCallbackRegistrationAttempt.RegisteredThenControlFailure ->
                FrameworkCallbackRegistration(
                    callback = callback,
                    controlFailureDuringRegistration = attempt.failure,
                )
        }
    }

    override fun unregisterNetworkCallback(registration: AndroidNetworkCallbackRegistration) {
        val frameworkRegistration =
            requireNotNull(registration as? FrameworkCallbackRegistration) {
                "Registration was not created by this facade."
            }
        callbackRegistrar.unregisterNetworkCallback(frameworkRegistration.callback)
    }

    private fun createBasicCallback(
        profile: ConnectivityCollectionProfile,
        events: AndroidDefaultNetworkEvents,
    ): ConnectivityManager.NetworkCallback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                events.onAvailable(AndroidNetworkIdentity(network))
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                val capabilities =
                    try {
                        captureCapabilities(networkCapabilities, profile)
                    } catch (failure: CancellationException) {
                        notifyControlFailure(
                            events,
                            AndroidCallbackControlFailure.Cancellation(failure),
                        )
                    } catch (failure: Error) {
                        notifyControlFailure(
                            events,
                            AndroidCallbackControlFailure.Fatal(failure),
                        )
                    }
                events.onCapabilitiesChanged(
                    AndroidNetworkIdentity(network),
                    capabilities,
                )
            }

            override fun onBlockedStatusChanged(
                network: Network,
                blocked: Boolean,
            ) {
                events.onBlockedStatusChanged(AndroidNetworkIdentity(network), blocked)
            }

            override fun onLost(network: Network) {
                events.onLost(AndroidNetworkIdentity(network))
            }
        }

    private fun createLocationAwareCallback(
        profile: ConnectivityCollectionProfile,
        events: AndroidDefaultNetworkEvents,
    ): ConnectivityManager.NetworkCallback =
        (locationAwareCallbackFactory ?: FrameworkAndroidLocationAwareCallbackFactory)
            .create(createBasicCallback(profile, events))

    private fun captureCapabilities(
        capabilities: NetworkCapabilities,
        profile: ConnectivityCollectionProfile,
    ): AndroidNetworkCapabilitiesSnapshot {
        val transports = captureTransports(capabilities)
        val containsVpn = NetworkTransport.VPN in transports
        val wifiInfo =
            when {
                NetworkTransport.WIFI !in transports || containsVpn -> null
                sdkInt >= Build.VERSION_CODES.S ->
                    (capabilities.transportInfo as? WifiInfo)?.let {
                        captureWifiInfo(
                            wifiInfo = FrameworkAndroidWifiInfoAccess(it),
                            origin = AndroidWifiInfoOrigin.NETWORK_CALLBACK,
                            sensitiveReason =
                                if (profile == ConnectivityCollectionProfile.BASIC) {
                                    ConnectivityObservationReason.POLICY_REDACTED
                                } else {
                                    sensitiveWifiAccess.sensitiveWifiAccessReason()
                                },
                        )
                    }
                AndroidConnectivityApiPolicy.shouldReadLegacyWifiManager(profile, sdkInt) ->
                    captureLegacyWifiInfo()
                else -> null
            }
        val unexpected =
            sdkInt >= Build.VERSION_CODES.S &&
                NetworkTransport.WIFI in transports &&
                !containsVpn &&
                capabilities.transportInfo != null &&
                capabilities.transportInfo !is WifiInfo
        return AndroidNetworkCapabilitiesSnapshot(
            transports = transports,
            hasInternetCapability =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            isValidated =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            hasCaptivePortalCapability =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            hasNotMeteredCapability =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            hasNotRoamingCapability =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
            hasNotSuspendedCapability =
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED),
            signalStrength =
                platformRead {
                    capabilities.signalStrength
                },
            wifiInfo = wifiInfo,
            wifiTransportInfoUnexpected = unexpected,
            wifiFeaturePresent =
                try {
                    wifiFeatureProvider.hasWifiFeature()
                } catch (failure: CancellationException) {
                    throw failure
                } catch (_: RuntimeException) {
                    null
                },
        )
    }

    private fun captureTransports(capabilities: NetworkCapabilities): Set<NetworkTransport> =
        buildSet {
            addIf(capabilities, NetworkCapabilities.TRANSPORT_WIFI, NetworkTransport.WIFI)
            addIf(capabilities, NetworkCapabilities.TRANSPORT_CELLULAR, NetworkTransport.CELLULAR)
            addIf(capabilities, NetworkCapabilities.TRANSPORT_ETHERNET, NetworkTransport.ETHERNET)
            addIf(capabilities, NetworkCapabilities.TRANSPORT_VPN, NetworkTransport.VPN)
            addIf(capabilities, NetworkCapabilities.TRANSPORT_BLUETOOTH, NetworkTransport.BLUETOOTH)
            addIf(capabilities, NetworkCapabilities.TRANSPORT_WIFI_AWARE, NetworkTransport.WIFI_AWARE)
            addIf(capabilities, NetworkCapabilities.TRANSPORT_LOWPAN, NetworkTransport.LOWPAN)
            if (sdkInt >= Build.VERSION_CODES.S) {
                addIf(capabilities, TRANSPORT_USB_API_31, NetworkTransport.USB)
            }
            if (sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                addIf(capabilities, TRANSPORT_THREAD_API_34, NetworkTransport.THREAD)
            }
            if (sdkInt >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                addIf(
                    capabilities,
                    TRANSPORT_SATELLITE_API_35,
                    NetworkTransport.SATELLITE,
                )
            }
        }

    private fun MutableSet<NetworkTransport>.addIf(
        capabilities: NetworkCapabilities,
        platformTransport: Int,
        domainTransport: NetworkTransport,
    ) {
        if (capabilities.hasTransport(platformTransport)) add(domainTransport)
    }

    @Suppress("DEPRECATION")
    private fun captureLegacyWifiInfo(): AndroidWifiInfoSnapshot? {
        val access = sensitiveWifiAccess.wifiAccessAssessment()
        access.baseAccessReason?.let { reason ->
            return missingWifiInfo(AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY, reason)
        }
        val provider =
            legacyWifiInfoProvider ?: return missingWifiInfo(
                AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                wifiServiceUnavailableReason(),
            )
        return try {
            captureWifiInfo(
                wifiInfo = provider.currentWifiInfo() ?: return null,
                origin = AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                sensitiveReason = access.sensitiveAccessReason,
            )
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: SecurityException) {
            missingWifiInfo(
                AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                ConnectivityObservationReason.PERMISSION_DENIED,
            )
        } catch (_: RuntimeException) {
            missingWifiInfo(
                AndroidWifiInfoOrigin.WIFI_MANAGER_LEGACY,
                ConnectivityObservationReason.PLATFORM_ERROR,
            )
        }
    }

    private fun wifiServiceUnavailableReason(): ConnectivityObservationReason =
        try {
            if (wifiFeatureProvider.hasWifiFeature()) {
                ConnectivityObservationReason.PLATFORM_ERROR
            } else {
                ConnectivityObservationReason.WIFI_HARDWARE_ABSENT
            }
        } catch (failure: CancellationException) {
            throw failure
        } catch (_: RuntimeException) {
            ConnectivityObservationReason.PLATFORM_ERROR
        }

    private fun captureWifiInfo(
        wifiInfo: AndroidWifiInfoAccess,
        origin: AndroidWifiInfoOrigin,
        sensitiveReason: ConnectivityObservationReason?,
    ): AndroidWifiInfoSnapshot {
        val ssid =
            if (sensitiveReason != null) {
                AndroidPlatformValue.missing(sensitiveReason)
            } else {
                platformReadSensitive {
                    val raw = wifiInfo.ssid
                    if (raw == WifiManager.UNKNOWN_SSID) {
                        throw PlatformRedactedValue
                    }
                    raw
                }
            }
        val bssid =
            if (sensitiveReason != null) {
                AndroidPlatformValue.missing(sensitiveReason)
            } else {
                platformReadSensitive {
                    val raw = wifiInfo.bssid
                    if (raw == WifiBssidRedactedValue) {
                        throw PlatformRedactedValue
                    }
                    raw
                }
            }
        return AndroidWifiInfoSnapshot(
            origin = origin,
            ssid = ssid,
            bssid = bssid,
            rssiDbm = platformRead { wifiInfo.rssi },
            frequencyMhz = platformRead { wifiInfo.frequency },
            linkSpeedMbps = platformRead { wifiInfo.linkSpeed },
            rxLinkSpeedMbps = platformRead { wifiInfo.rxLinkSpeedMbps },
            txLinkSpeedMbps = platformRead { wifiInfo.txLinkSpeedMbps },
            wifiStandard =
                if (sdkInt >= Build.VERSION_CODES.R) {
                    captureWifiStandard(wifiInfo)
                } else {
                    AndroidPlatformValue.missing(ConnectivityObservationReason.UNSUPPORTED_API)
                },
            securityType =
                if (sdkInt >= Build.VERSION_CODES.S) {
                    captureSecurityType(wifiInfo)
                } else {
                    AndroidPlatformValue.missing(ConnectivityObservationReason.UNSUPPORTED_API)
                },
        )
    }

    @android.annotation.SuppressLint("NewApi")
    private fun captureWifiStandard(wifiInfo: AndroidWifiInfoAccess): AndroidPlatformValue<Int> =
        platformRead { wifiInfo.wifiStandard }

    @android.annotation.SuppressLint("NewApi")
    private fun captureSecurityType(wifiInfo: AndroidWifiInfoAccess): AndroidPlatformValue<Int> =
        platformRead { wifiInfo.currentSecurityType }

    private fun missingWifiInfo(
        origin: AndroidWifiInfoOrigin,
        reason: ConnectivityObservationReason,
    ): AndroidWifiInfoSnapshot =
        AndroidWifiInfoSnapshot(
            origin = origin,
            ssid = AndroidPlatformValue.missing(reason),
            bssid = AndroidPlatformValue.missing(reason),
            rssiDbm = AndroidPlatformValue.missing(reason),
            frequencyMhz = AndroidPlatformValue.missing(reason),
            linkSpeedMbps = AndroidPlatformValue.missing(reason),
            rxLinkSpeedMbps = AndroidPlatformValue.missing(reason),
            txLinkSpeedMbps = AndroidPlatformValue.missing(reason),
            wifiStandard = AndroidPlatformValue.missing(reason),
            securityType = AndroidPlatformValue.missing(reason),
        )

    private class FrameworkCallbackRegistration(
        val callback: ConnectivityManager.NetworkCallback,
        override val controlFailureDuringRegistration: AndroidCallbackControlFailure? = null,
    ) : AndroidNetworkCallbackRegistration

    private companion object {
        const val WifiBssidRedactedValue = "02:00:00:00:00:00"

        // Inlined numeric constants avoid verifier/linkage references on older Android releases.
        const val TRANSPORT_USB_API_31 = 8
        const val TRANSPORT_THREAD_API_34 = 9
        const val TRANSPORT_SATELLITE_API_35 = 10
    }
}

internal object AndroidConnectivityApiPolicy {
    fun shouldIncludeLocationInformation(
        profile: ConnectivityCollectionProfile,
        sdkInt: Int,
        sensitiveAccessReason: ConnectivityObservationReason?,
    ): Boolean =
        profile == ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED &&
            sdkInt >= Build.VERSION_CODES.S &&
            sensitiveAccessReason == null

    fun shouldReadLegacyWifiManager(
        profile: ConnectivityCollectionProfile,
        sdkInt: Int,
    ): Boolean =
        profile == ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED &&
            sdkInt in Build.VERSION_CODES.Q..Build.VERSION_CODES.R
}

internal class AndroidPermissionAndLocation internal constructor(
    private val requestedPermissions: () -> Set<String>,
    private val permissionStatus: (String) -> Int,
    private val locationManagerProvider: () -> LocationManager?,
    private val locationEnabled: (LocationManager) -> Boolean,
) : AndroidSensitiveWifiAccess {
    constructor(context: Context) : this(
        requestedPermissions = {
            context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
                .requestedPermissions
                ?.toSet()
                .orEmpty()
        },
        permissionStatus = context::checkSelfPermission,
        locationManagerProvider = {
            context.getSystemService(LocationManager::class.java)
        },
        locationEnabled = LocationManager::isLocationEnabled,
    )

    override fun sensitiveWifiAccessReason(): ConnectivityObservationReason? {
        return wifiAccessAssessment().sensitiveAccessReason
    }

    override fun wifiAccessAssessment(): AndroidWifiAccessAssessment {
        val requested =
            when (val result = accessRead(requestedPermissions)) {
                is AndroidAccessRead.Value -> result.value
                is AndroidAccessRead.Missing ->
                    return AndroidWifiAccessAssessment(
                        baseAccessReason = result.reason,
                        sensitiveAccessReason = result.reason,
                    )
            }
        if (Manifest.permission.ACCESS_WIFI_STATE !in requested) {
            return AndroidWifiAccessAssessment(
                baseAccessReason = ConnectivityObservationReason.PERMISSION_NOT_DECLARED,
                sensitiveAccessReason = ConnectivityObservationReason.PERMISSION_NOT_DECLARED,
            )
        }

        val wifiPermission =
            when (
                val result =
                    accessRead {
                        permissionStatus(Manifest.permission.ACCESS_WIFI_STATE)
                    }
            ) {
                is AndroidAccessRead.Value -> result.value
                is AndroidAccessRead.Missing ->
                    return AndroidWifiAccessAssessment(
                        baseAccessReason = result.reason,
                        sensitiveAccessReason = result.reason,
                    )
            }
        if (wifiPermission != PackageManager.PERMISSION_GRANTED) {
            return AndroidWifiAccessAssessment(
                baseAccessReason = ConnectivityObservationReason.PERMISSION_DENIED,
                sensitiveAccessReason = ConnectivityObservationReason.PERMISSION_DENIED,
            )
        }

        val sensitiveReason =
            when {
                Manifest.permission.ACCESS_FINE_LOCATION !in requested ->
                    ConnectivityObservationReason.PERMISSION_NOT_DECLARED
                else -> sensitiveAccessReasonAfterDeclaration()
            }
        return AndroidWifiAccessAssessment(
            baseAccessReason = null,
            sensitiveAccessReason = sensitiveReason,
        )
    }

    private fun sensitiveAccessReasonAfterDeclaration(): ConnectivityObservationReason? {
        val finePermission =
            when (
                val result =
                    accessRead {
                        permissionStatus(Manifest.permission.ACCESS_FINE_LOCATION)
                    }
            ) {
                is AndroidAccessRead.Value -> result.value
                is AndroidAccessRead.Missing -> return result.reason
            }
        if (finePermission != PackageManager.PERMISSION_GRANTED) {
            return ConnectivityObservationReason.PERMISSION_DENIED
        }
        val locationManager =
            when (val result = accessRead(locationManagerProvider)) {
                is AndroidAccessRead.Value ->
                    result.value ?: return ConnectivityObservationReason.PLATFORM_ERROR
                is AndroidAccessRead.Missing -> return result.reason
            }
        return when (val result = accessRead { locationEnabled(locationManager) }) {
            is AndroidAccessRead.Value ->
                if (result.value) {
                    null
                } else {
                    ConnectivityObservationReason.LOCATION_SERVICES_DISABLED
                }
            is AndroidAccessRead.Missing -> result.reason
        }
    }

    private inline fun <T> accessRead(read: () -> T): AndroidAccessRead<T> =
        try {
            AndroidAccessRead.Value(read())
        } catch (failure: CancellationException) {
            throw failure
        } catch (failure: Error) {
            throw failure
        } catch (_: SecurityException) {
            AndroidAccessRead.Missing(ConnectivityObservationReason.PERMISSION_DENIED)
        } catch (_: RuntimeException) {
            AndroidAccessRead.Missing(ConnectivityObservationReason.PLATFORM_ERROR)
        }
}

private sealed interface AndroidAccessRead<out T> {
    data class Value<T>(
        val value: T,
    ) : AndroidAccessRead<T>

    data class Missing(
        val reason: ConnectivityObservationReason,
    ) : AndroidAccessRead<Nothing>
}

private class FrameworkAndroidConnectivityCallbackRegistrar(
    private val connectivityManager: ConnectivityManager,
) : AndroidConnectivityCallbackRegistrar {
    override fun registerDefaultNetworkCallback(
        callback: ConnectivityManager.NetworkCallback,
        handler: Handler,
    ): AndroidCallbackRegistrationAttempt =
        try {
            connectivityManager.registerDefaultNetworkCallback(callback, handler)
            AndroidCallbackRegistrationAttempt.Registered
        } catch (failure: Throwable) {
            AndroidCallbackRegistrationAttempt.FailedBeforeRegistration(failure)
        }

    override fun unregisterNetworkCallback(callback: ConnectivityManager.NetworkCallback) {
        connectivityManager.unregisterNetworkCallback(callback)
    }
}

private object FrameworkAndroidLocationAwareCallbackFactory :
    AndroidLocationAwareCallbackFactory {
    @android.annotation.SuppressLint("NewApi")
    override fun create(
        delegate: ConnectivityManager.NetworkCallback,
    ): ConnectivityManager.NetworkCallback =
        object :
            ConnectivityManager.NetworkCallback(
                ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO,
            ) {
            override fun onAvailable(network: Network) {
                delegate.onAvailable(network)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                delegate.onCapabilitiesChanged(network, networkCapabilities)
            }

            override fun onBlockedStatusChanged(
                network: Network,
                blocked: Boolean,
            ) {
                delegate.onBlockedStatusChanged(network, blocked)
            }

            override fun onLost(network: Network) {
                delegate.onLost(network)
            }
        }
}

private class FrameworkAndroidLegacyWifiInfoProvider(
    private val wifiManager: WifiManager,
) : AndroidLegacyWifiInfoProvider {
    @Suppress("DEPRECATION")
    override fun currentWifiInfo(): AndroidWifiInfoAccess? =
        wifiManager.connectionInfo?.let(::FrameworkAndroidWifiInfoAccess)
}

private class FrameworkAndroidWifiFeatureProvider(
    private val packageManager: PackageManager,
) : AndroidWifiFeatureProvider {
    override fun hasWifiFeature(): Boolean =
        packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)
}

private class FrameworkAndroidWifiInfoAccess(
    private val wifiInfo: WifiInfo,
) : AndroidWifiInfoAccess {
    override val ssid: String?
        get() = wifiInfo.ssid
    override val bssid: String?
        get() = wifiInfo.bssid
    override val rssi: Int?
        get() = wifiInfo.rssi
    override val frequency: Int?
        get() = wifiInfo.frequency
    override val linkSpeed: Int?
        get() = wifiInfo.linkSpeed
    override val rxLinkSpeedMbps: Int?
        get() = wifiInfo.rxLinkSpeedMbps
    override val txLinkSpeedMbps: Int?
        get() = wifiInfo.txLinkSpeedMbps
    override val wifiStandard: Int?
        @android.annotation.SuppressLint("NewApi")
        get() = wifiInfo.wifiStandard
    override val currentSecurityType: Int?
        @android.annotation.SuppressLint("NewApi")
        get() = wifiInfo.currentSecurityType
}

private object PlatformRedactedValue : RuntimeException()

private fun notifyControlFailure(
    events: AndroidDefaultNetworkEvents,
    failure: AndroidCallbackControlFailure,
): Nothing {
    val primary = failure.throwable
    try {
        events.onControlFailure(failure)
    } catch (secondary: Throwable) {
        primary.addSuppressedByIdentity(secondary)
        if (secondary is InterruptedException) Thread.currentThread().interrupt()
    }
    throw primary
}

private fun Throwable.addSuppressedByIdentity(secondary: Throwable) {
    if (this !== secondary && suppressed.none { existing -> existing === secondary }) {
        addSuppressed(secondary)
    }
}

private inline fun <T : Any> platformRead(block: () -> T?): AndroidPlatformValue<T> =
    try {
        block()?.let { AndroidPlatformValue.value(it) }
            ?: AndroidPlatformValue.missing(ConnectivityObservationReason.NOT_REPORTED)
    } catch (failure: CancellationException) {
        throw failure
    } catch (_: SecurityException) {
        AndroidPlatformValue.missing(ConnectivityObservationReason.PERMISSION_DENIED)
    } catch (_: RuntimeException) {
        AndroidPlatformValue.missing(ConnectivityObservationReason.PLATFORM_ERROR)
    }

private inline fun <T : Any> platformReadSensitive(block: () -> T?): AndroidPlatformValue<T> =
    try {
        block()?.let { AndroidPlatformValue.value(it) }
            ?: AndroidPlatformValue.missing(ConnectivityObservationReason.NOT_REPORTED)
    } catch (failure: CancellationException) {
        throw failure
    } catch (_: PlatformRedactedValue) {
        AndroidPlatformValue.missing(ConnectivityObservationReason.REDACTED_BY_PLATFORM)
    } catch (_: SecurityException) {
        AndroidPlatformValue.missing(ConnectivityObservationReason.PERMISSION_DENIED)
    } catch (_: RuntimeException) {
        AndroidPlatformValue.missing(ConnectivityObservationReason.PLATFORM_ERROR)
    }
