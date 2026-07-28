package com.wifitestorchestrator.agent.platform.connectivity

import android.Manifest
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityFailureOperation
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationReason
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverCommandResult
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverLifecycle
import java.time.Instant
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowNetworkCapabilities

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29])
class AndroidConnectivityManagerFacadeTest {
    @Test
    fun `capture capabilities preserves cancellation from wifi feature lookup`() {
        val cancellation = CancellationException("wifi feature lookup cancelled")
        val fixture =
            fixture(
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw cancellation },
            )
        fixture.register(ConnectivityCollectionProfile.BASIC)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.emitWifiCapabilities()
            }

        assertSame(cancellation, thrown)
        assertNull(fixture.events.lastCapabilities)
    }

    @Test
    fun `legacy connection info preserves cancellation`() {
        val cancellation = CancellationException("connection info cancelled")
        val fixture =
            fixture(
                legacyWifiInfoProvider =
                    AndroidLegacyWifiInfoProvider {
                        throw cancellation
                    },
            )
        fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.emitWifiCapabilities()
            }

        assertSame(cancellation, thrown)
        assertNull(fixture.events.lastCapabilities)
    }

    @Test
    fun `wifi service unavailable reason preserves cancellation`() {
        val cancellation = CancellationException("feature fallback cancelled")
        val fixture =
            fixture(
                legacyWifiInfoProvider = null,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw cancellation },
            )
        fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.emitWifiCapabilities()
            }

        assertSame(cancellation, thrown)
        assertNull(fixture.events.lastCapabilities)
    }

    @Test
    fun `requested permission lookup preserves cancellation`() {
        val cancellation = CancellationException("package info cancelled")
        val access =
            permissionAndLocation(
                requestedPermissions = { throw cancellation },
            )

        val thrown =
            assertFailsWith<CancellationException> {
                access.sensitiveWifiAccessReason()
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `location enabled lookup preserves cancellation`() {
        val cancellation = CancellationException("location lookup cancelled")
        val access =
            permissionAndLocation(
                locationEnabled = { throw cancellation },
            )

        val thrown =
            assertFailsWith<CancellationException> {
                access.sensitiveWifiAccessReason()
            }

        assertSame(cancellation, thrown)
    }

    @Test
    fun `requested permissions follows the complete failure matrix exactly once`() {
        assertPermissionFailureMatrix(
            expectedBaseForSecurity = ConnectivityObservationReason.PERMISSION_DENIED,
            expectedBaseForRuntime = ConnectivityObservationReason.PLATFORM_ERROR,
        ) { failure, calls ->
            permissionAndLocation(
                requestedPermissions = {
                    calls.incrementAndGet()
                    throw failure
                },
            )
        }
    }

    @Test
    fun `permission status follows the complete failure matrix exactly once`() {
        assertPermissionFailureMatrix(
            expectedBaseForSecurity = ConnectivityObservationReason.PERMISSION_DENIED,
            expectedBaseForRuntime = ConnectivityObservationReason.PLATFORM_ERROR,
        ) { failure, calls ->
            permissionAndLocation(
                permissionStatus = {
                    calls.incrementAndGet()
                    throw failure
                },
            )
        }
    }

    @Test
    fun `location manager provider follows the complete failure matrix exactly once`() {
        assertPermissionFailureMatrix(
            expectedBaseForSecurity = null,
            expectedBaseForRuntime = null,
        ) { failure, calls ->
            permissionAndLocation(
                locationManagerProvider = {
                    calls.incrementAndGet()
                    throw failure
                },
            )
        }
    }

    @Test
    fun `location enabled follows the complete failure matrix exactly once`() {
        assertPermissionFailureMatrix(
            expectedBaseForSecurity = null,
            expectedBaseForRuntime = null,
        ) { failure, calls ->
            permissionAndLocation(
                locationEnabled = {
                    calls.incrementAndGet()
                    throw failure
                },
            )
        }
    }

    @Test
    fun `ordinary platform read preserves cancellation`() {
        val cancellation = CancellationException("RSSI read cancelled")
        val fixture =
            fixture(
                legacyWifiInfoProvider =
                    wifiInfoProvider(
                        AndroidWifiInfoAccessFake(
                            rssiRead = { throw cancellation },
                        ),
                    ),
            )
        fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.emitWifiCapabilities()
            }

        assertSame(cancellation, thrown)
        assertNull(fixture.events.lastCapabilities)
    }

    @Test
    fun `sensitive platform read preserves cancellation`() {
        val cancellation = CancellationException("SSID read cancelled")
        val fixture =
            fixture(
                legacyWifiInfoProvider =
                    wifiInfoProvider(
                        AndroidWifiInfoAccessFake(
                            ssidRead = { throw cancellation },
                        ),
                    ),
            )
        fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.emitWifiCapabilities()
            }

        assertSame(cancellation, thrown)
        assertNull(fixture.events.lastCapabilities)
    }

    @Test
    fun `error identity is preserved by facade reads`() {
        val featureError = AssertionError("feature lookup failed")
        val featureFixture =
            fixture(
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw featureError },
            )
        featureFixture.register(ConnectivityCollectionProfile.BASIC)

        val thrownFeatureError =
            assertFailsWith<AssertionError> {
                featureFixture.emitWifiCapabilities()
            }

        assertSame(featureError, thrownFeatureError)

        val wifiInfoError = AssertionError("wifi info read failed")
        val wifiInfoFixture =
            fixture(
                legacyWifiInfoProvider =
                    wifiInfoProvider(
                        AndroidWifiInfoAccessFake(
                            rssiRead = { throw wifiInfoError },
                        ),
                    ),
            )
        wifiInfoFixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        val thrownWifiInfoError =
            assertFailsWith<AssertionError> {
                wifiInfoFixture.emitWifiCapabilities()
            }

        assertSame(wifiInfoError, thrownWifiInfoError)
    }

    @Test
    fun `callback failure notification cannot replace primary control failure`() {
        val primary = CancellationException("capability capture cancelled")
        val secondary = CustomCleanupThrowable("control notification failed")
        val fixture =
            fixture(
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw primary },
            )
        fixture.events.controlFailureNotificationFailure = secondary
        fixture.register(ConnectivityCollectionProfile.BASIC)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.emitWifiCapabilities()
            }

        assertSame(primary, thrown)
        assertEquals(1, primary.suppressed.size)
        assertSame(secondary, primary.suppressed.single())
        assertNull(fixture.events.lastCapabilities)
    }

    @Test
    fun `platform translations remain fail closed and reasoned`() {
        val securitySnapshot =
            captureAuthorized(
                AndroidWifiInfoAccessFake(
                    ssidRead = { throw SecurityException("permission denied") },
                ),
            )
        assertEquals(
            ConnectivityObservationReason.PERMISSION_DENIED,
            securitySnapshot.wifiInfo?.ssid?.reason,
        )

        val redactedSnapshot =
            captureAuthorized(
                AndroidWifiInfoAccessFake(
                    ssidRead = { WifiManager.UNKNOWN_SSID },
                ),
            )
        assertEquals(
            ConnectivityObservationReason.REDACTED_BY_PLATFORM,
            redactedSnapshot.wifiInfo?.ssid?.reason,
        )

        val runtimeSnapshot =
            captureAuthorized(
                AndroidWifiInfoAccessFake(
                    rssiRead = { throw IllegalStateException("framework read failed") },
                ),
            )
        assertEquals(
            ConnectivityObservationReason.PLATFORM_ERROR,
            runtimeSnapshot.wifiInfo?.rssiDbm?.reason,
        )

        val nullSnapshot =
            captureAuthorized(
                AndroidWifiInfoAccessFake(
                    rssiRead = { null },
                ),
            )
        assertEquals(
            ConnectivityObservationReason.NOT_REPORTED,
            nullSnapshot.wifiInfo?.rssiDbm?.reason,
        )
    }

    @Test
    fun `legacy API 29 and 30 preserve KPIs when sensitive identity is unavailable`() {
        val sensitiveCases =
            listOf(
                permissionAndLocation(
                    permissionStatus = { permission ->
                        if (permission == Manifest.permission.ACCESS_FINE_LOCATION) {
                            PackageManager.PERMISSION_DENIED
                        } else {
                            PackageManager.PERMISSION_GRANTED
                        }
                    },
                ) to ConnectivityObservationReason.PERMISSION_DENIED,
                permissionAndLocation(
                    locationEnabled = { false },
                ) to ConnectivityObservationReason.LOCATION_SERVICES_DISABLED,
                permissionAndLocation(
                    requestedPermissions = {
                        setOf(
                            Manifest.permission.ACCESS_WIFI_STATE,
                            Manifest.permission.ACCESS_COARSE_LOCATION,
                        )
                    },
                ) to ConnectivityObservationReason.PERMISSION_NOT_DECLARED,
            )

        listOf(Build.VERSION_CODES.Q, Build.VERSION_CODES.R).forEach { sdkInt ->
            sensitiveCases.forEach { (access, expectedReason) ->
                val snapshot =
                    captureAuthorized(
                        wifiInfo =
                            AndroidWifiInfoAccessFake(
                                wifiStandardRead = { 6 },
                            ),
                        sensitiveWifiAccess = access,
                        sdkInt = sdkInt,
                    )
                val wifiInfo = requireNotNull(snapshot.wifiInfo)

                assertEquals(expectedReason, wifiInfo.ssid.reason)
                assertEquals(expectedReason, wifiInfo.bssid.reason)
                assertEquals(-55, wifiInfo.rssiDbm.value)
                assertEquals(5180, wifiInfo.frequencyMhz.value)
                assertEquals(433, wifiInfo.linkSpeedMbps.value)
                assertEquals(390, wifiInfo.rxLinkSpeedMbps.value)
                assertEquals(351, wifiInfo.txLinkSpeedMbps.value)
                if (sdkInt >= Build.VERSION_CODES.R) {
                    assertEquals(6, wifiInfo.wifiStandard.value)
                } else {
                    assertEquals(
                        ConnectivityObservationReason.UNSUPPORTED_API,
                        wifiInfo.wifiStandard.reason,
                    )
                }
                assertEquals(
                    ConnectivityObservationReason.UNSUPPORTED_API,
                    wifiInfo.securityType.reason,
                )
            }
        }
    }

    @Test
    fun `legacy base permission and provider failures close every wifi field`() {
        val cases =
            listOf(
                Triple(
                    permissionAndLocation(
                        requestedPermissions = {
                            setOf(Manifest.permission.ACCESS_FINE_LOCATION)
                        },
                    ),
                    wifiInfoProvider(AndroidWifiInfoAccessFake()),
                    ConnectivityObservationReason.PERMISSION_NOT_DECLARED,
                ),
                Triple(
                    permissionAndLocation(
                        permissionStatus = { permission ->
                            if (permission == Manifest.permission.ACCESS_WIFI_STATE) {
                                PackageManager.PERMISSION_DENIED
                            } else {
                                PackageManager.PERMISSION_GRANTED
                            }
                        },
                    ),
                    wifiInfoProvider(AndroidWifiInfoAccessFake()),
                    ConnectivityObservationReason.PERMISSION_DENIED,
                ),
                Triple(
                    permissionAndLocation(),
                    AndroidLegacyWifiInfoProvider {
                        throw SecurityException("legacy provider denied")
                    },
                    ConnectivityObservationReason.PERMISSION_DENIED,
                ),
                Triple(
                    permissionAndLocation(),
                    AndroidLegacyWifiInfoProvider {
                        throw IllegalStateException("legacy provider failed")
                    },
                    ConnectivityObservationReason.PLATFORM_ERROR,
                ),
            )

        cases.forEach { (access, provider, expectedReason) ->
            val fixture =
                fixture(
                    legacyWifiInfoProvider = provider,
                    sensitiveWifiAccess = access,
                )
            fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)
            fixture.emitWifiCapabilities()

            requireNotNull(fixture.events.lastCapabilities?.wifiInfo)
                .allValues()
                .forEach { value -> assertEquals(expectedReason, value.reason) }
        }
    }

    @Test
    fun `wifi access assessment evaluates each successful dependency once`() {
        val requestedCalls = AtomicInteger()
        val permissionCalls = linkedMapOf<String, Int>()
        val locationProviderCalls = AtomicInteger()
        val locationEnabledCalls = AtomicInteger()
        val access =
            permissionAndLocation(
                requestedPermissions = {
                    requestedCalls.incrementAndGet()
                    setOf(
                        Manifest.permission.ACCESS_WIFI_STATE,
                        Manifest.permission.ACCESS_FINE_LOCATION,
                    )
                },
                permissionStatus = { permission ->
                    permissionCalls[permission] = (permissionCalls[permission] ?: 0) + 1
                    PackageManager.PERMISSION_GRANTED
                },
                locationManagerProvider = {
                    locationProviderCalls.incrementAndGet()
                    requireNotNull(
                        RuntimeEnvironment.getApplication()
                            .getSystemService(LocationManager::class.java),
                    )
                },
                locationEnabled = {
                    locationEnabledCalls.incrementAndGet()
                    true
                },
            )

        assertEquals(AndroidWifiAccessAssessment(null, null), access.wifiAccessAssessment())
        assertEquals(1, requestedCalls.get())
        assertEquals(
            mapOf(
                Manifest.permission.ACCESS_WIFI_STATE to 1,
                Manifest.permission.ACCESS_FINE_LOCATION to 1,
            ),
            permissionCalls,
        )
        assertEquals(1, locationProviderCalls.get())
        assertEquals(1, locationEnabledCalls.get())
    }

    @Test
    fun `missing wifi service distinguishes absent hardware`() {
        val fixture =
            fixture(
                legacyWifiInfoProvider = null,
                wifiFeatureProvider = AndroidWifiFeatureProvider { false },
            )
        fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        fixture.emitWifiCapabilities()

        val wifiInfo = requireNotNull(fixture.events.lastCapabilities?.wifiInfo)
        listOf(
            wifiInfo.ssid,
            wifiInfo.bssid,
            wifiInfo.rssiDbm,
            wifiInfo.frequencyMhz,
            wifiInfo.linkSpeedMbps,
            wifiInfo.rxLinkSpeedMbps,
            wifiInfo.txLinkSpeedMbps,
            wifiInfo.wifiStandard,
            wifiInfo.securityType,
        ).forEach { value ->
            assertEquals(ConnectivityObservationReason.WIFI_HARDWARE_ABSENT, value.reason)
        }
    }

    @Test
    fun `case A cancellation before effective registration skips unregister and preserves identity`() {
        val cancellation = CancellationException("registration cancelled before effective")
        val registrar =
            RecordingCallbackRegistrar().apply {
                failureBeforeRegistration = cancellation
            }
        val fixture = observerFixture(registrar = registrar)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(cancellation, thrown)
        assertRegistrationFailureTerminal(fixture, expectedUnregisterCalls = 0)
    }

    @Test
    fun `case A error before effective registration skips unregister and preserves identity`() {
        val error = AssertionError("registration failed before effective")
        val registrar =
            RecordingCallbackRegistrar().apply {
                failureBeforeRegistration = error
            }
        val fixture = observerFixture(registrar = registrar)

        val thrown =
            assertFailsWith<AssertionError> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(error, thrown)
        assertRegistrationFailureTerminal(fixture, expectedUnregisterCalls = 0)
    }

    @Test
    fun `case B cancellation after effective registration cleans exactly once`() {
        val cancellation = CancellationException("synchronous callback cancelled")
        val registrar = synchronousCapabilitiesRegistrar()
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw cancellation },
            )

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(cancellation, thrown)
        assertRegistrationFailureTerminal(fixture, expectedUnregisterCalls = 1)
    }

    @Test
    fun `case B error after effective registration cleans exactly once`() {
        val error = AssertionError("synchronous callback failed")
        val registrar = synchronousCapabilitiesRegistrar()
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw error },
            )

        val thrown =
            assertFailsWith<AssertionError> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(error, thrown)
        assertRegistrationFailureTerminal(fixture, expectedUnregisterCalls = 1)
    }

    @Test
    fun `case C basic callback cancellation reconciles active observer and listener`() {
        val cancellation = CancellationException("active basic callback cancelled")
        val fixture =
            observerFixture(
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw cancellation },
            )
        val delivered = mutableListOf<ConnectivityObserverLifecycle>()
        fixture.observer.setListener { state -> delivered += state.lifecycle }
        val started =
            assertIs<ConnectivityObserverCommandResult.Accepted>(
                fixture.observer.start(ConnectivityCollectionProfile.BASIC),
            )
        assertEquals(ConnectivityObserverLifecycle.ACTIVE, started.state.lifecycle)
        assertEquals(1, fixture.registrar.activeRegistrations)

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.registrar.emitLatestWifiCapabilities()
            }

        assertSame(cancellation, thrown)
        assertActiveCallbackFailureTerminal(fixture, delivered)
    }

    @Test
    fun `case C location aware callback error reconciles active observer and listener`() {
        val error = AssertionError("active location-aware callback failed")
        val callbackFactory = RecordingLocationAwareCallbackFactory()
        val fixture =
            observerFixture(
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw error },
                sdkInt = Build.VERSION_CODES.S,
                locationAwareCallbackFactory = callbackFactory,
            )
        val delivered = mutableListOf<ConnectivityObserverLifecycle>()
        fixture.observer.setListener { state -> delivered += state.lifecycle }
        val started =
            assertIs<ConnectivityObserverCommandResult.Accepted>(
                fixture.observer.start(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED),
            )
        assertEquals(ConnectivityObserverLifecycle.ACTIVE, started.state.lifecycle)
        assertEquals(1, fixture.registrar.activeRegistrations)
        assertEquals(1, callbackFactory.createCalls)

        val thrown =
            assertFailsWith<AssertionError> {
                fixture.registrar.emitLatestWifiCapabilities()
            }

        assertSame(error, thrown)
        assertActiveCallbackFailureTerminal(fixture, delivered)
    }

    @Test
    fun `primary control failure suppresses interrupted unregister and restores interrupt`() {
        val primary = CancellationException("callback cancelled before interrupted cleanup")
        val interruption = InterruptedException("unregister interrupted")
        val registrar =
            synchronousCapabilitiesRegistrar().apply {
                unregisterFailure = interruption
            }
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw primary },
            )
        assertTrue(!Thread.interrupted())
        try {
            val thrown =
                assertFailsWith<CancellationException> {
                    fixture.observer.start(ConnectivityCollectionProfile.BASIC)
                }

            assertSame(primary, thrown)
            assertEquals(1, primary.suppressed.size)
            assertSame(interruption, primary.suppressed.single())
            assertTrue(Thread.currentThread().isInterrupted)
            assertOperationalCleanupFailure(fixture)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `primary control failure suppresses custom cleanup throwable by identity`() {
        val primary = CancellationException("callback cancelled before custom cleanup failure")
        val secondary = CustomCleanupThrowable("custom unregister failure")
        val registrar =
            synchronousCapabilitiesRegistrar().apply {
                unregisterFailure = secondary
            }
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw primary },
            )

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(primary, thrown)
        assertEquals(1, primary.suppressed.size)
        assertSame(secondary, primary.suppressed.single())
        assertOperationalCleanupFailure(fixture)
    }

    @Test
    fun `primary control failure avoids self suppression during cleanup`() {
        val primary = CancellationException("same callback and cleanup failure")
        val registrar =
            synchronousCapabilitiesRegistrar().apply {
                unregisterFailure = primary
            }
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw primary },
            )

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(primary, thrown)
        assertTrue(primary.suppressed.isEmpty())
        assertOperationalCleanupFailure(fixture)
    }

    @Test
    fun `primary control failure suppresses cleanup error without replacement`() {
        val primary = CancellationException("callback cancelled before fatal cleanup")
        val secondary = AssertionError("fatal unregister failure")
        val registrar =
            synchronousCapabilitiesRegistrar().apply {
                unregisterFailure = secondary
            }
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider = AndroidWifiFeatureProvider { throw primary },
            )

        val thrown =
            assertFailsWith<CancellationException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(primary, thrown)
        assertEquals(1, primary.suppressed.size)
        assertSame(secondary, primary.suppressed.single())
        assertOperationalCleanupFailure(fixture)
    }

    @Test
    fun `old generation control failure propagates without altering replacement session`() {
        var callbackFailure: Throwable? = null
        val registrar = RecordingCallbackRegistrar()
        val fixture =
            observerFixture(
                registrar = registrar,
                wifiFeatureProvider =
                    AndroidWifiFeatureProvider {
                        callbackFailure?.let { throw it }
                        true
                    },
            )
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val oldCallback = registrar.latestCallback
        fixture.observer.stop()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val replacementState = fixture.observer.currentState()
        val error = AssertionError("late callback from old generation")
        callbackFailure = error

        val thrown =
            assertFailsWith<AssertionError> {
                oldCallback.onCapabilitiesChanged(testNetwork(99), wifiCapabilities())
            }

        assertSame(error, thrown)
        assertEquals(replacementState, fixture.observer.currentState())
        assertEquals(ConnectivityObserverLifecycle.ACTIVE, replacementState.lifecycle)
        assertEquals(2, registrar.registerCalls)
        assertEquals(1, registrar.unregisterCalls)
        assertEquals(1, registrar.activeRegistrations)
        assertEquals(1, fixture.dispatchers.dispatcherCloseCalls)

        fixture.observer.stop()
        assertEquals(2, registrar.unregisterCalls)
        assertEquals(0, registrar.activeRegistrations)
        assertEquals(2, fixture.dispatchers.dispatcherCloseCalls)
    }

    private fun observerFixture(
        registrar: RecordingCallbackRegistrar = RecordingCallbackRegistrar(),
        wifiFeatureProvider: AndroidWifiFeatureProvider = AndroidWifiFeatureProvider { true },
        sdkInt: Int = Build.VERSION_CODES.Q,
        locationAwareCallbackFactory: AndroidLocationAwareCallbackFactory =
            AndroidLocationAwareCallbackFactory { delegate -> delegate },
    ): ObserverFacadeFixture {
        val dispatchers = RecordingDispatcherFactory()
        val facade =
            FrameworkAndroidConnectivityManagerFacade(
                callbackRegistrar = registrar,
                legacyWifiInfoProvider = wifiInfoProvider(AndroidWifiInfoAccessFake()),
                sensitiveWifiAccess = AndroidSensitiveWifiAccess { null },
                wifiFeatureProvider = wifiFeatureProvider,
                sdkInt = sdkInt,
                locationAwareCallbackFactory = locationAwareCallbackFactory,
            )
        return ObserverFacadeFixture(
            observer =
                AndroidConnectivityObserver(
                    connectivityFacade = facade,
                    dispatcherFactory = dispatchers,
                    timeSource = FixedObservationTimeSource,
                    mapper = AndroidConnectivitySnapshotMapper(),
                ),
            registrar = registrar,
            dispatchers = dispatchers,
        )
    }

    private fun synchronousCapabilitiesRegistrar(): RecordingCallbackRegistrar =
        RecordingCallbackRegistrar().apply {
            registerHook = { callback ->
                assertEquals(1, activeRegistrations)
                callback.onCapabilitiesChanged(testNetwork(7), wifiCapabilities())
            }
        }

    private fun assertRegistrationFailureTerminal(
        fixture: ObserverFacadeFixture,
        expectedUnregisterCalls: Int,
    ) {
        assertEquals(1, fixture.registrar.registerCalls)
        assertEquals(0, fixture.registrar.activeRegistrations)
        assertEquals(expectedUnregisterCalls, fixture.registrar.unregisterCalls)
        assertEquals(1, fixture.dispatchers.dispatcherCloseCalls)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertNull(fixture.observer.currentState().snapshot)
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(expectedUnregisterCalls, fixture.registrar.unregisterCalls)
        assertEquals(1, fixture.dispatchers.dispatcherCloseCalls)
    }

    private fun assertActiveCallbackFailureTerminal(
        fixture: ObserverFacadeFixture,
        delivered: List<ConnectivityObserverLifecycle>,
    ) {
        assertEquals(1, fixture.registrar.registerCalls)
        assertEquals(0, fixture.registrar.activeRegistrations)
        assertEquals(1, fixture.registrar.unregisterCalls)
        assertEquals(1, fixture.dispatchers.dispatcherCloseCalls)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertNull(fixture.observer.currentState().snapshot)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, delivered.last())
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.registrar.unregisterCalls)
        assertEquals(1, fixture.dispatchers.dispatcherCloseCalls)
    }

    private fun assertOperationalCleanupFailure(fixture: ObserverFacadeFixture) {
        assertEquals(1, fixture.registrar.registerCalls)
        assertEquals(1, fixture.registrar.unregisterCalls)
        assertEquals(1, fixture.registrar.activeRegistrations)
        assertEquals(1, fixture.dispatchers.dispatcherCloseCalls)
        assertEquals(ConnectivityObserverLifecycle.FAILED, fixture.observer.currentState().lifecycle)
        assertEquals(
            ConnectivityFailureOperation.UNREGISTER_CALLBACK,
            fixture.observer.currentState().failure?.operation,
        )
    }

    private fun captureAuthorized(
        wifiInfo: AndroidWifiInfoAccess,
        sensitiveWifiAccess: AndroidSensitiveWifiAccess = AndroidSensitiveWifiAccess { null },
        sdkInt: Int = Build.VERSION_CODES.Q,
    ): AndroidNetworkCapabilitiesSnapshot {
        val fixture =
            fixture(
                legacyWifiInfoProvider = wifiInfoProvider(wifiInfo),
                sensitiveWifiAccess = sensitiveWifiAccess,
                sdkInt = sdkInt,
            )
        fixture.register(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)
        fixture.emitWifiCapabilities()
        return requireNotNull(fixture.events.lastCapabilities)
    }

    private fun fixture(
        legacyWifiInfoProvider: AndroidLegacyWifiInfoProvider? =
            wifiInfoProvider(AndroidWifiInfoAccessFake()),
        sensitiveWifiAccess: AndroidSensitiveWifiAccess =
            AndroidSensitiveWifiAccess { null },
        wifiFeatureProvider: AndroidWifiFeatureProvider =
            AndroidWifiFeatureProvider { true },
        sdkInt: Int = Build.VERSION_CODES.Q,
    ): FacadeFixture {
        val registrar = RecordingCallbackRegistrar()
        val events = RecordingEvents()
        return FacadeFixture(
            facade =
                FrameworkAndroidConnectivityManagerFacade(
                    callbackRegistrar = registrar,
                    legacyWifiInfoProvider = legacyWifiInfoProvider,
                    sensitiveWifiAccess = sensitiveWifiAccess,
                    wifiFeatureProvider = wifiFeatureProvider,
                    sdkInt = sdkInt,
                ),
            registrar = registrar,
            events = events,
        )
    }

    private fun permissionAndLocation(
        requestedPermissions: () -> Set<String> = {
            setOf(
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.ACCESS_FINE_LOCATION,
            )
        },
        permissionStatus: (String) -> Int = { PackageManager.PERMISSION_GRANTED },
        locationManagerProvider: (() -> LocationManager?)? = null,
        locationEnabled: (LocationManager) -> Boolean = { true },
    ): AndroidPermissionAndLocation {
        val application = RuntimeEnvironment.getApplication()
        val locationManager =
            requireNotNull(application.getSystemService(LocationManager::class.java))
        return AndroidPermissionAndLocation(
            requestedPermissions = requestedPermissions,
            permissionStatus = permissionStatus,
            locationManagerProvider = locationManagerProvider ?: { locationManager },
            locationEnabled = locationEnabled,
        )
    }

    private fun assertPermissionFailureMatrix(
        expectedBaseForSecurity: ConnectivityObservationReason?,
        expectedBaseForRuntime: ConnectivityObservationReason?,
        accessFactory: (Throwable, AtomicInteger) -> AndroidPermissionAndLocation,
    ) {
        listOf(
            CancellationException("dependency cancelled"),
            AssertionError("dependency error"),
        ).forEach { failure ->
            val calls = AtomicInteger()
            val thrown =
                runCatching {
                    accessFactory(failure, calls).wifiAccessAssessment()
                }.exceptionOrNull()

            assertSame(failure, thrown)
            assertEquals(1, calls.get())
        }

        val securityCalls = AtomicInteger()
        val security =
            accessFactory(SecurityException("dependency denied"), securityCalls)
                .wifiAccessAssessment()
        assertEquals(expectedBaseForSecurity, security.baseAccessReason)
        assertEquals(
            ConnectivityObservationReason.PERMISSION_DENIED,
            security.sensitiveAccessReason,
        )
        assertEquals(1, securityCalls.get())

        val runtimeCalls = AtomicInteger()
        val runtime =
            accessFactory(IllegalStateException("dependency failed"), runtimeCalls)
                .wifiAccessAssessment()
        assertEquals(expectedBaseForRuntime, runtime.baseAccessReason)
        assertEquals(
            ConnectivityObservationReason.PLATFORM_ERROR,
            runtime.sensitiveAccessReason,
        )
        assertEquals(1, runtimeCalls.get())
    }

    private fun AndroidWifiInfoSnapshot.allValues(): List<AndroidPlatformValue<*>> =
        listOf(
            ssid,
            bssid,
            rssiDbm,
            frequencyMhz,
            linkSpeedMbps,
            rxLinkSpeedMbps,
            txLinkSpeedMbps,
            wifiStandard,
            securityType,
        )
}

private data class FacadeFixture(
    val facade: FrameworkAndroidConnectivityManagerFacade,
    val registrar: RecordingCallbackRegistrar,
    val events: RecordingEvents,
) {
    fun register(profile: ConnectivityCollectionProfile) {
        facade.registerDefaultNetworkCallback(
            profile = profile,
            handler = Handler(Looper.getMainLooper()),
            events = events,
        )
    }

    fun emitWifiCapabilities() {
        registrar.emitLatestWifiCapabilities()
    }
}

private data class ObserverFacadeFixture(
    val observer: AndroidConnectivityObserver,
    val registrar: RecordingCallbackRegistrar,
    val dispatchers: RecordingDispatcherFactory,
)

private class RecordingCallbackRegistrar : AndroidConnectivityCallbackRegistrar {
    private val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private val activeCallbacks = linkedSetOf<ConnectivityManager.NetworkCallback>()

    var failureBeforeRegistration: Throwable? = null
    var registerHook: ((ConnectivityManager.NetworkCallback) -> Unit)? = null
    var unregisterFailure: Throwable? = null

    var registerCalls: Int = 0
        private set
    var unregisterCalls: Int = 0
        private set
    val activeRegistrations: Int
        get() = activeCallbacks.size
    val latestCallback: ConnectivityManager.NetworkCallback
        get() = callbacks.last()

    override fun registerDefaultNetworkCallback(
        callback: ConnectivityManager.NetworkCallback,
        handler: Handler,
    ): AndroidCallbackRegistrationAttempt {
        check(handler.looper === Looper.getMainLooper())
        registerCalls += 1
        callbacks += callback
        failureBeforeRegistration?.let { failure ->
            return AndroidCallbackRegistrationAttempt.FailedBeforeRegistration(failure)
        }
        activeCallbacks += callback
        return try {
            registerHook?.invoke(callback)
            AndroidCallbackRegistrationAttempt.Registered
        } catch (failure: CancellationException) {
            AndroidCallbackRegistrationAttempt.RegisteredThenControlFailure(
                AndroidCallbackControlFailure.Cancellation(failure),
            )
        } catch (failure: Error) {
            AndroidCallbackRegistrationAttempt.RegisteredThenControlFailure(
                AndroidCallbackControlFailure.Fatal(failure),
            )
        }
    }

    override fun unregisterNetworkCallback(callback: ConnectivityManager.NetworkCallback) {
        check(callback in activeCallbacks)
        unregisterCalls += 1
        unregisterFailure?.let { throw it }
        check(activeCallbacks.remove(callback))
    }

    fun emitLatestWifiCapabilities() {
        latestCallback.onCapabilitiesChanged(testNetwork(1), wifiCapabilities())
    }
}

private class RecordingEvents : AndroidDefaultNetworkEvents {
    var lastCapabilities: AndroidNetworkCapabilitiesSnapshot? = null
        private set
    var controlFailureNotificationFailure: Throwable? = null

    override fun onAvailable(network: AndroidNetworkIdentity) = Unit

    override fun onCapabilitiesChanged(
        network: AndroidNetworkIdentity,
        capabilities: AndroidNetworkCapabilitiesSnapshot,
    ) {
        lastCapabilities = capabilities
    }

    override fun onControlFailure(failure: AndroidCallbackControlFailure) {
        controlFailureNotificationFailure?.let { throw it }
        throw failure.throwable
    }

    override fun onBlockedStatusChanged(
        network: AndroidNetworkIdentity,
        blocked: Boolean,
    ) = Unit

    override fun onLost(network: AndroidNetworkIdentity) = Unit
}

private class AndroidWifiInfoAccessFake(
    private val ssidRead: () -> String? = { "\"Lab Wi-Fi\"" },
    private val bssidRead: () -> String? = { "aa:bb:cc:dd:ee:ff" },
    private val rssiRead: () -> Int? = { -55 },
    private val frequencyRead: () -> Int? = { 5180 },
    private val linkSpeedRead: () -> Int? = { 433 },
    private val rxLinkSpeedRead: () -> Int? = { 390 },
    private val txLinkSpeedRead: () -> Int? = { 351 },
    private val wifiStandardRead: () -> Int? = { null },
    private val currentSecurityTypeRead: () -> Int? = { null },
) : AndroidWifiInfoAccess {
    override val ssid: String?
        get() = ssidRead()
    override val bssid: String?
        get() = bssidRead()
    override val rssi: Int?
        get() = rssiRead()
    override val frequency: Int?
        get() = frequencyRead()
    override val linkSpeed: Int?
        get() = linkSpeedRead()
    override val rxLinkSpeedMbps: Int?
        get() = rxLinkSpeedRead()
    override val txLinkSpeedMbps: Int?
        get() = txLinkSpeedRead()
    override val wifiStandard: Int?
        get() = wifiStandardRead()
    override val currentSecurityType: Int?
        get() = currentSecurityTypeRead()
}

private class RecordingDispatcherFactory : AndroidCallbackDispatcherFactory {
    private val dispatchers = mutableListOf<RecordingDispatcher>()
    val dispatcherCloseCalls: Int
        get() = dispatchers.sumOf { it.closeCalls }

    override fun create(): AndroidCallbackDispatcher =
        RecordingDispatcher().also(dispatchers::add)
}

private class RecordingDispatcher : AndroidCallbackDispatcher {
    override val handler: Handler = Handler(Looper.getMainLooper())
    var closeCalls: Int = 0
        private set

    override fun close() {
        closeCalls += 1
    }
}

private class RecordingLocationAwareCallbackFactory : AndroidLocationAwareCallbackFactory {
    var createCalls: Int = 0
        private set

    override fun create(
        delegate: ConnectivityManager.NetworkCallback,
    ): ConnectivityManager.NetworkCallback {
        createCalls += 1
        return delegate
    }
}

private class CustomCleanupThrowable(
    message: String,
) : Throwable(message)

private object FixedObservationTimeSource : AndroidObservationTimeSource {
    override fun capture(): AndroidObservationTime =
        AndroidObservationTime(
            observedAtUtc = Instant.parse("2026-07-27T12:00:00Z"),
            elapsedRealtimeNanos = 1,
        )
}

private fun wifiInfoProvider(
    wifiInfo: AndroidWifiInfoAccess,
): AndroidLegacyWifiInfoProvider = AndroidLegacyWifiInfoProvider { wifiInfo }

private fun testNetwork(netId: Int): Network = ShadowNetwork.newInstance(netId)

private fun wifiCapabilities(): NetworkCapabilities =
    ShadowNetworkCapabilities.newInstance().also { capabilities ->
        Shadows.shadowOf(capabilities)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
    }
