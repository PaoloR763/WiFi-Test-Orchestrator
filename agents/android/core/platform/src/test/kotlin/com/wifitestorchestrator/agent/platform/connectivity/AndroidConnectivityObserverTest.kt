package com.wifitestorchestrator.agent.platform.connectivity

import android.os.Handler
import android.os.Looper
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityFailureOperation
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationReason
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverCommandResult
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverLifecycle
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverState
import java.io.File
import com.wifitestorchestrator.agent.domain.connectivity.NetworkTransport
import java.time.Instant
import java.util.concurrent.CancellationException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29])
class AndroidConnectivityObserverTest {
    @Test
    fun `construction is lazy and start stop are exact and idempotent`() {
        val waiterEvents = AtomicInteger()
        val fixture =
            fixture(
                cleanupWaiterObserver =
                    AndroidLifecycleCleanupWaiterObserver { _, _, _ ->
                        waiterEvents.incrementAndGet()
                    },
            )

        assertEquals(0, fixture.facade.registerCalls)
        assertEquals(0, fixture.dispatchers.createCalls)
        assertEquals(ConnectivityObserverLifecycle.NEW, fixture.observer.currentState().lifecycle)

        val first = fixture.observer.start()
        val repeated = fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val modeChange =
            fixture.observer.start(ConnectivityCollectionProfile.WIFI_TEST_AUTHORIZED)

        assertIs<ConnectivityObserverCommandResult.Accepted>(first)
        assertIs<ConnectivityObserverCommandResult.Accepted>(repeated)
        assertEquals(
            ConnectivityCollectionProfile.BASIC,
            fixture.observer.currentState().profile,
        )
        assertEquals(1, fixture.facade.registerCalls)
        assertEquals(1, fixture.dispatchers.createCalls)
        assertEquals(
            ConnectivityObservationReason.MODE_CHANGE_REQUIRES_RESTART,
            assertIs<ConnectivityObserverCommandResult.Rejected>(modeChange).reason,
        )

        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(0, waiterEvents.get())
    }

    @Test
    fun `fast switching ignores old network and old session callbacks without sleeps`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val firstSession = fixture.facade.sessions.single()
        val oldNetwork = AndroidNetworkIdentity("old")
        val newNetwork = AndroidNetworkIdentity("new")

        firstSession.onAvailable(oldNetwork)
        firstSession.onCapabilitiesChanged(oldNetwork, capabilities(NetworkTransport.CELLULAR))
        assertEquals(2, fixture.observer.currentState().snapshot?.sequence)

        firstSession.onAvailable(newNetwork)
        val afterSwitch = fixture.observer.currentState()
        firstSession.onCapabilitiesChanged(oldNetwork, capabilities(NetworkTransport.CELLULAR))
        firstSession.onLost(oldNetwork)
        assertEquals(afterSwitch, fixture.observer.currentState())

        firstSession.onCapabilitiesChanged(newNetwork, capabilities(NetworkTransport.ETHERNET))
        assertEquals(
            setOf(NetworkTransport.ETHERNET),
            fixture.observer.currentState().snapshot?.defaultNetwork?.transports?.value?.values,
        )
        assertEquals(4, fixture.observer.currentState().snapshot?.sequence)

        fixture.observer.stop()
        val stopped = fixture.observer.currentState()
        firstSession.onAvailable(oldNetwork)
        assertEquals(stopped, fixture.observer.currentState())

        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val secondSession = fixture.facade.sessions.last()
        val newInitial = fixture.observer.currentState()
        firstSession.onCapabilitiesChanged(newNetwork, capabilities(NetworkTransport.WIFI))
        assertEquals(newInitial, fixture.observer.currentState())
        secondSession.onAvailable(oldNetwork)
        secondSession.onCapabilitiesChanged(oldNetwork, capabilities(NetworkTransport.WIFI))
        assertEquals(2, fixture.observer.currentState().snapshot?.sequence)
        assertEquals(2, fixture.facade.registerCalls)
    }

    @Test
    fun `registration failure closes dispatcher and returns structured failure`() {
        val fixture = fixture()
        fixture.facade.failRegister = true

        val result = fixture.observer.start(ConnectivityCollectionProfile.BASIC)

        val failed = assertIs<ConnectivityObserverCommandResult.Failed>(result).state
        assertEquals(ConnectivityObserverLifecycle.FAILED, failed.lifecycle)
        assertEquals(
            ConnectivityFailureOperation.REGISTER_CALLBACK,
            failed.failure?.operation,
        )
        assertEquals(
            ConnectivityObservationReason.REGISTRATION_FAILED,
            failed.failure?.reason,
        )
        assertEquals(1, fixture.facade.registerCalls)
        assertEquals(0, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertIs<ConnectivityObserverCommandResult.Failed>(fixture.observer.stop())
    }

    @Test
    fun `unregister failure is not reported as success and is attempted once`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        fixture.facade.failUnregister = true

        val result = fixture.observer.stop()

        val failed = assertIs<ConnectivityObserverCommandResult.Failed>(result).state
        assertEquals(
            ConnectivityFailureOperation.UNREGISTER_CALLBACK,
            failed.failure?.operation,
        )
        assertEquals(
            ConnectivityObservationReason.UNREGISTRATION_FAILED,
            failed.failure?.reason,
        )
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertIs<ConnectivityObserverCommandResult.Failed>(fixture.observer.stop())
        assertEquals(1, fixture.facade.unregisterCalls)
        fixture.observer.close()
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(
            ConnectivityFailureOperation.UNREGISTER_CALLBACK,
            fixture.observer.currentState().failure?.operation,
        )
    }

    @Test
    fun `dispatcher cleanup failure is classified independently`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        fixture.dispatchers.created.single().failClose = true

        val result = fixture.observer.stop()

        val failed = assertIs<ConnectivityObserverCommandResult.Failed>(result).state
        assertEquals(ConnectivityFailureOperation.CLEANUP_THREAD, failed.failure?.operation)
        assertEquals(
            ConnectivityObservationReason.THREAD_CLEANUP_FAILED,
            failed.failure?.reason,
        )
        assertEquals(1, fixture.facade.unregisterCalls)
    }

    @Test
    fun `ordinary mapping failure reconciles resources immediately and retains snapshot`() {
        val fixture =
            fixture(
                mapper =
                    AndroidConnectivitySnapshotMapper(),
            )
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("network")
        events.onAvailable(network)
        events.onCapabilitiesChanged(
            network,
            capabilities(NetworkTransport.WIFI, invalidTransportSet = true),
        )

        assertEquals(ConnectivityObserverLifecycle.FAILED, fixture.observer.currentState().lifecycle)
        assertNoSession(fixture.observer)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertIs<ConnectivityObserverCommandResult.Failed>(fixture.observer.stop())
    }

    @Test
    fun `listener exceptions do not fail observer and close is terminal and idempotent`() {
        val fixture = fixture()
        fixture.observer.setListener { error("consumer failure") }
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("network")

        events.onAvailable(network)
        assertEquals(ConnectivityObserverLifecycle.ACTIVE, fixture.observer.currentState().lifecycle)

        fixture.observer.close()
        fixture.observer.close()
        events.onLost(network)

        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        val rejected = fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        assertEquals(
            ConnectivityObservationReason.OBSERVER_CLOSED,
            assertIs<ConnectivityObserverCommandResult.Rejected>(rejected).reason,
        )
    }

    @Test
    fun `interrupted dispatcher cleanup leaves stop terminal and restores interrupt`() {
        Thread.interrupted()
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val interruption = InterruptedException("synthetic interrupted join")
        fixture.dispatchers.created.single().closeFailure = interruption

        try {
            val result = fixture.observer.stop()

            val failed = assertIs<ConnectivityObserverCommandResult.Failed>(result).state
            assertEquals(ConnectivityObserverLifecycle.FAILED, failed.lifecycle)
            assertEquals(ConnectivityFailureOperation.CLEANUP_THREAD, failed.failure?.operation)
            assertTrue(Thread.currentThread().isInterrupted)
            assertNoSession(fixture.observer)
            assertIs<ConnectivityObserverCommandResult.Failed>(fixture.observer.stop())
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            fixture.observer.close()
            fixture.observer.close()
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `interrupted dispatcher cleanup still lets close finish closed`() {
        Thread.interrupted()
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        fixture.dispatchers.created.single().closeFailure =
            InterruptedException("synthetic interrupted close")

        try {
            fixture.observer.close()

            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(
                ConnectivityFailureOperation.CLEANUP_THREAD,
                fixture.observer.currentState().failure?.operation,
            )
            assertTrue(Thread.currentThread().isInterrupted)
            assertNoSession(fixture.observer)
            fixture.observer.close()
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `primary unregister failure retains distinct cleanup failure as suppressed`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val primary = IllegalStateException("primary unregister")
        val cleanup = IllegalArgumentException("secondary cleanup")
        fixture.facade.unregisterFailure = primary
        fixture.dispatchers.created.single().closeFailure = cleanup

        val result = fixture.observer.stop()

        assertIs<ConnectivityObserverCommandResult.Failed>(result)
        assertEquals(1, primary.suppressed.size)
        assertSame(cleanup, primary.suppressed.single())
        assertNoSession(fixture.observer)

        val self = IllegalStateException("same failure instance")
        val selfFixture = fixture()
        selfFixture.observer.start(ConnectivityCollectionProfile.BASIC)
        selfFixture.facade.unregisterFailure = self
        selfFixture.dispatchers.created.single().closeFailure = self
        assertIs<ConnectivityObserverCommandResult.Failed>(selfFixture.observer.stop())
        assertTrue(self.suppressed.isEmpty())
    }

    @Test
    fun `listener cancellation and error propagate by identity while ordinary failures stay isolated`() {
        val cancellationFixture = fixture()
        val cancellation = CancellationException("listener cancelled")
        val propagatedCancellation =
            assertFailsWith<CancellationException> {
                cancellationFixture.observer.setListener { throw cancellation }
            }
        assertSame(cancellation, propagatedCancellation)
        assertEquals(
            ConnectivityObserverLifecycle.NEW,
            cancellationFixture.observer.currentState().lifecycle,
        )
        assertNoSession(cancellationFixture.observer)

        val errorFixture = fixture()
        val error = AssertionError("fatal listener failure")
        val propagatedError =
            assertFailsWith<AssertionError> {
                errorFixture.observer.setListener { throw error }
            }
        assertSame(error, propagatedError)

        val ordinaryFixture = fixture()
        val result = ordinaryFixture.observer.setListener { error("ordinary consumer failure") }
        assertIs<ConnectivityObserverCommandResult.Accepted>(result)
    }

    @Test
    fun `registration cancellation cleans dispatcher and propagates by identity`() {
        val fixture = fixture()
        val cancellation = CancellationException("registration cancelled")
        fixture.facade.registerFailure = cancellation

        val propagated =
            assertFailsWith<CancellationException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(cancellation, propagated)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(0, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
    }

    @Test
    fun `unregister and cleanup cancellation propagate after terminal reconciliation`() {
        val unregisterFixture = fixture()
        unregisterFixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val unregisterCancellation = CancellationException("unregister cancelled")
        unregisterFixture.facade.unregisterFailure = unregisterCancellation

        val propagatedUnregister =
            assertFailsWith<CancellationException> {
                unregisterFixture.observer.stop()
            }

        assertSame(unregisterCancellation, propagatedUnregister)
        assertEquals(
            ConnectivityObserverLifecycle.FAILED,
            unregisterFixture.observer.currentState().lifecycle,
        )
        assertEquals(
            ConnectivityFailureOperation.UNREGISTER_CALLBACK,
            unregisterFixture.observer.currentState().failure?.operation,
        )
        assertNoSession(unregisterFixture.observer)
        assertEquals(1, unregisterFixture.facade.unregisterCalls)
        assertEquals(1, unregisterFixture.dispatchers.totalCloseCalls)
        assertIs<ConnectivityObserverCommandResult.Failed>(unregisterFixture.observer.stop())

        val cleanupFixture = fixture()
        cleanupFixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val cleanupCancellation = CancellationException("cleanup cancelled")
        cleanupFixture.dispatchers.created.single().closeFailure = cleanupCancellation

        val propagatedCleanup =
            assertFailsWith<CancellationException> {
                cleanupFixture.observer.stop()
            }

        assertSame(cleanupCancellation, propagatedCleanup)
        assertEquals(
            ConnectivityFailureOperation.CLEANUP_THREAD,
            cleanupFixture.observer.currentState().failure?.operation,
        )
        assertNoSession(cleanupFixture.observer)
        assertEquals(1, cleanupFixture.facade.unregisterCalls)
        assertEquals(1, cleanupFixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `mapping cancellation cleans active session while mapping error propagates`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val cancellation = CancellationException("mapping cancelled")
        fixture.time.nextFailure = cancellation
        val events = fixture.facade.sessions.single()

        val propagated =
            assertFailsWith<CancellationException> {
                events.onAvailable(AndroidNetworkIdentity("cancelled-network"))
            }

        assertSame(cancellation, propagated)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertNoSession(fixture.observer)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)

        val errorFixture = fixture()
        errorFixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val error = AssertionError("mapping error")
        errorFixture.time.nextFailure = error
        val propagatedError =
            assertFailsWith<AssertionError> {
                errorFixture.facade.sessions.single()
                    .onAvailable(AndroidNetworkIdentity("fatal-network"))
            }
        assertSame(error, propagatedError)
        assertEquals(
            ConnectivityObserverLifecycle.STOPPED,
            errorFixture.observer.currentState().lifecycle,
        )
        assertNoSession(errorFixture.observer)
        assertEquals(1, errorFixture.facade.unregisterCalls)
        assertEquals(1, errorFixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `ordinary mapping failure retains primary and combines cleanup failures by identity`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("mapping-secondary-failures")
        events.onAvailable(network)
        val retained = fixture.observer.currentState().snapshot
        val observed = mutableListOf<ConnectivityObserverState>()
        fixture.observer.setListener(observed::add)
        val mappingFailure = IllegalStateException("mapping failed")
        val unregisterFailure = IllegalArgumentException("unregister also failed")
        val interruption = InterruptedException("dispatcher close interrupted")
        fixture.facade.unregisterFailure = unregisterFailure
        fixture.dispatchers.created.single().closeFailure = interruption
        assertFalse(Thread.interrupted())
        try {
            events.onCapabilitiesChanged(
                network,
                capabilities(
                    NetworkTransport.WIFI,
                    invalidTransportSet = true,
                    mappingFailure = mappingFailure,
                ),
            )

            val terminal = fixture.observer.currentState()
            assertEquals(ConnectivityObserverLifecycle.FAILED, terminal.lifecycle)
            assertEquals(ConnectivityFailureOperation.MAP_PLATFORM_DATA, terminal.failure?.operation)
            assertSame(retained, terminal.snapshot)
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertEquals(1, observed.count { it.lifecycle == ConnectivityObserverLifecycle.FAILED })
            assertEquals(2, mappingFailure.suppressed.size)
            assertSame(unregisterFailure, mappingFailure.suppressed[0])
            assertSame(interruption, mappingFailure.suppressed[1])
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `mapping cancellation remains primary through self and interrupted cleanup failures`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val cancellation = CancellationException("mapping cancelled before cleanup failures")
        val interruption = InterruptedException("dispatcher close interrupted")
        fixture.time.nextFailure = cancellation
        fixture.facade.unregisterFailure = cancellation
        fixture.dispatchers.created.single().closeFailure = interruption
        assertFalse(Thread.interrupted())
        try {
            val thrown =
                assertFailsWith<CancellationException> {
                    fixture.facade.sessions.single()
                        .onAvailable(AndroidNetworkIdentity("cancelled-with-cleanup-failures"))
                }

            assertSame(cancellation, thrown)
            assertEquals(1, cancellation.suppressed.size)
            assertSame(interruption, cancellation.suppressed.single())
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(ConnectivityObserverLifecycle.FAILED, fixture.observer.currentState().lifecycle)
            assertEquals(
                ConnectivityFailureOperation.UNREGISTER_CALLBACK,
                fixture.observer.currentState().failure?.operation,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `non runtime mapping throwable fails closed and propagates by identity`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val throwable = Throwable("non-runtime mapping control failure")
        fixture.time.nextFailure = throwable

        val thrown =
            runCatching {
                fixture.facade.sessions.single()
                    .onAvailable(AndroidNetworkIdentity("custom-mapping-failure"))
            }.exceptionOrNull()

        assertSame(throwable, thrown)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `mapping cleanup avoids self suppression and survives failure time capture`() {
        val selfFixture = fixture()
        selfFixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val selfEvents = selfFixture.facade.sessions.single()
        val selfNetwork = AndroidNetworkIdentity("mapping-self-suppression")
        selfEvents.onAvailable(selfNetwork)
        val sameFailure = IllegalStateException("same mapping and unregister failure")
        selfFixture.facade.unregisterFailure = sameFailure

        selfEvents.onCapabilitiesChanged(
            selfNetwork,
            capabilities(
                NetworkTransport.WIFI,
                invalidTransportSet = true,
                mappingFailure = sameFailure,
            ),
        )

        assertTrue(sameFailure.suppressed.isEmpty())
        assertEquals(ConnectivityObserverLifecycle.FAILED, selfFixture.observer.currentState().lifecycle)
        assertNoSession(selfFixture.observer)

        val timeFixture = fixture()
        timeFixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val timeEvents = timeFixture.facade.sessions.single()
        val timeNetwork = AndroidNetworkIdentity("failure-time-capture")
        timeEvents.onAvailable(timeNetwork)
        val retained = timeFixture.observer.currentState().snapshot
        timeFixture.time.failureAtCapture =
            timeFixture.time.captureCalls + 2 to IllegalStateException("failure clock unavailable")

        timeEvents.onCapabilitiesChanged(
            timeNetwork,
            capabilities(NetworkTransport.WIFI, invalidTransportSet = true),
        )

        val terminal = timeFixture.observer.currentState()
        assertEquals(ConnectivityObserverLifecycle.FAILED, terminal.lifecycle)
        assertEquals(ConnectivityFailureOperation.MAP_PLATFORM_DATA, terminal.failure?.operation)
        assertSame(retained, terminal.snapshot)
        assertEquals(1, timeFixture.facade.unregisterCalls)
        assertEquals(1, timeFixture.dispatchers.totalCloseCalls)
        assertNoSession(timeFixture.observer)
    }

    @Test
    fun `no valid time publishes stopped propagates primary and permits restart`() {
        val fixture = fixture()
        val primary = IllegalStateException("initial observation time unavailable")
        val clockFailure = IllegalStateException("terminal observation time unavailable")
        val listenerFailure = CancellationException("terminal listener cancelled")
        val observed = mutableListOf<ConnectivityObserverLifecycle>()
        fixture.observer.setListener { delivered ->
            observed += delivered.lifecycle
            if (delivered.lifecycle == ConnectivityObserverLifecycle.STOPPED) {
                throw listenerFailure
            }
        }
        fixture.time.failAtCapture(1, primary)
        fixture.time.failAtCapture(2, clockFailure)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.start(ConnectivityCollectionProfile.BASIC)
                }
            val thrown =
                assertFailsWith<ExecutionException> {
                    future.get(5, TimeUnit.SECONDS)
                }

            assertSame(primary, thrown.cause)
        } finally {
            shutdown(executor)
        }

        assertEquals(
            listOf(clockFailure, listenerFailure),
            primary.suppressed.toList(),
        )
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertNull(fixture.observer.currentState().failure)
        assertNull(fixture.observer.currentState().snapshot)
        assertEquals(1, observed.count { it == ConnectivityObserverLifecycle.STOPPED })
        assertEquals(0, fixture.facade.registerCalls)
        assertEquals(0, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)

        val restarted =
            assertIs<ConnectivityObserverCommandResult.Accepted>(
                fixture.observer.start(ConnectivityCollectionProfile.BASIC),
            )
        assertEquals(ConnectivityObserverLifecycle.ACTIVE, restarted.state.lifecycle)
        assertEquals(1, fixture.facade.registerCalls)
        assertEquals(2, fixture.dispatchers.createCalls)
        assertNoListenerDeliveryContext(fixture.observer)

        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(2, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `time capture as sole start failure is propagated after dated failure`() {
        val fixture = fixture()
        val timeFailure = IllegalStateException("first observation time failed")
        fixture.time.failAtCapture(1, timeFailure)

        val thrown =
            assertFailsWith<IllegalStateException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(timeFailure, thrown)
        val terminal = fixture.observer.currentState()
        val captured = requireNotNull(fixture.time.lastSuccessfulTime)
        assertEquals(ConnectivityObserverLifecycle.FAILED, terminal.lifecycle)
        assertEquals(ConnectivityFailureOperation.MAP_PLATFORM_DATA, terminal.failure?.operation)
        assertEquals(captured.observedAtUtc, terminal.failure?.occurredAtUtc)
        assertEquals(captured.elapsedRealtimeNanos, terminal.failure?.elapsedRealtimeNanos)
        assertTrue(timeFailure.suppressed.isEmpty())
        assertEquals(0, fixture.facade.registerCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `failed terminal reuses exact last successful observation time`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("last-successful-time")
        events.onAvailable(network)
        val mappingFailure = IllegalStateException("mapping failed after timestamp")
        val clockFailure = IllegalStateException("terminal clock failed")
        fixture.time.failAtCapture(fixture.time.captureCalls + 2, clockFailure)

        events.onCapabilitiesChanged(
            network,
            capabilities(
                NetworkTransport.WIFI,
                invalidTransportSet = true,
                mappingFailure = mappingFailure,
            ),
        )

        val captured = requireNotNull(fixture.time.lastSuccessfulTime)
        val terminal = fixture.observer.currentState()
        assertEquals(ConnectivityObserverLifecycle.FAILED, terminal.lifecycle)
        assertEquals(captured.observedAtUtc, terminal.failure?.occurredAtUtc)
        assertEquals(captured.elapsedRealtimeNanos, terminal.failure?.elapsedRealtimeNanos)
        assertEquals(listOf(clockFailure), mappingFailure.suppressed.toList())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `failed terminal reuses exact retained snapshot time`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val retained = requireNotNull(fixture.observer.currentState().snapshot)
        val mappingFailure = IllegalStateException("callback timestamp unavailable")
        val clockFailure = IllegalStateException("terminal timestamp unavailable")
        fixture.time.failAtCapture(fixture.time.captureCalls + 1, mappingFailure)
        fixture.time.failAtCapture(fixture.time.captureCalls + 2, clockFailure)

        val thrown =
            assertFailsWith<IllegalStateException> {
                fixture.facade.sessions.single()
                    .onAvailable(AndroidNetworkIdentity("retained-snapshot-time"))
            }

        assertSame(mappingFailure, thrown)
        val terminal = fixture.observer.currentState()
        assertEquals(ConnectivityObserverLifecycle.FAILED, terminal.lifecycle)
        assertSame(retained, terminal.snapshot)
        assertEquals(retained.observedAtUtc, terminal.failure?.occurredAtUtc)
        assertEquals(
            retained.elapsedRealtimeNanos,
            terminal.failure?.elapsedRealtimeNanos,
        )
        assertEquals(listOf(clockFailure), mappingFailure.suppressed.toList())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `mapping cleanup and clock failures preserve causal suppression order`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("causal-failure-order")
        events.onAvailable(network)
        val mappingFailure = IllegalStateException("mapping primary")
        val unregisterFailure = IllegalArgumentException("unregister secondary")
        val dispatcherFailure = IllegalStateException("dispatcher secondary")
        val clockFailure = IllegalStateException("clock secondary")
        fixture.facade.unregisterFailure = unregisterFailure
        fixture.dispatchers.created.single().closeFailure = dispatcherFailure
        fixture.time.failAtCapture(fixture.time.captureCalls + 2, clockFailure)

        events.onCapabilitiesChanged(
            network,
            capabilities(
                NetworkTransport.WIFI,
                invalidTransportSet = true,
                mappingFailure = mappingFailure,
            ),
        )

        assertEquals(
            listOf(unregisterFailure, dispatcherFailure, clockFailure),
            mappingFailure.suppressed.toList(),
        )
        assertEquals(ConnectivityObserverLifecycle.FAILED, fixture.observer.currentState().lifecycle)
        assertEquals(
            ConnectivityFailureOperation.MAP_PLATFORM_DATA,
            fixture.observer.currentState().failure?.operation,
        )
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `same mapping and clock failure propagates without self suppression`() {
        val fixture = fixture()
        val sameFailure = IllegalStateException("same mapping and terminal clock failure")
        fixture.time.failAtCapture(1, sameFailure)
        fixture.time.failAtCapture(2, sameFailure)

        val thrown =
            assertFailsWith<IllegalStateException> {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertSame(sameFailure, thrown)
        assertTrue(sameFailure.suppressed.isEmpty())
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(0, fixture.facade.registerCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `interrupted terminal clock is suppressed and restores interrupt flag`() {
        Thread.interrupted()
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("interrupted-terminal-clock")
        events.onAvailable(network)
        val mappingFailure = IllegalStateException("mapping before interrupted clock")
        val interruption = InterruptedException("terminal clock interrupted")
        fixture.time.failAtCapture(fixture.time.captureCalls + 2, interruption)
        try {
            events.onCapabilitiesChanged(
                network,
                capabilities(
                    NetworkTransport.WIFI,
                    invalidTransportSet = true,
                    mappingFailure = mappingFailure,
                ),
            )

            assertEquals(listOf(interruption), mappingFailure.suppressed.toList())
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(
                ConnectivityObserverLifecycle.FAILED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `no time completion releases every waiting caller with the same primary`() {
        val fixture = fixture()
        val primary = IllegalStateException("initial clock primary")
        val clockFailure = IllegalStateException("terminal clock secondary")
        val clockEntered = CountDownLatch(1)
        val releaseClock = CountDownLatch(1)
        fixture.time.failAtCapture(1, primary)
        fixture.time.failAtCapture(2, clockFailure)
        fixture.time.captureHook = { capture ->
            if (capture == 2) {
                clockEntered.countDown()
                assertTrue(releaseClock.await(5, TimeUnit.SECONDS))
            }
        }
        val executor = Executors.newFixedThreadPool(3)
        try {
            val start =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.start(ConnectivityCollectionProfile.BASIC)
                }
            assertTrue(clockEntered.await(5, TimeUnit.SECONDS))
            val waitersInvoked = CountDownLatch(2)
            val firstStop =
                executor.submit<ConnectivityObserverCommandResult> {
                    waitersInvoked.countDown()
                    fixture.observer.stop()
                }
            val secondStop =
                executor.submit<ConnectivityObserverCommandResult> {
                    waitersInvoked.countDown()
                    fixture.observer.stop()
                }
            assertTrue(waitersInvoked.await(5, TimeUnit.SECONDS))
            assertFailsWith<TimeoutException> {
                firstStop.get(1, TimeUnit.SECONDS)
            }
            assertFailsWith<TimeoutException> {
                secondStop.get(1, TimeUnit.SECONDS)
            }

            releaseClock.countDown()
            listOf(start, firstStop, secondStop).forEach { future ->
                val thrown =
                    assertFailsWith<ExecutionException> {
                        future.get(5, TimeUnit.SECONDS)
                    }
                assertSame(primary, thrown.cause)
            }

            assertEquals(listOf(clockFailure), primary.suppressed.toList())
            assertEquals(
                ConnectivityObserverLifecycle.STOPPED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(0, fixture.facade.registerCalls)
            assertEquals(0, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseClock.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `active listener installation control failures reconcile the session by identity`() {
        listOf(
            CancellationException("active listener installation cancelled"),
            AssertionError("active listener installation failed"),
            Throwable("active listener installation custom control failure"),
        ).forEach { failure ->
            val fixture = fixture()
            fixture.observer.start(ConnectivityCollectionProfile.BASIC)

            val thrown =
                runCatching {
                    fixture.observer.setListener { throwFailure(failure) }
                }.exceptionOrNull()

            assertSame(failure, thrown)
            assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertNoListenerDeliveryContext(fixture.observer)
        }
    }

    @Test
    fun `active listener callback control failures reconcile the session by identity`() {
        listOf(
            CancellationException("active callback listener cancelled"),
            AssertionError("active callback listener failed"),
            Throwable("active callback listener custom control failure"),
        ).forEach { failure ->
            val fixture = fixture()
            fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            fixture.observer.setListener { delivered ->
                if (delivered.snapshot?.sequence == 1L) throwFailure(failure)
            }

            val thrown =
                runCatching {
                    fixture.facade.sessions.single()
                        .onAvailable(AndroidNetworkIdentity("listener-control"))
                }.exceptionOrNull()

            assertSame(failure, thrown)
            assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertNoListenerDeliveryContext(fixture.observer)
        }
    }

    @Test
    fun `terminal listener can stop close and fail without recursive cleanup`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("terminal-listener-control")
        events.onAvailable(network)
        val observed = mutableListOf<ConnectivityObserverState>()
        val cancellation = CancellationException("terminal listener cancelled")
        val mappingFailure = IllegalStateException("terminal mapping failure")
        var reentrantStop: ConnectivityObserverCommandResult? = null
        fixture.observer.setListener { delivered ->
            observed += delivered
            if (delivered.lifecycle == ConnectivityObserverLifecycle.FAILED) {
                reentrantStop = fixture.observer.stop()
                fixture.observer.close()
                throw cancellation
            }
        }

        val thrown =
            assertFailsWith<CancellationException> {
                events.onCapabilitiesChanged(
                    network,
                    capabilities(
                        NetworkTransport.WIFI,
                        invalidTransportSet = true,
                        mappingFailure = mappingFailure,
                    ),
                )
            }

        assertSame(cancellation, thrown)
        assertEquals(1, cancellation.suppressed.size)
        assertSame(mappingFailure, cancellation.suppressed.single())
        assertIs<ConnectivityObserverCommandResult.Failed>(reentrantStop)
        assertEquals(
            listOf(
                ConnectivityObserverLifecycle.ACTIVE,
                ConnectivityObserverLifecycle.FAILED,
            ),
            observed.map { it.lifecycle },
        )
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(
            ConnectivityFailureOperation.MAP_PLATFORM_DATA,
            fixture.observer.currentState().failure?.operation,
        )
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        assertNoCloseInProgress(fixture.observer)
        assertNoListenerDeliveryContext(fixture.observer)
    }

    @Test
    fun `active listener failure races stop and close without deadlock or duplicate cleanup`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val deliveryEntered = CountDownLatch(1)
        val releaseDelivery = CountDownLatch(1)
        val unregisterEntered = CountDownLatch(1)
        val releaseCleanup = CountDownLatch(1)
        val failure = AssertionError("concurrent active listener failure")
        fixture.observer.setListener { delivered ->
            if (delivered.snapshot?.sequence == 1L) {
                deliveryEntered.countDown()
                assertTrue(releaseDelivery.await(5, TimeUnit.SECONDS))
                throw failure
            }
        }
        fixture.facade.unregisterHook = {
            unregisterEntered.countDown()
            assertTrue(releaseCleanup.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(3)
        try {
            val callback =
                executor.submit<Unit> {
                    fixture.facade.sessions.single()
                        .onAvailable(AndroidNetworkIdentity("concurrent-listener-control"))
                }
            assertTrue(deliveryEntered.await(5, TimeUnit.SECONDS))
            val stop = executor.submit<ConnectivityObserverCommandResult> { fixture.observer.stop() }
            assertTrue(unregisterEntered.await(5, TimeUnit.SECONDS))
            val close = executor.submit<Unit> { fixture.observer.close() }
            awaitCondition { fixture.observer.diagnosticsForTesting().closeInProgress }
            releaseDelivery.countDown()
            awaitCondition { fixture.observer.diagnosticsForTesting().pendingFailureCount == 1 }
            releaseCleanup.countDown()

            listOf(callback, stop, close).forEach { future ->
                val thrown = runCatching { future.get(5, TimeUnit.SECONDS) }.exceptionOrNull()
                assertSame(failure, thrown?.cause)
            }
            assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertNoCloseInProgress(fixture.observer)
            assertNoListenerDeliveryContext(fixture.observer)
        } finally {
            releaseDelivery.countDown()
            releaseCleanup.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `callback control cancellation cleans active session and propagates by identity`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val cancellation = CancellationException("active callback cancelled")
        val events = fixture.facade.sessions.single()

        val thrown =
            assertFailsWith<CancellationException> {
                events.onControlFailure(
                    AndroidCallbackControlFailure.Cancellation(cancellation),
                )
            }

        assertSame(cancellation, thrown)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertNull(fixture.observer.currentState().snapshot)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `old generation callback control error leaves replacement session active`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val oldEvents = fixture.facade.sessions.single()
        fixture.observer.stop()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val replacement = fixture.observer.currentState()
        val error = AssertionError("old generation callback failed")

        val thrown =
            assertFailsWith<AssertionError> {
                oldEvents.onControlFailure(AndroidCallbackControlFailure.Fatal(error))
            }

        assertSame(error, thrown)
        assertEquals(replacement, fixture.observer.currentState())
        assertEquals(ConnectivityObserverLifecycle.ACTIVE, replacement.lifecycle)
        assertEquals(2, fixture.facade.registerCalls)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)

        fixture.observer.stop()
        assertEquals(2, fixture.facade.unregisterCalls)
        assertEquals(2, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `external lifecycle operations and listeners never run under observer lock`() {
        val fixture = fixture()
        val network = AndroidNetworkIdentity("synchronous")
        fixture.dispatchers.createHook = {
            assertFalse(fixture.observer.lifecycleLockHeldByCurrentThreadForTesting())
        }
        fixture.facade.registerHook = { events ->
            assertFalse(fixture.observer.lifecycleLockHeldByCurrentThreadForTesting())
            events.onAvailable(network)
        }
        fixture.facade.unregisterHook = {
            assertFalse(fixture.observer.lifecycleLockHeldByCurrentThreadForTesting())
            fixture.observer.currentState()
        }
        fixture.observer.setListener {
            assertFalse(fixture.observer.lifecycleLockHeldByCurrentThreadForTesting())
            fixture.observer.currentState()
        }

        val started = fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        fixture.dispatchers.created.single().closeHook = {
            assertFalse(fixture.observer.lifecycleLockHeldByCurrentThreadForTesting())
            fixture.observer.currentState()
        }
        val stopped = fixture.observer.stop()

        assertIs<ConnectivityObserverCommandResult.Accepted>(started)
        assertEquals(1, started.state.snapshot?.sequence)
        assertIs<ConnectivityObserverCommandResult.Accepted>(stopped)
        assertEquals(1, fixture.facade.registerCalls)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `register reentrant stop defers cleanup without waiting for itself`() {
        val fixture = fixture()
        val reentrant = AtomicReference<ConnectivityObserverCommandResult?>()
        fixture.facade.registerHook = {
            reentrant.set(fixture.observer.stop())
        }

        val started =
            runWithWatchdog {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertDeferredReentrantStop(reentrant.get())
        assertIs<ConnectivityObserverCommandResult.Accepted>(started)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, started.state.lifecycle)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.registerCalls)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)

        val terminal = fixture.observer.currentState()
        fixture.facade.sessions.single()
            .onAvailable(AndroidNetworkIdentity("stale-register-stop"))
        assertEquals(terminal, fixture.observer.currentState())
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `register reentrant close is finalized by the outer lifecycle owner`() {
        val fixture = fixture()
        val reentrantReturns = AtomicInteger()
        fixture.facade.registerHook = {
            fixture.observer.close()
            reentrantReturns.incrementAndGet()
        }

        val started =
            runWithWatchdog {
                fixture.observer.start(ConnectivityCollectionProfile.BASIC)
            }

        assertEquals(1, reentrantReturns.get())
        assertFalse(started.lifecycleOrNull() == ConnectivityObserverLifecycle.STOPPING)
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.registerCalls)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)

        val terminal = fixture.observer.currentState()
        fixture.facade.sessions.single()
            .onAvailable(AndroidNetworkIdentity("stale-register-close"))
        assertEquals(terminal, fixture.observer.currentState())
        fixture.observer.close()
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `unregister reentrant stop observes deferred rejection and cleanup remains exact`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val reentrant = AtomicReference<ConnectivityObserverCommandResult?>()
        fixture.facade.unregisterHook = {
            reentrant.set(fixture.observer.stop())
        }

        val stopped = runWithWatchdog { fixture.observer.stop() }

        assertDeferredReentrantStop(reentrant.get())
        assertIs<ConnectivityObserverCommandResult.Accepted>(stopped)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, stopped.state.lifecycle)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `unregister reentrant close is finalized after exact cleanup`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val reentrantReturns = AtomicInteger()
        fixture.facade.unregisterHook = {
            fixture.observer.close()
            reentrantReturns.incrementAndGet()
        }

        val stopped = runWithWatchdog { fixture.observer.stop() }

        assertEquals(1, reentrantReturns.get())
        assertFalse(stopped.lifecycleOrNull() == ConnectivityObserverLifecycle.STOPPING)
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        fixture.observer.close()
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `dispatcher close reentrant stop cannot await its cleanup completion`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val reentrant = AtomicReference<ConnectivityObserverCommandResult?>()
        fixture.dispatchers.created.single().closeHook = {
            reentrant.set(fixture.observer.stop())
        }

        val stopped = runWithWatchdog { fixture.observer.stop() }

        assertDeferredReentrantStop(reentrant.get())
        assertIs<ConnectivityObserverCommandResult.Accepted>(stopped)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, stopped.state.lifecycle)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        assertIs<ConnectivityObserverCommandResult.Accepted>(fixture.observer.stop())
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `dispatcher close reentrant close reaches closed after outer stop`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val reentrantReturns = AtomicInteger()
        fixture.dispatchers.created.single().closeHook = {
            fixture.observer.close()
            reentrantReturns.incrementAndGet()
        }

        val stopped = runWithWatchdog { fixture.observer.stop() }

        assertEquals(1, reentrantReturns.get())
        assertFalse(stopped.lifecycleOrNull() == ConnectivityObserverLifecycle.STOPPING)
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        fixture.observer.close()
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `second close reentrant during outer close never awaits itself`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val reentrantReturns = AtomicInteger()
        fixture.dispatchers.created.single().closeHook = {
            fixture.observer.close()
            reentrantReturns.incrementAndGet()
        }

        runWithWatchdog { fixture.observer.close() }

        assertEquals(1, reentrantReturns.get())
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        fixture.observer.close()
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `terminal listener close during outer close returns without awaiting itself`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val listenerCloseReturns = AtomicInteger()
        fixture.observer.setListener { observed ->
            if (observed.lifecycle == ConnectivityObserverLifecycle.STOPPED) {
                fixture.observer.close()
                listenerCloseReturns.incrementAndGet()
            }
        }

        runWithWatchdog { fixture.observer.close() }

        assertEquals(1, listenerCloseReturns.get())
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        assertNoCloseInProgress(fixture.observer)
        fixture.observer.close()
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `terminal listener close after stop initiates a new normal close`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val listenerCloseReturns = AtomicInteger()
        fixture.observer.setListener { observed ->
            if (observed.lifecycle == ConnectivityObserverLifecycle.STOPPED) {
                fixture.observer.close()
                listenerCloseReturns.incrementAndGet()
            }
        }

        val stopped = runWithWatchdog { fixture.observer.stop() }

        assertEquals(1, listenerCloseReturns.get())
        assertIs<ConnectivityObserverCommandResult.Accepted>(stopped)
        assertFalse(stopped.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
        assertEquals(ConnectivityObserverLifecycle.STOPPED, stopped.state.lifecycle)
        assertEquals(ConnectivityObserverLifecycle.CLOSED, fixture.observer.currentState().lifecycle)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
        assertNoCloseInProgress(fixture.observer)
        fixture.observer.close()
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `terminal listener close breaks concurrent stop close wait cycle`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val cleanupEntered = CountDownLatch(1)
        val releaseCleanup = CountDownLatch(1)
        fixture.dispatchers.created.single().closeHook = {
            cleanupEntered.countDown()
            assertTrue(releaseCleanup.await(5, TimeUnit.SECONDS))
        }
        val listenerObservedExistingClose = AtomicReference<Boolean?>()
        val listenerCloseReturned = CountDownLatch(1)
        fixture.observer.setListener { observed ->
            if (observed.lifecycle == ConnectivityObserverLifecycle.STOPPED) {
                listenerObservedExistingClose.set(hasCloseInProgress(fixture.observer))
                fixture.observer.close()
                listenerCloseReturned.countDown()
            }
        }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            assertTrue(cleanupEntered.await(5, TimeUnit.SECONDS))
            val closeInvoked = CountDownLatch(1)
            val closeFuture =
                executor.submit {
                    closeInvoked.countDown()
                    fixture.observer.close()
                }
            assertTrue(closeInvoked.await(5, TimeUnit.SECONDS))
            assertFailsWith<TimeoutException> {
                closeFuture.get(1, TimeUnit.SECONDS)
            }
            assertTrue(hasCloseInProgress(fixture.observer))

            releaseCleanup.countDown()
            val stopped = stopFuture.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertEquals(true, listenerObservedExistingClose.get())
            assertTrue(listenerCloseReturned.await(5, TimeUnit.SECONDS))
            assertIs<ConnectivityObserverCommandResult.Accepted>(stopped)
            assertFalse(stopped.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertNoCloseInProgress(fixture.observer)
        } finally {
            releaseCleanup.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `listener delivery context is cleared after every callback outcome`() {
        val normalFixture = fixture()
        normalFixture.observer.setListener { }
        assertNoListenerDeliveryContext(normalFixture.observer)
        normalFixture.observer.close()
        assertEquals(
            ConnectivityObserverLifecycle.CLOSED,
            normalFixture.observer.currentState().lifecycle,
        )

        val ordinaryFixture = fixture()
        assertIs<ConnectivityObserverCommandResult.Accepted>(
            ordinaryFixture.observer.setListener { error("ordinary listener failure") },
        )
        assertNoListenerDeliveryContext(ordinaryFixture.observer)
        ordinaryFixture.observer.close()
        assertEquals(
            ConnectivityObserverLifecycle.CLOSED,
            ordinaryFixture.observer.currentState().lifecycle,
        )

        val cancellationFixture = fixture()
        val cancellation = CancellationException("listener delivery cancelled")
        val propagatedCancellation =
            assertFailsWith<CancellationException> {
                cancellationFixture.observer.setListener { throw cancellation }
            }
        assertSame(cancellation, propagatedCancellation)
        assertNoListenerDeliveryContext(cancellationFixture.observer)
        cancellationFixture.observer.close()
        assertEquals(
            ConnectivityObserverLifecycle.CLOSED,
            cancellationFixture.observer.currentState().lifecycle,
        )

        val errorFixture = fixture()
        val error = AssertionError("listener delivery failed")
        val propagatedError =
            assertFailsWith<AssertionError> {
                errorFixture.observer.setListener { throw error }
            }
        assertSame(error, propagatedError)
        assertNoListenerDeliveryContext(errorFixture.observer)
        errorFixture.observer.close()
        assertEquals(
            ConnectivityObserverLifecycle.CLOSED,
            errorFixture.observer.currentState().lifecycle,
        )

        val throwableFixture = fixture()
        val throwable = Throwable("other listener control failure")
        val propagatedThrowable =
            assertFailsWith<Throwable> {
                throwableFixture.observer.setListener { throw throwable }
            }
        assertSame(throwable, propagatedThrowable)
        assertNoListenerDeliveryContext(throwableFixture.observer)
        throwableFixture.observer.close()
        assertEquals(
            ConnectivityObserverLifecycle.CLOSED,
            throwableFixture.observer.currentState().lifecycle,
        )
    }

    @Test
    fun `blocked registration allows concurrent stop and close without deadlock`() {
        val fixture = fixture()
        val registerEntered = CountDownLatch(1)
        val releaseRegister = CountDownLatch(1)
        fixture.facade.registerHook = {
            registerEntered.countDown()
            assertTrue(releaseRegister.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(3)
        try {
            val startFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.start(ConnectivityCollectionProfile.BASIC)
                }
            assertTrue(registerEntered.await(5, TimeUnit.SECONDS))
            val stopInvoked = CountDownLatch(1)
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    stopInvoked.countDown()
                    fixture.observer.stop()
                }
            assertTrue(stopInvoked.await(5, TimeUnit.SECONDS))
            val closeInvoked = CountDownLatch(1)
            val closeFuture =
                executor.submit {
                    closeInvoked.countDown()
                    fixture.observer.close()
                }
            assertTrue(closeInvoked.await(5, TimeUnit.SECONDS))
            releaseRegister.countDown()

            val startResult = startFuture.get(5, TimeUnit.SECONDS)
            val stopResult = stopFuture.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertIs<ConnectivityObserverCommandResult.Accepted>(startResult)
            assertEquals(ConnectivityObserverLifecycle.STOPPED, startResult.state.lifecycle)
            assertIs<ConnectivityObserverCommandResult.Accepted>(stopResult)
            assertFalse(stopResult.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.registerCalls)
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseRegister.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `blocked cleanup confirms second stop waiter before concurrent close`() {
        val repeatedStopThread = AtomicReference<Thread?>()
        val closeThread = AtomicReference<Thread?>()
        val repeatedStopRegistered = CountDownLatch(1)
        val closeRegistered = CountDownLatch(1)
        val repeatedStopRegisteredThread = AtomicReference<Thread?>()
        val closeRegisteredThread = AtomicReference<Thread?>()
        val interruptedEvents = AtomicInteger()
        val fixture =
            fixture(
                cleanupWaiterObserver =
                    AndroidLifecycleCleanupWaiterObserver { kind, phase, thread ->
                        when (phase) {
                            AndroidLifecycleCleanupWaiterPhase.REGISTERED ->
                                when (kind) {
                                    AndroidLifecycleCleanupWaiterKind.STOP -> {
                                        repeatedStopRegisteredThread.set(thread)
                                        repeatedStopRegistered.countDown()
                                    }
                                    AndroidLifecycleCleanupWaiterKind.CLOSE -> {
                                        closeRegisteredThread.set(thread)
                                        closeRegistered.countDown()
                                    }
                                }
                            AndroidLifecycleCleanupWaiterPhase.INTERRUPTED ->
                                interruptedEvents.incrementAndGet()
                        }
                    },
            )
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        fixture.dispatchers.created.single().closeHook = {
            closeEntered.countDown()
            assertTrue(releaseClose.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(3)
        try {
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            assertTrue(closeEntered.await(5, TimeUnit.SECONDS))
            val repeatedStop =
                executor.submit<ConnectivityObserverCommandResult> {
                    repeatedStopThread.set(Thread.currentThread())
                    fixture.observer.stop()
                }
            assertTrue(repeatedStopRegistered.await(5, TimeUnit.SECONDS))
            assertSame(repeatedStopThread.get(), repeatedStopRegisteredThread.get())
            val closeFuture =
                executor.submit {
                    closeThread.set(Thread.currentThread())
                    fixture.observer.close()
                }
            assertTrue(closeRegistered.await(5, TimeUnit.SECONDS))
            assertSame(closeThread.get(), closeRegisteredThread.get())
            releaseClose.countDown()

            val first = stopFuture.get(5, TimeUnit.SECONDS)
            val second = repeatedStop.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertIs<ConnectivityObserverCommandResult.Accepted>(first)
            assertIs<ConnectivityObserverCommandResult.Accepted>(second)
            assertFalse(first.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
            assertFalse(second.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertEquals(0, interruptedEvents.get())
        } finally {
            releaseClose.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `close completed before second stop rejects with observer closed`() {
        val closeThread = AtomicReference<Thread?>()
        val closeRegistered = CountDownLatch(1)
        val closeRegisteredThread = AtomicReference<Thread?>()
        val stopWaiterEvents = AtomicInteger()
        val fixture =
            fixture(
                cleanupWaiterObserver =
                    AndroidLifecycleCleanupWaiterObserver { kind, phase, thread ->
                        if (
                            kind == AndroidLifecycleCleanupWaiterKind.CLOSE &&
                            phase == AndroidLifecycleCleanupWaiterPhase.REGISTERED
                        ) {
                            closeRegisteredThread.set(thread)
                            closeRegistered.countDown()
                        } else if (kind == AndroidLifecycleCleanupWaiterKind.STOP) {
                            stopWaiterEvents.incrementAndGet()
                        }
                    },
            )
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        fixture.dispatchers.created.single().closeHook = {
            closeEntered.countDown()
            assertTrue(releaseClose.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            assertTrue(closeEntered.await(5, TimeUnit.SECONDS))
            val closeFuture =
                executor.submit {
                    closeThread.set(Thread.currentThread())
                    fixture.observer.close()
                }
            assertTrue(closeRegistered.await(5, TimeUnit.SECONDS))
            assertSame(closeThread.get(), closeRegisteredThread.get())
            releaseClose.countDown()

            val first = stopFuture.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)
            val second = fixture.observer.stop()

            assertIs<ConnectivityObserverCommandResult.Accepted>(first)
            assertFalse(first.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
            val rejected = assertIs<ConnectivityObserverCommandResult.Rejected>(second)
            assertEquals(ConnectivityObservationReason.OBSERVER_CLOSED, rejected.reason)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
            assertEquals(0, stopWaiterEvents.get())
        } finally {
            releaseClose.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `uncoordinated blocked cleanup accepts only contractual stop outcomes`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        fixture.dispatchers.created.single().closeHook = {
            closeEntered.countDown()
            assertTrue(releaseClose.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(3)
        try {
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            assertTrue(closeEntered.await(5, TimeUnit.SECONDS))
            val repeatedStop =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            val closeFuture =
                executor.submit {
                    fixture.observer.close()
                }
            releaseClose.countDown()

            val first = stopFuture.get(5, TimeUnit.SECONDS)
            val second = repeatedStop.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertIs<ConnectivityObserverCommandResult.Accepted>(first)
            assertFalse(first.state.lifecycle == ConnectivityObserverLifecycle.STOPPING)
            when (second) {
                is ConnectivityObserverCommandResult.Accepted ->
                    assertEquals(ConnectivityObserverLifecycle.STOPPED, second.state.lifecycle)
                is ConnectivityObserverCommandResult.Rejected ->
                    assertEquals(ConnectivityObservationReason.OBSERVER_CLOSED, second.reason)
                is ConnectivityObserverCommandResult.Failed ->
                    error("Concurrent repeated stop must not report an operational failure.")
            }
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseClose.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `interrupted cleanup waiter restores interrupt after exact cleanup`() {
        val waiterThread = AtomicReference<Thread?>()
        val registeredThread = AtomicReference<Thread?>()
        val interruptedThread = AtomicReference<Thread?>()
        val waiterRegistered = CountDownLatch(1)
        val waiterInterrupted = CountDownLatch(1)
        val fixture =
            fixture(
                cleanupWaiterObserver =
                    AndroidLifecycleCleanupWaiterObserver { kind, phase, thread ->
                        if (kind == AndroidLifecycleCleanupWaiterKind.STOP) {
                            when (phase) {
                                AndroidLifecycleCleanupWaiterPhase.REGISTERED -> {
                                    registeredThread.set(thread)
                                    waiterRegistered.countDown()
                                }
                                AndroidLifecycleCleanupWaiterPhase.INTERRUPTED -> {
                                    interruptedThread.set(thread)
                                    waiterInterrupted.countDown()
                                }
                            }
                        }
                    },
            )
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        fixture.dispatchers.created.single().closeHook = {
            closeEntered.countDown()
            assertTrue(releaseClose.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            assertTrue(closeEntered.await(5, TimeUnit.SECONDS))
            val waiterFuture =
                executor.submit<Pair<Throwable?, Boolean>> {
                    waiterThread.set(Thread.currentThread())
                    try {
                        fixture.observer.stop()
                        null to Thread.currentThread().isInterrupted
                    } catch (failure: Throwable) {
                        failure to Thread.currentThread().isInterrupted
                    } finally {
                        Thread.interrupted()
                    }
                }
            assertTrue(waiterRegistered.await(5, TimeUnit.SECONDS))
            assertSame(waiterThread.get(), registeredThread.get())

            requireNotNull(waiterThread.get()).interrupt()
            assertTrue(waiterInterrupted.await(5, TimeUnit.SECONDS))
            assertSame(waiterThread.get(), interruptedThread.get())
            releaseClose.countDown()

            val first = stopFuture.get(5, TimeUnit.SECONDS)
            val (waiterFailure, interruptRestored) = waiterFuture.get(5, TimeUnit.SECONDS)
            assertIs<ConnectivityObserverCommandResult.Accepted>(first)
            assertIs<InterruptedException>(waiterFailure)
            assertTrue(interruptRestored)

            fixture.observer.close()
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseClose.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `interrupted cleanup remains coherent with concurrent close`() {
        Thread.interrupted()
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val closeEntered = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        fixture.dispatchers.created.single().apply {
            closeHook = {
                closeEntered.countDown()
                assertTrue(releaseClose.await(5, TimeUnit.SECONDS))
            }
            closeFailure = InterruptedException("concurrent interrupted cleanup")
        }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val stopFuture =
                executor.submit<Pair<ConnectivityObserverCommandResult, Boolean>> {
                    try {
                        val result = fixture.observer.stop()
                        result to Thread.currentThread().isInterrupted
                    } finally {
                        Thread.interrupted()
                    }
                }
            assertTrue(closeEntered.await(5, TimeUnit.SECONDS))
            val closeFuture = executor.submit { fixture.observer.close() }
            releaseClose.countDown()

            val (stopResult, interrupted) = stopFuture.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertIs<ConnectivityObserverCommandResult.Failed>(stopResult)
            assertTrue(interrupted)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseClose.countDown()
            shutdown(executor)
            Thread.interrupted()
        }
    }

    @Test
    fun `mapping failure delivers ACTIVE N then FAILED N with the retained snapshot`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("mapping-failed-delivery")
        events.onAvailable(network)
        val observed = mutableListOf<ConnectivityObserverState>()
        fixture.observer.setListener(observed::add)

        events.onCapabilitiesChanged(
            network,
            capabilities(NetworkTransport.WIFI, invalidTransportSet = true),
        )

        assertActiveThenFailedWithRetainedSnapshot(fixture.observer, observed)
        fixture.observer.stop()
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `unregister failure delivers ACTIVE N then FAILED N with the retained snapshot`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val observed = mutableListOf<ConnectivityObserverState>()
        fixture.observer.setListener(observed::add)
        fixture.facade.failUnregister = true

        val stopped = fixture.observer.stop()

        assertIs<ConnectivityObserverCommandResult.Failed>(stopped)
        assertActiveThenFailedWithRetainedSnapshot(fixture.observer, observed)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `dispatcher failure delivers ACTIVE N then FAILED N with the retained snapshot`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val observed = mutableListOf<ConnectivityObserverState>()
        fixture.observer.setListener(observed::add)
        fixture.dispatchers.created.single().failClose = true

        val stopped = fixture.observer.stop()

        assertIs<ConnectivityObserverCommandResult.Failed>(stopped)
        assertActiveThenFailedWithRetainedSnapshot(fixture.observer, observed)
        assertEquals(1, fixture.facade.unregisterCalls)
        assertEquals(1, fixture.dispatchers.totalCloseCalls)
    }

    @Test
    fun `listener replacement before pending failure delivery bootstraps FAILED once`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val oldEntered = CountDownLatch(1)
        val releaseOld = CountDownLatch(1)
        val oldObserved = CopyOnWriteArrayList<ConnectivityObserverState>()
        val newObserved = CopyOnWriteArrayList<ConnectivityObserverState>()
        fixture.observer.setListener { observed ->
            oldObserved += observed
            if (observed.snapshot?.sequence == 1L) {
                oldEntered.countDown()
                assertTrue(releaseOld.await(5, TimeUnit.SECONDS))
            }
        }
        val events = fixture.facade.sessions.single()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val callback =
                executor.submit {
                    events.onAvailable(AndroidNetworkIdentity("pending-failed-replacement"))
                }
            assertTrue(oldEntered.await(5, TimeUnit.SECONDS))
            fixture.facade.failUnregister = true
            val failed =
                assertIs<ConnectivityObserverCommandResult.Failed>(fixture.observer.stop()).state

            fixture.observer.setListener(newObserved::add)
            releaseOld.countDown()
            callback.get(5, TimeUnit.SECONDS)

            assertEquals(
                listOf(
                    ConnectivityObserverLifecycle.ACTIVE,
                    ConnectivityObserverLifecycle.ACTIVE,
                ),
                oldObserved.map(ConnectivityObserverState::lifecycle),
            )
            assertEquals(listOf(failed), newObserved)
            assertEquals(ConnectivityObserverLifecycle.FAILED, newObserved.single().lifecycle)
            assertEquals(fixture.observer.currentState(), newObserved.single())
        } finally {
            releaseOld.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `listener removal before pending failure delivery prevents later FAILED`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val deliveryEntered = CountDownLatch(1)
        val releaseDelivery = CountDownLatch(1)
        val observed = CopyOnWriteArrayList<ConnectivityObserverState>()
        fixture.observer.setListener { state ->
            observed += state
            if (state.snapshot?.sequence == 1L) {
                deliveryEntered.countDown()
                assertTrue(releaseDelivery.await(5, TimeUnit.SECONDS))
            }
        }
        val events = fixture.facade.sessions.single()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val callback =
                executor.submit {
                    events.onAvailable(AndroidNetworkIdentity("pending-failed-removal"))
                }
            assertTrue(deliveryEntered.await(5, TimeUnit.SECONDS))
            fixture.dispatchers.created.single().failClose = true
            assertIs<ConnectivityObserverCommandResult.Failed>(fixture.observer.stop())
            assertIs<ConnectivityObserverCommandResult.Accepted>(
                fixture.observer.setListener(null),
            )
            releaseDelivery.countDown()
            callback.get(5, TimeUnit.SECONDS)

            assertEquals(
                listOf(
                    ConnectivityObserverLifecycle.ACTIVE,
                    ConnectivityObserverLifecycle.ACTIVE,
                ),
                observed.map(ConnectivityObserverState::lifecycle),
            )
            assertEquals(ConnectivityObserverLifecycle.FAILED, fixture.observer.currentState().lifecycle)
        } finally {
            releaseDelivery.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `bootstrap followed by callback is delivered in strictly increasing order`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val listenerEntered = CountDownLatch(1)
        val releaseListener = CountDownLatch(1)
        val sequences = CopyOnWriteArrayList<Long>()
        val executor = Executors.newFixedThreadPool(2)
        try {
            val listenerFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.setListener { observed ->
                        val sequence = requireNotNull(observed.snapshot).sequence
                        sequences += sequence
                        if (sequence == 0L) {
                            listenerEntered.countDown()
                            assertTrue(releaseListener.await(5, TimeUnit.SECONDS))
                        }
                    }
                }
            assertTrue(listenerEntered.await(5, TimeUnit.SECONDS))
            val callbackFuture =
                executor.submit {
                    fixture.facade.sessions.single()
                        .onAvailable(AndroidNetworkIdentity("bootstrap-race"))
                }
            callbackFuture.get(5, TimeUnit.SECONDS)
            releaseListener.countDown()
            assertIs<ConnectivityObserverCommandResult.Accepted>(
                listenerFuture.get(5, TimeUnit.SECONDS),
            )

            assertEquals(listOf(0L, 1L), sequences)
            assertStrictlyIncreasing(sequences)
        } finally {
            releaseListener.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `listener replacement invalidates old pending notifications`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val oldEntered = CountDownLatch(1)
        val releaseOld = CountDownLatch(1)
        val oldSequences = CopyOnWriteArrayList<Long>()
        val newSequences = CopyOnWriteArrayList<Long>()
        fixture.observer.setListener { observed ->
            val sequence = requireNotNull(observed.snapshot).sequence
            oldSequences += sequence
            if (sequence == 1L) {
                oldEntered.countDown()
                assertTrue(releaseOld.await(5, TimeUnit.SECONDS))
            }
        }
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("listener-replacement")
        val executor = Executors.newSingleThreadExecutor()
        try {
            val firstCallback = executor.submit { events.onAvailable(network) }
            assertTrue(oldEntered.await(5, TimeUnit.SECONDS))
            events.onCapabilitiesChanged(network, capabilities(NetworkTransport.WIFI))

            fixture.observer.setListener { observed ->
                newSequences += requireNotNull(observed.snapshot).sequence
            }
            releaseOld.countDown()
            firstCallback.get(5, TimeUnit.SECONDS)

            assertEquals(listOf(0L, 1L), oldSequences)
            assertEquals(listOf(2L), newSequences)
            assertStrictlyIncreasing(oldSequences)
            assertStrictlyIncreasing(newSequences)
            assertNoListenerDeliveryContext(fixture.observer)
        } finally {
            releaseOld.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `two concurrent callbacks remain serialized without duplicate sequence`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val firstEntered = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val sequences = CopyOnWriteArrayList<Long>()
        fixture.observer.setListener { observed ->
            val sequence = requireNotNull(observed.snapshot).sequence
            sequences += sequence
            if (sequence == 1L) {
                firstEntered.countDown()
                assertTrue(releaseFirst.await(5, TimeUnit.SECONDS))
            }
        }
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("concurrent-callbacks")
        val executor = Executors.newFixedThreadPool(2)
        try {
            val available = executor.submit { events.onAvailable(network) }
            assertTrue(firstEntered.await(5, TimeUnit.SECONDS))
            val capabilities =
                executor.submit {
                    events.onCapabilitiesChanged(
                        network,
                        capabilities(NetworkTransport.WIFI),
                    )
                }
            capabilities.get(5, TimeUnit.SECONDS)
            releaseFirst.countDown()
            available.get(5, TimeUnit.SECONDS)

            assertEquals(listOf(0L, 1L, 2L), sequences)
            assertStrictlyIncreasing(sequences)
        } finally {
            releaseFirst.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `listener can replace itself reentrantly without duplicate bootstrap`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val firstSequences = mutableListOf<Long>()
        val secondSequences = mutableListOf<Long>()
        val second =
            com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationListener {
                observed ->
                fixture.observer.currentState()
                secondSequences += requireNotNull(observed.snapshot).sequence
            }

        fixture.observer.setListener { observed ->
            fixture.observer.currentState()
            firstSequences += requireNotNull(observed.snapshot).sequence
            fixture.observer.setListener(second)
        }
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        fixture.facade.sessions.single()
            .onAvailable(AndroidNetworkIdentity("reentrant-listener"))

        assertEquals(listOf(0L), firstSequences)
        assertEquals(listOf(0L, 1L), secondSequences)
        assertStrictlyIncreasing(secondSequences)
        assertNoListenerDeliveryContext(fixture.observer)
    }

    @Test
    fun `listener removed during delivery receives no later pending notification`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val deliveryEntered = CountDownLatch(1)
        val releaseDelivery = CountDownLatch(1)
        val sequences = CopyOnWriteArrayList<Long>()
        fixture.observer.setListener { observed ->
            val sequence = requireNotNull(observed.snapshot).sequence
            sequences += sequence
            if (sequence == 1L) {
                deliveryEntered.countDown()
                assertTrue(releaseDelivery.await(5, TimeUnit.SECONDS))
            }
        }
        val events = fixture.facade.sessions.single()
        val network = AndroidNetworkIdentity("listener-removal")
        val executor = Executors.newSingleThreadExecutor()
        try {
            val firstCallback = executor.submit { events.onAvailable(network) }
            assertTrue(deliveryEntered.await(5, TimeUnit.SECONDS))
            assertIs<ConnectivityObserverCommandResult.Accepted>(
                fixture.observer.setListener(null),
            )
            events.onCapabilitiesChanged(network, capabilities(NetworkTransport.WIFI))
            releaseDelivery.countDown()
            firstCallback.get(5, TimeUnit.SECONDS)

            assertEquals(listOf(0L, 1L), sequences)
            assertStrictlyIncreasing(sequences)
        } finally {
            releaseDelivery.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `blocked dispatcher creation reconciles concurrent stop and close`() {
        val fixture = fixture()
        val createEntered = CountDownLatch(1)
        val releaseCreate = CountDownLatch(1)
        fixture.dispatchers.createHook = {
            createEntered.countDown()
            assertTrue(releaseCreate.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(3)
        try {
            val startFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.start(ConnectivityCollectionProfile.BASIC)
                }
            assertTrue(createEntered.await(5, TimeUnit.SECONDS))
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            val closeFuture = executor.submit { fixture.observer.close() }
            releaseCreate.countDown()

            val started = startFuture.get(5, TimeUnit.SECONDS)
            val stopped = stopFuture.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertFalse(started.lifecycleOrNull() == ConnectivityObserverLifecycle.STOPPING)
            assertFalse(stopped.lifecycleOrNull() == ConnectivityObserverLifecycle.STOPPING)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertTrue(fixture.facade.registerCalls in 0..1)
            assertEquals(fixture.facade.registerCalls, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseCreate.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `blocked unregister allows concurrent close and exactly once cleanup`() {
        val fixture = fixture()
        fixture.observer.start(ConnectivityCollectionProfile.BASIC)
        val unregisterEntered = CountDownLatch(1)
        val releaseUnregister = CountDownLatch(1)
        fixture.facade.unregisterHook = {
            unregisterEntered.countDown()
            assertTrue(releaseUnregister.await(5, TimeUnit.SECONDS))
        }
        val executor = Executors.newFixedThreadPool(2)
        try {
            val stopFuture =
                executor.submit<ConnectivityObserverCommandResult> {
                    fixture.observer.stop()
                }
            assertTrue(unregisterEntered.await(5, TimeUnit.SECONDS))
            val closeFuture = executor.submit { fixture.observer.close() }
            releaseUnregister.countDown()

            val stopped = stopFuture.get(5, TimeUnit.SECONDS)
            closeFuture.get(5, TimeUnit.SECONDS)

            assertFalse(stopped.lifecycleOrNull() == ConnectivityObserverLifecycle.STOPPING)
            assertEquals(
                ConnectivityObserverLifecycle.CLOSED,
                fixture.observer.currentState().lifecycle,
            )
            assertEquals(1, fixture.facade.unregisterCalls)
            assertEquals(1, fixture.dispatchers.totalCloseCalls)
            assertNoSession(fixture.observer)
        } finally {
            releaseUnregister.countDown()
            shutdown(executor)
        }
    }

    @Test
    fun `failure after generation reservation leaves no retained session`() {
        val fixture = fixture()
        fixture.dispatchers.createFailure = IllegalStateException("factory failed")

        val result = fixture.observer.start(ConnectivityCollectionProfile.BASIC)

        val failed = assertIs<ConnectivityObserverCommandResult.Failed>(result)
        assertEquals(ConnectivityObserverLifecycle.FAILED, failed.state.lifecycle)
        assertEquals(0, fixture.facade.registerCalls)
        assertEquals(0, fixture.facade.unregisterCalls)
        assertEquals(0, fixture.dispatchers.totalCloseCalls)
        assertNoSession(fixture.observer)
    }

    @Test
    fun `reflection token matrices are independently complete`() {
        validateReflectionTokenMatrix(
            required = requiredReflectionTokens,
            actual = ReflectionAccessDetector.forbiddenTokens,
        )

        assertEquals(REQUIRED_REFLECTION_TOKEN_COUNT, requiredReflectionTokens.size)
        assertEquals(requiredReflectionTokens.size, requiredReflectionTokens.distinct().size)
    }

    @Test
    fun `reflection matrix validation rejects every omitted required token`() {
        requiredReflectionTokens.forEach { omittedToken ->
            val mutatedRequiredMatrix =
                requiredReflectionTokens.filterNot { token ->
                    token == omittedToken
                }
            val remainingRequiredTokens =
                requiredReflectionTokens.filterNot { token ->
                    token == omittedToken
                }

            assertEquals(REQUIRED_REFLECTION_TOKEN_COUNT - 1, mutatedRequiredMatrix.size)
            assertFalse(omittedToken in mutatedRequiredMatrix)
            assertEquals(remainingRequiredTokens, mutatedRequiredMatrix)
            assertEquals(mutatedRequiredMatrix.size, mutatedRequiredMatrix.distinct().size)
            remainingRequiredTokens.forEach { remainingToken ->
                assertEquals(1, mutatedRequiredMatrix.count { token -> token == remainingToken })
            }

            val failure =
                assertFailsWith<IllegalArgumentException> {
                    validateReflectionTokenMatrix(
                        required = requiredReflectionTokens,
                        actual = mutatedRequiredMatrix,
                    )
                }

            assertEquals(
                "Reflection token matrix mismatch: actualCount=14, " +
                    "missing=[$omittedToken], unexpected=[].",
                failure.message,
            )
        }
    }

    @Test
    fun `reflection matrix validation rejects duplicates extras and empty matrices`() {
        val duplicatedToken = requiredReflectionTokens.first()
        val duplicateMatrix = requiredReflectionTokens + duplicatedToken
        val duplicatedTokens =
            duplicateMatrix.groupingBy { it }.eachCount().filterValues { count -> count > 1 }

        assertEquals(REQUIRED_REFLECTION_TOKEN_COUNT + 1, duplicateMatrix.size)
        assertEquals(mapOf(duplicatedToken to 2), duplicatedTokens)
        val duplicateFailure =
            assertFailsWith<IllegalArgumentException> {
                validateReflectionTokenMatrix(
                    required = requiredReflectionTokens,
                    actual = duplicateMatrix,
                )
            }
        assertEquals(
            "The detector reflection matrix contains duplicates=[$duplicatedToken].",
            duplicateFailure.message,
        )

        val syntheticExtraToken = "unexpected." + "reflection-token"
        val extraTokenMatrix = requiredReflectionTokens + syntheticExtraToken

        assertEquals(REQUIRED_REFLECTION_TOKEN_COUNT + 1, extraTokenMatrix.size)
        assertFalse(syntheticExtraToken in requiredReflectionTokens)
        requiredReflectionTokens.forEach { requiredToken ->
            assertEquals(1, extraTokenMatrix.count { token -> token == requiredToken })
        }
        assertEquals(extraTokenMatrix.size, extraTokenMatrix.distinct().size)
        val extraFailure =
            assertFailsWith<IllegalArgumentException> {
                validateReflectionTokenMatrix(
                    required = requiredReflectionTokens,
                    actual = extraTokenMatrix,
                )
            }
        assertEquals(
            "Reflection token matrix mismatch: actualCount=16, " +
                "missing=[], unexpected=[$syntheticExtraToken].",
            extraFailure.message,
        )

        val emptyFailure =
            assertFailsWith<IllegalArgumentException> {
                validateReflectionTokenMatrix(
                    required = requiredReflectionTokens,
                    actual = emptyList(),
                )
            }
        assertTrue(emptyFailure.message.orEmpty().contains("actualCount=0"))
    }

    @Test
    fun `reflection detector rejects every required token`() {
        requiredReflectionTokens.forEach { token ->
            assertEquals(
                listOf(token),
                ReflectionAccessDetector.findings("prefix $token suffix"),
            )
        }
    }

    @Test
    fun `reflection detector accepts benign text and uses intentional case matching`() {
        assertTrue(
            ReflectionAccessDetector.findings(
                "observer callbacks remain lifecycle driven",
            ).isEmpty(),
        )
        assertTrue(
            ReflectionAccessDetector.findings(
                "method" + "handles and un" + "safe are lower-case prose",
            ).isEmpty(),
        )
    }

    @Test
    fun `reflection detector covers boundaries and reports every finding`() {
        val first = requiredReflectionTokens.first()
        val last = requiredReflectionTokens.last()
        assertEquals(
            listOf(first),
            ReflectionAccessDetector.findings(first + " benign"),
        )
        assertEquals(
            listOf(last),
            ReflectionAccessDetector.findings("benign " + last),
        )
        val multiple =
            listOf(
                requiredReflectionTokens[0],
                requiredReflectionTokens[6],
                requiredReflectionTokens[12],
            )
        assertEquals(
            multiple,
            ReflectionAccessDetector.findings(multiple.joinToString("|")),
        )
    }

    @Test
    fun `complete observer test source contains no reflection access`() {
        val source =
            File(
                requireNotNull(System.getProperty("wto.android.platform.projectDir")),
                "src/test/kotlin/com/wifitestorchestrator/agent/platform/connectivity/" +
                    "AndroidConnectivityObserverTest.kt",
            ).readText()

        assertTrue(
            ReflectionAccessDetector.findings(source).isEmpty(),
            "Forbidden reflection access found in the complete observer test source.",
        )
    }

    private fun assertDeferredReentrantStop(result: ConnectivityObserverCommandResult?) {
        assertEquals(
            ConnectivityObservationReason.OBSERVER_STOPPED,
            assertIs<ConnectivityObserverCommandResult.Rejected>(requireNotNull(result)).reason,
        )
    }

    private fun assertActiveThenFailedWithRetainedSnapshot(
        observer: AndroidConnectivityObserver,
        observed: List<ConnectivityObserverState>,
    ) {
        assertEquals(
            listOf(
                ConnectivityObserverLifecycle.ACTIVE,
                ConnectivityObserverLifecycle.FAILED,
            ),
            observed.map { it.lifecycle },
        )
        val active = observed.first()
        val failed = observed.last()
        assertSame(active.snapshot, failed.snapshot)
        assertEquals(
            requireNotNull(active.snapshot).sequence,
            requireNotNull(failed.snapshot).sequence,
        )
        assertEquals(1, observed.count { it.lifecycle == ConnectivityObserverLifecycle.FAILED })
        assertEquals(observer.currentState(), failed)
    }

    private fun <T> runWithWatchdog(block: () -> T): T {
        val executor = Executors.newSingleThreadExecutor()
        return try {
            executor.submit<T> { block() }.get(5, TimeUnit.SECONDS)
        } finally {
            shutdown(executor)
        }
    }

    private fun awaitCondition(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition()) {
            check(System.nanoTime() < deadline) {
                "Condition was not reached before watchdog expiry."
            }
            Thread.yield()
        }
    }

    private fun assertStrictlyIncreasing(sequences: List<Long>) {
        assertEquals(sequences.distinct(), sequences)
        assertTrue(sequences.zipWithNext().all { (previous, next) -> previous < next })
    }

    private fun ConnectivityObserverCommandResult.lifecycleOrNull():
        ConnectivityObserverLifecycle? =
        when (this) {
            is ConnectivityObserverCommandResult.Accepted -> state.lifecycle
            is ConnectivityObserverCommandResult.Failed -> state.lifecycle
            is ConnectivityObserverCommandResult.Rejected -> null
        }

    private fun assertNoSession(observer: AndroidConnectivityObserver) {
        assertFalse(observer.diagnosticsForTesting().sessionPresent)
    }

    private fun hasCloseInProgress(observer: AndroidConnectivityObserver): Boolean {
        return observer.diagnosticsForTesting().closeInProgress
    }

    private fun assertNoCloseInProgress(observer: AndroidConnectivityObserver) {
        assertFalse(hasCloseInProgress(observer))
    }

    private fun assertNoListenerDeliveryContext(observer: AndroidConnectivityObserver) {
        assertEquals(0, observer.diagnosticsForTesting().listenerDeliveriesInProgress)
    }

    private fun shutdown(executor: ExecutorService) {
        executor.shutdownNow()
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
    }

    private fun fixture(
        mapper: AndroidConnectivitySnapshotMapper = AndroidConnectivitySnapshotMapper(),
        cleanupWaiterObserver: AndroidLifecycleCleanupWaiterObserver =
            AndroidLifecycleCleanupWaiterObserver { _, _, _ -> },
    ): Fixture {
        val facade = FakeConnectivityFacade()
        val dispatchers = FakeDispatcherFactory()
        val time = DeterministicTimeSource()
        return Fixture(
            observer =
                AndroidConnectivityObserver(
                    connectivityFacade = facade,
                    dispatcherFactory = dispatchers,
                    timeSource = time,
                    mapper = mapper,
                    cleanupWaiterObserver = cleanupWaiterObserver,
            ),
            facade = facade,
            dispatchers = dispatchers,
            time = time,
        )
    }

    private fun capabilities(
        transport: NetworkTransport,
        invalidTransportSet: Boolean = false,
        mappingFailure: Throwable =
            IllegalStateException("synthetic mapping failure"),
    ): AndroidNetworkCapabilitiesSnapshot =
        AndroidNetworkCapabilitiesSnapshot(
            transports =
                if (invalidTransportSet) {
                    object : AbstractSet<NetworkTransport>() {
                        override val size: Int = 1

                        override fun iterator(): Iterator<NetworkTransport> =
                            throwFailure(mappingFailure)
                    }
                } else {
                    setOf(transport)
                },
            hasInternetCapability = true,
            isValidated = true,
            hasCaptivePortalCapability = false,
            hasNotMeteredCapability = true,
            hasNotRoamingCapability = true,
            hasNotSuspendedCapability = true,
            signalStrength =
                AndroidPlatformValue.missing(ConnectivityObservationReason.NOT_REPORTED),
            wifiInfo = null,
            wifiTransportInfoUnexpected = false,
            wifiFeaturePresent = true,
        )

    private data class Fixture(
        val observer: AndroidConnectivityObserver,
        val facade: FakeConnectivityFacade,
        val dispatchers: FakeDispatcherFactory,
        val time: DeterministicTimeSource,
    )
}

private const val REQUIRED_REFLECTION_TOKEN_COUNT = 15

private val requiredReflectionTokens: List<String> =
    listOf(
        "get" + "DeclaredField",
        "get" + "DeclaredMethod",
        "get" + "DeclaredConstructor",
        "declaredF" + "ields",
        "declaredM" + "ethods",
        "isAccess" + "ible",
        "setAccess" + "ible",
        "trySetAccess" + "ible",
        "java." + "lang.reflect",
        "kotlin." + "reflect",
        "Class" + ".forName",
        "MethodH" + "andles",
        "Uns" + "afe",
        "::class" + ".java",
        ".javaC" + "lass",
    )

private fun validateReflectionTokenMatrix(
    required: List<String>,
    actual: List<String>,
) {
    require(required.size == REQUIRED_REFLECTION_TOKEN_COUNT) {
        "The normative reflection matrix must contain exactly " +
            "$REQUIRED_REFLECTION_TOKEN_COUNT tokens; actualCount=${required.size}."
    }
    val requiredDuplicates =
        required.groupingBy { it }.eachCount().filterValues { count -> count > 1 }.keys
    require(requiredDuplicates.isEmpty()) {
        "The normative reflection matrix contains duplicates=$requiredDuplicates."
    }
    val actualDuplicates =
        actual.groupingBy { it }.eachCount().filterValues { count -> count > 1 }.keys
    require(actualDuplicates.isEmpty()) {
        "The detector reflection matrix contains duplicates=$actualDuplicates."
    }
    val missing = required.filterNot(actual::contains)
    val unexpected = actual.filterNot(required::contains)
    require(
        actual.size == REQUIRED_REFLECTION_TOKEN_COUNT &&
            missing.isEmpty() &&
            unexpected.isEmpty(),
    ) {
        "Reflection token matrix mismatch: actualCount=${actual.size}, " +
            "missing=$missing, unexpected=$unexpected."
    }
}

private object ReflectionAccessDetector {
    val forbiddenTokens: List<String> =
        listOf(
            "getDeclared" + "Field",
            "getDeclared" + "Method",
            "getDeclared" + "Constructor",
            "declared" + "Fields",
            "declared" + "Methods",
            "is" + "Accessible",
            "set" + "Accessible",
            "trySet" + "Accessible",
            "java.lang." + "reflect",
            "kotlin." + "reflect",
            "Class." + "forName",
            "Method" + "Handles",
            "Un" + "safe",
            "::class." + "java",
            ".java" + "Class",
        )

    fun findings(source: String): List<String> =
        forbiddenTokens.filter { token -> token in source }
}

private class FakeConnectivityFacade : AndroidConnectivityManagerFacade {
    private val registerCounter = AtomicInteger()
    private val unregisterCounter = AtomicInteger()
    val registerCalls: Int
        get() = registerCounter.get()
    val unregisterCalls: Int
        get() = unregisterCounter.get()

    @Volatile
    var failRegister: Boolean = false

    @Volatile
    var failUnregister: Boolean = false

    @Volatile
    var registerFailure: Throwable? = null

    @Volatile
    var unregisterFailure: Throwable? = null

    @Volatile
    var registerHook: ((AndroidDefaultNetworkEvents) -> Unit)? = null

    @Volatile
    var unregisterHook: (() -> Unit)? = null

    val sessions = CopyOnWriteArrayList<AndroidDefaultNetworkEvents>()

    override fun registerDefaultNetworkCallback(
        profile: ConnectivityCollectionProfile,
        handler: Handler,
        events: AndroidDefaultNetworkEvents,
    ): AndroidNetworkCallbackRegistration {
        registerCounter.incrementAndGet()
        assertTrue(handler.looper === Looper.getMainLooper())
        registerHook?.invoke(events)
        registerFailure?.let(::throwFailure)
        if (failRegister) error("synthetic registration failure")
        sessions += events
        return FakeRegistration
    }

    override fun unregisterNetworkCallback(registration: AndroidNetworkCallbackRegistration) {
        unregisterCounter.incrementAndGet()
        assertTrue(registration === FakeRegistration)
        unregisterHook?.invoke()
        unregisterFailure?.let(::throwFailure)
        if (failUnregister) error("synthetic unregister failure")
    }

    private object FakeRegistration : AndroidNetworkCallbackRegistration
}

private class FakeDispatcherFactory : AndroidCallbackDispatcherFactory {
    private val createCounter = AtomicInteger()
    val createCalls: Int
        get() = createCounter.get()
    val created = CopyOnWriteArrayList<FakeDispatcher>()
    val totalCloseCalls: Int
        get() = created.sumOf { it.closeCalls }

    @Volatile
    var createHook: (() -> Unit)? = null

    @Volatile
    var createFailure: Throwable? = null

    override fun create(): AndroidCallbackDispatcher {
        createCounter.incrementAndGet()
        createHook?.invoke()
        createFailure?.let(::throwFailure)
        return FakeDispatcher().also(created::add)
    }
}

private class FakeDispatcher : AndroidCallbackDispatcher {
    override val handler: Handler = Handler(Looper.getMainLooper())
    private val closeCounter = AtomicInteger()
    val closeCalls: Int
        get() = closeCounter.get()

    @Volatile
    var failClose: Boolean = false

    @Volatile
    var closeFailure: Throwable? = null

    @Volatile
    var closeHook: (() -> Unit)? = null

    override fun close() {
        closeCounter.incrementAndGet()
        closeHook?.invoke()
        closeFailure?.let(::throwFailure)
        if (failClose) error("synthetic cleanup failure")
    }
}

private class DeterministicTimeSource : AndroidObservationTimeSource {
    private var next: Long = 1
    private val failuresAtCapture = mutableMapOf<Int, Throwable>()
    var nextFailure: Throwable? = null
    var failureAtCapture: Pair<Int, Throwable>? = null
    var captureHook: ((Int) -> Unit)? = null
    var captureCalls: Int = 0
        private set
    var lastSuccessfulTime: AndroidObservationTime? = null
        private set

    @Synchronized
    fun failAtCapture(
        capture: Int,
        failure: Throwable,
    ) {
        check(capture > captureCalls) {
            "A deterministic time failure must target a future capture."
        }
        check(failuresAtCapture.put(capture, failure) == null) {
            "Only one deterministic failure can be scheduled per capture."
        }
    }

    @Synchronized
    override fun capture(): AndroidObservationTime {
        captureCalls += 1
        captureHook?.invoke(captureCalls)
        nextFailure?.let { failure ->
            nextFailure = null
            throwFailure(failure)
        }
        failuresAtCapture.remove(captureCalls)?.let(::throwFailure)
        failureAtCapture?.let { (target, failure) ->
            if (captureCalls == target) {
                failureAtCapture = null
                throwFailure(failure)
            }
        }
        val value = next++
        return AndroidObservationTime(
            observedAtUtc = Instant.parse("2026-07-26T12:00:00Z").plusNanos(value),
            elapsedRealtimeNanos = value,
        ).also { captured ->
            lastSuccessfulTime = captured
        }
    }
}

private fun throwFailure(failure: Throwable): Nothing = throw failure
