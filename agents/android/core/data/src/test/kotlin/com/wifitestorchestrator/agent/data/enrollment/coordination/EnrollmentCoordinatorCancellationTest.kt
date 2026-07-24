package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest

class EnrollmentCoordinatorCancellationTest {
    @Test
    fun `cancellation before acquiring the mutex performs no work`() = runTest {
        val fixture = CoordinatorFixture()
        val deferred =
            async(start = CoroutineStart.LAZY) {
                fixture.coordinator().enroll(fixture.attempt)
            }

        deferred.cancel()
        deferred.join()

        assertTrue(deferred.isCancelled)
        assertEquals(emptyList(), fixture.events.snapshot())
        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
    }

    @Test
    fun `canceled waiter neither cancels nor interferes with mutex owner`() = runTest {
        val fixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        fixture.call.action = {
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            acceptedResult(fixture.attempt)
        }
        val owner =
            async(Dispatchers.Default) {
                fixture.coordinator().enroll(fixture.attempt)
            }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val waiter =
            async(Dispatchers.Default) {
                fixture.coordinator().enroll(secondAttempt())
            }

        waiter.cancel()
        waiter.join()
        release.countDown()

        assertTrue(waiter.isCancelled)
        assertIs<Enrolled>(owner.await())
        assertEquals(1, fixture.repository.preflightCount.get())
        assertEquals(1, fixture.call.executeCount.get())
        assertEquals(0, fixture.call.cancelCount.get())
    }

    @Test
    fun `cancellation during preflight propagates without touching Keystore or guard`() = runTest {
        val fixture = CoordinatorFixture()
        val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
        val release = kotlinx.coroutines.CompletableDeferred<Unit>()
        fixture.repository.preflightAction = {
            entered.complete(Unit)
            release.await()
            error("unreachable")
        }
        val deferred =
            async { fixture.coordinator().enroll(fixture.attempt) }
        entered.await()

        deferred.cancel()
        deferred.join()

        assertTrue(deferred.isCancelled)
        assertEquals(0, fixture.protector.prepareCount.get())
        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
    }

    @Test
    fun `cancellation after newCall but before execute does not create ambiguity`() = runTest {
        val dispatcher = NthDispatchGateDispatcher(blockDispatchNumber = 2)
        val fixture = CoordinatorFixture(dispatcher = dispatcher)
        val deferred =
            async(Dispatchers.Default) {
                fixture.coordinator().enroll(fixture.attempt)
            }
        assertTrue(dispatcher.blocked.await(5, TimeUnit.SECONDS))

        deferred.cancel()
        dispatcher.release.countDown()
        deferred.join()

        assertTrue(deferred.isCancelled)
        assertEquals(1, fixture.client.newCallCount.get())
        assertEquals(0, fixture.call.executeCount.get())
        assertEquals(1, fixture.call.cancelCount.get())
        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
    }

    @Test
    fun `cancellation during inspect or prepare never reaches network`() = runTest {
        listOf("inspect", "prepare").forEach { stage ->
            val fixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            if (stage == "inspect") {
                fixture.repository.preflightAction = {
                    ProtectedEnrollmentPreflightResult.Compatible(
                        storedEnrollment(fixture.attempt),
                    )
                }
                fixture.protector.inspectAction = {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    CredentialProtectionInspection.Compatible(
                        CredentialKeySecurityLevel.TRUSTED_ENVIRONMENT,
                    )
                }
            } else {
                fixture.protector.prepareAction = {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    CredentialProtectionPreparation.AlreadyCompatible
                }
            }
            val deferred =
                async(Dispatchers.Default) {
                    fixture.coordinator().enroll(fixture.attempt)
                }
            assertTrue(entered.await(5, TimeUnit.SECONDS))

            deferred.cancel()
            release.countDown()
            deferred.join()

            assertTrue(deferred.isCancelled)
            assertEquals(0, fixture.client.newCallCount.get())
            assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
        }
    }

    @Test
    fun `cancellation after execute starts cancels once and marks ambiguity`() = runTest {
        val fixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        fixture.call.action = {
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            acceptedResult(fixture.attempt)
        }
        val deferred =
            async(Dispatchers.Default) {
                fixture.coordinator().enroll(fixture.attempt)
            }
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        deferred.cancel(CancellationException("synthetic cancellation"))
        assertFalse(deferred.isCompleted)
        release.countDown()
        deferred.join()

        assertTrue(deferred.isCancelled)
        assertEquals(1, fixture.call.executeCount.get())
        assertEquals(1, fixture.call.cancelCount.get())
        assertEquals(0, fixture.protector.protectCount.get())
        assertEquals(0, fixture.repository.persistCount.get())
        assertTrue(
            fixture.guard.snapshot() is
                ProcessEnrollmentGuardState.RemoteOutcomeUnresolved ||
                fixture.guard.snapshot() is
                ProcessEnrollmentGuardState.RemoteAcceptedNotDurable,
        )
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `canceled running call holds mutex until worker terminates`() = runTest {
        val fixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
        val firstExecuteEntered = CompletableDeferred<Unit>()
        val firstExecuteRelease = CountDownLatch(1)
        val cancelObserved = CompletableDeferred<Unit>()
        val secondPreflightEntered = CompletableDeferred<Unit>()
        val secondPreflightRelease = CompletableDeferred<Unit>()
        val activeExecutions = AtomicInteger(0)
        val maximumActiveExecutions = AtomicInteger(0)
        val observedCancellation = AtomicReference<CancellationException?>()

        fixture.repository.preflightAction = {
            if (fixture.repository.preflightCount.get() == 1) {
                ProtectedEnrollmentPreflightResult.Absent
            } else {
                secondPreflightEntered.complete(Unit)
                secondPreflightRelease.await()
                ProtectedEnrollmentPreflightResult.Absent
            }
        }
        fixture.call.action = {
            val active = activeExecutions.incrementAndGet()
            maximumActiveExecutions.updateAndGet { current -> maxOf(current, active) }
            try {
                firstExecuteEntered.complete(Unit)
                check(firstExecuteRelease.await(5, TimeUnit.SECONDS))
                acceptedResult(fixture.attempt)
            } finally {
                activeExecutions.decrementAndGet()
            }
        }
        fixture.call.cancelAction = {
            cancelObserved.complete(Unit)
        }
        val firstCancellation = CancellationException("primary cancellation")
        val first =
            async(start = CoroutineStart.LAZY) {
                try {
                    fixture.coordinator().enroll(fixture.attempt)
                } catch (cancellation: CancellationException) {
                    observedCancellation.set(cancellation)
                    throw cancellation
                }
            }
        first.start()
        runCurrent()
        firstExecuteEntered.await()

        val retryCall =
            FakeEnrollmentCall(fixture.events) {
                val active = activeExecutions.incrementAndGet()
                maximumActiveExecutions.updateAndGet { current -> maxOf(current, active) }
                try {
                    acceptedResult(fixture.attempt)
                } finally {
                    activeExecutions.decrementAndGet()
                }
            }
        fixture.client.call = retryCall
        first.cancel(firstCancellation)
        cancelObserved.await()
        runCurrent()

        assertFalse(first.isCompleted)
        assertEquals(1, activeExecutions.get())
        assertEquals(1L, firstExecuteRelease.count)
        assertEquals(1, fixture.call.cancelCount.get())

        val retry =
            async(start = CoroutineStart.UNDISPATCHED) {
                fixture.coordinator().enroll(
                    fixture.attempt,
                    EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY,
                )
            }
        runCurrent()

        assertFalse(first.isCompleted)
        assertFalse(retry.isCompleted)
        assertFalse(secondPreflightEntered.isCompleted)
        assertEquals(1, fixture.repository.preflightCount.get())
        assertEquals(1, fixture.protector.prepareCount.get())
        assertEquals(1, fixture.client.newCallCount.get())
        assertEquals(1, fixture.call.executeCount.get())
        assertEquals(0, retryCall.executeCount.get())
        assertEquals(1, activeExecutions.get())
        assertEquals(1, maximumActiveExecutions.get())
        assertEquals(0, fixture.protector.protectCount.get())
        assertEquals(0, fixture.repository.persistCount.get())
        assertEquals(1L, firstExecuteRelease.count)

        firstExecuteRelease.countDown()
        first.join()
        runCurrent()

        assertTrue(first.isCancelled)
        assertTrue(secondPreflightEntered.isCompleted)
        val propagatedCancellation = requireNotNull(observedCancellation.get())
        assertTrue(
            propagatedCancellation === firstCancellation ||
                propagatedCancellation.cause === firstCancellation,
        )
        assertEquals(1, fixture.call.cancelCount.get())
        assertEquals(0, fixture.protector.protectCount.get())
        assertEquals(0, fixture.repository.persistCount.get())
        assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
            fixture.guard.snapshot(),
        )

        secondPreflightRelease.complete(Unit)
        assertIs<Enrolled>(retry.await())

        assertEquals(1, maximumActiveExecutions.get())
        assertEquals(2, fixture.repository.preflightCount.get())
        assertEquals(2, fixture.protector.prepareCount.get())
        assertEquals(2, fixture.client.newCallCount.get())
        assertEquals(1, retryCall.executeCount.get())
        assertEquals(1, fixture.protector.protectCount.get())
        assertEquals(1, fixture.repository.persistCount.get())
        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
    }

    @Test
    fun `cancellation remains primary when call cleanup throws Error`() = runTest {
        val fixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val observedCancellation = AtomicReference<CancellationException?>()
        fixture.call.action = {
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            acceptedResult(fixture.attempt)
        }
        fixture.call.cancelAction = {
            throw AssertionError("synthetic cleanup failure")
        }
        val primaryCancellation = CancellationException("primary cancellation")
        val deferred =
            async(Dispatchers.Default) {
                try {
                    fixture.coordinator().enroll(fixture.attempt)
                } catch (cancellation: CancellationException) {
                    observedCancellation.set(cancellation)
                    throw cancellation
                }
            }
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        deferred.cancel(primaryCancellation)
        release.countDown()
        deferred.join()

        assertTrue(deferred.isCancelled)
        val propagatedCancellation = requireNotNull(observedCancellation.get())
        assertTrue(
            propagatedCancellation === primaryCancellation ||
                propagatedCancellation.cause === primaryCancellation,
        )
        val cleanupFailure =
            generateSequence<Throwable>(propagatedCancellation) { it.cause }
                .flatMap { it.suppressed.asSequence() }
                .single()
        assertEquals(
            "EnrollmentCall cancellation cleanup failed (<redacted>).",
            cleanupFailure.message,
        )
        assertFalse(cleanupFailure.message.orEmpty().contains("synthetic cleanup failure"))
        assertEquals(null, cleanupFailure.cause)
        assertEquals(1, fixture.call.cancelCount.get())
        assertTrue(fixture.guard.snapshot() !is ProcessEnrollmentGuardState.Open)
    }

    @Test
    fun `cancellation during protect and persist propagates as accepted not durable`() = runTest {
        val protectFixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
        val protectEntered = CountDownLatch(1)
        val protectRelease = CountDownLatch(1)
        protectFixture.protector.protectAction = {
            protectEntered.countDown()
            check(protectRelease.await(5, TimeUnit.SECONDS))
            ProtectCredentialResultForTest.protected(it)
        }
        val protecting =
            async(Dispatchers.Default) {
                protectFixture.coordinator().enroll(protectFixture.attempt)
            }
        assertTrue(protectEntered.await(5, TimeUnit.SECONDS))
        protecting.cancel()
        protectRelease.countDown()
        protecting.join()
        assertTrue(protecting.isCancelled)
        assertEquals(0, protectFixture.repository.persistCount.get())
        assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
            protectFixture.guard.snapshot(),
        )

        val persistFixture = CoordinatorFixture()
        val persistEntered = kotlinx.coroutines.CompletableDeferred<Unit>()
        val persistRelease = kotlinx.coroutines.CompletableDeferred<Unit>()
        persistFixture.repository.persistAction = {
            persistEntered.complete(Unit)
            persistRelease.await()
            PersistProtectedEnrollmentResult.Written
        }
        val persisting =
            async { persistFixture.coordinator().enroll(persistFixture.attempt) }
        persistEntered.await()
        persisting.cancel()
        persisting.join()
        assertTrue(persisting.isCancelled)
        assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
            persistFixture.guard.snapshot(),
        )
    }

    @Test
    fun `cancellation during reconciliation preserves accepted not durable guard`() = runTest {
        val fixture = CoordinatorFixture()
        val readEntered = kotlinx.coroutines.CompletableDeferred<Unit>()
        val readRelease = kotlinx.coroutines.CompletableDeferred<Unit>()
        fixture.repository.persistAction = {
            PersistProtectedEnrollmentResult.Failure(
                com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError.IO,
            )
        }
        fixture.repository.readAction = {
            readEntered.complete(Unit)
            readRelease.await()
            error("unreachable")
        }
        val deferred = async { fixture.coordinator().enroll(fixture.attempt) }
        readEntered.await()

        deferred.cancel()
        deferred.join()

        assertTrue(deferred.isCancelled)
        assertEquals(1, fixture.repository.readCount.get())
        assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
            fixture.guard.snapshot(),
        )
    }

    @Test
    fun `cancellation after durable commit propagates without blocking future attempts`() =
        runTest {
            val fixture = CoordinatorFixture()
            fixture.repository.persistAction = {
                currentCoroutineContext().cancel(
                    CancellationException("after synthetic commit"),
                )
                PersistProtectedEnrollmentResult.Written
            }

            val deferred = async { fixture.coordinator().enroll(fixture.attempt) }
            deferred.join()

            assertTrue(deferred.isCancelled)
            assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
            assertEquals(1, fixture.repository.persistCount.get())
        }
}

private class NthDispatchGateDispatcher(
    private val blockDispatchNumber: Int,
) : CoroutineDispatcher() {
    private val count = AtomicInteger(0)
    val blocked = CountDownLatch(1)
    val release = CountDownLatch(1)

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        val number = count.incrementAndGet()
        Dispatchers.IO.dispatch(
            context,
            Runnable {
                if (number == blockDispatchNumber) {
                    blocked.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                block.run()
            },
        )
    }
}

private object ProtectCredentialResultForTest {
    fun protected(
        credential: com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential,
    ): com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult =
        com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
            .Protected(testEnvelope(credential.metadata))
}
