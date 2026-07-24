package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentFailureReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest

class EnrollmentCoordinatorConcurrencyTest {
    @Test
    fun `two coordinators share one mutex and second rereads durable state`() = runTest {
        val fixture = CoordinatorFixture(dispatcher = Dispatchers.IO)
        val enteredExecute = CountDownLatch(1)
        val releaseExecute = CountDownLatch(1)
        fixture.call.action = {
            enteredExecute.countDown()
            check(releaseExecute.await(5, TimeUnit.SECONDS))
            acceptedResult(fixture.attempt)
        }
        fixture.repository.preflightAction = {
            if (fixture.repository.preflightCount.get() == 1) {
                ProtectedEnrollmentPreflightResult.Absent
            } else {
                ProtectedEnrollmentPreflightResult.Compatible(
                    storedEnrollment(fixture.attempt),
                )
            }
        }
        val firstCoordinator = fixture.coordinator()
        val secondCoordinator = fixture.coordinator()

        val first = async(Dispatchers.Default) { firstCoordinator.enroll(fixture.attempt) }
        assertTrue(enteredExecute.await(5, TimeUnit.SECONDS))
        val second = async(Dispatchers.Default) { secondCoordinator.enroll(fixture.attempt) }
        releaseExecute.countDown()

        assertIs<Enrolled>(first.await())
        assertIs<AlreadyEnrolled>(second.await())
        assertEquals(2, fixture.repository.preflightCount.get())
        assertEquals(1, fixture.client.newCallCount.get())
        assertEquals(1, fixture.call.executeCount.get())
        assertEquals(1, fixture.repository.persistCount.get())
        assertEquals(1, fixture.protector.inspectCount.get())
    }

    @Test
    fun `public factory coordinators share the production process guard`() = runTest {
        val firstAttempt = validAttempt()
        val firstEvents = EventLog()
        val firstExecuteEntered = CountDownLatch(1)
        val firstExecuteRelease = CountDownLatch(1)
        val firstCall =
            FakeEnrollmentCall(firstEvents) {
                firstExecuteEntered.countDown()
                check(firstExecuteRelease.await(5, TimeUnit.SECONDS))
                acceptedResult(firstAttempt)
            }
        val firstClient = FakeEnrollmentClient(firstEvents, firstCall)
        val firstRepository = FakeProtectedEnrollmentRepository(firstEvents)
        val firstProtector = FakeCredentialProtector(firstEvents)
        val firstCoordinator =
            EnrollmentCoordinatorFactory.create(
                enrollmentClient = firstClient,
                protectedEnrollmentRepository = firstRepository,
                credentialProtector = firstProtector,
            )

        val secondAttempt = secondAttempt()
        val secondEvents = EventLog()
        val secondPreflightEntered = CountDownLatch(1)
        val secondCall =
            FakeEnrollmentCall(secondEvents) {
                acceptedResult(secondAttempt)
            }
        val secondClient = FakeEnrollmentClient(secondEvents, secondCall)
        val secondRepository =
            FakeProtectedEnrollmentRepository(secondEvents).apply {
                preflightAction = {
                    secondPreflightEntered.countDown()
                    ProtectedEnrollmentPreflightResult.Compatible(
                        storedEnrollment(secondAttempt),
                    )
                }
            }
        val secondProtector = FakeCredentialProtector(secondEvents)
        val secondCoordinator =
            EnrollmentCoordinatorFactory.create(
                enrollmentClient = secondClient,
                protectedEnrollmentRepository = secondRepository,
                credentialProtector = secondProtector,
            )

        val publicCreate =
            EnrollmentCoordinatorFactory::class.java.declaredMethods.single {
                it.name == "create"
            }
        assertFalse(
            publicCreate.parameterTypes.any {
                it.name.startsWith("kotlinx.coroutines")
            },
        )
        assertFalse(
            EnrollmentCoordinatorFactory::class.java.methods.any {
                it.name.contains("reset", ignoreCase = true)
            },
        )

        val first =
            async(Dispatchers.Default) {
                firstCoordinator.enroll(firstAttempt)
            }
        assertTrue(firstExecuteEntered.await(5, TimeUnit.SECONDS))
        lateinit var second: Deferred<EnrollmentCoordinatorResult>
        val secondPreflightsWhileFirstBlocked: Int
        try {
            second =
                async(
                    context = Dispatchers.Default,
                    start = CoroutineStart.UNDISPATCHED,
                ) {
                    secondCoordinator.enroll(secondAttempt)
                }
            secondPreflightsWhileFirstBlocked =
                secondRepository.preflightCount.get()
        } finally {
            firstExecuteRelease.countDown()
        }

        assertIs<Enrolled>(first.await())
        assertTrue(secondPreflightEntered.await(5, TimeUnit.SECONDS))
        assertIs<AlreadyEnrolled>(second.await())

        assertEquals(0, secondPreflightsWhileFirstBlocked)
        assertEquals(1, firstRepository.preflightCount.get())
        assertEquals(1, firstClient.newCallCount.get())
        assertEquals(1, firstCall.executeCount.get())
        assertEquals(1, secondRepository.preflightCount.get())
        assertEquals(0, secondClient.newCallCount.get())
        assertEquals(1, secondProtector.inspectCount.get())
        assertIs<ProcessEnrollmentGuardState.Open>(
            ProductionProcessEnrollmentGuard.shared.snapshot(),
        )
    }

    @Test
    fun `unresolved outcome blocks a different attempt before Keystore and network`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.call.action = {
            EnrollmentResult.Failed(EnrollmentFailureReason.TIMEOUT)
        }
        assertIs<RemoteOutcomeAmbiguous>(
            fixture.coordinator().enroll(fixture.attempt),
        )
        val beforePrepare = fixture.protector.prepareCount.get()
        val beforeCalls = fixture.client.newCallCount.get()

        val blocked = assertIs<LocalStateBlocked>(
            fixture.coordinator().enroll(secondAttempt()),
        )

        assertEquals(
            LocalStateBlockedReason.PREVIOUS_REMOTE_OUTCOME_UNRESOLVED,
            blocked.reason,
        )
        assertEquals(beforePrepare, fixture.protector.prepareCount.get())
        assertEquals(beforeCalls, fixture.client.newCallCount.get())
    }

    @Test
    fun `same live attempt requires explicit manual intent and can clear guard durably`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.call.action = {
            EnrollmentResult.Failed(EnrollmentFailureReason.TIMEOUT)
        }
        assertIs<RemoteOutcomeAmbiguous>(
            fixture.coordinator().enroll(fixture.attempt),
        )

        assertIs<LocalStateBlocked>(
            fixture.coordinator().enroll(
                fixture.attempt,
                EnrollmentInvocationIntent.INITIAL,
            ),
        )
        fixture.client.call =
            FakeEnrollmentCall(fixture.events) {
                acceptedResult(fixture.attempt)
            }

        val retried =
            fixture.coordinator().enroll(
                fixture.attempt,
                EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY,
            )

        assertIs<Enrolled>(retried)
        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
        assertEquals(2, fixture.client.newCallCount.get())
    }

    @Test
    fun `manual retry cannot substitute a different attempt after a known failure`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.call.action = {
            EnrollmentResult.Failed(EnrollmentFailureReason.DNS)
        }
        assertIs<KnownTransientFailure>(
            fixture.coordinator().enroll(fixture.attempt),
        )
        val callsBeforeRetry = fixture.client.newCallCount.get()

        val blocked =
            assertIs<LocalStateBlocked>(
                fixture.coordinator().enroll(
                    secondAttempt(),
                    EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY,
                ),
            )

        assertEquals(
            LocalStateBlockedReason.MANUAL_RETRY_REQUIRES_SAME_LIVE_ATTEMPT,
            blocked.reason,
        )
        assertEquals(callsBeforeRetry, fixture.client.newCallCount.get())

        val implicitRetry =
            assertIs<LocalStateBlocked>(
                fixture.coordinator().enroll(fixture.attempt),
            )
        assertEquals(
            LocalStateBlockedReason.RETRY_REQUIRES_MANUAL_INTENT,
            implicitRetry.reason,
        )
        assertEquals(callsBeforeRetry, fixture.client.newCallCount.get())

        assertIs<KnownTransientFailure>(
            fixture.coordinator().enroll(
                fixture.attempt,
                EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY,
            ),
        )
        assertEquals(callsBeforeRetry + 1, fixture.client.newCallCount.get())
    }

    @Test
    fun `compatible preflight resolves a prior process ambiguity`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.guard.markRemoteOutcomeUnresolved(fixture.attempt.attemptId)
        fixture.repository.preflightAction = {
            ProtectedEnrollmentPreflightResult.Compatible(
                storedEnrollment(fixture.attempt),
            )
        }

        assertIs<AlreadyEnrolled>(fixture.coordinator().enroll(secondAttempt()))

        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
        assertEquals(0, fixture.client.newCallCount.get())
    }

    @Test
    fun `Exception and Error release the process mutex`() = runTest {
        val exceptionFixture = CoordinatorFixture()
        exceptionFixture.repository.preflightAction = {
            if (exceptionFixture.repository.preflightCount.get() == 1) {
                throw IllegalStateException("synthetic")
            }
            ProtectedEnrollmentPreflightResult.Absent
        }

        assertIs<LocalStateBlocked>(
            exceptionFixture.coordinator().enroll(exceptionFixture.attempt),
        )
        assertIs<Enrolled>(
            exceptionFixture.coordinator().enroll(exceptionFixture.attempt),
        )

        val errorFixture = CoordinatorFixture()
        errorFixture.repository.preflightAction = {
            if (errorFixture.repository.preflightCount.get() == 1) {
                throw AssertionError("synthetic")
            }
            ProtectedEnrollmentPreflightResult.Absent
        }
        assertFailsWith<AssertionError> {
            errorFixture.coordinator().enroll(errorFixture.attempt)
        }
        assertIs<Enrolled>(errorFixture.coordinator().enroll(errorFixture.attempt))
    }

    @Test
    fun `Error after remote acceptance blocks a different attempt and releases mutex`() =
        runTest {
            val fixture = CoordinatorFixture()
            fixture.protector.protectAction = { throw AssertionError("synthetic") }

            assertFailsWith<AssertionError> {
                fixture.coordinator().enroll(fixture.attempt)
            }

            assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
                fixture.guard.snapshot(),
            )
            val blocked = assertIs<LocalStateBlocked>(
                fixture.coordinator().enroll(secondAttempt()),
            )
            assertEquals(
                LocalStateBlockedReason.PREVIOUS_REMOTE_ACCEPTED_NOT_DURABLE,
                blocked.reason,
            )
        }
}
