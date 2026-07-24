package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentFailureReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentRejectionReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ReadProtectedEnrollmentResult
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class EnrollmentCoordinatorFailureWindowTest {
    @Test
    fun `uncertain persistence reconciles only an equivalent C06 candidate`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.repository.persistAction = {
            PersistProtectedEnrollmentResult.Failure(LocalPersistenceError.IO)
        }
        fixture.repository.readAction = {
            ReadProtectedEnrollmentResult.Compatible(
                storedEnrollment(fixture.attempt),
            )
        }

        val result = assertIs<Enrolled>(fixture.coordinator().enroll(fixture.attempt))

        assertEquals(EnrollmentSuccessKind.RECONCILED_AFTER_FAILURE, result.kind)
        assertEquals(
            PersistenceDisposition.RECONCILED_AFTER_FAILURE,
            result.persistenceDisposition,
        )
        assertEquals(DurabilityEvidence.AUTHORITATIVE_RECONCILIATION, result.durabilityEvidence)
        assertEquals(1, fixture.client.newCallCount.get())
        assertEquals(1, fixture.protector.protectCount.get())
        assertEquals(1, fixture.repository.persistCount.get())
        assertEquals(1, fixture.repository.readCount.get())
        assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
    }

    @Test
    fun `compatible but non equivalent reconciliation never fabricates success`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.repository.persistAction = {
            PersistProtectedEnrollmentResult.Failure(LocalPersistenceError.IO)
        }
        fixture.repository.readAction = {
            ReadProtectedEnrollmentResult.Compatible(
                storedEnrollment(
                    attempt = fixture.attempt,
                    metadata =
                        testCredentialMetadata(
                            issuedAt = Instant.parse("2026-07-12T12:00:00Z"),
                        ),
                ),
            )
        }

        val result = assertIs<PersistenceFailure>(
            fixture.coordinator().enroll(fixture.attempt),
        )

        assertEquals(
            PersistenceFailureReason.RECONCILIATION_NOT_EQUIVALENT,
            result.reason,
        )
        assertEquals(PersistenceDisposition.DURABILITY_CONFLICT, result.persistenceDisposition)
        assertEquals(
            DurabilityEvidence.CONFLICTING_AFTER_FAILURE,
            result.durabilityEvidence,
        )
        assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
            fixture.guard.snapshot(),
        )
    }

    @Test
    fun `uncertain persistence performs exactly one read and no repeated side effect`() =
        runTest {
            val fixture = CoordinatorFixture()
            fixture.repository.persistAction = {
                PersistProtectedEnrollmentResult.Failure(LocalPersistenceError.IO)
            }
            fixture.repository.readAction = { ReadProtectedEnrollmentResult.Absent }

            val result = assertIs<PersistenceFailure>(
                fixture.coordinator().enroll(fixture.attempt),
            )

            assertEquals(PersistenceFailureReason.RECONCILIATION_ABSENT, result.reason)
            assertEquals(DurabilityEvidence.ABSENT_AFTER_FAILURE, result.durabilityEvidence)
            assertEquals(1, fixture.client.newCallCount.get())
            assertEquals(1, fixture.call.executeCount.get())
            assertEquals(1, fixture.protector.protectCount.get())
            assertEquals(1, fixture.repository.persistCount.get())
            assertEquals(1, fixture.repository.readCount.get())
        }

    @Test
    fun `corrupt unsupported and failed reconciliation stay unknown and blocked`() = runTest {
        val readResults =
            listOf(
                ReadProtectedEnrollmentResult.Corrupt,
                ReadProtectedEnrollmentResult.Unsupported,
                ReadProtectedEnrollmentResult.Failure(LocalPersistenceError.CORRUPTION),
            )

        readResults.forEach { readResult ->
            val fixture = CoordinatorFixture()
            fixture.repository.persistAction = {
                PersistProtectedEnrollmentResult.Failure(LocalPersistenceError.IO)
            }
            fixture.repository.readAction = { readResult }

            val result = assertIs<PersistenceFailure>(
                fixture.coordinator().enroll(fixture.attempt),
            )

            assertEquals(
                PersistenceDisposition.DURABILITY_UNKNOWN,
                result.persistenceDisposition,
            )
            assertEquals(
                DurabilityEvidence.UNKNOWN_AFTER_FAILURE,
                result.durabilityEvidence,
            )
            assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
                fixture.guard.snapshot(),
            )
        }
    }

    @Test
    fun `defensive acceptance mismatch is accepted remotely but never protected`() = runTest {
        val fixture = CoordinatorFixture()
        val otherLocalIdentity =
            LocalInstallationIdentity(
                validValueForFailureWindow(
                    InstallationId.parse("40000000-0000-4000-8000-000000000003"),
                ),
            )
        fixture.call.action = {
            acceptedResult(
                attempt = fixture.attempt,
                acceptance =
                    testAcceptance(
                        attempt = fixture.attempt,
                        localIdentity = otherLocalIdentity,
                    ),
            )
        }

        val result = assertIs<ResponseIncompatible>(
            fixture.coordinator().enroll(fixture.attempt),
        )

        assertEquals(
            ResponseIncompatibleReason.DEFENSIVE_ACCEPTANCE_VALIDATION_FAILED,
            result.reason,
        )
        assertEquals(201, result.statusCode)
        assertEquals(RemoteDisposition.ACCEPTED, result.remoteDisposition)
        assertEquals(0, fixture.protector.protectCount.get())
        assertEquals(0, fixture.repository.persistCount.get())
        assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
            fixture.guard.snapshot(),
        )
    }

    @Test
    fun `incompatible wire response preserves unknown status as null`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.call.action = {
            EnrollmentResult.Failed(EnrollmentFailureReason.MALFORMED_JSON)
        }

        val result = assertIs<ResponseIncompatible>(
            fixture.coordinator().enroll(fixture.attempt),
        )

        assertNull(result.statusCode)
        assertEquals(RemoteDisposition.OUTCOME_UNRESOLVED, result.remoteDisposition)
    }

    @Test
    fun `manual retry can receive clock token rejection and never claims fifteen minutes`() =
        runTest {
            val fixture = CoordinatorFixture()
            fixture.call.action = {
                EnrollmentResult.Failed(EnrollmentFailureReason.TIMEOUT)
            }
            assertIs<RemoteOutcomeAmbiguous>(
                fixture.coordinator().enroll(fixture.attempt),
            )
            fixture.client.call =
                FakeEnrollmentCall(fixture.events) {
                    EnrollmentResult.Rejected(
                        reason =
                            EnrollmentRejectionReason
                                .AUTHENTICATION_TOKEN_OR_CLOCK_REJECTED,
                        statusCode = 401,
                        correlationId = fixture.attempt.command.correlationId,
                    )
                }

            val retried =
                fixture.coordinator().enroll(
                    fixture.attempt,
                    EnrollmentInvocationIntent.MANUAL_SAME_LIVE_ATTEMPT_ONLY,
                )

            assertIs<RemoteRejected>(retried)
            assertEquals(2, fixture.client.newCallCount.get())
            assertIs<ProcessEnrollmentGuardState.RemoteOutcomeUnresolved>(
                fixture.guard.snapshot(),
            )
        }

    @Test
    fun `reported at epoch is preserved and never replaced with zero semantics`() = runTest {
        val fixture = CoordinatorFixture()
        val epochAttempt = validAttempt(reportedAt = Instant.EPOCH)
        fixture.call.action = { acceptedResult(epochAttempt) }

        assertIs<Enrolled>(fixture.coordinator().enroll(epochAttempt))

        assertEquals(Instant.EPOCH.toString(), epochAttempt.command.agentReportedAt)
    }

    @Test
    fun `process death model is an explicitly fresh non durable guard`() {
        val oldGuard = ProcessEnrollmentGuard()
        val attempt = validAttempt()
        oldGuard.markRemoteOutcomeUnresolved(attempt.attemptId)

        val afterProcessRestart = ProcessEnrollmentGuard()

        assertIs<ProcessEnrollmentGuardState.RemoteOutcomeUnresolved>(oldGuard.snapshot())
        assertIs<ProcessEnrollmentGuardState.Open>(afterProcessRestart.snapshot())
    }
}

private fun <T : Any> validValueForFailureWindow(
    result: com.wifitestorchestrator.agent.domain.error.ValidationResult<T>,
): T =
    when (result) {
        is com.wifitestorchestrator.agent.domain.error.Valid -> result.value
        is com.wifitestorchestrator.agent.domain.error.Invalid ->
            error("Synthetic failure-window value is invalid")
    }
