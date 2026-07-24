package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentFailureReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentRejectionReason
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.test.runTest

class EnrollmentCoordinatorStateMatrixTest {
    @Test
    fun `every blocking C06 preflight state stops before Keystore and network`() = runTest {
        val cases =
            listOf(
                ProtectedEnrollmentPreflightResult.Conflict to
                    LocalStateBlockedReason.IDENTITY_OR_SERVER_CONFLICT,
                ProtectedEnrollmentPreflightResult.Corrupt to
                    LocalStateBlockedReason.CORRUPT,
                ProtectedEnrollmentPreflightResult.Unsupported to
                    LocalStateBlockedReason.UNSUPPORTED,
            )

        cases.forEach { (preflight, expectedReason) ->
            val fixture = CoordinatorFixture()
            fixture.repository.preflightAction = { preflight }

            val result = assertIs<LocalStateBlocked>(fixture.coordinator().enroll(fixture.attempt))

            assertEquals(expectedReason, result.reason)
            assertEquals(listOf("preflight"), fixture.events.snapshot())
        }

        val incomplete = CoordinatorFixture()
        incomplete.repository.preflightAction = {
            ProtectedEnrollmentPreflightResult.LocalStateIncomplete
        }
        assertIs<MissingPrecondition>(incomplete.coordinator().enroll(incomplete.attempt))
        assertEquals(listOf("preflight"), incomplete.events.snapshot())
    }

    @Test
    fun `every C06 preflight failure has a closed reason`() = runTest {
        LocalPersistenceError.entries.forEach { error ->
            val fixture = CoordinatorFixture()
            fixture.repository.preflightAction = {
                ProtectedEnrollmentPreflightResult.Failure(error)
            }

            val result = assertIs<LocalStateBlocked>(fixture.coordinator().enroll(fixture.attempt))

            assertEquals("PREFLIGHT_${error.name}", result.reason.name)
            assertEquals(0, fixture.protector.prepareCount.get())
            assertEquals(0, fixture.client.newCallCount.get())
        }
    }

    @Test
    fun `durable state never prepares a missing incompatible or unavailable key`() = runTest {
        val cases =
            listOf(
                CredentialProtectionInspection.Missing,
                CredentialProtectionInspection.Incompatible,
            ) +
                CredentialProtectionError.entries.map {
                    CredentialProtectionInspection.Unavailable(it)
                }

        cases.forEach { inspection ->
            val fixture = CoordinatorFixture()
            fixture.repository.preflightAction = {
                ProtectedEnrollmentPreflightResult.Compatible(
                    storedEnrollment(fixture.attempt),
                )
            }
            fixture.protector.inspectAction = { inspection }

            val result = fixture.coordinator().enroll(fixture.attempt)

            when (inspection) {
                CredentialProtectionInspection.Missing,
                CredentialProtectionInspection.Incompatible,
                -> assertIs<KeyIncompatible>(result)
                is CredentialProtectionInspection.Unavailable ->
                    assertIs<PlatformFailure>(result)
                is CredentialProtectionInspection.Compatible ->
                    error("Not part of the blocking matrix")
            }
            assertEquals(1, fixture.protector.inspectCount.get())
            assertEquals(0, fixture.protector.prepareCount.get())
            assertEquals(0, fixture.client.newCallCount.get())
        }
    }

    @Test
    fun `absent state accepts both successful preparation results`() = runTest {
        listOf(
            CredentialProtectionPreparation.Created,
            CredentialProtectionPreparation.AlreadyCompatible,
        ).forEach { preparation ->
            val fixture = CoordinatorFixture()
            fixture.protector.prepareAction = { preparation }

            assertIs<Enrolled>(fixture.coordinator().enroll(fixture.attempt))
            assertEquals(1, fixture.protector.prepareCount.get())
            assertEquals(0, fixture.protector.inspectCount.get())
        }
    }

    @Test
    fun `every preparation failure is closed before network`() = runTest {
        CredentialProtectionError.entries.forEach { error ->
            val fixture = CoordinatorFixture()
            fixture.protector.prepareAction = {
                CredentialProtectionPreparation.Failure(error)
            }

            val result = fixture.coordinator().enroll(fixture.attempt)

            if (error == CredentialProtectionError.KEY_INCOMPATIBLE) {
                assertIs<KeyIncompatible>(result)
            } else {
                assertIs<PlatformFailure>(result)
            }
            assertEquals(0, fixture.client.newCallCount.get())
        }
    }

    @Test
    fun `every protection failure is closed after known remote acceptance`() = runTest {
        CredentialProtectionError.entries.forEach { error ->
            val fixture = CoordinatorFixture()
            fixture.protector.protectAction = {
                ProtectCredentialResult.Failure(error)
            }

            val result = assertIs<ProtectionFailure>(
                fixture.coordinator().enroll(fixture.attempt),
            )

            assertEquals(error.name, result.reason.name)
            assertEquals(RemoteDisposition.ACCEPTED, result.remoteDisposition)
            assertEquals(0, fixture.repository.persistCount.get())
            assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
                fixture.guard.snapshot(),
            )
        }
    }

    @Test
    fun `C03 rejection matrix remains known and does not become ambiguous`() = runTest {
        EnrollmentRejectionReason.entries.forEach { reason ->
            val fixture = CoordinatorFixture()
            fixture.call.action = {
                EnrollmentResult.Rejected(
                    reason = reason,
                    statusCode = rejectionStatus(reason),
                    correlationId = fixture.attempt.command.correlationId,
                )
            }

            val result = assertIs<RemoteRejected>(
                fixture.coordinator().enroll(fixture.attempt),
            )

            assertEquals(reason.name, result.reason.name)
            assertEquals(RemoteDisposition.KNOWN_REJECTED, result.remoteDisposition)
            assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
        }
    }

    @Test
    fun `C03 failure matrix has conservative closed classifications`() = runTest {
        EnrollmentFailureReason.entries.forEach { reason ->
            val fixture = CoordinatorFixture()
            fixture.call.action = { EnrollmentResult.Failed(reason) }

            val result = fixture.coordinator().enroll(fixture.attempt)

            when (reason) {
                EnrollmentFailureReason.INVALID_LOCAL_REQUEST,
                EnrollmentFailureReason.INVALID_ENDPOINT,
                -> {
                    assertIs<InvalidConfiguration>(result)
                    assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
                }
                EnrollmentFailureReason.DNS,
                EnrollmentFailureReason.CONNECTION,
                -> {
                    assertIs<KnownTransientFailure>(result)
                    assertIs<ProcessEnrollmentGuardState.Open>(fixture.guard.snapshot())
                }
                EnrollmentFailureReason.TLS,
                EnrollmentFailureReason.TIMEOUT,
                EnrollmentFailureReason.CANCELLED,
                EnrollmentFailureReason.INCOMPLETE_RESPONSE,
                EnrollmentFailureReason.IO,
                -> {
                    assertIs<RemoteOutcomeAmbiguous>(result)
                    assertIs<ProcessEnrollmentGuardState.RemoteOutcomeUnresolved>(
                        fixture.guard.snapshot(),
                    )
                }
                else -> {
                    val incompatible = assertIs<ResponseIncompatible>(result)
                    assertEquals(null, incompatible.statusCode)
                    assertIs<ProcessEnrollmentGuardState.RemoteOutcomeUnresolved>(
                        fixture.guard.snapshot(),
                    )
                }
            }
            assertEquals(0, fixture.protector.protectCount.get())
            assertEquals(0, fixture.repository.persistCount.get())
        }
    }

    @Test
    fun `every definitive C06 persist refusal is fail closed`() = runTest {
        val cases =
            listOf(
                PersistProtectedEnrollmentResult.Conflict,
                PersistProtectedEnrollmentResult.Rollback,
                PersistProtectedEnrollmentResult.PendingRejected,
                PersistProtectedEnrollmentResult.InvalidCandidate,
                PersistProtectedEnrollmentResult.Corrupt,
                PersistProtectedEnrollmentResult.Unsupported,
            )

        cases.forEach { persistence ->
            val fixture = CoordinatorFixture()
            fixture.repository.persistAction = { persistence }

            val result = assertIs<PersistenceFailure>(
                fixture.coordinator().enroll(fixture.attempt),
            )

            assertEquals(PersistenceDisposition.NOT_DURABLE, result.persistenceDisposition)
            assertEquals(0, fixture.repository.readCount.get())
            assertIs<ProcessEnrollmentGuardState.RemoteAcceptedNotDurable>(
                fixture.guard.snapshot(),
            )
        }
    }

    @Test
    fun `every C06 persistence Failure performs one reconciliation only`() = runTest {
        LocalPersistenceError.entries.forEach { error ->
            val fixture = CoordinatorFixture()
            fixture.repository.persistAction = {
                PersistProtectedEnrollmentResult.Failure(error)
            }
            fixture.repository.readAction = {
                com.wifitestorchestrator.agent.data.persistence
                    .ReadProtectedEnrollmentResult.Absent
            }

            assertIs<PersistenceFailure>(
                fixture.coordinator().enroll(fixture.attempt),
            )

            assertEquals(1, fixture.repository.persistCount.get())
            assertEquals(1, fixture.repository.readCount.get())
            assertEquals(1, fixture.call.executeCount.get())
            assertEquals(1, fixture.protector.protectCount.get())
        }
    }

    private fun rejectionStatus(reason: EnrollmentRejectionReason): Int =
        when (reason) {
            EnrollmentRejectionReason.AUTHENTICATION_TOKEN_OR_CLOCK_REJECTED -> 401
            EnrollmentRejectionReason.CONFLICT -> 409
            EnrollmentRejectionReason.REQUEST_TOO_LARGE -> 413
            EnrollmentRejectionReason.CONTRACT_REJECTED -> 422
            EnrollmentRejectionReason.RATE_LIMITED -> 429
            EnrollmentRejectionReason.SERVICE_UNAVAILABLE -> 503
        }
}
