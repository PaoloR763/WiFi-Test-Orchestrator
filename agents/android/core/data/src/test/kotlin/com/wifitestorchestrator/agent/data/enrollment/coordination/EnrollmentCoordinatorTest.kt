package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

class EnrollmentCoordinatorTest {
    @Test
    fun `happy path executes the exact C06 C05 C03 C05 C06 order once`() = runTest {
        val fixture = CoordinatorFixture()

        val result = fixture.coordinator().enroll(fixture.attempt)

        val enrolled = assertIs<Enrolled>(result)
        assertEquals(EnrollmentSuccessKind.NEWLY_WRITTEN, enrolled.kind)
        assertEquals(PersistenceDisposition.NEWLY_WRITTEN, enrolled.persistenceDisposition)
        assertEquals(DurabilityEvidence.TRANSACTION_CONFIRMED, enrolled.durabilityEvidence)
        assertNull(enrolled.anomaly)
        assertEquals(
            listOf("preflight", "prepare", "newCall", "execute", "protect", "persist"),
            fixture.events.snapshot(),
        )
        assertEquals(1, fixture.repository.preflightCount.get())
        assertEquals(1, fixture.protector.prepareCount.get())
        assertEquals(0, fixture.protector.inspectCount.get())
        assertEquals(1, fixture.client.newCallCount.get())
        assertEquals(1, fixture.call.executeCount.get())
        assertEquals(1, fixture.protector.protectCount.get())
        assertEquals(1, fixture.repository.persistCount.get())
        assertEquals(0, fixture.repository.readCount.get())
    }

    @Test
    fun `compatible durable state inspects only and returns already enrolled`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.repository.preflightAction = {
            ProtectedEnrollmentPreflightResult.Compatible(
                storedEnrollment(fixture.attempt),
            )
        }
        fixture.protector.inspectAction = {
            CredentialProtectionInspection.Compatible(
                CredentialKeySecurityLevel.TRUSTED_ENVIRONMENT,
            )
        }

        val result = fixture.coordinator().enroll(fixture.attempt)

        assertIs<AlreadyEnrolled>(result)
        assertEquals(listOf("preflight", "inspect"), fixture.events.snapshot())
        assertEquals(0, fixture.protector.prepareCount.get())
        assertEquals(0, fixture.client.newCallCount.get())
        assertEquals(0, fixture.protector.protectCount.get())
        assertEquals(0, fixture.repository.persistCount.get())
    }

    @Test
    fun `replaced is durable success with a structured anomaly`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.repository.persistAction = {
            PersistProtectedEnrollmentResult.Replaced
        }

        val result = assertIs<Enrolled>(fixture.coordinator().enroll(fixture.attempt))

        assertEquals(EnrollmentSuccessKind.REPLACED, result.kind)
        assertEquals(PersistenceDisposition.REPLACED, result.persistenceDisposition)
        assertEquals(
            EnrollmentAnomaly.UNEXPECTED_DURABLE_REPLACEMENT,
            result.anomaly,
        )
    }

    @Test
    fun `existing equivalent is reported as durable acceptance`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.repository.persistAction = {
            PersistProtectedEnrollmentResult.ExistingEquivalent
        }

        val result = assertIs<Enrolled>(fixture.coordinator().enroll(fixture.attempt))

        assertEquals(EnrollmentSuccessKind.EXISTING_EQUIVALENT, result.kind)
        assertEquals(
            PersistenceDisposition.EXISTING_EQUIVALENT,
            result.persistenceDisposition,
        )
    }
}
