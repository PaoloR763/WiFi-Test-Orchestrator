package com.wifitestorchestrator.agent.domain.enrollment

import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.DeviceId
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class EnrollmentAcceptanceTest {
    private val rawSecret =
        "wto_ac_1.10000000-0000-4000-8000-000000000004.${"A".repeat(43)}"

    @Test
    fun acceptancePreservesLocalAndBackendIdentity() {
        val acceptance = acceptance()

        assertEquals(localIdentity(), acceptance.localIdentity)
        assertEquals(backendIdentity(), acceptance.backendIdentity)
    }

    @Test
    fun acceptancePreservesProtocolAndServerTime() {
        val acceptance = acceptance()

        assertEquals(Instant.parse("2026-07-12T12:00:01Z"), acceptance.serverReceivedAt)
        assertEquals(ProtocolVersion.CURRENT, acceptance.protocolVersion)
    }

    @Test
    fun acceptanceContainsDeliveredCredentialWithoutTransitiveRawGetter() {
        val acceptance = acceptance()

        assertEquals("10000000-0000-4000-8000-000000000004", acceptance.deliveredCredential.metadata.credentialId.toString())
        assertFalse(acceptance.deliveredCredential::class.java.methods.any { it.name == "getSecret" })
    }

    @Test
    fun acceptanceToStringRedactsTheDeliveredCredential() {
        val rendered = acceptance().toString()

        assertFalse(rawSecret in rendered)
        assertFalse("10000000-0000-4000-8000-000000000004" in rendered)
        assertTrue("deliveredCredential=<redacted>" in rendered)
    }

    @Test
    fun noEnrollmentStateOrEnrolledModelExists() {
        val absentClasses =
            listOf(
                "com.wifitestorchestrator.agent.domain.enrollment.EnrollmentState",
                "com.wifitestorchestrator.agent.domain.enrollment.Enrolled",
                "com.wifitestorchestrator.agent.domain.enrollment.PreparedEnrollment",
                "com.wifitestorchestrator.agent.domain.enrollment.RecoveryRequired",
            )

        assertTrue(absentClasses.all { runCatching { Class.forName(it) }.isFailure })
        assertFalse(
            BackendEnrollmentAcceptance::class.java.methods.any {
                it.name.contains("persist", ignoreCase = true) ||
                    it.name.contains("authenticate", ignoreCase = true) ||
                    it.name.contains("retry", ignoreCase = true)
            },
        )
    }

    private fun acceptance(): BackendEnrollmentAcceptance =
        BackendEnrollmentAcceptance(
            localIdentity = localIdentity(),
            backendIdentity = backendIdentity(),
            deliveredCredential = deliveredCredential(),
            serverReceivedAt = Instant.parse("2026-07-12T12:00:01Z"),
            protocolVersion = valid(ProtocolVersion.parse("1.0.0")),
        )

    private fun localIdentity(): LocalInstallationIdentity =
        LocalInstallationIdentity(
            valid(InstallationId.parse("10000000-0000-4000-8000-000000000001")),
        )

    private fun backendIdentity(): BackendAgentIdentity =
        BackendAgentIdentity(
            valid(AgentId.parse("10000000-0000-4000-8000-000000000002")),
            valid(DeviceId.parse("10000000-0000-4000-8000-000000000003")),
        )

    private fun deliveredCredential(): DeliveredCredential {
        val id = valid(CredentialId.parse("10000000-0000-4000-8000-000000000004"))
        val metadata =
            valid(
                CredentialMetadata.create(
                    credentialId = id,
                    version = valid(CredentialVersion.from(1)),
                    issuedAt = Instant.parse("2026-07-12T12:00:01Z"),
                    expiresAt = Instant.parse("2026-10-10T12:00:01Z"),
                    deliveryState = CredentialDeliveryState.ACTIVE,
                ),
            )
        val secret = valid(AgentCredentialSecret.parse(rawSecret))
        return valid(DeliveredCredential.create(metadata, secret))
    }

    private fun <T : Any> valid(result: ValidationResult<T>): T = assertIs<Valid<T>>(result).value
}
