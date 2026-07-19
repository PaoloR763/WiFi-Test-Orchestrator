package com.wifitestorchestrator.agent.contracts

import com.wifitestorchestrator.agent.contracts.enrollment.AgentCredentialDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentPlatformDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationRequestDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import com.wifitestorchestrator.agent.contracts.enrollment.CredentialDeliveryStateDto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

class GoldenEnrollmentFixturesTest {
    @Test
    fun validRegistrationRequestFixtureDecodesAndRoundTrips() {
        val source = CanonicalContractFixtures.read("valid/agent-registration-request.json")
        val decoded = strictJson.decodeFromString<AgentRegistrationRequestDto>(source)

        assertEquals("1.0.0", decoded.schemaVersion)
        assertEquals(AgentPlatformDto.WINDOWS, decoded.platform)
        assertTrue(decoded.enrollmentToken.startsWith("wto_enr_1."))
        assertTrue(
            strictJson.parseToJsonElement(source) ==
                strictJson.parseToJsonElement(strictJson.encodeToString(decoded)),
        )
    }

    @Test
    fun validRegistrationResponseFixtureDecodesAndRoundTrips() {
        val source = CanonicalContractFixtures.read("valid/agent-registration-response.json")
        val decoded = strictJson.decodeFromString<AgentRegistrationResponseDto>(source)

        assertEquals("1.0.0", decoded.protocolVersion)
        assertEquals(CredentialDeliveryStateDto.ACTIVE, decoded.credential.state)
        assertTrue(decoded.credential.credential.startsWith("wto_ac_1."))
        assertTrue(
            strictJson.parseToJsonElement(source) ==
                strictJson.parseToJsonElement(strictJson.encodeToString(decoded)),
        )
    }

    @Test
    fun validCredentialFixtureDecodesAndRoundTrips() {
        val source = CanonicalContractFixtures.read("valid/agent-credential.json")
        val decoded = strictJson.decodeFromString<AgentCredentialDto>(source)

        assertEquals(1, decoded.credentialVersion)
        assertEquals(CredentialDeliveryStateDto.ACTIVE, decoded.state)
        assertTrue(
            strictJson.parseToJsonElement(source) ==
                strictJson.parseToJsonElement(strictJson.encodeToString(decoded)),
        )
    }

    @Test
    fun canonicalRequestUnknownFieldIsRejectedStructurally() {
        val source = CanonicalContractFixtures.read("invalid/registration-unknown-field.json")

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentRegistrationRequestDto>(source)
        }
    }

    @Test
    fun canonicalCredentialUnknownFieldIsRejectedStructurally() {
        val source = CanonicalContractFixtures.read("invalid/credential-unknown-field.json")

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentCredentialDto>(source)
        }
    }

    @Test
    fun schemaInvalidIdempotencyRemainsStructurallyDecodable() {
        val source = CanonicalContractFixtures.read("invalid/registration-bad-idempotency.json")

        val decoded = strictJson.decodeFromString<AgentRegistrationRequestDto>(source)

        assertEquals("NOT-A-UUID", decoded.idempotencyKey)
    }

    @Test
    fun allRequiredCanonicalEnrollmentFixturesExist() {
        val fixtures =
            listOf(
                "valid/agent-registration-request.json",
                "valid/agent-registration-response.json",
                "valid/agent-credential.json",
                "invalid/registration-unknown-field.json",
                "invalid/registration-bad-idempotency.json",
                "invalid/credential-unknown-field.json",
            )

        fixtures.forEach { fixture ->
            strictJson.parseToJsonElement(CanonicalContractFixtures.read(fixture))
        }
        assertEquals(6, fixtures.size)
    }
}
