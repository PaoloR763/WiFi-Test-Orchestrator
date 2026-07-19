package com.wifitestorchestrator.agent.contracts

import com.wifitestorchestrator.agent.contracts.enrollment.AgentCredentialDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentEnrollmentContract
import com.wifitestorchestrator.agent.contracts.enrollment.AgentPlatformDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationRequestDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import com.wifitestorchestrator.agent.contracts.enrollment.CredentialDeliveryStateDto
import com.wifitestorchestrator.agent.contracts.version.AgentContractVersions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

class EnrollmentDtosTest {
    @Test
    fun requestEncodingUsesExactlyThePublicSnakeCaseFields() {
        val decoded = validRequest()
        val encoded = strictJson.parseToJsonElement(strictJson.encodeToString(decoded)).jsonObject

        assertEquals(
            setOf(
                "schema_version",
                "idempotency_key",
                "enrollment_token",
                "installation_id",
                "display_name",
                "platform",
                "platform_version",
                "agent_version",
                "protocol_min_version",
                "protocol_max_version",
                "agent_reported_at",
            ),
            encoded.keys,
        )
    }

    @Test
    fun missingRequiredRequestFieldIsRejected() {
        val payload = requestObject().without("schema_version")

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentRegistrationRequestDto>(payload.toString())
        }
    }

    @Test
    fun nullForNonNullableRequestFieldIsRejected() {
        val payload = requestObject().replacing("display_name", JsonNull)

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentRegistrationRequestDto>(payload.toString())
        }
    }

    @Test
    fun unknownPlatformIsRejectedWithoutFallback() {
        val payload = requestObject().replacing("platform", JsonPrimitive("other"))

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentRegistrationRequestDto>(payload.toString())
        }
    }

    @Test
    fun allPublicPlatformSerialNamesAreExact() {
        val expected =
            mapOf(
                AgentPlatformDto.SIMULATED to "\"simulated\"",
                AgentPlatformDto.WINDOWS to "\"windows\"",
                AgentPlatformDto.LINUX to "\"linux\"",
                AgentPlatformDto.ANDROID to "\"android\"",
                AgentPlatformDto.IOS to "\"ios\"",
            )

        expected.forEach { (platform, encoded) ->
            assertEquals(encoded, strictJson.encodeToString(platform))
        }
    }

    @Test
    fun responseRequiresNestedCredential() {
        val payload = responseObject().without("credential")

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentRegistrationResponseDto>(payload.toString())
        }
    }

    @Test
    fun activeCredentialDeliveryStateIsAccepted() {
        assertEquals(CredentialDeliveryStateDto.ACTIVE, validResponse().credential.state)
    }

    @Test
    fun pendingCredentialDeliveryStateIsAccepted() {
        val credential = credentialObject().replacing("state", JsonPrimitive("pending"))
        val payload = responseObject().replacing("credential", credential)

        val decoded = strictJson.decodeFromString<AgentRegistrationResponseDto>(payload.toString())

        assertEquals(CredentialDeliveryStateDto.PENDING, decoded.credential.state)
    }

    @Test
    fun unknownCredentialDeliveryStateIsRejected() {
        val payload = credentialObject().replacing("state", JsonPrimitive("unknown"))

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentCredentialDto>(payload.toString())
        }
    }

    @Test
    fun credentialVersionRemainsAnInt() {
        assertEquals(1, validCredential().credentialVersion)
    }

    @Test
    fun booleanCredentialVersionIsNotCoercedToInt() {
        val payload = credentialObject().replacing("credential_version", JsonPrimitive(true))

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentCredentialDto>(payload.toString())
        }
    }

    @Test
    fun missingRequiredCredentialFieldIsRejected() {
        val payload = credentialObject().without("credential")

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<AgentCredentialDto>(payload.toString())
        }
    }

    @Test
    fun contractMetadataMatchesThePublishedApi() {
        assertEquals("/api/v1/agent-enrollments", AgentEnrollmentContract.PATH)
        assertEquals("Idempotency-Key", AgentEnrollmentContract.IDEMPOTENCY_HEADER)
        assertEquals("X-Correlation-ID", AgentEnrollmentContract.CORRELATION_HEADER)
        assertEquals("1.0.0", AgentContractVersions.SCHEMA_VERSION)
        assertEquals("1.0.0", AgentContractVersions.AGENT_PROTOCOL_VERSION)
    }

    private fun validRequest(): AgentRegistrationRequestDto =
        strictJson.decodeFromString(
            CanonicalContractFixtures.read("valid/agent-registration-request.json"),
        )

    private fun validResponse(): AgentRegistrationResponseDto =
        strictJson.decodeFromString(
            CanonicalContractFixtures.read("valid/agent-registration-response.json"),
        )

    private fun validCredential(): AgentCredentialDto =
        strictJson.decodeFromString(CanonicalContractFixtures.read("valid/agent-credential.json"))

    private fun requestObject(): JsonObject =
        strictJson
            .parseToJsonElement(CanonicalContractFixtures.read("valid/agent-registration-request.json"))
            .jsonObject

    private fun responseObject(): JsonObject =
        strictJson
            .parseToJsonElement(CanonicalContractFixtures.read("valid/agent-registration-response.json"))
            .jsonObject

    private fun credentialObject(): JsonObject =
        strictJson
            .parseToJsonElement(CanonicalContractFixtures.read("valid/agent-credential.json"))
            .jsonObject

    private fun JsonObject.without(name: String): JsonObject = JsonObject(this - name)

    private fun JsonObject.replacing(
        name: String,
        value: kotlinx.serialization.json.JsonElement,
    ): JsonObject = JsonObject(this + (name to value))
}
