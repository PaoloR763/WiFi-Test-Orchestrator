package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import com.wifitestorchestrator.agent.contracts.error.ErrorEnvelopeDto
import com.wifitestorchestrator.agent.contracts.version.AgentContractVersions
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.DeviceId
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import com.wifitestorchestrator.agent.domain.version.SchemaVersion
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private val integerPattern = Regex("-?(?:0|[1-9][0-9]*)")
private val errorCodePattern = Regex("[a-z][a-z0-9_]+")
private val jsonWhitespace = setOf(' ', '\t', '\r', '\n')

internal object EnrollmentPayloadDecoder {
    fun decodeSuccess(bytes: ByteArray): DecodedPayload<AgentRegistrationResponseDto> =
        decode(bytes, ::validateSuccessShape, EnrollmentJson::decodeSuccess)

    fun decodeError(bytes: ByteArray): DecodedPayload<ErrorEnvelopeDto> =
        decode(bytes, ::validateErrorShape, EnrollmentJson::decodeError)

    private fun <T : Any> decode(
        bytes: ByteArray,
        validate: (JsonElement) -> EnrollmentFailureReason?,
        deserialize: (String) -> T?,
    ): DecodedPayload<T> {
        if (bytes.isEmpty()) return DecodedPayload.Failure(EnrollmentFailureReason.EMPTY_BODY)
        val raw = decodeUtf8(bytes)
            ?: return DecodedPayload.Failure(EnrollmentFailureReason.MALFORMED_JSON)
        if (raw.isNotEmpty() && raw.all(jsonWhitespace::contains)) {
            return DecodedPayload.Failure(EnrollmentFailureReason.EMPTY_BODY)
        }
        when (JsonDuplicateKeyDetector.validate(raw)) {
            RawJsonValidation.MALFORMED ->
                return DecodedPayload.Failure(EnrollmentFailureReason.MALFORMED_JSON)
            RawJsonValidation.DUPLICATE_PROPERTY ->
                return DecodedPayload.Failure(EnrollmentFailureReason.INVALID_RESPONSE_SHAPE)
            RawJsonValidation.VALID -> Unit
        }
        val element =
            try {
                EnrollmentJson.instance.parseToJsonElement(raw)
            } catch (_: SerializationException) {
                return DecodedPayload.Failure(EnrollmentFailureReason.MALFORMED_JSON)
            } catch (_: IllegalArgumentException) {
                return DecodedPayload.Failure(EnrollmentFailureReason.MALFORMED_JSON)
            }
        validate(element)?.let { return DecodedPayload.Failure(it) }
        val decoded =
            deserialize(raw)
                ?: return DecodedPayload.Failure(
                    EnrollmentFailureReason.INVALID_RESPONSE_SHAPE,
                )
        return DecodedPayload.Success(decoded)
    }
}

internal sealed interface DecodedPayload<out T : Any> {
    class Success<out T : Any>(val value: T) : DecodedPayload<T> {
        override fun toString(): String = "DecodedPayload.Success(<redacted>)"
    }

    data class Failure(val reason: EnrollmentFailureReason) : DecodedPayload<Nothing>
}

private fun decodeUtf8(bytes: ByteArray): String? =
    try {
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: Exception) {
        null
    }

private fun validateSuccessShape(rootElement: JsonElement): EnrollmentFailureReason? {
    val validator = ElementValidator()
    val root =
        validator.exactObject(
            rootElement,
            setOf(
                "schema_version",
                "device_id",
                "agent_id",
                "protocol_version",
                "server_received_at",
                "credential",
            ),
        ) ?: return validator.reason
    val schemaVersion = validator.string(root, "schema_version") ?: return validator.reason
    val deviceId = validator.string(root, "device_id") ?: return validator.reason
    val agentId = validator.string(root, "agent_id") ?: return validator.reason
    val protocolVersion = validator.string(root, "protocol_version") ?: return validator.reason
    val serverReceivedAt = validator.string(root, "server_received_at") ?: return validator.reason
    val credential =
        validator.exactObject(
            root["credential"],
            setOf(
                "schema_version",
                "credential_id",
                "credential_version",
                "credential",
                "issued_at",
                "expires_at",
                "state",
            ),
        ) ?: return validator.reason
    val credentialSchema = validator.string(credential, "schema_version") ?: return validator.reason
    val credentialId = validator.string(credential, "credential_id") ?: return validator.reason
    val credentialVersion = validator.integer(credential, "credential_version") ?: return validator.reason
    val credentialSecret = validator.string(credential, "credential") ?: return validator.reason
    val issuedAt = validator.string(credential, "issued_at") ?: return validator.reason
    val expiresAt = validator.string(credential, "expires_at") ?: return validator.reason
    val state = validator.string(credential, "state") ?: return validator.reason

    if (
        SchemaVersion.parse(schemaVersion) !is Valid ||
        schemaVersion != AgentContractVersions.SCHEMA_VERSION ||
        DeviceId.parse(deviceId) !is Valid ||
        AgentId.parse(agentId) !is Valid ||
        ProtocolVersion.parse(protocolVersion) !is Valid ||
        protocolVersion != AgentContractVersions.AGENT_PROTOCOL_VERSION ||
        EnrollmentWireTimestamp.parse(serverReceivedAt) == null ||
        SchemaVersion.parse(credentialSchema) !is Valid ||
        credentialSchema != AgentContractVersions.SCHEMA_VERSION ||
        CredentialId.parse(credentialId) !is Valid ||
        credentialVersion !in 1..Int.MAX_VALUE ||
        AgentCredentialSecret.parse(credentialSecret) !is Valid ||
        state !in setOf("active", "pending")
    ) {
        return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
    }
    val issued = EnrollmentWireTimestamp.parse(issuedAt)
        ?: return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
    val expires = EnrollmentWireTimestamp.parse(expiresAt)
        ?: return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
    if (expires <= issued) return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS

    val parsedCredentialId = (CredentialId.parse(credentialId) as Valid).value
    val parsedSecret = (AgentCredentialSecret.parse(credentialSecret) as Valid).value
    if (parsedCredentialId != parsedSecret.credentialId) {
        return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
    }
    return null
}

private fun validateErrorShape(rootElement: JsonElement): EnrollmentFailureReason? {
    val validator = ElementValidator()
    val root =
        validator.exactObject(rootElement, setOf("schema_version", "error"))
            ?: return validator.reason
    val schemaVersion = validator.string(root, "schema_version") ?: return validator.reason
    val error =
        validator.exactObject(
            root["error"],
            setOf("code", "message", "details", "correlation_id"),
        ) ?: return validator.reason
    val code = validator.string(error, "code") ?: return validator.reason
    val message = validator.string(error, "message") ?: return validator.reason
    val correlationId = validator.string(error, "correlation_id") ?: return validator.reason

    if (
        SchemaVersion.parse(schemaVersion) !is Valid ||
        schemaVersion != AgentContractVersions.SCHEMA_VERSION ||
        code.codePointLength() !in 3..64 ||
        !errorCodePattern.matches(code) ||
        message.codePointLength() !in 1..256 ||
        CorrelationId.parse(correlationId) !is Valid
    ) {
        return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
    }

    val details = error["details"] ?: return EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
    if (details === JsonNull) return null
    if (details !is JsonArray) return EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
    if (details.size > 32) return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
    details.forEach { detailElement ->
        val detail =
            validator.exactObject(detailElement, setOf("location", "type"))
                ?: return validator.reason
        val location = validator.array(detail, "location") ?: return validator.reason
        val type = validator.string(detail, "type") ?: return validator.reason
        if (location.size > 8 || type.codePointLength() > 64) {
            return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
        }
        location.forEach { part ->
            if (part !is JsonPrimitive || !part.isString) {
                return EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
            }
            if (part.content.codePointLength() > 64) {
                return EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
            }
        }
    }
    return null
}

private class ElementValidator {
    var reason: EnrollmentFailureReason = EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
        private set

    fun exactObject(element: JsonElement?, expectedKeys: Set<String>): JsonObject? {
        if (element !is JsonObject || element.keys != expectedKeys) {
            reason = EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
            return null
        }
        return element
    }

    fun string(parent: JsonObject, name: String): String? {
        val element = parent[name]
        if (element !is JsonPrimitive || !element.isString) {
            reason = EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
            return null
        }
        return element.content
    }

    fun integer(parent: JsonObject, name: String): Int? {
        val element = parent[name]
        if (
            element !is JsonPrimitive ||
            element.isString ||
            !integerPattern.matches(element.content)
        ) {
            reason = EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
            return null
        }
        return element.content.toIntOrNull().also {
            if (it == null) reason = EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS
        }
    }

    fun array(parent: JsonObject, name: String): JsonArray? {
        val element = parent[name]
        if (element !is JsonArray) {
            reason = EnrollmentFailureReason.INVALID_RESPONSE_SHAPE
            return null
        }
        return element
    }
}
