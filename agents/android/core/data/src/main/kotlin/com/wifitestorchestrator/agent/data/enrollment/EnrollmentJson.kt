package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationRequestDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import com.wifitestorchestrator.agent.contracts.error.ErrorEnvelopeDto
import com.wifitestorchestrator.agent.contracts.version.AgentContractVersions
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private const val MAX_REQUEST_BYTES = 32 * 1024
private const val ANDROID_PLATFORM = "android"

@OptIn(ExperimentalSerializationApi::class)
internal object EnrollmentJson {
    val instance: Json =
        Json {
            ignoreUnknownKeys = false
            isLenient = false
            coerceInputValues = false
            explicitNulls = true
            exceptionsWithDebugInfo = false
            decodeEnumsCaseInsensitive = false
            useAlternativeNames = false
            allowSpecialFloatingPointValues = false
            allowStructuredMapKeys = false
            encodeDefaults = true
        }

    fun encodeRequest(dto: AgentRegistrationRequestDto): ByteArray? =
        try {
            instance
                .encodeToString(AgentRegistrationRequestDto.serializer(), dto)
                .encodeToByteArray()
        } catch (_: SerializationException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }

    fun encodeValidatedRequest(command: EnrollmentCommand): ByteArray? {
        val dto = EnrollmentRequestMapper.map(command)
        val bytes = encodeRequest(dto) ?: return null
        if (bytes.isEmpty() || bytes.size > MAX_REQUEST_BYTES) return null
        val root =
            try {
                instance.parseToJsonElement(bytes.decodeToString()) as? JsonObject
            } catch (_: SerializationException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            } ?: return null
        val expected =
            command.enrollmentToken.useSecret { token ->
                mapOf(
                    "schema_version" to AgentContractVersions.SCHEMA_VERSION,
                    "idempotency_key" to command.idempotencyKey.toString(),
                    "enrollment_token" to token,
                    "installation_id" to command.localIdentity.installationId.toString(),
                    "display_name" to command.displayName,
                    "platform" to ANDROID_PLATFORM,
                    "platform_version" to command.platformVersion,
                    "agent_version" to command.agentVersion.toString(),
                    "protocol_min_version" to AgentContractVersions.AGENT_PROTOCOL_VERSION,
                    "protocol_max_version" to AgentContractVersions.AGENT_PROTOCOL_VERSION,
                    "agent_reported_at" to command.agentReportedAt,
                )
            }
        if (root.keys != expected.keys) return null
        return bytes.takeIf {
            expected.all { (name, value) ->
                val element = root[name]
                element is JsonPrimitive && element.isString && element.content == value
            }
        }
    }

    fun decodeSuccess(raw: String): AgentRegistrationResponseDto? =
        try {
            instance.decodeFromString(AgentRegistrationResponseDto.serializer(), raw)
        } catch (_: SerializationException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }

    fun decodeError(raw: String): ErrorEnvelopeDto? =
        try {
            instance.decodeFromString(ErrorEnvelopeDto.serializer(), raw)
        } catch (_: SerializationException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
}
