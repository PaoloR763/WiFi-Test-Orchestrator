package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.contracts.capability.BackgroundExecutionDto
import com.wifitestorchestrator.agent.contracts.capability.BackgroundExecutionStatusDto
import com.wifitestorchestrator.agent.contracts.capability.CapabilityDto
import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestContract
import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestDto
import com.wifitestorchestrator.agent.contracts.capability.CapabilityReasonCodeDto
import com.wifitestorchestrator.agent.contracts.capability.CapabilityReasonDto
import com.wifitestorchestrator.agent.contracts.capability.ImplementationStatusDto
import com.wifitestorchestrator.agent.contracts.capability.ImplementationStatusValueDto
import com.wifitestorchestrator.agent.contracts.capability.LimitationsDto
import com.wifitestorchestrator.agent.contracts.capability.LimitationsStatusDto
import com.wifitestorchestrator.agent.contracts.capability.PermissionRequirementDto
import com.wifitestorchestrator.agent.contracts.capability.PermissionRequirementStatusDto
import com.wifitestorchestrator.agent.contracts.capability.ProviderDto
import com.wifitestorchestrator.agent.contracts.capability.ProviderImplementationDto
import com.wifitestorchestrator.agent.contracts.capability.ProviderStatusDto
import com.wifitestorchestrator.agent.contracts.capability.TechnicalSupportDto
import com.wifitestorchestrator.agent.contracts.capability.TechnicalSupportStatusDto
import com.wifitestorchestrator.agent.contracts.capability.UserInteractionDto
import com.wifitestorchestrator.agent.contracts.capability.UserInteractionStatusDto
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentWireTimestamp
import com.wifitestorchestrator.agent.domain.capability.AndroidCapability
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityCatalog
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFacts
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilitySnapshot
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilitySnapshotResult
import com.wifitestorchestrator.agent.domain.capability.BackgroundExecutionStatus
import com.wifitestorchestrator.agent.domain.capability.CapabilityReason
import com.wifitestorchestrator.agent.domain.capability.CapabilityReasonCode
import com.wifitestorchestrator.agent.domain.capability.ImplementationStatus
import com.wifitestorchestrator.agent.domain.capability.LimitationsStatus
import com.wifitestorchestrator.agent.domain.capability.PermissionRequirementStatus
import com.wifitestorchestrator.agent.domain.capability.ProviderStatus
import com.wifitestorchestrator.agent.domain.capability.TechnicalSupportStatus
import com.wifitestorchestrator.agent.domain.capability.UserInteractionStatus
import com.wifitestorchestrator.agent.domain.capability.WifiHardwarePresence
import com.wifitestorchestrator.agent.domain.identity.AgentId
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CapabilityManifestCodec {
    fun semanticFingerprint(input: CapabilityManifestSemanticInput): Sha256Value? {
        val dtoCapabilities = input.snapshot.capabilities.map(AndroidCapability::toDto)
        if (!validateCapabilityMatrix(dtoCapabilities, input.snapshot.platformVersion)) return null
        val semantic =
            JsonObject(
                mapOf(
                    "schema_version" to JsonPrimitive(CapabilityManifestContract.SCHEMA_VERSION),
                    "agent_id" to JsonPrimitive(input.agentId.toString()),
                    "agent_version" to JsonPrimitive(input.agentVersion.toString()),
                    "platform" to JsonPrimitive(CapabilityManifestContract.PLATFORM),
                    "platform_version" to JsonPrimitive(input.snapshot.platformVersion),
                    "protocol_version" to JsonPrimitive(input.protocolVersion.toString()),
                    "capability_catalog_version" to
                        JsonPrimitive(CapabilityManifestContract.CATALOG_VERSION),
                    "capabilities" to
                        CapabilityJson.strict.encodeToJsonElement(
                            kotlinx.serialization.builtins.ListSerializer(CapabilityDto.serializer()),
                            dtoCapabilities,
                        ),
                ),
            )
        return CanonicalJson.encode(semantic)?.sha256()
    }

    fun freeze(
        input: CapabilityManifestSemanticInput,
        manifestId: String,
        manifestSequence: Long,
        generatedAt: Instant,
    ): CapabilityManifestFreezeResult {
        if (manifestSequence < 0 || !isCanonicalV4Uuid(manifestId)) {
            return CapabilityManifestFreezeResult.Invalid
        }
        val generatedAtWire =
            EnrollmentWireTimestamp.render(generatedAt)
                ?: return CapabilityManifestFreezeResult.Invalid
        val dto =
            CapabilityManifestDto(
                schemaVersion = CapabilityManifestContract.SCHEMA_VERSION,
                manifestId = manifestId,
                manifestSequence = manifestSequence,
                agentId = input.agentId.toString(),
                agentVersion = input.agentVersion.toString(),
                platform = CapabilityManifestContract.PLATFORM,
                platformVersion = input.snapshot.platformVersion,
                protocolVersion = input.protocolVersion.toString(),
                capabilityCatalogVersion = CapabilityManifestContract.CATALOG_VERSION,
                generatedAt = generatedAtWire,
                capabilities = input.snapshot.capabilities.map(AndroidCapability::toDto),
            )
        val element =
            CapabilityJson.strict.encodeToJsonElement(CapabilityManifestDto.serializer(), dto)
        val payload =
            CanonicalJson.encode(element)
                ?.takeIf { it.isNotEmpty() && it.size <= CapabilityManifestContract.MAX_REQUEST_BYTES }
                ?: return CapabilityManifestFreezeResult.Invalid
        val fingerprint =
            semanticFingerprint(input) ?: return CapabilityManifestFreezeResult.Invalid
        return CapabilityManifestFreezeResult.Frozen(
            FrozenCapabilityManifest(
                manifestId = manifestId,
                manifestSequence = manifestSequence,
                generatedAt = generatedAt,
                semanticFingerprint = fingerprint,
                canonicalDigest = requireNotNull(payload.sha256()),
                canonicalPayload = payload,
            ),
        )
    }

    internal fun validateCurrentReservation(
        canonicalPayload: ByteArray,
        canonicalDigest: Sha256Value,
        semanticFingerprint: Sha256Value,
        expectedAgentId: AgentId,
        expectedManifestId: String,
        expectedSequence: Long,
    ): FrozenCapabilityManifest? {
        val validated =
            validatePersisted(
                canonicalPayload = canonicalPayload,
                canonicalDigest = canonicalDigest,
                semanticFingerprint = semanticFingerprint,
                expectedAgentId = expectedAgentId,
                expectedManifestId = expectedManifestId,
                expectedSequence = expectedSequence,
            ) ?: return null
        val document = CanonicalJson.parseCanonical(canonicalPayload) as? JsonObject ?: return null
        val platformVersion = document.stringProperty("platform_version") ?: return null
        val capabilities = document["capabilities"] ?: return null
        return validated.takeIf {
            validateCapabilityMatrix(
                actual = capabilities,
                platformVersion = platformVersion,
            )
        }
    }

    internal fun validatePersisted(
        canonicalPayload: ByteArray,
        canonicalDigest: Sha256Value,
        semanticFingerprint: Sha256Value,
        expectedAgentId: AgentId,
        expectedManifestId: String,
        expectedSequence: Long,
    ): FrozenCapabilityManifest? {
        if (
            canonicalPayload.isEmpty() ||
            canonicalPayload.size > CapabilityManifestContract.MAX_REQUEST_BYTES ||
            expectedSequence < 0 ||
            !isCanonicalV4Uuid(expectedManifestId)
        ) {
            return null
        }
        val element = CanonicalJson.parseCanonical(canonicalPayload) as? JsonObject ?: return null
        if (!requireNotNull(canonicalPayload.sha256()).contentEquals(canonicalDigest)) return null
        val generatedAt =
            validatePersistedProfile(
                element = element,
                expectedAgentId = expectedAgentId,
                expectedManifestId = expectedManifestId,
                expectedSequence = expectedSequence,
            ) ?: return null

        val semanticElement =
            JsonObject(
                element.filterKeys {
                    it != "manifest_id" &&
                        it != "manifest_sequence" &&
                        it != "generated_at"
                },
            )
        val recomputedFingerprint =
            CanonicalJson.encode(semanticElement)?.sha256() ?: return null
        if (!recomputedFingerprint.contentEquals(semanticFingerprint)) return null
        return FrozenCapabilityManifest(
            manifestId = expectedManifestId,
            manifestSequence = expectedSequence,
            generatedAt = generatedAt,
            semanticFingerprint = semanticFingerprint,
            canonicalDigest = canonicalDigest,
            canonicalPayload = canonicalPayload,
        )
    }

    private fun validatePersistedProfile(
        element: JsonObject,
        expectedAgentId: AgentId,
        expectedManifestId: String,
        expectedSequence: Long,
    ): Instant? {
        val profile =
            PersistedManifestProfile(
                schemaVersion = element.stringProperty("schema_version") ?: return null,
                catalogVersion =
                    element.stringProperty("capability_catalog_version") ?: return null,
            )
        return when (profile) {
            CAPABILITY_MANIFEST_V1_PROFILE ->
                CapabilityManifestV1Validator.validate(
                    document = element,
                    expectedAgentId = expectedAgentId,
                    expectedManifestId = expectedManifestId,
                    expectedSequence = expectedSequence,
                )
            else -> null
        }
    }

    private fun validateCapabilityMatrix(
        actual: List<CapabilityDto>,
        platformVersion: String,
    ): Boolean =
        validateCapabilityMatrix(
            actual =
                CapabilityJson.strict.encodeToJsonElement(
                    ListSerializer(CapabilityDto.serializer()),
                    actual,
                ),
            platformVersion = platformVersion,
        )

    private fun validateCapabilityMatrix(
        actual: JsonElement,
        platformVersion: String,
    ): Boolean {
        val expected =
            WifiHardwarePresence.entries.mapNotNull { presence ->
                val built =
                    AndroidCapabilityCatalog.build(
                        AndroidCapabilityFacts(platformVersion, presence),
                    )
                (built as? AndroidCapabilitySnapshotResult.Built)
                    ?.snapshot
                    ?.capabilities
                    ?.map(AndroidCapability::toDto)
            }
        return expected.any { capabilities ->
            CapabilityJson.strict.encodeToJsonElement(
                ListSerializer(CapabilityDto.serializer()),
                capabilities,
            ) == actual
        }
    }
}

private fun AndroidCapability.toDto(): CapabilityDto =
    CapabilityDto(
        id = id,
        version = version,
        technicalSupport =
            TechnicalSupportDto(
                status = technicalSupport.status.toDto(),
                reason = technicalSupport.reason.toDto(),
            ),
        implementationStatus =
            ImplementationStatusDto(
                status = implementationStatus.status.toDto(),
                reason = implementationStatus.reason.toDto(),
            ),
        permissionRequirement =
            PermissionRequirementDto(
                status = permissionRequirement.status.toDto(),
                permissions = permissionRequirement.permissions,
                reason = permissionRequirement.reason.toDto(),
            ),
        userInteraction =
            UserInteractionDto(
                status = userInteraction.status.toDto(),
                reason = userInteraction.reason.toDto(),
            ),
        backgroundExecution =
            BackgroundExecutionDto(
                status = backgroundExecution.status.toDto(),
                reason = backgroundExecution.reason.toDto(),
            ),
        provider =
            ProviderDto(
                status = provider.status.toDto(),
                implementations =
                    provider.implementations.map {
                        ProviderImplementationDto(
                            providerId = it.providerId,
                            providerVersion = it.providerVersion,
                            method = it.method,
                        )
                    },
                reason = provider.reason.toDto(),
            ),
        limitations =
            LimitationsDto(
                status = limitations.status.toDto(),
                maxDurationSeconds = limitations.maxDurationSeconds,
                maxThroughputBps = limitations.maxThroughputBps,
                maxPayloadBytes = limitations.maxPayloadBytes,
                maxConcurrency = limitations.maxConcurrency,
                maxStreams = limitations.maxStreams,
                reason = limitations.reason.toDto(),
            ),
    )

private fun TechnicalSupportStatus.toDto(): TechnicalSupportStatusDto =
    TechnicalSupportStatusDto.valueOf(name)

private fun ImplementationStatus.toDto(): ImplementationStatusValueDto =
    ImplementationStatusValueDto.valueOf(name)

private fun PermissionRequirementStatus.toDto(): PermissionRequirementStatusDto =
    PermissionRequirementStatusDto.valueOf(name)

private fun UserInteractionStatus.toDto(): UserInteractionStatusDto =
    UserInteractionStatusDto.valueOf(name)

private fun BackgroundExecutionStatus.toDto(): BackgroundExecutionStatusDto =
    BackgroundExecutionStatusDto.valueOf(name)

private fun ProviderStatus.toDto(): ProviderStatusDto = ProviderStatusDto.valueOf(name)

private fun LimitationsStatus.toDto(): LimitationsStatusDto =
    LimitationsStatusDto.valueOf(name)

private fun CapabilityReason?.toDto(): CapabilityReasonDto? =
    this?.let {
        CapabilityReasonDto(
            code = CapabilityReasonCodeDto.valueOf(it.code.name),
            detail = null,
        )
    }

internal fun ByteArray.sha256(): Sha256Value? =
    Sha256Value.from(MessageDigest.getInstance("SHA-256").digest(this))

internal fun isCanonicalV4Uuid(raw: String): Boolean {
    val parsed =
        try {
            UUID.fromString(raw)
        } catch (_: IllegalArgumentException) {
            return false
        }
    return parsed.toString() == raw &&
        parsed.version() == 4 &&
        parsed.variant() == 2 &&
        parsed != UUID(0L, 0L)
}

private data class PersistedManifestProfile(
    val schemaVersion: String,
    val catalogVersion: String,
)

private val CAPABILITY_MANIFEST_V1_PROFILE =
    PersistedManifestProfile(
        schemaVersion = CapabilityManifestV1Validator.SCHEMA_VERSION,
        catalogVersion = CapabilityManifestV1Validator.CATALOG_VERSION,
    )

private fun JsonObject.stringProperty(key: String): String? {
    val primitive = this[key] as? JsonPrimitive ?: return null
    return primitive.content.takeIf { primitive.isString }
}
