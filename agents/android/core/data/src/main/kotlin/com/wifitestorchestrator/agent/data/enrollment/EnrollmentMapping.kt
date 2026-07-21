package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentPlatformDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationRequestDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import com.wifitestorchestrator.agent.contracts.enrollment.CredentialDeliveryStateDto
import com.wifitestorchestrator.agent.contracts.version.AgentContractVersions
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.enrollment.BackendEnrollmentAcceptance
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.DeviceId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import com.wifitestorchestrator.agent.domain.version.SchemaVersion

internal object EnrollmentRequestMapper {
    fun map(command: EnrollmentCommand): AgentRegistrationRequestDto =
        command.enrollmentToken.useSecret { rawToken ->
            AgentRegistrationRequestDto(
                schemaVersion = AgentContractVersions.SCHEMA_VERSION,
                idempotencyKey = command.idempotencyKey.toString(),
                enrollmentToken = rawToken,
                installationId = command.localIdentity.installationId.toString(),
                displayName = command.displayName,
                platform = AgentPlatformDto.ANDROID,
                platformVersion = command.platformVersion,
                agentVersion = command.agentVersion.toString(),
                protocolMinVersion = AgentContractVersions.AGENT_PROTOCOL_VERSION,
                protocolMaxVersion = AgentContractVersions.AGENT_PROTOCOL_VERSION,
                agentReportedAt = command.agentReportedAt,
            )
        }
}

internal object EnrollmentResponseMapper {
    fun map(
        dto: AgentRegistrationResponseDto,
        localIdentity: LocalInstallationIdentity,
    ): EnrollmentDomainMappingResult {
        if (SchemaVersion.parse(dto.schemaVersion) is Invalid) {
            return EnrollmentDomainMappingResult.Invalid
        }
        val deviceId = DeviceId.parse(dto.deviceId).valueOrNull() ?: return invalid()
        val agentId = AgentId.parse(dto.agentId).valueOrNull() ?: return invalid()
        val protocolVersion =
            ProtocolVersion.parse(dto.protocolVersion).valueOrNull() ?: return invalid()
        val serverReceivedAt = EnrollmentWireTimestamp.parse(dto.serverReceivedAt) ?: return invalid()

        val credential = dto.credential
        if (SchemaVersion.parse(credential.schemaVersion) is Invalid) return invalid()
        val credentialId =
            CredentialId.parse(credential.credentialId).valueOrNull() ?: return invalid()
        val credentialVersion =
            CredentialVersion.from(credential.credentialVersion).valueOrNull() ?: return invalid()
        val credentialSecret =
            AgentCredentialSecret.parse(credential.credential).valueOrNull() ?: return invalid()
        val issuedAt = EnrollmentWireTimestamp.parse(credential.issuedAt) ?: return invalid()
        val expiresAt = EnrollmentWireTimestamp.parse(credential.expiresAt) ?: return invalid()
        val deliveryState =
            when (credential.state) {
                CredentialDeliveryStateDto.ACTIVE -> CredentialDeliveryState.ACTIVE
                CredentialDeliveryStateDto.PENDING -> CredentialDeliveryState.PENDING
            }
        val metadata =
            CredentialMetadata
                .create(
                    credentialId = credentialId,
                    version = credentialVersion,
                    issuedAt = issuedAt,
                    expiresAt = expiresAt,
                    deliveryState = deliveryState,
                ).valueOrNull()
                ?: return invalid()
        val deliveredCredential =
            DeliveredCredential.create(metadata, credentialSecret).valueOrNull() ?: return invalid()

        return EnrollmentDomainMappingResult.Valid(
            BackendEnrollmentAcceptance(
                localIdentity = localIdentity,
                backendIdentity = BackendAgentIdentity(agentId = agentId, deviceId = deviceId),
                deliveredCredential = deliveredCredential,
                serverReceivedAt = serverReceivedAt,
                protocolVersion = protocolVersion,
            ),
        )
    }

    private fun invalid(): EnrollmentDomainMappingResult = EnrollmentDomainMappingResult.Invalid
}

internal sealed interface EnrollmentDomainMappingResult {
    class Valid(val value: BackendEnrollmentAcceptance) : EnrollmentDomainMappingResult {
        override fun toString(): String = "EnrollmentDomainMappingResult.Valid(<redacted>)"
    }

    data object Invalid : EnrollmentDomainMappingResult
}

private fun <T : Any> ValidationResult<T>.valueOrNull(): T? =
    when (this) {
        is Valid -> value
        is Invalid -> null
    }
