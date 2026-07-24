package com.wifitestorchestrator.agent.data.persistence.room

import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment
import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeCreationResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeValidation
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.DeviceId
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import com.wifitestorchestrator.agent.domain.version.SemanticVersion
import java.time.Instant

private const val ACTIVE_DELIVERY_STATE = "ACTIVE"
private const val PENDING_DELIVERY_STATE = "PENDING"
private const val MIN_NANOSECOND = 0L
private const val MAX_NANOSECOND = 999_999_999L
private const val MAX_KEY_ALIAS_SIZE = 128
private val recognizedKeyAlias =
    Regex("""com\.wifitestorchestrator\.agent\.credential\.aead\.v([1-9][0-9]{0,9})""")

internal sealed interface MappedProtectedEnrollment {
    data object Absent : MappedProtectedEnrollment

    data class Compatible(
        val enrollment: StoredProtectedEnrollment,
        val entity: ProtectedEnrollmentEntity,
    ) : MappedProtectedEnrollment

    data object Corrupt : MappedProtectedEnrollment

    data object Unsupported : MappedProtectedEnrollment
}

internal sealed interface MappedProtectedEnrollmentWrite {
    data class Active(val entity: ProtectedEnrollmentEntity) :
        MappedProtectedEnrollmentWrite

    data object Pending : MappedProtectedEnrollmentWrite

    data object Invalid : MappedProtectedEnrollmentWrite
}

internal fun mapProtectedEnrollment(
    localState: MappedLocalState,
    observedRows: ObservedProtectedEnrollmentRows,
): MappedProtectedEnrollment {
    if (observedRows == ObservedProtectedEnrollmentRows.Corrupt) {
        return MappedProtectedEnrollment.Corrupt
    }
    val rows = (observedRows as ObservedProtectedEnrollmentRows.Valid).rows
    if (rows.size > 1) return MappedProtectedEnrollment.Corrupt
    val entity = rows.singleOrNull() ?: return MappedProtectedEnrollment.Absent
    val configured =
        localState as? MappedLocalState.Configured
            ?: return MappedProtectedEnrollment.Corrupt
    return entity.toMappedProtectedEnrollment(configured)
}

internal fun ProtectedEnrollmentWrite.toMappedWrite(): MappedProtectedEnrollmentWrite {
    if (credentialMetadata.deliveryState == CredentialDeliveryState.PENDING) {
        return MappedProtectedEnrollmentWrite.Pending
    }
    if (
        credentialMetadata.deliveryState != CredentialDeliveryState.ACTIVE ||
        protocolVersion != ProtocolVersion.CURRENT ||
        serverReceivedAt < credentialMetadata.issuedAt ||
        serverReceivedAt >= credentialMetadata.expiresAt ||
        protectedCredential.validate() !is ProtectedCredentialEnvelopeValidation.Valid ||
        protectedCredential.credentialId != credentialMetadata.credentialId ||
        protectedCredential.credentialVersion != credentialMetadata.version
    ) {
        return MappedProtectedEnrollmentWrite.Invalid
    }

    val nonce = protectedCredential.copyNonce()
    val sealedCredential = protectedCredential.copySealedCredential()
    val serverReceived = PersistedInstant.from(serverReceivedAt)
    val issued = PersistedInstant.from(credentialMetadata.issuedAt)
    val expires = PersistedInstant.from(credentialMetadata.expiresAt)
    return MappedProtectedEnrollmentWrite.Active(
        ProtectedEnrollmentEntity(
            singletonId = LOCAL_STATE_SINGLETON_ID,
            installationId = expectedLocalIdentity.installationId.toString(),
            serverBaseUrl = expectedServerConfiguration.baseUrl.toString(),
            agentId = backendIdentity.agentId.toString(),
            deviceId = backendIdentity.deviceId.toString(),
            protocolVersion = protocolVersion.toString(),
            serverReceivedAtEpochSeconds = serverReceived.epochSeconds,
            serverReceivedAtNanoseconds = serverReceived.nanoseconds.toLong(),
            credentialId = credentialMetadata.credentialId.toString(),
            credentialVersion = credentialMetadata.version.value.toLong(),
            issuedAtEpochSeconds = issued.epochSeconds,
            issuedAtNanoseconds = issued.nanoseconds.toLong(),
            expiresAtEpochSeconds = expires.epochSeconds,
            expiresAtNanoseconds = expires.nanoseconds.toLong(),
            credentialDeliveryState = ACTIVE_DELIVERY_STATE,
            cryptoVersion = protectedCredential.cryptoVersion.value.toLong(),
            keyAlias = protectedCredential.keyAlias.value,
            nonce = nonce,
            sealedCredential = sealedCredential,
        ),
    )
}

internal fun ProtectedEnrollmentEntity.hasEquivalentMetadata(
    other: ProtectedEnrollmentEntity,
): Boolean =
    singletonId == other.singletonId &&
        installationId == other.installationId &&
        serverBaseUrl == other.serverBaseUrl &&
        agentId == other.agentId &&
        deviceId == other.deviceId &&
        protocolVersion == other.protocolVersion &&
        serverReceivedAtEpochSeconds == other.serverReceivedAtEpochSeconds &&
        serverReceivedAtNanoseconds == other.serverReceivedAtNanoseconds &&
        credentialId == other.credentialId &&
        credentialVersion == other.credentialVersion &&
        issuedAtEpochSeconds == other.issuedAtEpochSeconds &&
        issuedAtNanoseconds == other.issuedAtNanoseconds &&
        expiresAtEpochSeconds == other.expiresAtEpochSeconds &&
        expiresAtNanoseconds == other.expiresAtNanoseconds &&
        credentialDeliveryState == other.credentialDeliveryState &&
        cryptoVersion == other.cryptoVersion &&
        keyAlias == other.keyAlias

internal fun ProtectedEnrollmentEntity.hasSameBackendIdentity(
    other: ProtectedEnrollmentEntity,
): Boolean = agentId == other.agentId && deviceId == other.deviceId

internal fun ProtectedEnrollmentEntity.isByteIdenticalTo(
    other: ProtectedEnrollmentEntity,
): Boolean =
    hasEquivalentMetadata(other) &&
        nonce.contentEquals(other.nonce) &&
        sealedCredential.contentEquals(other.sealedCredential)

internal fun ProtectedEnrollmentEntity.clearEnvelopeCopies() {
    nonce.fill(0)
    sealedCredential.fill(0)
}

private fun ProtectedEnrollmentEntity.toMappedProtectedEnrollment(
    configured: MappedLocalState.Configured,
): MappedProtectedEnrollment {
    if (singletonId != LOCAL_STATE_SINGLETON_ID) return MappedProtectedEnrollment.Corrupt

    val installationId = InstallationId.parse(installationId).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val serverBaseUrl = ServerBaseUrl.parse(serverBaseUrl).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    if (
        installationId.toString() != this.installationId ||
        serverBaseUrl.toString() != this.serverBaseUrl ||
        configured.installation.localIdentity.installationId != installationId ||
        configured.serverConfiguration.configuration.baseUrl != serverBaseUrl
    ) {
        return MappedProtectedEnrollment.Corrupt
    }

    val agentId = AgentId.parse(agentId).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val deviceId = DeviceId.parse(deviceId).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val credentialId = CredentialId.parse(credentialId).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    if (
        agentId.toString() != this.agentId ||
        deviceId.toString() != this.deviceId ||
        credentialId.toString() != this.credentialId
    ) {
        return MappedProtectedEnrollment.Corrupt
    }

    val parsedSemanticProtocol = SemanticVersion.parse(protocolVersion).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val protocolSupported = parsedSemanticProtocol == ProtocolVersion.CURRENT.value

    val credentialVersion = credentialVersion.toPositiveIntOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val cryptoVersion = cryptoVersion.toPositiveIntOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val aliasVersion =
        if (keyAlias.length in 1..MAX_KEY_ALIAS_SIZE) {
            recognizedKeyAlias.matchEntire(keyAlias)?.groupValues?.get(1)?.toIntOrNull()
        } else {
            null
        }
            ?: return MappedProtectedEnrollment.Corrupt
    if (aliasVersion != cryptoVersion) return MappedProtectedEnrollment.Corrupt

    val deliveryState =
        when (credentialDeliveryState) {
            ACTIVE_DELIVERY_STATE -> CredentialDeliveryState.ACTIVE
            PENDING_DELIVERY_STATE -> CredentialDeliveryState.PENDING
            else -> return MappedProtectedEnrollment.Corrupt
        }

    val serverReceivedAt = persistedInstantOrNull(
        serverReceivedAtEpochSeconds,
        serverReceivedAtNanoseconds,
    ) ?: return MappedProtectedEnrollment.Corrupt
    val issuedAt = persistedInstantOrNull(issuedAtEpochSeconds, issuedAtNanoseconds)
        ?: return MappedProtectedEnrollment.Corrupt
    val expiresAt = persistedInstantOrNull(expiresAtEpochSeconds, expiresAtNanoseconds)
        ?: return MappedProtectedEnrollment.Corrupt
    if (serverReceivedAt < issuedAt || serverReceivedAt >= expiresAt) {
        return MappedProtectedEnrollment.Corrupt
    }

    val typedVersion = CredentialVersion.from(credentialVersion).validValueOrNull()
        ?: return MappedProtectedEnrollment.Corrupt
    val metadata =
        CredentialMetadata.create(
            credentialId = credentialId,
            version = typedVersion,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            deliveryState = deliveryState,
        ).validValueOrNull()
            ?: return MappedProtectedEnrollment.Corrupt

    if (
        nonce.size !in 1..MAX_GENERIC_NONCE_SIZE_BYTES ||
        sealedCredential.size !in 1..MAX_GENERIC_CIPHERTEXT_SIZE_BYTES
    ) {
        return MappedProtectedEnrollment.Corrupt
    }

    val currentCrypto = cryptoVersion == CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE
    val currentAlias =
        aliasVersion == CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE &&
            keyAlias == CredentialProtectionPolicyV1.KEY_ALIAS_VALUE
    if (!currentCrypto || !currentAlias) {
        return MappedProtectedEnrollment.Unsupported
    }

    val envelope =
        when (
            val created =
                ProtectedCredentialEnvelope.create(
                    cryptoVersion = cryptoVersion,
                    keyAlias = keyAlias,
                    credentialId = credentialId,
                    credentialVersion = typedVersion,
                    nonce = nonce,
                    sealedCredential = sealedCredential,
                )
        ) {
            is ProtectedCredentialEnvelopeCreationResult.Valid -> created.envelope
            is ProtectedCredentialEnvelopeCreationResult.Invalid ->
                return MappedProtectedEnrollment.Corrupt
        }

    if (deliveryState == CredentialDeliveryState.PENDING || !protocolSupported) {
        return MappedProtectedEnrollment.Unsupported
    }

    return MappedProtectedEnrollment.Compatible(
        enrollment =
            StoredProtectedEnrollment(
                localIdentity = LocalInstallationIdentity(installationId),
                serverConfiguration = ServerConfiguration(serverBaseUrl),
                backendIdentity = BackendAgentIdentity(agentId = agentId, deviceId = deviceId),
                protocolVersion = ProtocolVersion.CURRENT,
                serverReceivedAt = serverReceivedAt,
                credentialMetadata = metadata,
                protectedCredential = envelope,
            ),
        entity = this,
    )
}

private fun persistedInstantOrNull(
    epochSeconds: Long,
    nanoseconds: Long,
): Instant? {
    if (nanoseconds !in MIN_NANOSECOND..MAX_NANOSECOND) return null
    return PersistedInstant(epochSeconds, nanoseconds.toInt()).toInstantOrNull()
}

private fun Long.toPositiveIntOrNull(): Int? {
    if (this !in 1L..Int.MAX_VALUE.toLong()) return null
    return toInt()
}

private fun <T : Any> com.wifitestorchestrator.agent.domain.error.ValidationResult<T>
    .validValueOrNull(): T? = (this as? Valid<T>)?.value

private fun ProtectedCredentialEnvelope.copyNonce(): ByteArray {
    var copy = ByteArray(0)
    useNonce { nonce -> copy = nonce.copyOf() }
    return copy
}

private fun ProtectedCredentialEnvelope.copySealedCredential(): ByteArray {
    var copy = ByteArray(0)
    useSealedCredential { sealed -> copy = sealed.copyOf() }
    return copy
}
