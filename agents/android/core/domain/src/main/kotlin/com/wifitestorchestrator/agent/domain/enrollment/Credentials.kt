package com.wifitestorchestrator.agent.domain.enrollment

import com.wifitestorchestrator.agent.domain.error.CredentialMetadataKind
import com.wifitestorchestrator.agent.domain.error.CredentialMetadataViolation
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidCredentialMetadata
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.time.Instant

class CredentialVersion private constructor(val value: Int) {
    override fun equals(other: Any?): Boolean =
        other is CredentialVersion && value == other.value

    override fun hashCode(): Int = value

    override fun toString(): String = value.toString()

    companion object {
        fun from(value: Int): ValidationResult<CredentialVersion> =
            if (value >= 1) {
                Valid(CredentialVersion(value))
            } else {
                Invalid(
                    InvalidCredentialMetadata(
                        CredentialMetadataKind.VERSION,
                        CredentialMetadataViolation.NON_POSITIVE_VERSION,
                    ),
                )
            }
    }
}

enum class CredentialDeliveryState {
    ACTIVE,
    PENDING,
}

class CredentialMetadata private constructor(
    val credentialId: CredentialId,
    val version: CredentialVersion,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val deliveryState: CredentialDeliveryState,
) {
    fun usabilityAt(now: Instant): CredentialUsability =
        when {
            now >= expiresAt -> CredentialUsability.Expired
            deliveryState == CredentialDeliveryState.ACTIVE -> CredentialUsability.Usable
            else -> CredentialUsability.PendingActivation
        }

    override fun equals(other: Any?): Boolean =
        other is CredentialMetadata &&
            credentialId == other.credentialId &&
            version == other.version &&
            issuedAt == other.issuedAt &&
            expiresAt == other.expiresAt &&
            deliveryState == other.deliveryState

    override fun hashCode(): Int {
        var result = credentialId.hashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + issuedAt.hashCode()
        result = 31 * result + expiresAt.hashCode()
        result = 31 * result + deliveryState.hashCode()
        return result
    }

    override fun toString(): String =
        "CredentialMetadata(" +
            "credentialId=$credentialId, " +
            "version=$version, " +
            "issuedAt=$issuedAt, " +
            "expiresAt=$expiresAt, " +
            "deliveryState=$deliveryState)"

    companion object {
        fun create(
            credentialId: CredentialId,
            version: CredentialVersion,
            issuedAt: Instant,
            expiresAt: Instant,
            deliveryState: CredentialDeliveryState,
        ): ValidationResult<CredentialMetadata> {
            if (expiresAt <= issuedAt) {
                return Invalid(
                    InvalidCredentialMetadata(
                        CredentialMetadataKind.VALIDITY_WINDOW,
                        CredentialMetadataViolation.EXPIRY_NOT_AFTER_ISSUE,
                    ),
                )
            }
            return Valid(
                CredentialMetadata(
                    credentialId = credentialId,
                    version = version,
                    issuedAt = issuedAt,
                    expiresAt = expiresAt,
                    deliveryState = deliveryState,
                ),
            )
        }
    }
}

sealed interface CredentialUsability {
    data object Usable : CredentialUsability

    data object PendingActivation : CredentialUsability

    data object Expired : CredentialUsability
}

class DeliveredCredential private constructor(
    val metadata: CredentialMetadata,
    private val secret: AgentCredentialSecret,
) {
    fun <T> useSecret(block: (String) -> T): T = secret.useSecret(block)

    override fun toString(): String =
        "DeliveredCredential(metadata=$metadata, secret=<redacted>)"

    companion object {
        fun create(
            metadata: CredentialMetadata,
            secret: AgentCredentialSecret,
        ): ValidationResult<DeliveredCredential> {
            if (metadata.credentialId != secret.credentialId) {
                return Invalid(
                    InvalidCredentialMetadata(
                        CredentialMetadataKind.DELIVERED_CREDENTIAL,
                        CredentialMetadataViolation.CREDENTIAL_ID_MISMATCH,
                    ),
                )
            }
            return Valid(DeliveredCredential(metadata, secret))
        }
    }
}
