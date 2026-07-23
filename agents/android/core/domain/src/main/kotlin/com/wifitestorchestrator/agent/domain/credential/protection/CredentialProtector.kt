package com.wifitestorchestrator.agent.domain.credential.protection

import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential

/**
 * Blocking credential-protection port. Every operation must run off the Android main thread.
 * Implementations must not retain a credential passed to [protect].
 */
interface CredentialProtector {
    fun inspect(): CredentialProtectionInspection

    fun prepare(): CredentialProtectionPreparation

    fun protect(credential: DeliveredCredential): ProtectCredentialResult

    /**
     * Makes a validated plaintext credential available only while [block] runs. Capturing the
     * credential, its raw String, or any derived bytes outside [block] violates this contract.
     */
    fun useDecryptedCredential(
        envelope: ProtectedCredentialEnvelope,
        block: (AgentCredentialSecret) -> Unit,
    ): UseDecryptedCredentialResult
}

enum class CredentialProtectionError {
    KEY_MISSING,
    KEY_INCOMPATIBLE,
    KEY_INVALIDATED,
    KEY_PERMANENTLY_INVALIDATED,
    KEYSTORE_TEMPORARILY_UNAVAILABLE,
    DEVICE_LOCKED,
    PROVIDER_FAILURE,
    MALFORMED_ENVELOPE,
    INVALID_NONCE,
    UNSUPPORTED_CRYPTO_VERSION,
    UNKNOWN_KEY_ALIAS,
    AUTHENTICATION_FAILED,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    ;

    override fun toString(): String = "CredentialProtectionError(<redacted>)"
}

sealed interface CredentialProtectionInspection {
    object Missing : CredentialProtectionInspection {
        override fun toString(): String = "CredentialProtectionInspection.Missing(<redacted>)"
    }

    class Compatible(val securityLevel: CredentialKeySecurityLevel) :
        CredentialProtectionInspection {
        override fun toString(): String =
            "CredentialProtectionInspection.Compatible(<redacted>)"
    }

    object Incompatible : CredentialProtectionInspection {
        override fun toString(): String =
            "CredentialProtectionInspection.Incompatible(<redacted>)"
    }

    class Unavailable(val error: CredentialProtectionError) : CredentialProtectionInspection {
        override fun toString(): String =
            "CredentialProtectionInspection.Unavailable(<redacted>)"
    }
}

sealed interface CredentialProtectionPreparation {
    object Created : CredentialProtectionPreparation {
        override fun toString(): String = "CredentialProtectionPreparation.Created(<redacted>)"
    }

    object AlreadyCompatible : CredentialProtectionPreparation {
        override fun toString(): String =
            "CredentialProtectionPreparation.AlreadyCompatible(<redacted>)"
    }

    class Failure(val error: CredentialProtectionError) : CredentialProtectionPreparation {
        override fun toString(): String =
            "CredentialProtectionPreparation.Failure(<redacted>)"
    }
}

sealed interface ProtectCredentialResult {
    class Protected(val envelope: ProtectedCredentialEnvelope) : ProtectCredentialResult {
        override fun toString(): String = "ProtectCredentialResult.Protected(<redacted>)"
    }

    class Failure(val error: CredentialProtectionError) : ProtectCredentialResult {
        override fun toString(): String = "ProtectCredentialResult.Failure(<redacted>)"
    }
}

sealed interface UseDecryptedCredentialResult {
    object Used : UseDecryptedCredentialResult {
        override fun toString(): String = "UseDecryptedCredentialResult.Used(<redacted>)"
    }

    class Failure(val error: CredentialProtectionError) : UseDecryptedCredentialResult {
        override fun toString(): String =
            "UseDecryptedCredentialResult.Failure(<redacted>)"
    }
}
