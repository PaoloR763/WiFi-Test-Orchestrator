package com.wifitestorchestrator.agent.domain.credential.protection

import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.identity.CredentialId

class ProtectedCredentialEnvelope private constructor(
    val cryptoVersion: CredentialCryptoVersion,
    val keyAlias: CredentialKeyAlias,
    val credentialId: CredentialId,
    val credentialVersion: CredentialVersion,
    nonce: ByteArray,
    sealedCredential: ByteArray,
) {
    private val nonce: ByteArray = nonce.copyOf()
    private val sealedCredential: ByteArray = sealedCredential.copyOf()

    /**
     * Supplies a defensive nonce copy only for the duration of [block]. Capturing it outside the
     * callback violates this API contract. The temporary copy is cleared before returning.
     */
    fun useNonce(block: (ByteArray) -> Unit) {
        useDefensiveCopy(nonce, block)
    }

    /**
     * Supplies a defensive sealed-credential copy only for the duration of [block]. Capturing it
     * outside the callback violates this API contract. The temporary copy is cleared before
     * returning.
     */
    fun useSealedCredential(block: (ByteArray) -> Unit) {
        useDefensiveCopy(sealedCredential, block)
    }

    fun validate(): ProtectedCredentialEnvelopeValidation =
        when {
            cryptoVersion != CredentialProtectionPolicyV1.cryptoVersion ->
                ProtectedCredentialEnvelopeValidation.Invalid(
                    CredentialProtectionError.UNSUPPORTED_CRYPTO_VERSION,
                )
            keyAlias != CredentialProtectionPolicyV1.keyAlias ->
                ProtectedCredentialEnvelopeValidation.Invalid(
                    CredentialProtectionError.UNKNOWN_KEY_ALIAS,
                )
            nonce.size != CredentialProtectionPolicyV1.NONCE_SIZE_BYTES ->
                ProtectedCredentialEnvelopeValidation.Invalid(
                    CredentialProtectionError.INVALID_NONCE,
                )
            sealedCredential.size != CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES ->
                ProtectedCredentialEnvelopeValidation.Invalid(
                    CredentialProtectionError.MALFORMED_ENVELOPE,
                )
            else -> ProtectedCredentialEnvelopeValidation.Valid
        }

    override fun toString(): String = "ProtectedCredentialEnvelope(<redacted>)"

    companion object {
        fun create(
            cryptoVersion: Int,
            keyAlias: String,
            credentialId: CredentialId,
            credentialVersion: CredentialVersion,
            nonce: ByteArray,
            sealedCredential: ByteArray,
        ): ProtectedCredentialEnvelopeCreationResult {
            val parsedVersion =
                CredentialCryptoVersion.fromValue(cryptoVersion)
                    ?: return ProtectedCredentialEnvelopeCreationResult.Invalid(
                        CredentialProtectionError.UNSUPPORTED_CRYPTO_VERSION,
                    )
            val parsedAlias =
                CredentialKeyAlias.fromValue(keyAlias)
                    ?: return ProtectedCredentialEnvelopeCreationResult.Invalid(
                        CredentialProtectionError.UNKNOWN_KEY_ALIAS,
                    )
            if (nonce.size != CredentialProtectionPolicyV1.NONCE_SIZE_BYTES) {
                return ProtectedCredentialEnvelopeCreationResult.Invalid(
                    CredentialProtectionError.INVALID_NONCE,
                )
            }
            if (sealedCredential.size != CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) {
                return ProtectedCredentialEnvelopeCreationResult.Invalid(
                    CredentialProtectionError.MALFORMED_ENVELOPE,
                )
            }
            return ProtectedCredentialEnvelopeCreationResult.Valid(
                ProtectedCredentialEnvelope(
                    cryptoVersion = parsedVersion,
                    keyAlias = parsedAlias,
                    credentialId = credentialId,
                    credentialVersion = credentialVersion,
                    nonce = nonce,
                    sealedCredential = sealedCredential,
                ),
            )
        }
    }
}

sealed interface ProtectedCredentialEnvelopeCreationResult {
    class Valid(val envelope: ProtectedCredentialEnvelope) :
        ProtectedCredentialEnvelopeCreationResult {
        override fun toString(): String =
            "ProtectedCredentialEnvelopeCreationResult.Valid(<redacted>)"
    }

    class Invalid(val error: CredentialProtectionError) :
        ProtectedCredentialEnvelopeCreationResult {
        override fun toString(): String =
            "ProtectedCredentialEnvelopeCreationResult.Invalid(<redacted>)"
    }
}

sealed interface ProtectedCredentialEnvelopeValidation {
    object Valid : ProtectedCredentialEnvelopeValidation {
        override fun toString(): String = "ProtectedCredentialEnvelopeValidation.Valid(<redacted>)"
    }

    class Invalid(val error: CredentialProtectionError) : ProtectedCredentialEnvelopeValidation {
        override fun toString(): String =
            "ProtectedCredentialEnvelopeValidation.Invalid(<redacted>)"
    }
}

private fun useDefensiveCopy(
    source: ByteArray,
    block: (ByteArray) -> Unit,
) {
    val copy = source.copyOf()
    try {
        block(copy)
    } finally {
        copy.fill(0)
    }
}
