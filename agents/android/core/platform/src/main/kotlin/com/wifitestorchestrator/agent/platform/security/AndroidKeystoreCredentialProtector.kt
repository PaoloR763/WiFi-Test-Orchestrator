package com.wifitestorchestrator.agent.platform.security

import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionAadV1
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeCreationResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeValidation
import com.wifitestorchestrator.agent.domain.credential.protection.UseDecryptedCredentialResult
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential
import com.wifitestorchestrator.agent.domain.error.Valid
import java.nio.charset.StandardCharsets
import javax.crypto.SecretKey

internal class AndroidKeystoreCredentialProtector(
    private val keyAccess: CredentialKeyAccess,
    private val credentialCipher: AesGcmCredentialCipher,
    private val operationGuard: BlockingOperationGuard,
    private val bufferCleaner: SensitiveBufferCleaner,
    private val lifecycleLock: CredentialKeyLifecycleLock,
) : CredentialProtector {
    override fun inspect(): CredentialProtectionInspection {
        operationGuard.checkOffMainThread()
        return lifecycleLock.withLifecycleLock {
            when (val inspection = inspectKeySafely()) {
                InternalKeyResolution.Missing -> CredentialProtectionInspection.Missing
                InternalKeyResolution.Incompatible -> CredentialProtectionInspection.Incompatible
                is InternalKeyResolution.Compatible ->
                    CredentialProtectionInspection.Compatible(inspection.securityLevel)
                is InternalKeyResolution.Failure ->
                    CredentialProtectionInspection.Unavailable(inspection.error)
            }
        }
    }

    override fun prepare(): CredentialProtectionPreparation {
        operationGuard.checkOffMainThread()
        return when (val resolution = ensureCompatibleKey()) {
            is InternalKeyPreparation.Ready ->
                if (resolution.created) {
                    CredentialProtectionPreparation.Created
                } else {
                    CredentialProtectionPreparation.AlreadyCompatible
                }
            is InternalKeyPreparation.Failure ->
                CredentialProtectionPreparation.Failure(resolution.error)
        }
    }

    override fun protect(credential: DeliveredCredential): ProtectCredentialResult {
        operationGuard.checkOffMainThread()
        val key =
            when (val resolution = ensureCompatibleKey()) {
                is InternalKeyPreparation.Ready -> resolution.key
                is InternalKeyPreparation.Failure ->
                    return ProtectCredentialResult.Failure(resolution.error)
            }
        return credential.useSecret { raw ->
            val plaintext = raw.toStrictCredentialBytes()
                ?: return@useSecret ProtectCredentialResult.Failure(
                    CredentialProtectionError.ENCRYPTION_FAILED,
                )
            withCleanupPreservingPrimaryFailure(
                cleanup = { bufferCleaner.clean(plaintext) },
            ) {
                protectBytes(
                    key = key,
                    plaintext = plaintext,
                    credential = credential,
                )
            }
        }
    }

    override fun useDecryptedCredential(
        envelope: ProtectedCredentialEnvelope,
        block: (AgentCredentialSecret) -> Unit,
    ): UseDecryptedCredentialResult {
        operationGuard.checkOffMainThread()
        when (val validation = envelope.validate()) {
            ProtectedCredentialEnvelopeValidation.Valid -> Unit
            is ProtectedCredentialEnvelopeValidation.Invalid ->
                return UseDecryptedCredentialResult.Failure(validation.error)
        }
        val key =
            when (val resolution = resolveExistingKey()) {
                is InternalKeyResolution.Compatible -> resolution.key
                InternalKeyResolution.Missing ->
                    return UseDecryptedCredentialResult.Failure(
                        CredentialProtectionError.KEY_MISSING,
                    )
                InternalKeyResolution.Incompatible ->
                    return UseDecryptedCredentialResult.Failure(
                        CredentialProtectionError.KEY_INCOMPATIBLE,
                    )
                is InternalKeyResolution.Failure ->
                    return UseDecryptedCredentialResult.Failure(resolution.error)
            }
        val plaintext =
            when (val decryption = decryptBytes(key, envelope)) {
                is InternalDecryption.Decrypted -> decryption.plaintext
                is InternalDecryption.Failure ->
                    return UseDecryptedCredentialResult.Failure(decryption.error)
            }
        return withCleanupPreservingPrimaryFailure(
            cleanup = { bufferCleaner.clean(plaintext) },
        ) {
            if (plaintext.size != CredentialProtectionPolicyV1.PLAINTEXT_SIZE_BYTES) {
                return@withCleanupPreservingPrimaryFailure UseDecryptedCredentialResult.Failure(
                    CredentialProtectionError.DECRYPTION_FAILED,
                )
            }
            if (plaintext.any { byte -> (byte.toInt() and 0xff) > 0x7f }) {
                return@withCleanupPreservingPrimaryFailure UseDecryptedCredentialResult.Failure(
                    CredentialProtectionError.DECRYPTION_FAILED,
                )
            }
            val raw = String(plaintext, StandardCharsets.US_ASCII)
            val parsed = AgentCredentialSecret.parse(raw)
            if (parsed !is Valid || parsed.value.credentialId != envelope.credentialId) {
                return@withCleanupPreservingPrimaryFailure UseDecryptedCredentialResult.Failure(
                    CredentialProtectionError.DECRYPTION_FAILED,
                )
            }
            block(parsed.value)
            UseDecryptedCredentialResult.Used
        }
    }

    private fun protectBytes(
        key: SecretKey,
        plaintext: ByteArray,
        credential: DeliveredCredential,
    ): ProtectCredentialResult {
        val encryption =
            try {
                var result: AesGcmEncryption? = null
                CredentialProtectionAadV1.useBytes(
                    credential.metadata.credentialId,
                    credential.metadata.version,
                ) { aad ->
                    result = credentialCipher.encrypt(key, plaintext, aad)
                }
                result ?: return ProtectCredentialResult.Failure(
                    CredentialProtectionError.ENCRYPTION_FAILED,
                )
            } catch (failure: Exception) {
                return ProtectCredentialResult.Failure(
                    failure.toCredentialProtectionError(
                        default = CredentialProtectionError.ENCRYPTION_FAILED,
                    ),
                )
            }
        return withCleanupPreservingPrimaryFailure(
            cleanup = {
                cleanBuffers(bufferCleaner, encryption.nonce, encryption.sealedCredential)
            },
        ) {
            when (
                val created =
                    ProtectedCredentialEnvelope.create(
                        cryptoVersion = CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE,
                        keyAlias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
                        credentialId = credential.metadata.credentialId,
                        credentialVersion = credential.metadata.version,
                        nonce = encryption.nonce,
                        sealedCredential = encryption.sealedCredential,
                    )
            ) {
                is ProtectedCredentialEnvelopeCreationResult.Valid ->
                    ProtectCredentialResult.Protected(created.envelope)
                is ProtectedCredentialEnvelopeCreationResult.Invalid ->
                    ProtectCredentialResult.Failure(created.error)
            }
        }
    }

    private fun decryptBytes(
        key: SecretKey,
        envelope: ProtectedCredentialEnvelope,
    ): InternalDecryption =
        try {
            var plaintext: ByteArray? = null
            envelope.useNonce { nonce ->
                envelope.useSealedCredential { sealedCredential ->
                    CredentialProtectionAadV1.useBytes(
                        envelope.credentialId,
                        envelope.credentialVersion,
                    ) { aad ->
                        plaintext =
                            credentialCipher.decrypt(
                                key = key,
                                nonce = nonce,
                                sealedCredential = sealedCredential,
                                aad = aad,
                            )
                    }
                }
            }
            val decrypted = plaintext
                ?: return InternalDecryption.Failure(CredentialProtectionError.DECRYPTION_FAILED)
            InternalDecryption.Decrypted(decrypted)
        } catch (failure: Exception) {
            InternalDecryption.Failure(
                failure.toCredentialProtectionError(
                    default = CredentialProtectionError.DECRYPTION_FAILED,
                    authenticationFailure = true,
                ),
            )
        }

    private fun ensureCompatibleKey(): InternalKeyPreparation =
        lifecycleLock.withLifecycleLock {
            when (val initial = inspectKeySafely()) {
                is InternalKeyResolution.Compatible ->
                    InternalKeyPreparation.Ready(initial.key, created = false)
                InternalKeyResolution.Incompatible ->
                    InternalKeyPreparation.Failure(CredentialProtectionError.KEY_INCOMPATIBLE)
                is InternalKeyResolution.Failure -> InternalKeyPreparation.Failure(initial.error)
                InternalKeyResolution.Missing -> createAndReinspect()
            }
        }

    private fun createAndReinspect(): InternalKeyPreparation {
        val creationFailure =
            try {
                keyAccess.create()
                null
            } catch (failure: Exception) {
                failure.rethrowCancellationIfPresent()
                failure
            }
        val afterCreation = inspectKeySafely()
        return when (afterCreation) {
            is InternalKeyResolution.Compatible ->
                InternalKeyPreparation.Ready(
                    key = afterCreation.key,
                    created = creationFailure == null,
                )
            InternalKeyResolution.Incompatible ->
                InternalKeyPreparation.Failure(CredentialProtectionError.KEY_INCOMPATIBLE)
            is InternalKeyResolution.Failure -> InternalKeyPreparation.Failure(afterCreation.error)
            InternalKeyResolution.Missing ->
                InternalKeyPreparation.Failure(
                    creationFailure?.toCredentialProtectionError(
                        default = CredentialProtectionError.PROVIDER_FAILURE,
                    ) ?: CredentialProtectionError.PROVIDER_FAILURE,
                )
        }
    }

    private fun resolveExistingKey(): InternalKeyResolution =
        lifecycleLock.withLifecycleLock(::inspectKeySafely)

    private fun inspectKeySafely(): InternalKeyResolution =
        try {
            when (val inspection = keyAccess.inspect()) {
                InternalCredentialKeyInspection.Missing -> InternalKeyResolution.Missing
                InternalCredentialKeyInspection.Incompatible -> InternalKeyResolution.Incompatible
                is InternalCredentialKeyInspection.Compatible ->
                    InternalKeyResolution.Compatible(
                        key = inspection.key,
                        securityLevel = inspection.securityLevel,
                    )
            }
        } catch (failure: Exception) {
            InternalKeyResolution.Failure(
                failure.toCredentialProtectionError(
                    default = CredentialProtectionError.PROVIDER_FAILURE,
                ),
            )
        }
}

private sealed interface InternalKeyResolution {
    object Missing : InternalKeyResolution

    object Incompatible : InternalKeyResolution

    class Compatible(
        val key: SecretKey,
        val securityLevel:
            com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel,
    ) : InternalKeyResolution

    class Failure(val error: CredentialProtectionError) : InternalKeyResolution
}

private sealed interface InternalKeyPreparation {
    class Ready(
        val key: SecretKey,
        val created: Boolean,
    ) : InternalKeyPreparation

    class Failure(val error: CredentialProtectionError) : InternalKeyPreparation
}

private sealed interface InternalDecryption {
    class Decrypted(val plaintext: ByteArray) : InternalDecryption

    class Failure(val error: CredentialProtectionError) : InternalDecryption
}

internal fun String.toStrictCredentialBytes(): ByteArray? {
    if (length != CredentialProtectionPolicyV1.PLAINTEXT_SIZE_BYTES) return null
    val bytes = ByteArray(length)
    forEachIndexed { index, character ->
        if (character.code !in 0..0x7f) {
            bytes.fill(0)
            return null
        }
        bytes[index] = character.code.toByte()
    }
    return bytes
}
