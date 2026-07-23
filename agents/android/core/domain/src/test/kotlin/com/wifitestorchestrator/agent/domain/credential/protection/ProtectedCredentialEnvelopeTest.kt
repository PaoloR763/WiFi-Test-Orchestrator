package com.wifitestorchestrator.agent.domain.credential.protection

import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.io.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ProtectedCredentialEnvelopeTest {
    @Test
    fun validV1EnvelopeIsClosedAndValidates() {
        val envelope = validEnvelope()

        assertEquals(CredentialCryptoVersion.V1, envelope.cryptoVersion)
        assertEquals(CredentialKeyAlias.V1, envelope.keyAlias)
        assertEquals(credentialId(), envelope.credentialId)
        assertEquals(credentialVersion(), envelope.credentialVersion)
        assertSame(ProtectedCredentialEnvelopeValidation.Valid, envelope.validate())
    }

    @Test
    fun unknownVersionAndAliasAreRejectedBeforeArrayValidation() {
        val unsupportedVersion =
            createEnvelope(cryptoVersion = 2, keyAlias = "unknown", nonceSize = 0, sealedSize = 0)
        val unknownAlias =
            createEnvelope(cryptoVersion = 1, keyAlias = "unknown", nonceSize = 0, sealedSize = 0)

        assertEquals(
            CredentialProtectionError.UNSUPPORTED_CRYPTO_VERSION,
            assertIs<ProtectedCredentialEnvelopeCreationResult.Invalid>(unsupportedVersion).error,
        )
        assertEquals(
            CredentialProtectionError.UNKNOWN_KEY_ALIAS,
            assertIs<ProtectedCredentialEnvelopeCreationResult.Invalid>(unknownAlias).error,
        )
    }

    @Test
    fun invalidNonceAndSealedSizesAreRejectedDeterministically() {
        listOf(0, 11, 13, 1_024).forEach { size ->
            val invalid =
                assertIs<ProtectedCredentialEnvelopeCreationResult.Invalid>(
                    createEnvelope(nonceSize = size),
                )
            assertEquals(CredentialProtectionError.INVALID_NONCE, invalid.error)
        }
        listOf(0, 104, 106, 1_024).forEach { size ->
            val invalid =
                assertIs<ProtectedCredentialEnvelopeCreationResult.Invalid>(
                    createEnvelope(sealedSize = size),
                )
            assertEquals(CredentialProtectionError.MALFORMED_ENVELOPE, invalid.error)
        }
    }

    @Test
    fun constructorAndCallbacksUseDefensiveCopies() {
        val nonce = ByteArray(12) { 1 }
        val sealed = ByteArray(105) { 2 }
        val envelope = validEnvelope(nonce = nonce, sealed = sealed)
        nonce.fill(9)
        sealed.fill(9)

        var escapedNonce: ByteArray? = null
        envelope.useNonce { copy ->
            assertTrue(copy.all { it == 1.toByte() })
            copy.fill(7)
            escapedNonce = copy
        }
        assertTrue(escapedNonce!!.all { it == 0.toByte() })
        envelope.useNonce { copy -> assertTrue(copy.all { it == 1.toByte() }) }

        var escapedSealed: ByteArray? = null
        envelope.useSealedCredential { copy ->
            assertTrue(copy.all { it == 2.toByte() })
            copy.fill(8)
            escapedSealed = copy
        }
        assertTrue(escapedSealed!!.all { it == 0.toByte() })
        envelope.useSealedCredential { copy -> assertTrue(copy.all { it == 2.toByte() }) }
    }

    @Test
    fun envelopeUsesReferenceEqualityAndIsNotSerializableOrDataLike() {
        val first = validEnvelope()
        val second = validEnvelope()

        assertNotEquals(first, second)
        assertFalse(Serializable::class.java.isAssignableFrom(ProtectedCredentialEnvelope::class.java))
        val declaredMethods = ProtectedCredentialEnvelope::class.java.declaredMethods.map { it.name }
        assertFalse("equals" in declaredMethods)
        assertFalse("hashCode" in declaredMethods)
        assertFalse(declaredMethods.any { it == "copy" || it.startsWith("component") })
    }

    @Test
    fun everyEnvelopeAndFactoryRepresentationIsRedacted() {
        val alias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE
        val nonceFragment = "010101"
        val sealedFragment = "020202"
        val envelope = validEnvelope()
        val values =
            listOf(
                envelope.toString(),
                ProtectedCredentialEnvelopeCreationResult.Valid(envelope).toString(),
                ProtectedCredentialEnvelopeCreationResult.Invalid(
                    CredentialProtectionError.MALFORMED_ENVELOPE,
                ).toString(),
                ProtectedCredentialEnvelopeValidation.Valid.toString(),
                ProtectedCredentialEnvelopeValidation.Invalid(
                    CredentialProtectionError.INVALID_NONCE,
                ).toString(),
                CredentialCryptoVersion.V1.toString(),
                CredentialKeyAlias.V1.toString(),
            )

        values.forEach { rendered ->
            assertTrue("<redacted>" in rendered)
            assertFalse(alias in rendered)
            assertFalse(nonceFragment in rendered)
            assertFalse(sealedFragment in rendered)
        }
    }

    private fun validEnvelope(
        nonce: ByteArray = ByteArray(12) { 1 },
        sealed: ByteArray = ByteArray(105) { 2 },
    ): ProtectedCredentialEnvelope =
        assertIs<ProtectedCredentialEnvelopeCreationResult.Valid>(
            ProtectedCredentialEnvelope.create(
                cryptoVersion = 1,
                keyAlias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
                credentialId = credentialId(),
                credentialVersion = credentialVersion(),
                nonce = nonce,
                sealedCredential = sealed,
            ),
        ).envelope

    private fun createEnvelope(
        cryptoVersion: Int = 1,
        keyAlias: String = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
        nonceSize: Int = 12,
        sealedSize: Int = 105,
    ): ProtectedCredentialEnvelopeCreationResult =
        ProtectedCredentialEnvelope.create(
            cryptoVersion = cryptoVersion,
            keyAlias = keyAlias,
            credentialId = credentialId(),
            credentialVersion = credentialVersion(),
            nonce = ByteArray(nonceSize),
            sealedCredential = ByteArray(sealedSize),
        )

    private fun credentialId(): CredentialId =
        (CredentialId.parse(CREDENTIAL_ID) as Valid).value

    private fun credentialVersion(): CredentialVersion =
        (CredentialVersion.from(1) as Valid).value

    private companion object {
        const val CREDENTIAL_ID = "10000000-0000-4000-8000-000000000001"
    }
}
