package com.wifitestorchestrator.agent.platform.security

import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import javax.crypto.AEADBadTagException
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

class AesGcmCredentialCipherTest {
    @Test
    fun hostJcaRoundTripHasExactV1SizesAndUniqueProviderNonces() {
        val cipher = AesGcmCredentialCipher()
        val plaintext = TEST_CREDENTIAL_RAW.encodeToByteArray()
        val aad = ByteArray(CredentialProtectionPolicyV1.AAD_SIZE_BYTES) { it.toByte() }

        val first = cipher.encrypt(TEST_KEY, plaintext, aad)
        val second = cipher.encrypt(TEST_KEY, plaintext, aad)

        assertEquals(89, plaintext.size)
        assertEquals(12, first.nonce.size)
        assertEquals(105, first.sealedCredential.size)
        assertFalse(first.nonce.contentEquals(second.nonce))
        assertContentEquals(
            plaintext,
            cipher.decrypt(TEST_KEY, first.nonce, first.sealedCredential, aad),
        )
    }

    @Test
    fun ciphertextTagNonceAadAndKeyChangesAllFailAuthentication() {
        val cipher = AesGcmCredentialCipher()
        val plaintext = TEST_CREDENTIAL_RAW.encodeToByteArray()
        val aad = ByteArray(103) { index -> index.toByte() }
        val encrypted = cipher.encrypt(TEST_KEY, plaintext, aad)

        val changedCiphertext = encrypted.sealedCredential.copyOf().also { it[0] = it[0].inc() }
        val changedTag = encrypted.sealedCredential.copyOf().also { it[it.lastIndex] = it.last().inc() }
        val changedNonce = encrypted.nonce.copyOf().also { it[0] = it[0].inc() }
        val changedAad = aad.copyOf().also { it[0] = it[0].inc() }

        listOf(
            Triple(TEST_KEY, encrypted.nonce, changedCiphertext to aad),
            Triple(TEST_KEY, encrypted.nonce, changedTag to aad),
            Triple(TEST_KEY, changedNonce, encrypted.sealedCredential to aad),
            Triple(TEST_KEY, encrypted.nonce, encrypted.sealedCredential to changedAad),
            Triple(OTHER_KEY, encrypted.nonce, encrypted.sealedCredential to aad),
        ).forEach { (key, nonce, sealedAndAad) ->
            assertFailsWith<AEADBadTagException> {
                cipher.decrypt(key, nonce, sealedAndAad.first, sealedAndAad.second)
            }
        }
    }

    @Test
    fun eachOperationUsesAFreshHandleAndEncryptHasNoCallerIvParameter() {
        val handles = mutableListOf<RecordingHandle>()
        val factory =
            AeadCipherHandleFactory {
                RecordingHandle().also(handles::add)
            }
        val cipher = AesGcmCredentialCipher(factory)
        val plaintext = ByteArray(89)
        val aad = ByteArray(103)

        val encrypted = cipher.encrypt(TEST_KEY, plaintext, aad)
        cipher.decrypt(TEST_KEY, encrypted.nonce, encrypted.sealedCredential, aad)

        assertEquals(2, handles.size)
        assertNotSame(handles[0], handles[1])
        assertTrue(handles[0].encryptInitialized)
        assertFalse(handles[0].decryptInitialized)
        assertTrue(handles[1].decryptInitialized)
        assertEquals(128, handles[1].parameters?.tLen)
        assertContentEquals(ByteArray(12), handles[1].parameters?.iv)
        assertContentEquals(aad, handles[0].aad)
        assertContentEquals(aad, handles[1].aad)
    }

    @Test
    fun generatedNonceAndSealedSizeAreFailClosed() {
        val invalidNonceHandle = RecordingHandle(nonce = ByteArray(11) { 1 })
        val invalidSealedHandle = RecordingHandle(output = ByteArray(104) { 2 })
        val invalidNonce =
            AesGcmCredentialCipher(
                AeadCipherHandleFactory { invalidNonceHandle },
            )
        val invalidSealed =
            AesGcmCredentialCipher(
                AeadCipherHandleFactory { invalidSealedHandle },
            )

        assertFailsWith<InvalidGeneratedNonceException> {
            invalidNonce.encrypt(TEST_KEY, ByteArray(89), ByteArray(103))
        }
        assertFailsWith<InvalidSealedCredentialException> {
            invalidSealed.encrypt(TEST_KEY, ByteArray(89), ByteArray(103))
        }
        assertTrue(invalidNonceHandle.producedNonce!!.all { it == 0.toByte() })
        assertTrue(invalidNonceHandle.producedOutput!!.all { it == 0.toByte() })
        assertTrue(invalidSealedHandle.producedNonce!!.all { it == 0.toByte() })
        assertTrue(invalidSealedHandle.producedOutput!!.all { it == 0.toByte() })
    }
}

private class RecordingHandle(
    private val nonce: ByteArray = ByteArray(12),
    private val output: ByteArray = ByteArray(105),
) : AeadCipherHandle {
    var encryptInitialized = false
    var decryptInitialized = false
    var parameters: GCMParameterSpec? = null
    var aad: ByteArray? = null
    var producedNonce: ByteArray? = null
    var producedOutput: ByteArray? = null

    override fun initEncrypt(key: SecretKey) {
        encryptInitialized = true
    }

    override fun initDecrypt(
        key: SecretKey,
        parameters: GCMParameterSpec,
    ) {
        decryptInitialized = true
        this.parameters = parameters
    }

    override fun updateAad(aad: ByteArray) {
        this.aad = aad.copyOf()
    }

    override fun doFinal(input: ByteArray): ByteArray =
        output.copyOf().also { producedOutput = it }

    override fun iv(): ByteArray = nonce.copyOf().also { producedNonce = it }
}
