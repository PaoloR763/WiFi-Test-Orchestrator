package com.wifitestorchestrator.agent.platform.security

import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class AesGcmCredentialCipher(
    private val cipherFactory: AeadCipherHandleFactory = JcaAeadCipherHandleFactory,
) {
    fun encrypt(
        key: SecretKey,
        plaintext: ByteArray,
        aad: ByteArray,
    ): AesGcmEncryption {
        val cipher = cipherFactory.create()
        cipher.initEncrypt(key)
        cipher.updateAad(aad)
        val sealedCredential = cipher.doFinal(plaintext)
        val nonce =
            try {
                cipher.iv()
            } catch (failure: Throwable) {
                sealedCredential.fill(0)
                throw failure
            }
        if (nonce.size != CredentialProtectionPolicyV1.NONCE_SIZE_BYTES) {
            nonce.fill(0)
            sealedCredential.fill(0)
            throw InvalidGeneratedNonceException()
        }
        if (sealedCredential.size != CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) {
            nonce.fill(0)
            sealedCredential.fill(0)
            throw InvalidSealedCredentialException()
        }
        return AesGcmEncryption(nonce = nonce, sealedCredential = sealedCredential)
    }

    fun decrypt(
        key: SecretKey,
        nonce: ByteArray,
        sealedCredential: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val cipher = cipherFactory.create()
        cipher.initDecrypt(
            key,
            GCMParameterSpec(CredentialProtectionPolicyV1.AUTHENTICATION_TAG_SIZE_BITS, nonce),
        )
        cipher.updateAad(aad)
        return cipher.doFinal(sealedCredential)
    }
}

internal class AesGcmEncryption(
    val nonce: ByteArray,
    val sealedCredential: ByteArray,
) {
    override fun toString(): String = "AesGcmEncryption(<redacted>)"
}

internal fun interface AeadCipherHandleFactory {
    fun create(): AeadCipherHandle
}

internal interface AeadCipherHandle {
    fun initEncrypt(key: SecretKey)

    fun initDecrypt(
        key: SecretKey,
        parameters: GCMParameterSpec,
    )

    fun updateAad(aad: ByteArray)

    fun doFinal(input: ByteArray): ByteArray

    fun iv(): ByteArray
}

private object JcaAeadCipherHandleFactory : AeadCipherHandleFactory {
    override fun create(): AeadCipherHandle =
        JcaAeadCipherHandle(Cipher.getInstance(TRANSFORMATION))
}

private class JcaAeadCipherHandle(
    private val cipher: Cipher,
) : AeadCipherHandle {
    override fun initEncrypt(key: SecretKey) {
        cipher.init(Cipher.ENCRYPT_MODE, key)
    }

    override fun initDecrypt(
        key: SecretKey,
        parameters: GCMParameterSpec,
    ) {
        cipher.init(Cipher.DECRYPT_MODE, key, parameters)
    }

    override fun updateAad(aad: ByteArray) {
        cipher.updateAAD(aad)
    }

    override fun doFinal(input: ByteArray): ByteArray = cipher.doFinal(input)

    override fun iv(): ByteArray = cipher.iv
}

internal class InvalidGeneratedNonceException : Exception()

internal class InvalidSealedCredentialException : Exception()

private const val TRANSFORMATION = "AES/GCM/NoPadding"
