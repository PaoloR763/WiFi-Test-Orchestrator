package com.wifitestorchestrator.agent.domain.credential.protection

import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.UUID

object CredentialProtectionAadV1 {
    const val MAGIC: String = "WTO_ANDROID_AGENT_CREDENTIAL"

    /**
     * Supplies the canonical v1 AAD only for the duration of [block]. Retaining the array outside
     * the callback violates this API contract. The temporary array is cleared before returning.
     */
    fun useBytes(
        credentialId: CredentialId,
        credentialVersion: CredentialVersion,
        block: (ByteArray) -> Unit,
    ) {
        val bytes =
            encode(
                cryptoVersion = CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE,
                keyAlias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
                credentialId = credentialId,
                credentialVersion = credentialVersion.value,
            )
        try {
            block(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    internal fun encode(
        cryptoVersion: Int,
        keyAlias: String,
        credentialId: CredentialId,
        credentialVersion: Int,
    ): ByteArray {
        require(cryptoVersion > 0)
        require(credentialVersion > 0)
        val magicBytes = MAGIC.toStrictAscii()
        val aliasBytes = keyAlias.toStrictAscii()
        require(aliasBytes.size <= UShort.MAX_VALUE.toInt())
        val uuid = UUID.fromString(credentialId.toString())
        val size =
            magicBytes.size +
                Int.SIZE_BYTES +
                UShort.SIZE_BYTES +
                aliasBytes.size +
                (Long.SIZE_BYTES * 2) +
                Int.SIZE_BYTES
        return ByteBuffer
            .allocate(size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(magicBytes)
            .putInt(cryptoVersion)
            .putShort(aliasBytes.size.toShort())
            .put(aliasBytes)
            .putLong(uuid.mostSignificantBits)
            .putLong(uuid.leastSignificantBits)
            .putInt(credentialVersion)
            .array()
    }
}

private fun String.toStrictAscii(): ByteArray {
    require(all { it.code in 0..0x7f })
    return toByteArray(StandardCharsets.US_ASCII)
}
