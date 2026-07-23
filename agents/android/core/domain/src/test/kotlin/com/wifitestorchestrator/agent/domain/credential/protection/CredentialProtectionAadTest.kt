package com.wifitestorchestrator.agent.domain.credential.protection

import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CredentialProtectionAadTest {
    @Test
    fun v1GoldenVectorIsStableAndExactly103Bytes() {
        var observed: ByteArray? = null
        var hexadecimal = ""

        CredentialProtectionAadV1.useBytes(credentialId(), credentialVersion(1)) { bytes ->
            observed = bytes
            hexadecimal = bytes.toHexadecimal()
            assertEquals(CredentialProtectionPolicyV1.AAD_SIZE_BYTES, bytes.size)
        }

        assertEquals(GOLDEN_AAD_HEX, hexadecimal)
        assertTrue(observed!!.all { it == 0.toByte() })
    }

    @Test
    fun v1FieldsUseTheRequiredBigEndianLayout() {
        val bytes =
            CredentialProtectionAadV1.encode(
                cryptoVersion = 1,
                keyAlias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
                credentialId = credentialId(),
                credentialVersion = Int.MAX_VALUE,
            )
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(28).also(buffer::get)
        val cryptoVersion = buffer.int
        val aliasLength = buffer.short.toInt() and 0xffff
        val alias = ByteArray(aliasLength).also(buffer::get)

        assertEquals(CredentialProtectionAadV1.MAGIC, magic.decodeToString())
        assertEquals(1, cryptoVersion)
        assertEquals(49, aliasLength)
        assertEquals(CredentialProtectionPolicyV1.KEY_ALIAS_VALUE, alias.decodeToString())
        assertEquals("10000000000040008000000000000001", bytes.copyOfRange(83, 99).toHexadecimal())
        assertEquals(Int.MAX_VALUE, buffer.getInt(99))
        assertContentEquals(byteArrayOf(0x7f, -1, -1, -1), bytes.copyOfRange(99, 103))
    }

    @Test
    fun everyAuthenticatedFieldChangesTheAad() {
        val baseline = encoded(cryptoVersion = 1, keyAlias = ALIAS, id = FIRST_ID, version = 1)

        val variants =
            listOf(
                encoded(cryptoVersion = 2, keyAlias = ALIAS, id = FIRST_ID, version = 1),
                encoded(
                    cryptoVersion = 1,
                    keyAlias = ALIAS.dropLast(1) + "2",
                    id = FIRST_ID,
                    version = 1,
                ),
                encoded(cryptoVersion = 1, keyAlias = ALIAS, id = SECOND_ID, version = 1),
                encoded(cryptoVersion = 1, keyAlias = ALIAS, id = FIRST_ID, version = 2),
            )

        variants.forEach { variant -> assertFalse(baseline.contentEquals(variant)) }
        assertEquals(variants.size, variants.map { it.toHexadecimal() }.distinct().size)
    }

    @Test
    fun nonPositiveVersionsAndNonAsciiAliasAreRejected() {
        assertFailsWith<IllegalArgumentException> {
            encoded(cryptoVersion = 0, keyAlias = ALIAS, id = FIRST_ID, version = 1)
        }
        assertFailsWith<IllegalArgumentException> {
            encoded(cryptoVersion = 1, keyAlias = ALIAS, id = FIRST_ID, version = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            encoded(cryptoVersion = 1, keyAlias = ALIAS.dropLast(1) + "é", id = FIRST_ID, version = 1)
        }
    }

    @Test
    fun supportedCredentialVersionBoundariesHaveDistinctEncodings() {
        val first = encoded(cryptoVersion = 1, keyAlias = ALIAS, id = FIRST_ID, version = 1)
        val last =
            encoded(
                cryptoVersion = 1,
                keyAlias = ALIAS,
                id = FIRST_ID,
                version = Int.MAX_VALUE,
            )

        assertNotEquals(first.toHexadecimal(), last.toHexadecimal())
        assertEquals("00000001", first.takeLast(Int.SIZE_BYTES).toByteArray().toHexadecimal())
        assertEquals("7fffffff", last.takeLast(Int.SIZE_BYTES).toByteArray().toHexadecimal())
    }

    private fun encoded(
        cryptoVersion: Int,
        keyAlias: String,
        id: String,
        version: Int,
    ): ByteArray =
        CredentialProtectionAadV1.encode(
            cryptoVersion = cryptoVersion,
            keyAlias = keyAlias,
            credentialId = credentialId(id),
            credentialVersion = version,
        )

    private fun credentialId(raw: String = FIRST_ID): CredentialId =
        (CredentialId.parse(raw) as Valid).value

    private fun credentialVersion(value: Int): CredentialVersion =
        (CredentialVersion.from(value) as Valid).value

    private fun ByteArray.toHexadecimal(): String =
        joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private companion object {
        const val FIRST_ID = "10000000-0000-4000-8000-000000000001"
        const val SECOND_ID = "20000000-0000-4000-8000-000000000002"
        const val ALIAS = "com.wifitestorchestrator.agent.credential.aead.v1"
        const val GOLDEN_AAD_HEX =
            "57544f5f414e44524f49445f4147454e545f43524544454e5449414c" +
                "000000010031" +
                "636f6d2e77696669746573746f7263686573747261746f722e6167656e742e" +
                "63726564656e7469616c2e616561642e7631" +
                "10000000000040008000000000000001" +
                "00000001"
    }
}
