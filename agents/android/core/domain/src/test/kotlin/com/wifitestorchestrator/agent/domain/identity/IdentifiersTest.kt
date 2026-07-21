package com.wifitestorchestrator.agent.domain.identity

import com.wifitestorchestrator.agent.domain.error.IdentifierViolation
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidIdentifier
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class IdentifiersTest {
    @Test
    fun commonUuidIdentifiersAcceptVersionsOneThroughEight() {
        val factories: List<(String) -> ValidationResult<*>> =
            listOf(
                InstallationId::parse,
                AgentId::parse,
                DeviceId::parse,
                CredentialId::parse,
            )

        for (version in 1..8) {
            val raw = uuidWith(version = version)
            factories.forEach { factory -> assertIs<Valid<*>>(factory(raw)) }
        }
    }

    @Test
    fun nonRfcUuidVariantIsRejected() {
        val error = invalidError(AgentId.parse(uuidWith(version = 4, variantNibble = '7')))

        assertEquals(IdentifierViolation.INVALID_VARIANT, error.violation)
    }

    @Test
    fun uuidVersionsZeroAndNineAreRejected() {
        for (version in listOf(0, 9)) {
            val error = invalidError(DeviceId.parse(uuidWith(version = version)))
            assertEquals(IdentifierViolation.UNSUPPORTED_VERSION, error.violation)
        }
    }

    @Test
    fun uppercaseUuidIsRejectedAsNonCanonical() {
        val raw = "10000000-0000-4000-8000-00000000000A"
        val error = invalidError(CredentialId.parse(raw))

        assertEquals(IdentifierViolation.NON_CANONICAL, error.violation)
    }

    @Test
    fun alternateJavaUuidFormsAreRejectedAsNonCanonical() {
        val error = invalidError(InstallationId.parse("1-1-4-8-1"))

        assertEquals(IdentifierViolation.NON_CANONICAL, error.violation)
    }

    @Test
    fun malformedUuidIsRejected() {
        val error = invalidError(AgentId.parse("not-a-uuid"))

        assertEquals(IdentifierViolation.INVALID_FORMAT, error.violation)
    }

    @Test
    fun nilUuidIsRejectedAsASentinel() {
        val error = invalidError(InstallationId.parse("00000000-0000-0000-0000-000000000000"))

        assertEquals(IdentifierViolation.NIL_UUID, error.violation)
    }

    @Test
    fun generatedInstallationAndIdempotencyIdsAreCanonicalV4() {
        val generated = listOf(InstallationId.generate().toString(), IdempotencyKey.generate().toString())

        generated.forEach { raw ->
            assertEquals(raw.lowercase(), raw)
            val uuid = UUID.fromString(raw)
            assertEquals(4, uuid.version())
            assertEquals(2, uuid.variant())
        }
    }

    @Test
    fun installationIdCanBeValidatedFromUuid() {
        val raw = UUID.fromString(uuidWith(version = 7))

        assertEquals(raw.toString(), valid(InstallationId.fromUuid(raw)).toString())
    }

    @Test
    fun idempotencyKeyAcceptsOnlyVersionFour() {
        assertIs<Valid<IdempotencyKey>>(IdempotencyKey.parse(uuidWith(version = 4)))
        val error = invalidError(IdempotencyKey.parse(uuidWith(version = 1)))

        assertEquals(IdentifierViolation.UUID_V4_REQUIRED, error.violation)
    }

    @Test
    fun identifierTypesHaveTypeSpecificEqualityAndHashing() {
        val raw = uuidWith(version = 4)
        val installationA = valid(InstallationId.parse(raw))
        val installationB = valid(InstallationId.parse(raw))
        val agent = valid(AgentId.parse(raw))

        assertEquals(installationA, installationB)
        assertEquals(installationA.hashCode(), installationB.hashCode())
        assertNotEquals(installationA as Any, agent as Any)
    }

    @Test
    fun correlationIdPreservesCaseAndAllowsPublishedCharacters() {
        val raw = "Corr.Agent_01-test"
        val parsed = valid(CorrelationId.parse(raw))

        assertEquals(raw, parsed.toString())
        assertEquals(parsed, valid(CorrelationId.parse(raw)))
    }

    @Test
    fun correlationIdRejectsInvalidLengthAndCharacters() {
        val invalidValues = listOf("", "a".repeat(129), "-leading", "contains space", "café")

        invalidValues.forEach { assertIs<Invalid>(CorrelationId.parse(it)) }
        assertTrue(CorrelationId.parse("a".repeat(128)) is Valid)
    }

    private fun uuidWith(version: Int, variantNibble: Char = '8'): String =
        "10000000-0000-${version}000-${variantNibble}000-000000000001"

    private fun invalidError(result: ValidationResult<*>): InvalidIdentifier =
        assertIs<InvalidIdentifier>(assertIs<Invalid>(result).error)

    private fun <T : Any> valid(result: ValidationResult<T>): T = assertIs<Valid<T>>(result).value
}
