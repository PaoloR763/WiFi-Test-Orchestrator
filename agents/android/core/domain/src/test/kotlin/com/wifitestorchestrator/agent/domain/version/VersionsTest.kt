package com.wifitestorchestrator.agent.domain.version

import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidVersion
import com.wifitestorchestrator.agent.domain.error.UnsupportedProtocolVersion
import com.wifitestorchestrator.agent.domain.error.UnsupportedSchemaVersion
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.error.VersionViolation
import com.wifitestorchestrator.agent.domain.error.VersionKind
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class VersionsTest {
    @Test
    fun semanticVersionParsesCanonicalNumericComponents() {
        val version = valid(SemanticVersion.parse("12.34.56"))

        assertEquals(BigInteger("12"), version.major)
        assertEquals(BigInteger("34"), version.minor)
        assertEquals(BigInteger("56"), version.patch)
        assertEquals(null, version.preRelease)
        assertEquals("12.34.56", version.toString())
    }

    @Test
    fun semanticVersionSupportsLargeNumbersWithoutOverflow() {
        val raw = "123456789012345678901234.2.3"

        assertEquals(raw, valid(SemanticVersion.parse(raw)).toString())
    }

    @Test
    fun coreNumericLeadingZerosAreRejected() {
        listOf("01.0.0", "1.00.0", "1.0.00").forEach {
            assertEquals(VersionViolation.LEADING_ZERO, invalidVersion(SemanticVersion.parse(it)).violation)
        }
    }

    @Test
    fun validPrereleaseIsPreserved() {
        val raw = "1.0.0-alpha.1-x"
        val parsed = valid(SemanticVersion.parse(raw))

        assertEquals("alpha.1-x", parsed.preRelease)
        assertEquals(raw, parsed.toString())
    }

    @Test
    fun emptyPrereleaseIdentifiersAreRejected() {
        listOf("1.0.0-", "1.0.0-.alpha", "1.0.0-alpha..1", "1.0.0-alpha.").forEach {
            assertEquals(
                VersionViolation.PRERELEASE_EMPTY_IDENTIFIER,
                invalidVersion(SemanticVersion.parse(it)).violation,
            )
        }
    }

    @Test
    fun numericPrereleaseLeadingZeroIsRejected() {
        assertEquals(
            VersionViolation.PRERELEASE_NUMERIC_LEADING_ZERO,
            invalidVersion(SemanticVersion.parse("1.0.0-alpha.01")).violation,
        )
    }

    @Test
    fun invalidPrereleaseCharactersAreRejected() {
        assertEquals(
            VersionViolation.PRERELEASE_INVALID_CHARACTER,
            invalidVersion(SemanticVersion.parse("1.0.0-alpha_beta")).violation,
        )
    }

    @Test
    fun buildMetadataIsRejected() {
        assertEquals(
            VersionViolation.BUILD_METADATA_NOT_ALLOWED,
            invalidVersion(SemanticVersion.parse("1.0.0+build.1")).violation,
        )
    }

    @Test
    fun contractualTotalAndPrereleaseLengthsAreEnforced() {
        val exactMaximum = "1234567890123456789012345678.0.0"
        assertEquals(32, exactMaximum.length)
        assertIs<Valid<SemanticVersion>>(SemanticVersion.parse("0.0.0"))
        assertIs<Valid<SemanticVersion>>(SemanticVersion.parse(exactMaximum))
        assertIs<Invalid>(SemanticVersion.parse("1.0"))
        assertIs<Invalid>(SemanticVersion.parse("1" + exactMaximum))
        assertIs<Valid<SemanticVersion>>(SemanticVersion.parse("1.0.0-${"a".repeat(16)}"))
        assertEquals(
            VersionViolation.PRERELEASE_TOO_LONG,
            invalidVersion(SemanticVersion.parse("1.0.0-${"a".repeat(17)}")).violation,
        )
    }

    @Test
    fun semverComparisonFollowsNumericAndPrereleasePrecedence() {
        val ordered =
            listOf(
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.beta",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-beta.11",
                "1.0.0-rc.1",
                "1.0.0",
                "2.0.0",
            ).map { valid(SemanticVersion.parse(it)) }

        assertEquals(ordered, ordered.shuffled().sorted())
        assertTrue(valid(SemanticVersion.parse("1.0.0-9999999999999999")) < valid(SemanticVersion.parse("1.0.0-alpha")))
    }

    @Test
    fun schemaVersionDistinguishesInvalidFromUnsupported() {
        assertEquals(
            VersionKind.SCHEMA,
            assertIs<InvalidVersion>(assertIs<Invalid>(SchemaVersion.parse("bad")).error).kind,
        )
        assertEquals(UnsupportedSchemaVersion, assertIs<Invalid>(SchemaVersion.parse("1.1.0")).error)
    }

    @Test
    fun protocolVersionDistinguishesInvalidFromUnsupported() {
        assertEquals(
            VersionKind.PROTOCOL,
            assertIs<InvalidVersion>(assertIs<Invalid>(ProtocolVersion.parse("1.0")).error).kind,
        )
        assertEquals(
            UnsupportedProtocolVersion,
            assertIs<Invalid>(ProtocolVersion.parse("2.0.0")).error,
        )
    }

    @Test
    fun currentSchemaAndProtocolVersionsAreOneZeroZero() {
        assertEquals("1.0.0", valid(SchemaVersion.parse("1.0.0")).toString())
        assertEquals("1.0.0", valid(ProtocolVersion.parse("1.0.0")).toString())
        assertEquals(SchemaVersion.CURRENT, valid(SchemaVersion.parse("1.0.0")))
        assertEquals(ProtocolVersion.CURRENT, valid(ProtocolVersion.parse("1.0.0")))
    }

    @Test
    fun agentVersionHasSyntaxValidationButNoFixedSupportedValue() {
        assertEquals("999.42.7-preview", valid(AgentVersion.parse("999.42.7-preview")).toString())
        assertEquals(
            VersionKind.AGENT,
            assertIs<InvalidVersion>(assertIs<Invalid>(AgentVersion.parse("v1.0.0")).error).kind,
        )
    }

    private fun invalidVersion(result: ValidationResult<*>): InvalidVersion =
        assertIs<InvalidVersion>(assertIs<Invalid>(result).error)

    private fun <T : Any> valid(result: ValidationResult<T>): T = assertIs<Valid<T>>(result).value
}
