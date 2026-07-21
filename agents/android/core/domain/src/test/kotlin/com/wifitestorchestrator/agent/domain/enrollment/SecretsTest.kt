package com.wifitestorchestrator.agent.domain.enrollment

import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidSecretFormat
import com.wifitestorchestrator.agent.domain.error.SecretViolation
import com.wifitestorchestrator.agent.domain.error.Valid
import java.io.Serializable
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SecretsTest {
    private val locator = "10000000-0000-4000-8000-000000000001"
    private val enrollmentRaw = "wto_enr_1.$locator.${"B".repeat(43)}"
    private val credentialRaw = "wto_ac_1.$locator.${"A".repeat(43)}"

    @Test
    fun publishedEnrollmentTokenIsAccepted() {
        assertIs<Valid<EnrollmentToken>>(EnrollmentToken.parse(enrollmentRaw))
    }

    @Test
    fun publishedAgentCredentialIsAcceptedAndExposesOnlyItsLocator() {
        val credential = credential()

        assertEquals(locator, credential.credentialId.toString())
    }

    @Test
    fun invalidPrefixAndLengthAreRejected() {
        assertEquals(
            SecretViolation.INVALID_PREFIX,
            invalid(EnrollmentToken.parse(enrollmentRaw.replace("wto_enr_1", "wto_bad_1"))).violation,
        )
        assertEquals(
            SecretViolation.INVALID_LENGTH,
            invalid(AgentCredentialSecret.parse(credentialRaw.dropLast(1))).violation,
        )
    }

    @Test
    fun invalidAndUppercaseLocatorsAreRejected() {
        val invalidLocator = enrollmentRaw.replace(locator, "10000000-0000-9000-8000-000000000001")
        val uppercaseLocator = credentialRaw.replace(locator, locator.dropLast(1) + "A")

        assertEquals(SecretViolation.INVALID_LOCATOR, invalid(EnrollmentToken.parse(invalidLocator)).violation)
        assertEquals(SecretViolation.INVALID_LOCATOR, invalid(AgentCredentialSecret.parse(uppercaseLocator)).violation)
    }

    @Test
    fun malformedStructureAndBase64UrlSegmentAreRejected() {
        val malformed = enrollmentRaw.replaceFirst('.', ':')
        val invalidBase64 = credentialRaw.dropLast(1) + "+"

        assertEquals(SecretViolation.INVALID_STRUCTURE, invalid(EnrollmentToken.parse(malformed)).violation)
        assertEquals(
            SecretViolation.INVALID_SECRET_SEGMENT,
            invalid(AgentCredentialSecret.parse(invalidBase64)).violation,
        )
    }

    @Test
    fun toStringAlwaysRedactsRawMaterial() {
        val enrollment = assertIs<Valid<EnrollmentToken>>(EnrollmentToken.parse(enrollmentRaw)).value
        val credential = credential()

        assertFalse(enrollmentRaw in enrollment.toString())
        assertFalse(credentialRaw in credential.toString())
        assertTrue("<redacted>" in enrollment.toString())
        assertTrue("<redacted>" in credential.toString())
    }

    @Test
    fun errorsNeverContainRawMaterial() {
        val raw = credentialRaw.dropLast(1) + "+"
        val error = assertIs<Invalid>(AgentCredentialSecret.parse(raw)).error

        assertFalse(raw in error.toString())
        assertFalse(raw in error.description)
    }

    @Test
    fun secretWrappersAreNormalClassesWithoutDataClassApisOrValueEquality() {
        assertSensitiveApi(EnrollmentToken::class.java)
        assertSensitiveApi(AgentCredentialSecret::class.java)
        val first = credential()
        val second = credential()

        assertNotEquals(first, second)
    }

    @Test
    fun secretWrappersAreNotSerializable() {
        assertFalse(Serializable::class.java.isAssignableFrom(EnrollmentToken::class.java))
        assertFalse(Serializable::class.java.isAssignableFrom(AgentCredentialSecret::class.java))
    }

    @Test
    fun rawFieldIsPrivateAndThereIsNoPublicRawGetter() {
        listOf(EnrollmentToken::class.java, AgentCredentialSecret::class.java).forEach { type ->
            assertTrue(Modifier.isPrivate(type.getDeclaredField("raw").modifiers))
            assertFalse(type.methods.any { it.name == "getRaw" })
        }
    }

    @Test
    fun useSecretProvidesMaterialOnlyToTheExplicitCallback() {
        val enrollment = assertIs<Valid<EnrollmentToken>>(EnrollmentToken.parse(enrollmentRaw)).value
        val credential = credential()

        assertEquals(enrollmentRaw.length, enrollment.useSecret(String::length))
        assertTrue(
            credential.useSecret { it == credentialRaw },
            "The credential callback did not expose the expected value",
        )
    }

    @Test
    fun enrollmentLocatorHasNoPublicDomainType() {
        assertFalse(EnrollmentToken::class.java.methods.any { "Locator" in it.name || "TokenId" in it.name })
        assertTrue(
            runCatching {
                Class.forName("com.wifitestorchestrator.agent.domain.enrollment.EnrollmentTokenId")
            }.isFailure,
        )
    }

    private fun credential(): AgentCredentialSecret =
        assertIs<Valid<AgentCredentialSecret>>(AgentCredentialSecret.parse(credentialRaw)).value

    private fun invalid(result: com.wifitestorchestrator.agent.domain.error.ValidationResult<*>): InvalidSecretFormat =
        assertIs<InvalidSecretFormat>(assertIs<Invalid>(result).error)

    private fun assertSensitiveApi(type: Class<*>) {
        val methods = type.declaredMethods.map { it.name }
        assertFalse("copy" in methods)
        assertFalse(methods.any { it.startsWith("component") })
        assertFalse("equals" in methods)
        assertFalse("hashCode" in methods)
    }
}
