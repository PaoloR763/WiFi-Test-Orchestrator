package com.wifitestorchestrator.agent.domain.error

import java.lang.reflect.InvocationTargetException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ValidationResultTest {
    @Test
    fun validCarriesItsValue() {
        assertEquals("value", assertIs<Valid<String>>(Valid("value")).value)
    }

    @Test
    fun validRejectsNullAtTheJvmBoundary() {
        val constructor = Valid::class.java.getDeclaredConstructor(Any::class.java)

        val failure =
            assertFailsWith<InvocationTargetException> {
                constructor.newInstance(*arrayOfNulls<Any>(1))
            }

        assertIs<NullPointerException>(failure.cause)
    }

    @Test
    fun invalidCarriesAPlainDomainError() {
        val error = InvalidIdentifier(IdentifierKind.AGENT_ID, IdentifierViolation.INVALID_FORMAT)
        val result = Invalid(error)

        assertSame(error, result.error)
        assertFalse(Throwable::class.java.isAssignableFrom(error::class.java))
    }

    @Test
    fun mapTransformsOnlyValidValues() {
        assertEquals(Valid(4), Valid("test").map(String::length))
        var invoked = false
        val invalid = Invalid(UnsupportedSchemaVersion)

        val mapped = invalid.map {
            invoked = true
            it
        }

        assertSame(invalid, mapped)
        assertFalse(invoked)
    }

    @Test
    fun flatMapPreservesExhaustiveValidation() {
        val mapped = Valid(2).flatMap { Valid(it * 3) }
        val rejected = Valid(2).flatMap<Int, Int> { Invalid(UnsupportedProtocolVersion) }

        assertEquals(Valid(6), mapped)
        assertEquals(Invalid(UnsupportedProtocolVersion), rejected)
    }

    @Test
    fun errorCodesDescriptionsAndContextAreStableAndRedacted() {
        val raw = "wto_enr_1.secret-that-must-not-appear"
        val errors =
            listOf(
                InvalidIdentifier(IdentifierKind.CREDENTIAL_ID, IdentifierViolation.NON_CANONICAL),
                InvalidVersion(VersionKind.AGENT, VersionViolation.INVALID_FORMAT),
                UnsupportedSchemaVersion,
                UnsupportedProtocolVersion,
                InvalidConfiguration(
                    ConfigurationKind.SERVER_BASE_URL,
                    ConfigurationViolation.INSECURE,
                    ConfigurationIssue.INSECURE_SCHEME,
                ),
                InvalidSecretFormat(SecretKind.ENROLLMENT_TOKEN, SecretViolation.INVALID_PREFIX),
                InvalidCredentialMetadata(
                    CredentialMetadataKind.VALIDITY_WINDOW,
                    CredentialMetadataViolation.EXPIRY_NOT_AFTER_ISSUE,
                ),
            )

        assertEquals(
            listOf(
                "invalid_identifier",
                "invalid_version",
                "unsupported_schema_version",
                "unsupported_protocol_version",
                "invalid_configuration",
                "invalid_secret_format",
                "invalid_credential_metadata",
            ),
            errors.map(DomainValidationError::code),
        )
        assertTrue(errors.all { it.description.isNotBlank() })
        assertTrue(errors.all { raw !in it.toString() && raw !in it.description })
    }
}
