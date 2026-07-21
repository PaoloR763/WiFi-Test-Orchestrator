package com.wifitestorchestrator.agent.domain.enrollment

import com.wifitestorchestrator.agent.domain.error.CredentialMetadataViolation
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidCredentialMetadata
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.lang.reflect.Modifier
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CredentialsTest {
    private val credentialId = credentialId("10000000-0000-4000-8000-000000000001")
    private val issuedAt = Instant.parse("2026-07-12T12:00:00Z")
    private val expiresAt = Instant.parse("2026-10-10T12:00:00Z")

    @Test
    fun credentialVersionRejectsZeroAndAcceptsTheIntRange() {
        val error = assertIs<InvalidCredentialMetadata>(assertIs<Invalid>(CredentialVersion.from(0)).error)

        assertEquals(CredentialMetadataViolation.NON_POSITIVE_VERSION, error.violation)
        assertEquals(1, valid(CredentialVersion.from(1)).value)
        assertEquals(Int.MAX_VALUE, valid(CredentialVersion.from(Int.MAX_VALUE)).value)
    }

    @Test
    fun credentialVersionUsesValueEquality() {
        val first = valid(CredentialVersion.from(7))
        val second = valid(CredentialVersion.from(7))

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertNotEquals(first, valid(CredentialVersion.from(8)))
    }

    @Test
    fun metadataRequiresExpiryStrictlyAfterIssue() {
        for (invalidExpiry in listOf(issuedAt, issuedAt.minusSeconds(1))) {
            val error =
                assertIs<InvalidCredentialMetadata>(
                    assertIs<Invalid>(
                        CredentialMetadata.create(
                            credentialId,
                            valid(CredentialVersion.from(1)),
                            issuedAt,
                            invalidExpiry,
                            CredentialDeliveryState.ACTIVE,
                        ),
                    ).error,
                )
            assertEquals(CredentialMetadataViolation.EXPIRY_NOT_AFTER_ISSUE, error.violation)
        }
    }

    @Test
    fun activeCredentialIsUsableBeforeExpiry() {
        val metadata = metadata(CredentialDeliveryState.ACTIVE)

        assertEquals(CredentialUsability.Usable, metadata.usabilityAt(issuedAt))
        assertEquals(CredentialUsability.Usable, metadata.usabilityAt(expiresAt.minusNanos(1)))
    }

    @Test
    fun expiryBoundaryAndLaterAreExpired() {
        val metadata = metadata(CredentialDeliveryState.ACTIVE)

        assertEquals(CredentialUsability.Expired, metadata.usabilityAt(expiresAt))
        assertEquals(CredentialUsability.Expired, metadata.usabilityAt(expiresAt.plusSeconds(1)))
    }

    @Test
    fun pendingCredentialIsNeverUsableBeforeActivation() {
        val metadata = metadata(CredentialDeliveryState.PENDING)

        assertEquals(CredentialUsability.PendingActivation, metadata.usabilityAt(issuedAt))
        assertEquals(
            CredentialUsability.PendingActivation,
            metadata.usabilityAt(expiresAt.minusNanos(1)),
        )
    }

    @Test
    fun expiredPendingCredentialIsExpired() {
        val metadata = metadata(CredentialDeliveryState.PENDING)

        assertEquals(CredentialUsability.Expired, metadata.usabilityAt(expiresAt))
    }

    @Test
    fun metadataContainsOnlySafeRequiredFieldsAndUsesStructuralEquality() {
        val first = metadata(CredentialDeliveryState.ACTIVE)
        val second = metadata(CredentialDeliveryState.ACTIVE)

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertEquals(
            setOf("credentialId", "version", "issuedAt", "expiresAt", "deliveryState"),
            CredentialMetadata::class.java.declaredFields
                .filterNot { Modifier.isStatic(it.modifiers) }
                .map { it.name }
                .toSet(),
        )
        assertFalse(CredentialMetadata::class.java.declaredFields.any { "secret" in it.name.lowercase() })
    }

    @Test
    fun deliveredCredentialRequiresLocatorAndMetadataToMatch() {
        val otherId = "10000000-0000-4000-8000-000000000002"
        val mismatchSecret = credentialSecret(otherId)
        val error =
            assertIs<InvalidCredentialMetadata>(
                assertIs<Invalid>(DeliveredCredential.create(metadata(), mismatchSecret)).error,
            )

        assertEquals(CredentialMetadataViolation.CREDENTIAL_ID_MISMATCH, error.violation)
    }

    @Test
    fun deliveredCredentialProvidesExplicitSecretCallback() {
        val delivered = deliveredCredential()
        val expected = credentialRaw(credentialId.toString())

        assertTrue(
            delivered.useSecret { it == expected },
            "The delivered credential callback did not expose the expected value",
        )
        assertEquals(metadata(), delivered.metadata)
    }

    @Test
    fun deliveredCredentialRedactsSecretAndUsesReferenceEquality() {
        val first = deliveredCredential()
        val second = deliveredCredential()
        val raw = credentialRaw(credentialId.toString())

        assertFalse(raw in first.toString())
        assertTrue("secret=<redacted>" in first.toString())
        assertNotEquals(first, second)
        val methods = DeliveredCredential::class.java.declaredMethods.map { it.name }
        assertFalse("copy" in methods)
        assertFalse(methods.any { it.startsWith("component") })
        assertFalse("equals" in methods)
        assertFalse("hashCode" in methods)
    }

    @Test
    fun usabilityIsASealedFactInsteadOfABooleanApi() {
        assertFalse(CredentialMetadata::class.java.methods.any { it.name == "isUsable" })
        assertEquals(
            setOf(
                CredentialUsability.Usable,
                CredentialUsability.PendingActivation,
                CredentialUsability.Expired,
            ),
            setOf(
                metadata(CredentialDeliveryState.ACTIVE).usabilityAt(issuedAt),
                metadata(CredentialDeliveryState.PENDING).usabilityAt(issuedAt),
                metadata(CredentialDeliveryState.ACTIVE).usabilityAt(expiresAt),
            ),
        )
    }

    private fun metadata(
        state: CredentialDeliveryState = CredentialDeliveryState.ACTIVE,
    ): CredentialMetadata =
        valid(
            CredentialMetadata.create(
                credentialId = credentialId,
                version = valid(CredentialVersion.from(1)),
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                deliveryState = state,
            ),
        )

    private fun deliveredCredential(): DeliveredCredential =
        valid(DeliveredCredential.create(metadata(), credentialSecret(credentialId.toString())))

    private fun credentialSecret(id: String): AgentCredentialSecret =
        valid(AgentCredentialSecret.parse(credentialRaw(id)))

    private fun credentialRaw(id: String): String = "wto_ac_1.$id.${"A".repeat(43)}"

    private fun credentialId(raw: String): CredentialId = valid(CredentialId.parse(raw))

    private fun <T : Any> valid(result: ValidationResult<T>): T = assertIs<Valid<T>>(result).value
}
