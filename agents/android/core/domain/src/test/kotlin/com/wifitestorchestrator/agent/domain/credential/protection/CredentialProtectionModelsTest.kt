package com.wifitestorchestrator.agent.domain.credential.protection

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CredentialProtectionModelsTest {
    @Test
    fun policyIsClosedToTheApprovedV1Values() {
        assertTrue(CredentialCryptoVersion.entries == listOf(CredentialCryptoVersion.V1))
        assertTrue(CredentialKeyAlias.entries == listOf(CredentialKeyAlias.V1))
        assertTrue(CredentialProtectionPolicyV1.KEY_SIZE_BITS == 256)
        assertTrue(CredentialProtectionPolicyV1.NONCE_SIZE_BYTES == 12)
        assertTrue(CredentialProtectionPolicyV1.AUTHENTICATION_TAG_SIZE_BITS == 128)
        assertTrue(CredentialProtectionPolicyV1.PLAINTEXT_SIZE_BYTES == 89)
        assertTrue(CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES == 105)
    }

    @Test
    fun publicResultsHaveNoGenericUsedValueAndRedactTheirRepresentations() {
        val values =
            listOf(
                CredentialProtectionInspection.Missing,
                CredentialProtectionInspection.Compatible(CredentialKeySecurityLevel.UNKNOWN),
                CredentialProtectionInspection.Incompatible,
                CredentialProtectionInspection.Unavailable(
                    CredentialProtectionError.PROVIDER_FAILURE,
                ),
                CredentialProtectionPreparation.Created,
                CredentialProtectionPreparation.AlreadyCompatible,
                CredentialProtectionPreparation.Failure(
                    CredentialProtectionError.KEY_INCOMPATIBLE,
                ),
                ProtectCredentialResult.Failure(CredentialProtectionError.ENCRYPTION_FAILED),
                UseDecryptedCredentialResult.Used,
                UseDecryptedCredentialResult.Failure(
                    CredentialProtectionError.DECRYPTION_FAILED,
                ),
            )

        values.forEach { value -> assertTrue("<redacted>" in value.toString()) }
        CredentialProtectionError.entries.forEach { error ->
            assertTrue("<redacted>" in error.toString())
            assertFalse(error.name in error.toString())
        }
        assertFalse(UseDecryptedCredentialResult.Used::class.java.declaredFields.any { field ->
            !field.isSynthetic && field.name != "INSTANCE"
        })
        assertFalse(
            UseDecryptedCredentialResult::class.java.typeParameters.isNotEmpty(),
        )
    }

    @Test
    fun securityLevelIsEvidenceOnlyAndHasNoAndroidTypes() {
        assertTrue(CredentialKeySecurityLevel.entries.size == 6)
        CredentialKeySecurityLevel.entries.forEach { level ->
            assertTrue("<redacted>" in level.toString())
            assertFalse("android." in level::class.java.name)
        }
    }

    @Test
    fun publicPortExposesNoAndroidOrJcaTypesAndCallbackReturnsOnlyUnit() {
        val methods = CredentialProtector::class.java.declaredMethods
        val exposedTypes =
            methods.flatMap { method ->
                method.genericParameterTypes.map { it.typeName } + method.genericReturnType.typeName
            }
        val use = methods.single { it.name == "useDecryptedCredential" }

        assertFalse(exposedTypes.any { it.contains("android.") })
        assertFalse(exposedTypes.any { it.contains("javax.crypto") })
        assertFalse(exposedTypes.any { it.contains("java.security") })
        assertTrue(use.genericParameterTypes.last().typeName.contains("kotlin.Unit"))
    }
}
