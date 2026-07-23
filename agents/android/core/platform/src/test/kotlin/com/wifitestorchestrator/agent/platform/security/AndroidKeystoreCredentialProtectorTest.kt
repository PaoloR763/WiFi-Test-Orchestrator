package com.wifitestorchestrator.agent.platform.security

import android.security.keystore.KeyProperties
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.UseDecryptedCredentialResult
import java.util.Date
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

class AndroidKeystoreCredentialProtectorTest {
    @Test
    fun protectAndCallbackScopedUseRoundTripWithStrictSyntheticCredential() {
        val protector = protector()
        val protected = assertIs<ProtectCredentialResult.Protected>(protector.protect(deliveredCredential()))
        var callbackCount = 0

        val result =
            protector.useDecryptedCredential(protected.envelope) { secret ->
                callbackCount += 1
                secret.useSecret { raw -> assertEquals(TEST_CREDENTIAL_RAW, raw) }
                Unit
            }

        assertSame(UseDecryptedCredentialResult.Used, result)
        assertEquals(1, callbackCount)
    }

    @Test
    fun inspectIsReadOnlyPrepareIsIdempotentAndProtectCanCreate() {
        val inspectAccess = MutableCredentialKeyAccess()
        val inspectProtector = protector(keyAccess = inspectAccess)

        assertSame(CredentialProtectionInspection.Missing, inspectProtector.inspect())
        assertEquals(0, inspectAccess.createCount.get())
        assertSame(CredentialProtectionPreparation.Created, inspectProtector.prepare())
        assertSame(CredentialProtectionPreparation.AlreadyCompatible, inspectProtector.prepare())
        assertEquals(1, inspectAccess.createCount.get())

        val protectAccess = MutableCredentialKeyAccess()
        assertIs<ProtectCredentialResult.Protected>(
            protector(keyAccess = protectAccess).protect(deliveredCredential()),
        )
        assertEquals(1, protectAccess.createCount.get())
    }

    @Test
    fun pre361ProductKeyAccessCompletesCreateReinspectProtectAndDecryptLifecycle() {
        PRE_36_1_PLATFORM_VERSIONS.forEach { platformVersion ->
            val getter =
                RecordingUnlockedDeviceRequirementGetter(
                    failure = AssertionError("pre-36.1 getter must not be invoked"),
                )
            val usageGetter = RecordingRemainingUsageCountGetter()
            val randomizedProbe = RecordingRandomizedEncryptionRequirementProbe()
            val backend =
                SyntheticKeyInfoBackend(
                    unlockedDeviceRequirementGetter = getter,
                    remainingUsageCountGetter = usageGetter,
                )
            val candidate =
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = backend,
                            platformVersion = platformVersion,
                            randomizedEncryptionProbe = randomizedProbe,
                        ),
                )

            assertSame(CredentialProtectionInspection.Missing, candidate.inspect())
            assertSame(CredentialProtectionPreparation.Created, candidate.prepare())
            assertEquals(3, backend.inspectCount.get())
            assertEquals(1, backend.createCount.get())
            assertEquals(0, getter.invocationCount.get())
            assertSame(
                UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                backend.lastUnlockedDeviceRequirementEvidence,
            )
            assertSame(
                if (supportsRemainingUsageCountInspection(platformVersion)) {
                    RemainingUsageCountEvidence.UNRESTRICTED
                } else {
                    RemainingUsageCountEvidence.NOT_OBSERVABLE
                },
                backend.lastRemainingUsageCountEvidence,
            )
            assertIs<CredentialProtectionInspection.Compatible>(candidate.inspect())
            assertSame(CredentialProtectionPreparation.AlreadyCompatible, candidate.prepare())

            val protected =
                assertIs<ProtectCredentialResult.Protected>(
                    candidate.protect(deliveredCredential()),
                )
            var callbackCount = 0
            val used =
                candidate.useDecryptedCredential(protected.envelope) { secret ->
                    callbackCount += 1
                    secret.useSecret { raw -> assertEquals(TEST_CREDENTIAL_RAW, raw) }
                }

            assertSame(UseDecryptedCredentialResult.Used, used)
            assertEquals(1, callbackCount)
            assertEquals(1, backend.createCount.get())
            assertEquals(0, getter.invocationCount.get())
            assertEquals(
                if (supportsRemainingUsageCountInspection(platformVersion)) 5 else 0,
                usageGetter.invocationCount.get(),
            )
            assertEquals(5, randomizedProbe.invocationCount.get())
        }
    }

    @Test
    fun pre361ProductKeyAccessAcceptsCompatiblePreexistingAliasButDecryptMissingNeverCreates() {
        PRE_36_1_PLATFORM_VERSIONS.forEach { platformVersion ->
            val existingGetter = RecordingUnlockedDeviceRequirementGetter(result = false)
            val existingProbe = RecordingRandomizedEncryptionRequirementProbe()
            val existingBackend =
                SyntheticKeyInfoBackend(
                    initialAliasPresent = true,
                    unlockedDeviceRequirementGetter = existingGetter,
                )
            val existing =
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = existingBackend,
                            platformVersion = platformVersion,
                            randomizedEncryptionProbe = existingProbe,
                        ),
                )

            assertIs<CredentialProtectionInspection.Compatible>(existing.inspect())
            assertSame(CredentialProtectionPreparation.AlreadyCompatible, existing.prepare())
            assertEquals(0, existingBackend.createCount.get())
            assertEquals(0, existingGetter.invocationCount.get())
            assertEquals(2, existingProbe.invocationCount.get())
            assertSame(
                UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                existingBackend.lastUnlockedDeviceRequirementEvidence,
            )

            val incompatibleBackend =
                SyntheticKeyInfoBackend(
                    initialAliasPresent = true,
                    descriptorProvider = { unlockedEvidence, usageEvidence ->
                        androidKeyDescriptor(
                            algorithm = "HmacSHA256",
                            unlockedDeviceRequirement = unlockedEvidence,
                            remainingUsageCount = usageEvidence,
                        )
                    },
                )
            val incompatible =
                protector(
                    keyAccess = AndroidKeystoreKeyAccess(incompatibleBackend, platformVersion),
                )
            val incompatiblePreparation =
                assertIs<CredentialProtectionPreparation.Failure>(incompatible.prepare())
            assertEquals(
                CredentialProtectionError.KEY_INCOMPATIBLE,
                incompatiblePreparation.error,
            )
            assertEquals(0, incompatibleBackend.createCount.get())

            val impossibleEvidenceGetter =
                RecordingUnlockedDeviceRequirementGetter(
                    failure = AssertionError("pre-36.1 getter must not be invoked"),
                )
            val impossibleEvidenceBackend =
                SyntheticKeyInfoBackend(
                    initialAliasPresent = true,
                    unlockedDeviceRequirementGetter = impossibleEvidenceGetter,
                    descriptorProvider = { _, usageEvidence ->
                        androidKeyDescriptor(
                            unlockedDeviceRequirement =
                                UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                            remainingUsageCount = usageEvidence,
                        )
                    },
                )
            val impossibleEvidencePreparation =
                assertIs<CredentialProtectionPreparation.Failure>(
                    protector(
                        keyAccess =
                            AndroidKeystoreKeyAccess(
                                impossibleEvidenceBackend,
                                platformVersion,
                            ),
                    ).prepare(),
                )
            assertEquals(
                CredentialProtectionError.KEY_INCOMPATIBLE,
                impossibleEvidencePreparation.error,
            )
            assertSame(
                UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                impossibleEvidenceBackend.lastUnlockedDeviceRequirementEvidence,
            )
            assertEquals(0, impossibleEvidenceGetter.invocationCount.get())
            assertEquals(0, impossibleEvidenceBackend.createCount.get())

            val missingBackend = SyntheticKeyInfoBackend()
            val missing =
                protector(
                    keyAccess = AndroidKeystoreKeyAccess(missingBackend, platformVersion),
                )
            val result =
                missing.useDecryptedCredential(
                    sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray()),
                ) { Unit }

            assertEquals(
                CredentialProtectionError.KEY_MISSING,
                assertIs<UseDecryptedCredentialResult.Failure>(result).error,
            )
            assertEquals(0, missingBackend.createCount.get())
        }
    }

    @Test
    fun pre361UnexpectedInspectionFailureIsUnavailableAndNeverBecomesCompatibilityEvidence() {
        PRE_36_1_PLATFORM_VERSIONS.forEach { platformVersion ->
            val failure = IllegalStateException("synthetic KeyInfo inspection failure")
            val backend =
                SyntheticKeyInfoBackend(initialAliasPresent = true).also {
                    it.inspectFailure = failure
                }
            val keyAccess = AndroidKeystoreKeyAccess(backend, platformVersion)

            assertSame(failure, assertFailsWith<IllegalStateException> { keyAccess.inspect() })

            val candidate = protector(keyAccess = keyAccess)
            val inspection = assertIs<CredentialProtectionInspection.Unavailable>(candidate.inspect())
            val preparation = assertIs<CredentialProtectionPreparation.Failure>(candidate.prepare())

            assertEquals(CredentialProtectionError.PROVIDER_FAILURE, inspection.error)
            assertEquals(CredentialProtectionError.PROVIDER_FAILURE, preparation.error)
            assertEquals(0, backend.createCount.get())
        }
    }

    @Test
    fun api361ObservedFalseCompletesLifecycleAndOtherEvidenceFailsClosed() {
        val compatibleGetter = RecordingUnlockedDeviceRequirementGetter(result = false)
        val compatibleUsageGetter = RecordingRemainingUsageCountGetter()
        val compatibleProbe = RecordingRandomizedEncryptionRequirementProbe()
        val compatibleBackend =
            SyntheticKeyInfoBackend(
                unlockedDeviceRequirementGetter = compatibleGetter,
                remainingUsageCountGetter = compatibleUsageGetter,
            )
        val compatible =
            protector(
                keyAccess =
                    AndroidKeystoreKeyAccess(
                        backend = compatibleBackend,
                        platformVersion = API_36_1,
                        randomizedEncryptionProbe = compatibleProbe,
                    ),
            )

        assertSame(CredentialProtectionPreparation.Created, compatible.prepare())
        assertSame(
            UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
            compatibleBackend.lastUnlockedDeviceRequirementEvidence,
        )
        assertEquals(1, compatibleGetter.invocationCount.get())
        assertSame(CredentialProtectionPreparation.AlreadyCompatible, compatible.prepare())

        val protected =
            assertIs<ProtectCredentialResult.Protected>(
                compatible.protect(deliveredCredential()),
            )
        var callbackCount = 0
        val used =
            compatible.useDecryptedCredential(protected.envelope) { secret ->
                callbackCount += 1
                secret.useSecret { raw -> assertEquals(TEST_CREDENTIAL_RAW, raw) }
            }
        assertSame(UseDecryptedCredentialResult.Used, used)
        assertEquals(1, callbackCount)
        assertEquals(4, compatibleGetter.invocationCount.get())
        assertEquals(4, compatibleUsageGetter.invocationCount.get())
        assertEquals(4, compatibleProbe.invocationCount.get())

        val requiredGetter = RecordingUnlockedDeviceRequirementGetter(result = true)
        val requiredBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                unlockedDeviceRequirementGetter = requiredGetter,
            )
        assertSame(
            InternalCredentialKeyInspection.Incompatible,
            AndroidKeystoreKeyAccess(requiredBackend, API_36_1).inspect(),
        )
        assertEquals(1, requiredGetter.invocationCount.get())
        assertSame(
            UnlockedDeviceRequirementEvidence.REQUIRED,
            requiredBackend.lastUnlockedDeviceRequirementEvidence,
        )

        val artificialNotObservableGetter = RecordingUnlockedDeviceRequirementGetter(result = false)
        val notObservableBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                unlockedDeviceRequirementGetter = artificialNotObservableGetter,
                descriptorProvider = { _, usageEvidence ->
                    androidKeyDescriptor(
                        unlockedDeviceRequirement =
                            UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                        remainingUsageCount = usageEvidence,
                    )
                },
            )
        assertSame(
            InternalCredentialKeyInspection.Incompatible,
            AndroidKeystoreKeyAccess(notObservableBackend, API_36_1).inspect(),
        )
        assertEquals(1, artificialNotObservableGetter.invocationCount.get())

        val getterFailure = IllegalStateException("synthetic API 36.1 getter failure")
        val failingGetter = RecordingUnlockedDeviceRequirementGetter(failure = getterFailure)
        val failingBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                unlockedDeviceRequirementGetter = failingGetter,
            )
        val failingAccess = AndroidKeystoreKeyAccess(failingBackend, API_36_1)
        assertSame(
            getterFailure,
            assertFailsWith<IllegalStateException> { failingAccess.inspect() },
        )
        val publicResult =
            assertIs<CredentialProtectionInspection.Unavailable>(
                protector(keyAccess = failingAccess).inspect(),
            )
        assertEquals(CredentialProtectionError.PROVIDER_FAILURE, publicResult.error)
        assertEquals(2, failingGetter.invocationCount.get())
        assertEquals(0, failingBackend.createCount.get())
    }

    @Test
    fun api361GetterCancellationAndErrorPropagateThroughTheAdapter() {
        val cancellation = CancellationException("synthetic cancellation")
        val cancellingGetter =
            RecordingUnlockedDeviceRequirementGetter(
                failure = IllegalStateException("synthetic wrapper", cancellation),
            )
        val cancellingBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                unlockedDeviceRequirementGetter = cancellingGetter,
            )

        assertSame(
            cancellation,
            assertFailsWith<CancellationException> {
                protector(
                    keyAccess = AndroidKeystoreKeyAccess(cancellingBackend, API_36_1),
                ).inspect()
            },
        )
        assertEquals(1, cancellingGetter.invocationCount.get())

        val fatal = AssertionError("synthetic fatal")
        val fatalGetter = RecordingUnlockedDeviceRequirementGetter(failure = fatal)
        val fatalBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                unlockedDeviceRequirementGetter = fatalGetter,
            )
        assertSame(
            fatal,
            assertFailsWith<AssertionError> {
                protector(
                    keyAccess = AndroidKeystoreKeyAccess(fatalBackend, API_36_1),
                ).inspect()
            },
        )
        assertEquals(1, fatalGetter.invocationCount.get())
    }

    @Test
    fun everyStaticIncompatibilityShortCircuitsProbeAndLifecycleOperations() {
        val cases =
            listOf(
                StaticIncompatibilityCase("alias") { unlocked, usage ->
                    androidKeyDescriptor(
                        alias = "synthetic.other.alias",
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("algorithm") { unlocked, usage ->
                    androidKeyDescriptor(
                        algorithm = "HmacSHA256",
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("exportability") { unlocked, usage ->
                    androidKeyDescriptor(
                        encodedIsNull = false,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("format") { unlocked, usage ->
                    androidKeyDescriptor(
                        formatIsNull = false,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("size") { unlocked, usage ->
                    androidKeyDescriptor(
                        keySizeBits = 128,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("decrypt-only purposes") { unlocked, usage ->
                    androidKeyDescriptor(
                        purposes = KeyProperties.PURPOSE_DECRYPT,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("block mode") { unlocked, usage ->
                    androidKeyDescriptor(
                        blockModes = setOf(KeyProperties.BLOCK_MODE_CBC),
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("padding") { unlocked, usage ->
                    androidKeyDescriptor(
                        encryptionPaddings = setOf(KeyProperties.ENCRYPTION_PADDING_PKCS7),
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("user authentication") { unlocked, usage ->
                    androidKeyDescriptor(
                        userAuthenticationRequired = true,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("user confirmation") { unlocked, usage ->
                    androidKeyDescriptor(
                        userConfirmationRequired = true,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("trusted presence") { unlocked, usage ->
                    androidKeyDescriptor(
                        trustedUserPresenceRequired = true,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("confirmation and presence") { unlocked, usage ->
                    androidKeyDescriptor(
                        userConfirmationRequired = true,
                        trustedUserPresenceRequired = true,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("unlocked-device") { _, usage ->
                    androidKeyDescriptor(
                        unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.REQUIRED,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("validity start") { unlocked, usage ->
                    androidKeyDescriptor(
                        unlockedDeviceRequirement = unlocked,
                        keyValidityStart = Date(0),
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("origination validity") { unlocked, usage ->
                    androidKeyDescriptor(
                        unlockedDeviceRequirement = unlocked,
                        keyValidityForOriginationEnd = Date(0),
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("consumption validity") { unlocked, usage ->
                    androidKeyDescriptor(
                        unlockedDeviceRequirement = unlocked,
                        keyValidityForConsumptionEnd = Date(0),
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("origin") { unlocked, usage ->
                    androidKeyDescriptor(
                        origin = KeyProperties.ORIGIN_IMPORTED,
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = usage,
                    )
                },
                StaticIncompatibilityCase("remaining usage") { unlocked, _ ->
                    androidKeyDescriptor(
                        unlockedDeviceRequirement = unlocked,
                        remainingUsageCount = RemainingUsageCountEvidence.LIMITED,
                    )
                },
            )

        cases.forEach { case ->
            val probe = RecordingRandomizedEncryptionRequirementProbe()
            val backend =
                SyntheticKeyInfoBackend(
                    initialAliasPresent = true,
                    descriptorProvider = case.descriptorProvider,
                )
            val cipherHandleCreations = AtomicInteger()
            val candidate =
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = backend,
                            platformVersion = API_36_1,
                            randomizedEncryptionProbe = probe,
                        ),
                    credentialCipher =
                        AesGcmCredentialCipher(
                            AeadCipherHandleFactory {
                                cipherHandleCreations.incrementAndGet()
                                FixedOutputHandle(ByteArray(105))
                            },
                        ),
                )

            assertSame(
                CredentialProtectionInspection.Incompatible,
                candidate.inspect(),
                case.name,
            )
            assertEquals(
                CredentialProtectionError.KEY_INCOMPATIBLE,
                assertIs<CredentialProtectionPreparation.Failure>(candidate.prepare()).error,
                case.name,
            )
            assertEquals(
                CredentialProtectionError.KEY_INCOMPATIBLE,
                assertIs<ProtectCredentialResult.Failure>(
                    candidate.protect(deliveredCredential()),
                ).error,
                case.name,
            )
            assertEquals(0, probe.invocationCount.get(), case.name)
            assertEquals(0, backend.createCount.get(), case.name)
            assertEquals(0, cipherHandleCreations.get(), case.name)
        }
    }

    @Test
    fun limitedUsageAliasCannotProduceOrDecryptAnEnvelopeAndIsNeverReplaced() {
        val usageGetter = RecordingRemainingUsageCountGetter(result = 1)
        val probe = RecordingRandomizedEncryptionRequirementProbe()
        val backend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                remainingUsageCountGetter = usageGetter,
            )
        val cipherHandleCreations = AtomicInteger()
        val candidate =
            protector(
                keyAccess =
                    AndroidKeystoreKeyAccess(
                        backend = backend,
                        platformVersion = API_31,
                        randomizedEncryptionProbe = probe,
                    ),
                credentialCipher =
                    AesGcmCredentialCipher(
                        AeadCipherHandleFactory {
                            cipherHandleCreations.incrementAndGet()
                            FixedOutputHandle(ByteArray(105))
                        },
                    ),
            )

        assertEquals(
            CredentialProtectionError.KEY_INCOMPATIBLE,
            assertIs<ProtectCredentialResult.Failure>(
                candidate.protect(deliveredCredential()),
            ).error,
        )
        assertEquals(
            CredentialProtectionError.KEY_INCOMPATIBLE,
            assertIs<UseDecryptedCredentialResult.Failure>(
                candidate.useDecryptedCredential(
                    sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray()),
                ) { Unit },
            ).error,
        )
        assertSame(RemainingUsageCountEvidence.LIMITED, backend.lastRemainingUsageCountEvidence)
        assertEquals(2, usageGetter.invocationCount.get())
        assertEquals(0, probe.invocationCount.get())
        assertEquals(0, cipherHandleCreations.get())
        assertEquals(0, backend.createCount.get())
    }

    @Test
    fun usageGetterAndRandomizedProbeFailuresRemainClosedAndPreserveFatalSemantics() {
        val usageFailure = IllegalStateException("synthetic usage getter failure")
        val usageProbe = RecordingRandomizedEncryptionRequirementProbe()
        val failingUsageBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                remainingUsageCountGetter =
                    RecordingRemainingUsageCountGetter(failure = usageFailure),
            )
        val usageResult =
            assertIs<CredentialProtectionInspection.Unavailable>(
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = failingUsageBackend,
                            platformVersion = API_31,
                            randomizedEncryptionProbe = usageProbe,
                        ),
                ).inspect(),
            )
        assertEquals(CredentialProtectionError.PROVIDER_FAILURE, usageResult.error)
        assertEquals(0, usageProbe.invocationCount.get())

        val acceptedIvProbe =
            RecordingRandomizedEncryptionRequirementProbe(
                result = RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_ACCEPTED,
            )
        val acceptedIvBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
            )
        assertEquals(
            CredentialProtectionError.KEY_INCOMPATIBLE,
            assertIs<CredentialProtectionPreparation.Failure>(
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = acceptedIvBackend,
                            platformVersion = API_36_1,
                            randomizedEncryptionProbe = acceptedIvProbe,
                        ),
                ).prepare(),
            ).error,
        )
        assertEquals(1, acceptedIvProbe.invocationCount.get())

        val probeFailure = IllegalStateException("synthetic randomized probe failure")
        val failingProbe = RecordingRandomizedEncryptionRequirementProbe(failure = probeFailure)
        val probeResult =
            assertIs<CredentialProtectionInspection.Unavailable>(
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = SyntheticKeyInfoBackend(initialAliasPresent = true),
                            platformVersion = API_36_1,
                            randomizedEncryptionProbe = failingProbe,
                        ),
                ).inspect(),
            )
        assertEquals(CredentialProtectionError.PROVIDER_FAILURE, probeResult.error)
        assertEquals(1, failingProbe.invocationCount.get())

        val probeCancellation = CancellationException("synthetic probe cancellation")
        val cancellingProbe =
            RecordingRandomizedEncryptionRequirementProbe(
                failure = IllegalStateException("synthetic wrapper", probeCancellation),
            )
        assertSame(
            probeCancellation,
            assertFailsWith<CancellationException> {
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = SyntheticKeyInfoBackend(initialAliasPresent = true),
                            platformVersion = API_36_1,
                            randomizedEncryptionProbe = cancellingProbe,
                        ),
                ).inspect()
            },
        )
        assertEquals(1, cancellingProbe.invocationCount.get())

        val probeFatal = AssertionError("synthetic probe fatal")
        val fatalProbe = RecordingRandomizedEncryptionRequirementProbe(failure = probeFatal)
        assertSame(
            probeFatal,
            assertFailsWith<AssertionError> {
                protector(
                    keyAccess =
                        AndroidKeystoreKeyAccess(
                            backend = SyntheticKeyInfoBackend(initialAliasPresent = true),
                            platformVersion = API_36_1,
                            randomizedEncryptionProbe = fatalProbe,
                        ),
                ).inspect()
            },
        )
        assertEquals(1, fatalProbe.invocationCount.get())

        val cancellation = CancellationException("synthetic usage cancellation")
        val cancellingBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                remainingUsageCountGetter =
                    RecordingRemainingUsageCountGetter(failure = cancellation),
            )
        assertSame(
            cancellation,
            assertFailsWith<CancellationException> {
                protector(
                    keyAccess = AndroidKeystoreKeyAccess(cancellingBackend, API_31),
                ).inspect()
            },
        )

        val fatal = AssertionError("synthetic usage fatal")
        val fatalBackend =
            SyntheticKeyInfoBackend(
                initialAliasPresent = true,
                remainingUsageCountGetter = RecordingRemainingUsageCountGetter(failure = fatal),
            )
        assertSame(
            fatal,
            assertFailsWith<AssertionError> {
                protector(
                    keyAccess = AndroidKeystoreKeyAccess(fatalBackend, API_31),
                ).inspect()
            },
        )
    }

    @Test
    fun decryptWithMissingKeyNeverCreatesAndIncompatibleKeyIsNeverReplaced() {
        val validEnvelope = sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray())
        val missing = MutableCredentialKeyAccess()
        val missingResult = protector(keyAccess = missing).useDecryptedCredential(validEnvelope) { Unit }

        assertEquals(
            CredentialProtectionError.KEY_MISSING,
            assertIs<UseDecryptedCredentialResult.Failure>(missingResult).error,
        )
        assertEquals(0, missing.createCount.get())

        val incompatible =
            MutableCredentialKeyAccess(InternalCredentialKeyInspection.Incompatible)
        val preparation = protector(keyAccess = incompatible).prepare()
        val protection = protector(keyAccess = incompatible).protect(deliveredCredential())

        assertEquals(
            CredentialProtectionError.KEY_INCOMPATIBLE,
            assertIs<CredentialProtectionPreparation.Failure>(preparation).error,
        )
        assertEquals(
            CredentialProtectionError.KEY_INCOMPATIBLE,
            assertIs<ProtectCredentialResult.Failure>(protection).error,
        )
        assertEquals(0, incompatible.createCount.get())
    }

    @Test
    fun creationRaceFailureRereadsAndAcceptsOnlyTheCompatibleWinner() {
        var inspections = 0
        var creations = 0
        val racingAccess =
            object : CredentialKeyAccess {
                override fun inspect(): InternalCredentialKeyInspection {
                    inspections += 1
                    return if (inspections == 1) {
                        InternalCredentialKeyInspection.Missing
                    } else {
                        compatibleInspection()
                    }
                }

                override fun create() {
                    creations += 1
                    throw CredentialKeyAliasOccupiedException()
                }
            }

        val result = protector(keyAccess = racingAccess).prepare()

        assertSame(CredentialProtectionPreparation.AlreadyCompatible, result)
        assertEquals(2, inspections)
        assertEquals(1, creations)
    }

    @Test
    fun unknownSecurityEvidenceDoesNotBlockACompatibleKey() {
        val access =
            MutableCredentialKeyAccess(
                compatibleInspection(securityLevel = CredentialKeySecurityLevel.UNKNOWN),
            )

        val inspection = assertIs<CredentialProtectionInspection.Compatible>(protector(access).inspect())

        assertEquals(CredentialKeySecurityLevel.UNKNOWN, inspection.securityLevel)
        assertEquals(0, access.createCount.get())
    }

    @Test
    fun allAuthenticatedTamperingAndWrongKeyCollapseToAuthenticationFailed() {
        val original = sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray())
        val (nonce, sealed) = original.materialCopies()
        val changedCiphertext = sealed.copyOf().also { it[0] = it[0].inc() }
        val changedTag = sealed.copyOf().also { it[it.lastIndex] = it.last().inc() }
        val changedNonce = nonce.copyOf().also { it[0] = it[0].inc() }
        val changedAadEnvelope =
            envelope(
                nonce = nonce,
                sealedCredential = sealed,
                version = credentialVersion(2),
            )
        val cases =
            listOf(
                protector() to envelope(nonce, changedCiphertext),
                protector() to envelope(nonce, changedTag),
                protector() to envelope(changedNonce, sealed),
                protector() to changedAadEnvelope,
                protector(
                    keyAccess = MutableCredentialKeyAccess(compatibleInspection(OTHER_KEY)),
                ) to original,
            )

        cases.forEach { (candidate, candidateEnvelope) ->
            val result = candidate.useDecryptedCredential(candidateEnvelope) { Unit }
            assertEquals(
                CredentialProtectionError.AUTHENTICATION_FAILED,
                assertIs<UseDecryptedCredentialResult.Failure>(result).error,
            )
        }
    }

    @Test
    fun authenticatedNonAsciiMalformedAndCredentialIdMismatchFailClosed() {
        val nonAscii = ByteArray(89) { 'A'.code.toByte() }.also { it[42] = 0x80.toByte() }
        val malformed = ByteArray(89) { 'x'.code.toByte() }
        val mismatched = SECOND_CREDENTIAL_RAW.encodeToByteArray()

        listOf(nonAscii, malformed, mismatched).forEach { plaintext ->
            val result =
                protector().useDecryptedCredential(sealedEnvelopeFor(plaintext)) { Unit }
            assertEquals(
                CredentialProtectionError.DECRYPTION_FAILED,
                assertIs<UseDecryptedCredentialResult.Failure>(result).error,
            )
        }
    }

    @Test
    fun wrongAuthenticatedPlaintextLengthFailsBeforeParsing() {
        val shortPlaintextCipher =
            AesGcmCredentialCipher(
                AeadCipherHandleFactory { FixedOutputHandle(ByteArray(88)) },
            )
        val validEnvelope = sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray())

        val result =
            protector(credentialCipher = shortPlaintextCipher)
                .useDecryptedCredential(validEnvelope) { Unit }

        assertEquals(
            CredentialProtectionError.DECRYPTION_FAILED,
            assertIs<UseDecryptedCredentialResult.Failure>(result).error,
        )
    }

    @Test
    fun strictCredentialEncodingRejectsLengthAndNonAsciiWithoutReplacement() {
        assertEquals(89, TEST_CREDENTIAL_RAW.toStrictCredentialBytes()?.size)
        assertEquals(null, TEST_CREDENTIAL_RAW.dropLast(1).toStrictCredentialBytes())
        assertEquals(null, ("é" + TEST_CREDENTIAL_RAW.drop(1)).toStrictCredentialBytes())
    }

    @Test
    fun controlledBuffersAreZeroizedAfterProtectAndUseSuccess() {
        val protectCleaner = RecordingBufferCleaner()
        val protected =
            assertIs<ProtectCredentialResult.Protected>(
                protector(cleaner = protectCleaner).protect(deliveredCredential()),
            )

        assertEquals(3, protectCleaner.buffers.size)
        assertTrue(protectCleaner.buffers.all(ByteArray::isZeroed))

        val decryptCleaner = RecordingBufferCleaner()
        val result =
            protector(cleaner = decryptCleaner)
                .useDecryptedCredential(protected.envelope) { Unit }

        assertSame(UseDecryptedCredentialResult.Used, result)
        assertEquals(1, decryptCleaner.buffers.size)
        assertTrue(decryptCleaner.buffers.single().isZeroed())
    }

    @Test
    fun plaintextIsZeroizedAfterEncryptionFailure() {
        val cleaner = RecordingBufferCleaner()
        val cipher =
            AesGcmCredentialCipher(
                AeadCipherHandleFactory {
                    ThrowingHandle(IllegalStateException("synthetic provider failure"))
                },
            )

        val result = protector(credentialCipher = cipher, cleaner = cleaner).protect(deliveredCredential())

        assertEquals(
            CredentialProtectionError.ENCRYPTION_FAILED,
            assertIs<ProtectCredentialResult.Failure>(result).error,
        )
        assertEquals(1, cleaner.buffers.size)
        assertTrue(cleaner.buffers.single().isZeroed())
    }

    @Test
    fun callbackFailurePropagatesAfterCleanupAndCleanupFailureIsSuppressed() {
        val callbackFailure = IllegalStateException("synthetic callback failure")
        val cleanupFailure = IllegalArgumentException("synthetic cleanup failure")
        val cleaner = RecordingBufferCleaner(cleanupFailure)
        val validEnvelope = sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray())

        val observed =
            assertFailsWith<IllegalStateException> {
                protector(cleaner = cleaner).useDecryptedCredential(validEnvelope) {
                    throw callbackFailure
                }
            }

        assertSame(callbackFailure, observed)
        assertEquals(listOf(cleanupFailure), observed.suppressedExceptions)
        assertTrue(cleaner.buffers.single().isZeroed())
    }

    @Test
    fun nestedCancellationAndErrorArePropagatedWithoutMapping() {
        val cancellation = CancellationException("synthetic cancellation")
        val cancellingCipher =
            AesGcmCredentialCipher(
                AeadCipherHandleFactory {
                    ThrowingHandle(IllegalStateException("synthetic wrapper", cancellation))
                },
            )
        val fatal = AssertionError("synthetic fatal")
        val fatalAccess = MutableCredentialKeyAccess().also { it.inspectFailure = fatal }

        assertSame(
            cancellation,
            assertFailsWith<CancellationException> {
                protector(credentialCipher = cancellingCipher).protect(deliveredCredential())
            },
        )
        assertSame(
            fatal,
            assertFailsWith<AssertionError> { protector(fatalAccess).inspect() },
        )
    }

    @Test
    fun productionLifecycleLockIsSharedAcrossAdapterInstances() {
        val access = MutableCredentialKeyAccess()
        val executor = Executors.newFixedThreadPool(8)
        val protectors =
            List(24) {
                AndroidCredentialProtectionFactory.createForTesting(
                    keyAccess = access,
                    credentialCipher = AesGcmCredentialCipher(),
                    operationGuard = NoOpBlockingGuard,
                    bufferCleaner = ZeroizingBufferCleaner,
                    lifecycleLock = ProductionCredentialKeyLifecycleLocks.v1,
                )
            }
        try {
            val futures =
                protectors.map { candidate ->
                    executor.submit(Callable { candidate.prepare() })
                }
            val results = futures.map { future -> future.get(10, TimeUnit.SECONDS) }

            assertEquals(1, access.createCount.get())
            assertEquals(1, results.count { it === CredentialProtectionPreparation.Created })
            assertEquals(
                23,
                results.count { it === CredentialProtectionPreparation.AlreadyCompatible },
            )
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun publicFailuresAndInternalEncryptionRenderingNeverCarrySensitiveMaterialOrCauses() {
        val failure = ProtectCredentialResult.Failure(CredentialProtectionError.ENCRYPTION_FAILED)
        val rendering =
            listOf(
                failure.toString(),
                CredentialProtectionInspection.Unavailable(
                    CredentialProtectionError.PROVIDER_FAILURE,
                ).toString(),
                AesGcmEncryption(ByteArray(12), ByteArray(105)).toString(),
            ).joinToString()

        assertFalse(rendering.contains(TEST_CREDENTIAL_RAW))
        assertFalse(rendering.contains("com.wifitestorchestrator"))
        assertFalse(rendering.contains("Throwable"))
        assertFalse(rendering.contains("Exception"))
        assertTrue(rendering.contains("<redacted>"))
        assertEquals(
            setOf("error"),
            ProtectCredentialResult.Failure::class.java.declaredFields.map { it.name }.toSet(),
        )
    }
}

private class StaticIncompatibilityCase(
    val name: String,
    val descriptorProvider:
        (
            UnlockedDeviceRequirementEvidence,
            RemainingUsageCountEvidence,
        ) -> AndroidCredentialStaticKeyDescriptor,
)

private class FixedOutputHandle(
    private val output: ByteArray,
) : AeadCipherHandle {
    override fun initEncrypt(key: SecretKey) = Unit

    override fun initDecrypt(
        key: SecretKey,
        parameters: GCMParameterSpec,
    ) = Unit

    override fun updateAad(aad: ByteArray) = Unit

    override fun doFinal(input: ByteArray): ByteArray = output.copyOf()

    override fun iv(): ByteArray = ByteArray(12)
}

private class ThrowingHandle(
    private val failure: Throwable,
) : AeadCipherHandle {
    override fun initEncrypt(key: SecretKey) = Unit

    override fun initDecrypt(
        key: SecretKey,
        parameters: GCMParameterSpec,
    ) = Unit

    override fun updateAad(aad: ByteArray) = Unit

    override fun doFinal(input: ByteArray): ByteArray = throw failure

    override fun iv(): ByteArray = ByteArray(12)
}

private fun ProtectedCredentialEnvelope.materialCopies(): Pair<ByteArray, ByteArray> {
    var nonceCopy: ByteArray? = null
    var sealedCopy: ByteArray? = null
    useNonce { nonce -> nonceCopy = nonce.copyOf() }
    useSealedCredential { sealed -> sealedCopy = sealed.copyOf() }
    return checkNotNull(nonceCopy) to checkNotNull(sealedCopy)
}

private fun ByteArray.isZeroed(): Boolean = all { it == 0.toByte() }
