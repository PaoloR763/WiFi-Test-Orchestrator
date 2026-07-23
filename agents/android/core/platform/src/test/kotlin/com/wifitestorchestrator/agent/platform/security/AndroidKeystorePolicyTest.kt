package com.wifitestorchestrator.agent.platform.security

import android.security.keystore.KeyProperties
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import java.io.File
import java.util.Date
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29])
class AndroidKeystorePolicyTest {
    @Test
    fun keyGenParameterSpecHasTheExactV1Policy() {
        val spec = buildCredentialKeyGenParameterSpecV1()

        assertEquals(CredentialProtectionPolicyV1.KEY_ALIAS_VALUE, spec.keystoreAlias)
        assertEquals(256, spec.keySize)
        assertEquals(
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            spec.purposes,
        )
        assertEquals(setOf(KeyProperties.BLOCK_MODE_GCM), spec.blockModes.toSet())
        assertEquals(
            setOf(KeyProperties.ENCRYPTION_PADDING_NONE),
            spec.encryptionPaddings.toSet(),
        )
        assertTrue(spec.isRandomizedEncryptionRequired)
        assertFalse(spec.isUserAuthenticationRequired)
        assertFalse(spec.isUnlockedDeviceRequired)
        assertFalse(spec.isStrongBoxBacked)
        assertFalse(spec.isUserConfirmationRequired)
        assertFalse(spec.isUserPresenceRequired)
        assertFalse(spec.isDigestsSpecified)
        assertNull(spec.keyValidityStart)
        assertNull(spec.keyValidityForOriginationEnd)
        assertNull(spec.keyValidityForConsumptionEnd)
        assertNull(spec.attestationChallenge)
    }

    @Test
    fun unlockedDeviceEvidenceMatrixIsClosedAcrossObservationBoundary() {
        PRE_36_1_PLATFORM_VERSIONS.forEach { platformVersion ->
            assertTrue(
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement =
                            UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                    ),
                    platformVersion,
                ),
            )
            assertFalse(
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                    ),
                    platformVersion,
                ),
            )
            assertFalse(
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.REQUIRED,
                    ),
                    platformVersion,
                ),
            )
        }

        listOf(API_36_1, AndroidPlatformVersion(sdkInt = 37, sdkIntFull = 3_700_000))
            .forEach { platformVersion ->
                assertTrue(
                    AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                        androidKeyDescriptor(
                            unlockedDeviceRequirement =
                                UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                        ),
                        platformVersion,
                    ),
                )
                assertFalse(
                    AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                        androidKeyDescriptor(
                            unlockedDeviceRequirement =
                                UnlockedDeviceRequirementEvidence.REQUIRED,
                        ),
                        platformVersion,
                    ),
                )
                assertFalse(
                    AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                        androidKeyDescriptor(
                            unlockedDeviceRequirement =
                                UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                        ),
                        platformVersion,
                    ),
                )
            }

        assertFalse(
            AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                androidKeyDescriptor(
                    platformVersion = API_36_0,
                    algorithm = "HmacSHA256",
                    unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                ),
                API_36_0,
            ),
        )
        assertFalse(
            AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                androidKeyDescriptor(
                    algorithm = "HmacSHA256",
                    unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                ),
                API_36_1,
            ),
        )
        assertTrue(
            AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                androidKeyDescriptor(
                    securityLevel = CredentialKeySecurityLevel.UNKNOWN,
                    unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                ),
                API_36_1,
            ),
        )
    }

    @Test
    fun pre361ObserverNeverInvokesGetterAndAlwaysReturnsNotObservable() {
        PRE_36_1_PLATFORM_VERSIONS.forEach { platformVersion ->
            listOf(
                RecordingUnlockedDeviceRequirementGetter(result = false),
                RecordingUnlockedDeviceRequirementGetter(result = true),
                RecordingUnlockedDeviceRequirementGetter(
                    failure = IllegalStateException("synthetic getter failure"),
                ),
            ).forEach { getter ->
                assertSame(
                    UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                    observeUnlockedDeviceRequirementEvidence(platformVersion, getter),
                )
                assertEquals(0, getter.invocationCount.get())
            }
        }
    }

    @Test
    fun api361AndFutureObserverInvokesGetterOnceAndPropagatesFailuresByIdentity() {
        listOf(API_36_1, AndroidPlatformVersion(sdkInt = 37, sdkIntFull = 3_700_000))
            .forEach { platformVersion ->
                val falseGetter = RecordingUnlockedDeviceRequirementGetter(result = false)
                assertSame(
                    UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                    observeUnlockedDeviceRequirementEvidence(platformVersion, falseGetter),
                )
                assertEquals(1, falseGetter.invocationCount.get())

                val trueGetter = RecordingUnlockedDeviceRequirementGetter(result = true)
                assertSame(
                    UnlockedDeviceRequirementEvidence.REQUIRED,
                    observeUnlockedDeviceRequirementEvidence(platformVersion, trueGetter),
                )
                assertEquals(1, trueGetter.invocationCount.get())

                val failure = IllegalStateException("synthetic getter failure")
                val failingGetter = RecordingUnlockedDeviceRequirementGetter(failure = failure)
                assertSame(
                    failure,
                    assertFailsWith<IllegalStateException> {
                        observeUnlockedDeviceRequirementEvidence(platformVersion, failingGetter)
                    },
                )
                assertEquals(1, failingGetter.invocationCount.get())
            }

        val cancellation = CancellationException("synthetic cancellation")
        val cancellingGetter = RecordingUnlockedDeviceRequirementGetter(failure = cancellation)
        assertSame(
            cancellation,
            assertFailsWith<CancellationException> {
                observeUnlockedDeviceRequirementEvidence(API_36_1, cancellingGetter)
            },
        )
        assertEquals(1, cancellingGetter.invocationCount.get())

        val fatal = AssertionError("synthetic fatal")
        val fatalGetter = RecordingUnlockedDeviceRequirementGetter(failure = fatal)
        assertSame(
            fatal,
            assertFailsWith<AssertionError> {
                observeUnlockedDeviceRequirementEvidence(API_36_1, fatalGetter)
            },
        )
        assertEquals(1, fatalGetter.invocationCount.get())
    }

    @Test
    fun api29And30UsageObserverNeverInvokesGetterAndDoesNotInventEvidence() {
        listOf(API_29, API_30).forEach { platformVersion ->
            listOf(
                RecordingRemainingUsageCountGetter(
                    result = KeyProperties.UNRESTRICTED_USAGE_COUNT,
                ),
                RecordingRemainingUsageCountGetter(result = 1),
                RecordingRemainingUsageCountGetter(
                    failure = IllegalStateException("synthetic getter failure"),
                ),
            ).forEach { getter ->
                assertSame(
                    RemainingUsageCountEvidence.NOT_OBSERVABLE,
                    observeRemainingUsageCountEvidence(platformVersion, getter),
                )
                assertEquals(0, getter.invocationCount.get())
            }
        }
    }

    @Test
    fun api31AndLaterUsageObserverRequiresExactlyUnrestrictedAndPropagatesFailure() {
        listOf(API_31, API_35, API_36_0, API_36_1).forEach { platformVersion ->
            val unrestricted =
                RecordingRemainingUsageCountGetter(
                    result = KeyProperties.UNRESTRICTED_USAGE_COUNT,
                )
            assertSame(
                RemainingUsageCountEvidence.UNRESTRICTED,
                observeRemainingUsageCountEvidence(platformVersion, unrestricted),
            )
            assertEquals(1, unrestricted.invocationCount.get())

            listOf(0, 1, 2).forEach { limitedValue ->
                val limited = RecordingRemainingUsageCountGetter(result = limitedValue)
                assertSame(
                    RemainingUsageCountEvidence.LIMITED,
                    observeRemainingUsageCountEvidence(platformVersion, limited),
                )
                assertEquals(1, limited.invocationCount.get())
            }

            val failure = IllegalStateException("synthetic getter failure")
            val failing = RecordingRemainingUsageCountGetter(failure = failure)
            assertSame(
                failure,
                assertFailsWith<IllegalStateException> {
                    observeRemainingUsageCountEvidence(platformVersion, failing)
                },
            )
            assertEquals(1, failing.invocationCount.get())
        }

        val cancellation = CancellationException("synthetic cancellation")
        val cancelling = RecordingRemainingUsageCountGetter(failure = cancellation)
        assertSame(
            cancellation,
            assertFailsWith<CancellationException> {
                observeRemainingUsageCountEvidence(API_31, cancelling)
            },
        )
        assertEquals(1, cancelling.invocationCount.get())
        val fatal = AssertionError("synthetic fatal")
        val fatalGetter = RecordingRemainingUsageCountGetter(failure = fatal)
        assertSame(
            fatal,
            assertFailsWith<AssertionError> {
                observeRemainingUsageCountEvidence(API_31, fatalGetter)
            },
        )
        assertEquals(1, fatalGetter.invocationCount.get())
    }

    @Test
    fun remainingUsageEvidenceMatrixIsClosedAcrossApi31Boundary() {
        listOf(API_29, API_30).forEach { platformVersion ->
            assertTrue(
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement =
                            UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                        remainingUsageCount = RemainingUsageCountEvidence.NOT_OBSERVABLE,
                    ),
                    platformVersion,
                ),
            )
            listOf(
                RemainingUsageCountEvidence.UNRESTRICTED,
                RemainingUsageCountEvidence.LIMITED,
            ).forEach { evidence ->
                assertFalse(
                    AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                        androidKeyDescriptor(
                            platformVersion = platformVersion,
                            unlockedDeviceRequirement =
                                UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                            remainingUsageCount = evidence,
                        ),
                        platformVersion,
                    ),
                )
            }
        }

        listOf(API_31, API_35, API_36_0, API_36_1).forEach { platformVersion ->
            val unlockedEvidence =
                if (supportsUnlockedDeviceRequirementInspection(platformVersion)) {
                    UnlockedDeviceRequirementEvidence.NOT_REQUIRED
                } else {
                    UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE
                }
            assertTrue(
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement = unlockedEvidence,
                        remainingUsageCount = RemainingUsageCountEvidence.UNRESTRICTED,
                    ),
                    platformVersion,
                ),
            )
            listOf(
                RemainingUsageCountEvidence.LIMITED,
                RemainingUsageCountEvidence.NOT_OBSERVABLE,
            ).forEach { evidence ->
                assertFalse(
                    AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                        androidKeyDescriptor(
                            platformVersion = platformVersion,
                            unlockedDeviceRequirement = unlockedEvidence,
                            remainingUsageCount = evidence,
                        ),
                        platformVersion,
                    ),
                )
            }
        }
    }

    @Test
    fun confirmationAndTrustedPresenceAreIndependentStaticRestrictions() {
        val cases =
            listOf(
                Triple(false, false, true),
                Triple(true, false, false),
                Triple(false, true, false),
                Triple(true, true, false),
            )

        cases.forEach { (confirmationRequired, presenceRequired, expectedCompatible) ->
            assertEquals(
                expectedCompatible,
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                    androidKeyDescriptor(
                        userConfirmationRequired = confirmationRequired,
                        trustedUserPresenceRequired = presenceRequired,
                    ),
                    API_36_1,
                ),
            )
        }
    }

    @Test
    fun keyAccessOwnsMandatoryProbeForEveryStaticallyCompatibleCandidate() {
        val candidateBackend = SyntheticKeyInfoBackend(initialAliasPresent = true)
        val compatibleProbe = RecordingRandomizedEncryptionRequirementProbe()

        assertEquals(
            setOf("Candidate", "IncompatibleEntry", "Missing"),
            AndroidCredentialKeyStoreSnapshot::class.java.declaredClasses
                .map { nested -> nested.simpleName }
                .toSet(),
        )
        assertIs<AndroidCredentialKeyStoreSnapshot.Candidate>(
            candidateBackend.inspect(API_36_1),
        )
        assertEquals(0, compatibleProbe.invocationCount.get())

        assertIs<InternalCredentialKeyInspection.Compatible>(
            AndroidKeystoreKeyAccess(
                backend = candidateBackend,
                platformVersion = API_36_1,
                randomizedEncryptionProbe = compatibleProbe,
            ).inspect(),
        )
        assertEquals(1, compatibleProbe.invocationCount.get())

        val acceptingProbe =
            RecordingRandomizedEncryptionRequirementProbe(
                result = RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_ACCEPTED,
            )
        assertSame(
            InternalCredentialKeyInspection.Incompatible,
            AndroidKeystoreKeyAccess(
                backend = SyntheticKeyInfoBackend(initialAliasPresent = true),
                platformVersion = API_36_1,
                randomizedEncryptionProbe = acceptingProbe,
            ).inspect(),
        )
        assertEquals(1, acceptingProbe.invocationCount.get())

        val failure = IllegalStateException("synthetic provider failure")
        val failingProbe = RecordingRandomizedEncryptionRequirementProbe(failure = failure)
        assertSame(
            failure,
            assertFailsWith<IllegalStateException> {
                AndroidKeystoreKeyAccess(
                    backend = SyntheticKeyInfoBackend(initialAliasPresent = true),
                    platformVersion = API_36_1,
                    randomizedEncryptionProbe = failingProbe,
                ).inspect()
            },
        )
        assertEquals(1, failingProbe.invocationCount.get())
    }

    @Test
    fun pre361KnownApiLimitationRequiresEveryOtherObservableAttribute() {
        PRE_36_1_PLATFORM_VERSIONS.forEach { platformVersion ->
            val compatible =
                androidKeyDescriptor(
                    platformVersion = platformVersion,
                    unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE,
                )
            assertTrue(
                AndroidCredentialKeyPolicyV1.isStaticallyCompatible(compatible, platformVersion),
            )

            val notObservable = UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE
            val incompatible =
                listOf(
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        alias = "synthetic.other.alias",
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        algorithm = "HmacSHA256",
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        encodedIsNull = false,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        formatIsNull = false,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        keySizeBits = 128,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        purposes = KeyProperties.PURPOSE_ENCRYPT,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        blockModes = setOf(KeyProperties.BLOCK_MODE_CBC),
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        encryptionPaddings = setOf(KeyProperties.ENCRYPTION_PADDING_PKCS7),
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        userAuthenticationRequired = true,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        userConfirmationRequired = true,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        trustedUserPresenceRequired = true,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.REQUIRED,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        unlockedDeviceRequirement = UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        keyValidityStart = Date(0),
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        keyValidityForOriginationEnd = Date(0),
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        keyValidityForConsumptionEnd = Date(0),
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        origin = KeyProperties.ORIGIN_IMPORTED,
                        unlockedDeviceRequirement = notObservable,
                    ),
                    androidKeyDescriptor(
                        platformVersion = platformVersion,
                        remainingUsageCount = RemainingUsageCountEvidence.LIMITED,
                        unlockedDeviceRequirement = notObservable,
                    ),
                )

            assertTrue(
                incompatible.all {
                    !AndroidCredentialKeyPolicyV1.isStaticallyCompatible(it, platformVersion)
                },
            )
            assertTrue(incompatible.all { it.toString().contains("<redacted>") })
        }
    }

    @Test
    fun securityLevelAndVersionBoundaryCoverApi29Through361() {
        assertEquals(
            CredentialKeySecurityLevel.SOFTWARE,
            legacySecurityLevel(insideSecureHardware = false),
        )
        assertEquals(
            CredentialKeySecurityLevel.HARDWARE_BACKED_UNSPECIFIED,
            legacySecurityLevel(insideSecureHardware = true),
        )
        assertEquals(
            CredentialKeySecurityLevel.TRUSTED_ENVIRONMENT,
            modernSecurityLevel(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT),
        )
        assertEquals(
            CredentialKeySecurityLevel.STRONGBOX,
            modernSecurityLevel(KeyProperties.SECURITY_LEVEL_STRONGBOX),
        )
        assertEquals(
            CredentialKeySecurityLevel.UNKNOWN,
            modernSecurityLevel(-99),
        )
        assertFalse(supportsUnlockedDeviceRequirementInspection(29, 2_900_000))
        assertFalse(supportsUnlockedDeviceRequirementInspection(35, 3_500_000))
        assertFalse(supportsUnlockedDeviceRequirementInspection(36, 3_600_000))
        assertTrue(
            supportsUnlockedDeviceRequirementInspection(
                36,
                android.os.Build.VERSION_CODES_FULL.BAKLAVA_1,
            ),
        )
        assertTrue(supportsUnlockedDeviceRequirementInspection(37, 3_700_000))
        assertFalse(supportsRemainingUsageCountInspection(API_29))
        assertFalse(supportsRemainingUsageCountInspection(API_30))
        assertTrue(supportsRemainingUsageCountInspection(API_31))
        assertTrue(supportsRemainingUsageCountInspection(API_36_1))
        val robolectricApi29 = currentAndroidPlatformVersion()
        assertEquals(29, robolectricApi29.sdkInt)
        assertFalse(supportsUnlockedDeviceRequirementInspection(robolectricApi29))
    }

    @Test
    fun factoryIsContextFreeLazyAndPerformsNoKeystoreIo() {
        val create =
            AndroidCredentialProtectionFactory::class.java.declaredMethods.single {
                it.name == "create"
            }

        assertTrue(create.parameterTypes.isEmpty())
        assertIs<com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector>(
            AndroidCredentialProtectionFactory.create(),
        )
    }

    @Test
    fun allBlockingOperationsRejectTheMainThreadButConstructionDoesNot() {
        val access = MutableCredentialKeyAccess(compatibleInspection())
        val candidate =
            AndroidKeystoreCredentialProtector(
                keyAccess = access,
                credentialCipher = AesGcmCredentialCipher(),
                operationGuard = AndroidMainThreadGuard,
                bufferCleaner = ZeroizingBufferCleaner,
                lifecycleLock = CredentialKeyLifecycleLock(),
            )

        listOf<() -> Any>(
            { candidate.inspect() },
            { candidate.prepare() },
            { candidate.protect(deliveredCredential()) },
            {
                candidate.useDecryptedCredential(
                    sealedEnvelopeFor(TEST_CREDENTIAL_RAW.encodeToByteArray()),
                ) { Unit }
            },
        ).forEach { operation -> assertFailsWith<IllegalStateException> { operation() } }
        assertEquals(0, access.inspectCount.get())

        val backgroundFailure = AtomicReference<Throwable?>()
        Thread {
            try {
                AndroidMainThreadGuard.checkOffMainThread()
            } catch (failure: Throwable) {
                backgroundFailure.set(failure)
            }
        }.apply {
            start()
            join()
        }
        assertNull(backgroundFailure.get())
    }

    @Test
    fun sourceManifestContainsNoPermissionsOrComponents() {
        val projectDir = File(checkNotNull(System.getProperty("wto.android.platform.projectDir")))
        val manifest = File(projectDir, "src/main/AndroidManifest.xml").readText()

        listOf(
            "uses-permission",
            "<activity",
            "<service",
            "<receiver",
            "<provider",
            "android:process",
            "usesCleartextTraffic",
            "networkSecurityConfig",
        ).forEach { forbidden -> assertFalse(manifest.contains(forbidden)) }
        assertTrue(manifest.contains("<manifest />"))
    }

}
