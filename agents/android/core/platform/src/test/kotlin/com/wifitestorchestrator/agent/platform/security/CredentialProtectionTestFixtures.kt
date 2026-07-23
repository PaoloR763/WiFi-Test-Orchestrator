package com.wifitestorchestrator.agent.platform.security

import android.security.keystore.KeyProperties
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeCreationResult
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import java.time.Instant
import java.util.Date
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

internal const val TEST_CREDENTIAL_ID = "10000000-0000-4000-8000-000000000001"
internal const val SECOND_CREDENTIAL_ID = "20000000-0000-4000-8000-000000000002"
internal const val TEST_CREDENTIAL_RAW =
    "wto_ac_1.10000000-0000-4000-8000-000000000001." +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
internal const val SECOND_CREDENTIAL_RAW =
    "wto_ac_1.20000000-0000-4000-8000-000000000002." +
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

internal val TEST_KEY: SecretKey = SecretKeySpec(ByteArray(32) { index -> (index + 1).toByte() }, "AES")
internal val OTHER_KEY: SecretKey = SecretKeySpec(ByteArray(32) { index -> (index + 33).toByte() }, "AES")

internal val API_29 = AndroidPlatformVersion(sdkInt = 29, sdkIntFull = 2_900_000)
internal val API_30 = AndroidPlatformVersion(sdkInt = 30, sdkIntFull = 3_000_000)
internal val API_31 = AndroidPlatformVersion(sdkInt = 31, sdkIntFull = 3_100_000)
internal val API_35 = AndroidPlatformVersion(sdkInt = 35, sdkIntFull = 3_500_000)
internal val API_36_0 = AndroidPlatformVersion(sdkInt = 36, sdkIntFull = 3_600_000)
internal val API_36_1 =
    AndroidPlatformVersion(
        sdkInt = 36,
        sdkIntFull = android.os.Build.VERSION_CODES_FULL.BAKLAVA_1,
    )
internal val PRE_36_1_PLATFORM_VERSIONS = listOf(API_29, API_35, API_36_0)

internal fun deliveredCredential(): DeliveredCredential {
    val metadata =
        validValue(
            CredentialMetadata.create(
                credentialId = credentialId(),
                version = credentialVersion(),
                issuedAt = Instant.parse("2026-07-12T12:00:01Z"),
                expiresAt = Instant.parse("2026-10-10T12:00:01Z"),
                deliveryState = CredentialDeliveryState.ACTIVE,
            ),
        )
    return validValue(
        DeliveredCredential.create(
            metadata = metadata,
            secret = validValue(AgentCredentialSecret.parse(TEST_CREDENTIAL_RAW)),
        ),
    )
}

internal fun credentialId(raw: String = TEST_CREDENTIAL_ID): CredentialId =
    validValue(CredentialId.parse(raw))

internal fun credentialVersion(value: Int = 1): CredentialVersion =
    validValue(CredentialVersion.from(value))

internal fun envelope(
    nonce: ByteArray,
    sealedCredential: ByteArray,
    id: CredentialId = credentialId(),
    version: CredentialVersion = credentialVersion(),
): ProtectedCredentialEnvelope {
    val created =
        ProtectedCredentialEnvelope.create(
            cryptoVersion = CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE,
            keyAlias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
            credentialId = id,
            credentialVersion = version,
            nonce = nonce,
            sealedCredential = sealedCredential,
        )
    return (created as ProtectedCredentialEnvelopeCreationResult.Valid).envelope
}

internal fun compatibleInspection(
    key: SecretKey = TEST_KEY,
    securityLevel: CredentialKeySecurityLevel = CredentialKeySecurityLevel.UNKNOWN,
): InternalCredentialKeyInspection =
    InternalCredentialKeyInspection.Compatible(key, securityLevel)

internal fun androidKeyDescriptor(
    platformVersion: AndroidPlatformVersion = API_36_1,
    alias: String = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
    algorithm: String = KeyProperties.KEY_ALGORITHM_AES,
    encodedIsNull: Boolean = true,
    formatIsNull: Boolean = true,
    keySizeBits: Int = 256,
    purposes: Int = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    blockModes: Set<String> = setOf(KeyProperties.BLOCK_MODE_GCM),
    encryptionPaddings: Set<String> = setOf(KeyProperties.ENCRYPTION_PADDING_NONE),
    userAuthenticationRequired: Boolean = false,
    userConfirmationRequired: Boolean = false,
    trustedUserPresenceRequired: Boolean = false,
    unlockedDeviceRequirement: UnlockedDeviceRequirementEvidence =
        UnlockedDeviceRequirementEvidence.NOT_REQUIRED,
    keyValidityStart: Date? = null,
    keyValidityForOriginationEnd: Date? = null,
    keyValidityForConsumptionEnd: Date? = null,
    origin: Int = KeyProperties.ORIGIN_GENERATED,
    remainingUsageCount: RemainingUsageCountEvidence =
        if (supportsRemainingUsageCountInspection(platformVersion)) {
            RemainingUsageCountEvidence.UNRESTRICTED
        } else {
            RemainingUsageCountEvidence.NOT_OBSERVABLE
        },
    securityLevel: CredentialKeySecurityLevel = CredentialKeySecurityLevel.SOFTWARE,
): AndroidCredentialStaticKeyDescriptor =
    AndroidCredentialStaticKeyDescriptor(
        alias = alias,
        algorithm = algorithm,
        encodedIsNull = encodedIsNull,
        formatIsNull = formatIsNull,
        keySizeBits = keySizeBits,
        purposes = purposes,
        blockModes = blockModes,
        encryptionPaddings = encryptionPaddings,
        userAuthenticationRequired = userAuthenticationRequired,
        userConfirmationRequired = userConfirmationRequired,
        trustedUserPresenceRequired = trustedUserPresenceRequired,
        unlockedDeviceRequirement = unlockedDeviceRequirement,
        keyValidityStart = keyValidityStart,
        keyValidityForOriginationEnd = keyValidityForOriginationEnd,
        keyValidityForConsumptionEnd = keyValidityForConsumptionEnd,
        origin = origin,
        remainingUsageCount = remainingUsageCount,
        securityLevel = securityLevel,
    )

internal object NoOpBlockingGuard : BlockingOperationGuard {
    override fun checkOffMainThread() = Unit
}

internal class MutableCredentialKeyAccess(
    initial: InternalCredentialKeyInspection = InternalCredentialKeyInspection.Missing,
    private val generatedKey: SecretKey = TEST_KEY,
) : CredentialKeyAccess {
    private val monitor = Any()

    @Volatile
    var current: InternalCredentialKeyInspection = initial

    val inspectCount = AtomicInteger()
    val createCount = AtomicInteger()

    @Volatile
    var inspectFailure: Throwable? = null

    @Volatile
    var createFailure: Throwable? = null

    override fun inspect(): InternalCredentialKeyInspection {
        inspectCount.incrementAndGet()
        inspectFailure?.let(::throwUnchecked)
        return current
    }

    override fun create() {
        createCount.incrementAndGet()
        createFailure?.let(::throwUnchecked)
        synchronized(monitor) {
            if (current !is InternalCredentialKeyInspection.Missing) {
                throw CredentialKeyAliasOccupiedException()
            }
            current = compatibleInspection(generatedKey)
        }
    }
}

internal class SyntheticKeyInfoBackend(
    initialAliasPresent: Boolean = false,
    private val generatedKey: SecretKey = TEST_KEY,
    private val unlockedDeviceRequirementGetter: () -> Boolean = { false },
    private val remainingUsageCountGetter: () -> Int = {
        KeyProperties.UNRESTRICTED_USAGE_COUNT
    },
    private val descriptorProvider:
        (
            UnlockedDeviceRequirementEvidence,
            RemainingUsageCountEvidence,
        ) -> AndroidCredentialStaticKeyDescriptor =
        { unlockedEvidence, usageEvidence ->
            androidKeyDescriptor(
                unlockedDeviceRequirement = unlockedEvidence,
                remainingUsageCount = usageEvidence,
            )
        },
) : AndroidCredentialKeyStoreBackend {
    private val monitor = Any()

    @Volatile
    private var aliasPresent = initialAliasPresent

    val inspectCount = AtomicInteger()
    val createCount = AtomicInteger()

    @Volatile
    var inspectFailure: Throwable? = null

    @Volatile
    var createFailure: Throwable? = null

    @Volatile
    var lastUnlockedDeviceRequirementEvidence: UnlockedDeviceRequirementEvidence? = null
        private set

    @Volatile
    var lastRemainingUsageCountEvidence: RemainingUsageCountEvidence? = null
        private set

    override fun inspect(
        platformVersion: AndroidPlatformVersion,
    ): AndroidCredentialKeyStoreSnapshot {
        inspectCount.incrementAndGet()
        inspectFailure?.let(::throwUnchecked)
        if (!aliasPresent) return AndroidCredentialKeyStoreSnapshot.Missing
        val unlockedEvidence =
            observeUnlockedDeviceRequirementEvidence(
                platformVersion = platformVersion,
                readUnlockedDeviceRequired = unlockedDeviceRequirementGetter,
            )
        val usageEvidence =
            observeRemainingUsageCountEvidence(
                platformVersion = platformVersion,
                readRemainingUsageCount = remainingUsageCountGetter,
            )
        lastUnlockedDeviceRequirementEvidence = unlockedEvidence
        lastRemainingUsageCountEvidence = usageEvidence
        return AndroidCredentialKeyStoreSnapshot.Candidate(
            key = generatedKey,
            descriptor = descriptorProvider(unlockedEvidence, usageEvidence),
        )
    }

    override fun create() {
        createCount.incrementAndGet()
        createFailure?.let(::throwUnchecked)
        synchronized(monitor) {
            if (aliasPresent) throw CredentialKeyAliasOccupiedException()
            aliasPresent = true
        }
    }
}

internal class RecordingUnlockedDeviceRequirementGetter(
    private val result: Boolean = false,
    private val failure: Throwable? = null,
) : () -> Boolean {
    val invocationCount = AtomicInteger()

    override fun invoke(): Boolean {
        invocationCount.incrementAndGet()
        failure?.let(::throwUnchecked)
        return result
    }
}

internal class RecordingRemainingUsageCountGetter(
    private val result: Int = KeyProperties.UNRESTRICTED_USAGE_COUNT,
    private val failure: Throwable? = null,
) : () -> Int {
    val invocationCount = AtomicInteger()

    override fun invoke(): Int {
        invocationCount.incrementAndGet()
        failure?.let(::throwUnchecked)
        return result
    }
}

internal class RecordingRandomizedEncryptionRequirementProbe(
    private val result: RandomizedEncryptionProbeResult =
        RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_REJECTED,
    private val failure: Throwable? = null,
) : RandomizedEncryptionRequirementProbe {
    val invocationCount = AtomicInteger()

    override fun inspect(key: SecretKey): RandomizedEncryptionProbeResult {
        invocationCount.incrementAndGet()
        failure?.let(::throwUnchecked)
        return result
    }
}

internal class RecordingBufferCleaner(
    private val failure: Throwable? = null,
) : SensitiveBufferCleaner {
    val buffers = mutableListOf<ByteArray>()

    override fun clean(buffer: ByteArray) {
        buffers += buffer
        buffer.fill(0)
        failure?.let(::throwUnchecked)
    }
}

internal fun protector(
    keyAccess: CredentialKeyAccess = MutableCredentialKeyAccess(compatibleInspection()),
    credentialCipher: AesGcmCredentialCipher = AesGcmCredentialCipher(),
    cleaner: SensitiveBufferCleaner = ZeroizingBufferCleaner,
    lifecycleLock: CredentialKeyLifecycleLock = CredentialKeyLifecycleLock(),
): AndroidKeystoreCredentialProtector =
    AndroidKeystoreCredentialProtector(
        keyAccess = keyAccess,
        credentialCipher = credentialCipher,
        operationGuard = NoOpBlockingGuard,
        bufferCleaner = cleaner,
        lifecycleLock = lifecycleLock,
    )

internal fun sealedEnvelopeFor(
    plaintext: ByteArray,
    key: SecretKey = TEST_KEY,
    id: CredentialId = credentialId(),
    version: CredentialVersion = credentialVersion(),
): ProtectedCredentialEnvelope {
    var encryption: AesGcmEncryption? = null
    com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionAadV1.useBytes(
        id,
        version,
    ) { aad ->
        encryption = AesGcmCredentialCipher().encrypt(key, plaintext, aad)
    }
    val sealed = checkNotNull(encryption)
    return envelope(sealed.nonce, sealed.sealedCredential, id, version)
}

internal fun <T : Any> validValue(result: ValidationResult<T>): T =
    (result as Valid<T>).value

@Suppress("TooGenericExceptionThrown")
private fun throwUnchecked(failure: Throwable): Nothing = throw failure
