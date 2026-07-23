package com.wifitestorchestrator.agent.platform.security

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

internal interface CredentialKeyAccess {
    fun inspect(): InternalCredentialKeyInspection

    fun create()
}

internal sealed interface InternalCredentialKeyInspection {
    object Missing : InternalCredentialKeyInspection

    object Incompatible : InternalCredentialKeyInspection

    class Compatible(
        val key: SecretKey,
        val securityLevel: CredentialKeySecurityLevel,
    ) : InternalCredentialKeyInspection {
        override fun toString(): String = "InternalCredentialKeyInspection.Compatible(<redacted>)"
    }
}

internal interface AndroidCredentialKeyStoreBackend {
    fun inspect(platformVersion: AndroidPlatformVersion): AndroidCredentialKeyStoreSnapshot

    fun create()
}

internal sealed interface AndroidCredentialKeyStoreSnapshot {
    object Missing : AndroidCredentialKeyStoreSnapshot

    object IncompatibleEntry : AndroidCredentialKeyStoreSnapshot

    class Candidate(
        val key: SecretKey,
        val descriptor: AndroidCredentialStaticKeyDescriptor,
    ) : AndroidCredentialKeyStoreSnapshot {
        override fun toString(): String = "AndroidCredentialKeyStoreSnapshot.Candidate(<redacted>)"
    }
}

internal class AndroidKeystoreKeyAccess(
    private val backend: AndroidCredentialKeyStoreBackend = FrameworkAndroidCredentialKeyStoreBackend,
    private val platformVersion: AndroidPlatformVersion = currentAndroidPlatformVersion(),
    private val randomizedEncryptionProbe: RandomizedEncryptionRequirementProbe =
        FrameworkRandomizedEncryptionRequirementProbe,
) : CredentialKeyAccess {
    override fun inspect(): InternalCredentialKeyInspection {
        return when (val snapshot = backend.inspect(platformVersion)) {
            AndroidCredentialKeyStoreSnapshot.Missing -> InternalCredentialKeyInspection.Missing
            AndroidCredentialKeyStoreSnapshot.IncompatibleEntry ->
                InternalCredentialKeyInspection.Incompatible
            is AndroidCredentialKeyStoreSnapshot.Candidate -> inspectCandidate(snapshot)
        }
    }

    override fun create() = backend.create()

    private fun inspectCandidate(
        candidate: AndroidCredentialKeyStoreSnapshot.Candidate,
    ): InternalCredentialKeyInspection {
        if (
            !AndroidCredentialKeyPolicyV1.isStaticallyCompatible(
                candidate.descriptor,
                platformVersion,
            )
        ) {
            return InternalCredentialKeyInspection.Incompatible
        }
        return when (randomizedEncryptionProbe.inspect(candidate.key)) {
            RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_REJECTED ->
                InternalCredentialKeyInspection.Compatible(
                    key = candidate.key,
                    securityLevel = candidate.descriptor.securityLevel,
                )
            RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_ACCEPTED ->
                InternalCredentialKeyInspection.Incompatible
        }
    }
}

private object FrameworkAndroidCredentialKeyStoreBackend : AndroidCredentialKeyStoreBackend {
    override fun inspect(
        platformVersion: AndroidPlatformVersion,
    ): AndroidCredentialKeyStoreSnapshot {
        val keyStore = loadKeyStore()
        if (!keyStore.containsAlias(KEY_ALIAS)) return AndroidCredentialKeyStoreSnapshot.Missing
        val entry = keyStore.getEntry(KEY_ALIAS, null)
        if (entry !is KeyStore.SecretKeyEntry) {
            return AndroidCredentialKeyStoreSnapshot.IncompatibleEntry
        }
        val key = entry.secretKey
        val descriptor = readStaticDescriptor(key, platformVersion)
        return AndroidCredentialKeyStoreSnapshot.Candidate(
            key = key,
            descriptor = descriptor,
        )
    }

    override fun create() {
        if (loadKeyStore().containsAlias(KEY_ALIAS)) throw CredentialKeyAliasOccupiedException()
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        keyGenerator.init(buildCredentialKeyGenParameterSpecV1())
        keyGenerator.generateKey()
    }

    private fun readStaticDescriptor(
        key: SecretKey,
        platformVersion: AndroidPlatformVersion,
    ): AndroidCredentialStaticKeyDescriptor {
        val secretKeyFactory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
        val keyInfo = secretKeyFactory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return AndroidCredentialStaticKeyDescriptor(
            alias = keyInfo.keystoreAlias,
            algorithm = key.algorithm,
            encodedIsNull = key.encoded == null,
            formatIsNull = key.format == null,
            keySizeBits = keyInfo.keySize,
            purposes = keyInfo.purposes,
            blockModes = keyInfo.blockModes.toSet(),
            encryptionPaddings = keyInfo.encryptionPaddings.toSet(),
            userAuthenticationRequired = keyInfo.isUserAuthenticationRequired,
            userConfirmationRequired = keyInfo.isUserConfirmationRequired,
            trustedUserPresenceRequired = keyInfo.isTrustedUserPresenceRequired,
            unlockedDeviceRequirement =
                keyInfo.unlockedDeviceRequirementEvidence(platformVersion),
            keyValidityStart = keyInfo.keyValidityStart,
            keyValidityForOriginationEnd = keyInfo.keyValidityForOriginationEnd,
            keyValidityForConsumptionEnd = keyInfo.keyValidityForConsumptionEnd,
            origin = keyInfo.origin,
            remainingUsageCount = keyInfo.remainingUsageCountEvidence(platformVersion),
            securityLevel = keyInfo.toGenericSecurityLevel(),
        )
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    private const val PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE
}

internal enum class RandomizedEncryptionProbeResult {
    CALLER_PROVIDED_IV_REJECTED,
    CALLER_PROVIDED_IV_ACCEPTED,
}

internal fun interface RandomizedEncryptionRequirementProbe {
    fun inspect(key: SecretKey): RandomizedEncryptionProbeResult
}

private object FrameworkRandomizedEncryptionRequirementProbe :
    RandomizedEncryptionRequirementProbe {
    override fun inspect(key: SecretKey): RandomizedEncryptionProbeResult {
        val probeNonce = ByteArray(CredentialProtectionPolicyV1.NONCE_SIZE_BYTES)
        return try {
            Cipher.getInstance(TRANSFORMATION).init(
                Cipher.ENCRYPT_MODE,
                key,
                GCMParameterSpec(
                    CredentialProtectionPolicyV1.AUTHENTICATION_TAG_SIZE_BITS,
                    probeNonce,
                ),
            )
            RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_ACCEPTED
        } catch (_: InvalidAlgorithmParameterException) {
            RandomizedEncryptionProbeResult.CALLER_PROVIDED_IV_REJECTED
        } finally {
            probeNonce.fill(0)
        }
    }

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
}

internal fun buildCredentialKeyGenParameterSpecV1(): KeyGenParameterSpec =
    KeyGenParameterSpec
        .Builder(
            CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).setKeySize(CredentialProtectionPolicyV1.KEY_SIZE_BITS)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .setUserAuthenticationRequired(false)
        .setUnlockedDeviceRequired(false)
        .build()

internal class AndroidCredentialStaticKeyDescriptor(
    val alias: String,
    val algorithm: String,
    val encodedIsNull: Boolean,
    val formatIsNull: Boolean,
    val keySizeBits: Int,
    val purposes: Int,
    val blockModes: Set<String>,
    val encryptionPaddings: Set<String>,
    val userAuthenticationRequired: Boolean,
    val userConfirmationRequired: Boolean,
    val trustedUserPresenceRequired: Boolean,
    val unlockedDeviceRequirement: UnlockedDeviceRequirementEvidence,
    val keyValidityStart: Date?,
    val keyValidityForOriginationEnd: Date?,
    val keyValidityForConsumptionEnd: Date?,
    val origin: Int,
    val remainingUsageCount: RemainingUsageCountEvidence,
    val securityLevel: CredentialKeySecurityLevel,
) {
    override fun toString(): String = "AndroidCredentialStaticKeyDescriptor(<redacted>)"
}

internal object AndroidCredentialKeyPolicyV1 {
    fun isStaticallyCompatible(
        descriptor: AndroidCredentialStaticKeyDescriptor,
        platformVersion: AndroidPlatformVersion,
    ): Boolean =
        descriptor.alias == CredentialProtectionPolicyV1.KEY_ALIAS_VALUE &&
            descriptor.algorithm == KeyProperties.KEY_ALGORITHM_AES &&
            descriptor.encodedIsNull &&
            descriptor.formatIsNull &&
            descriptor.keySizeBits == CredentialProtectionPolicyV1.KEY_SIZE_BITS &&
            descriptor.purposes ==
            (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) &&
            descriptor.blockModes == setOf(KeyProperties.BLOCK_MODE_GCM) &&
            descriptor.encryptionPaddings == setOf(KeyProperties.ENCRYPTION_PADDING_NONE) &&
            !descriptor.userAuthenticationRequired &&
            !descriptor.userConfirmationRequired &&
            !descriptor.trustedUserPresenceRequired &&
            descriptor.unlockedDeviceRequirement.isCompatibleFor(platformVersion) &&
            descriptor.keyValidityStart == null &&
            descriptor.keyValidityForOriginationEnd == null &&
            descriptor.keyValidityForConsumptionEnd == null &&
            descriptor.origin == KeyProperties.ORIGIN_GENERATED &&
            descriptor.remainingUsageCount.isCompatibleFor(platformVersion)
}

internal enum class UnlockedDeviceRequirementEvidence {
    NOT_REQUIRED,
    REQUIRED,
    NOT_OBSERVABLE,
}

internal enum class RemainingUsageCountEvidence {
    UNRESTRICTED,
    LIMITED,
    NOT_OBSERVABLE,
}

internal class AndroidPlatformVersion(
    val sdkInt: Int,
    val sdkIntFull: Int,
)

private fun UnlockedDeviceRequirementEvidence.isCompatibleFor(
    platformVersion: AndroidPlatformVersion,
): Boolean {
    val inspectionSupported = supportsUnlockedDeviceRequirementInspection(platformVersion)
    return when (this) {
        UnlockedDeviceRequirementEvidence.NOT_REQUIRED -> inspectionSupported
        UnlockedDeviceRequirementEvidence.REQUIRED -> false
        UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE -> !inspectionSupported
    }
}

private fun RemainingUsageCountEvidence.isCompatibleFor(
    platformVersion: AndroidPlatformVersion,
): Boolean {
    val inspectionSupported = supportsRemainingUsageCountInspection(platformVersion)
    return when (this) {
        RemainingUsageCountEvidence.UNRESTRICTED -> inspectionSupported
        RemainingUsageCountEvidence.LIMITED -> false
        RemainingUsageCountEvidence.NOT_OBSERVABLE -> !inspectionSupported
    }
}

internal fun legacySecurityLevel(insideSecureHardware: Boolean): CredentialKeySecurityLevel =
    if (insideSecureHardware) {
        CredentialKeySecurityLevel.HARDWARE_BACKED_UNSPECIFIED
    } else {
        CredentialKeySecurityLevel.SOFTWARE
    }

internal fun modernSecurityLevel(securityLevel: Int): CredentialKeySecurityLevel =
    when (securityLevel) {
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> CredentialKeySecurityLevel.SOFTWARE
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
            CredentialKeySecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> CredentialKeySecurityLevel.STRONGBOX
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE ->
            CredentialKeySecurityLevel.UNKNOWN_SECURE
        else -> CredentialKeySecurityLevel.UNKNOWN
    }

@SuppressLint("InlinedApi")
internal fun supportsUnlockedDeviceRequirementInspection(
    sdkInt: Int,
    sdkIntFull: Int,
): Boolean =
    sdkInt >= Build.VERSION_CODES.BAKLAVA &&
        sdkIntFull >= Build.VERSION_CODES_FULL.BAKLAVA_1

internal fun supportsUnlockedDeviceRequirementInspection(
    platformVersion: AndroidPlatformVersion,
): Boolean =
    supportsUnlockedDeviceRequirementInspection(
        sdkInt = platformVersion.sdkInt,
        sdkIntFull = platformVersion.sdkIntFull,
    )

internal fun supportsRemainingUsageCountInspection(
    platformVersion: AndroidPlatformVersion,
): Boolean = platformVersion.sdkInt >= Build.VERSION_CODES.S

@SuppressLint("NewApi")
internal fun currentAndroidPlatformVersion(): AndroidPlatformVersion {
    val sdkInt = Build.VERSION.SDK_INT
    val sdkIntFull =
        if (sdkInt >= Build.VERSION_CODES.BAKLAVA) {
            Build.VERSION.SDK_INT_FULL
        } else {
            0
        }
    return AndroidPlatformVersion(sdkInt = sdkInt, sdkIntFull = sdkIntFull)
}

private fun KeyInfo.toGenericSecurityLevel(): CredentialKeySecurityLevel =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        modernSecurityLevel(securityLevel)
    } else {
        legacySecurityLevel(isInsideSecureHardware)
    }

@SuppressLint("NewApi")
private fun KeyInfo.unlockedDeviceRequirementEvidence(
    platformVersion: AndroidPlatformVersion,
): UnlockedDeviceRequirementEvidence =
    observeUnlockedDeviceRequirementEvidence(platformVersion) {
        isUnlockedDeviceRequired
    }

@SuppressLint("NewApi")
private fun KeyInfo.remainingUsageCountEvidence(
    platformVersion: AndroidPlatformVersion,
): RemainingUsageCountEvidence =
    observeRemainingUsageCountEvidence(platformVersion) {
        remainingUsageCount
    }

/**
 * Keeps the API 36.1 getter behind the production version guard while exposing a narrow test seam.
 * This is inline so the guarded framework call remains in the caller bytecode.
 */
internal inline fun observeUnlockedDeviceRequirementEvidence(
    platformVersion: AndroidPlatformVersion,
    readUnlockedDeviceRequired: () -> Boolean,
): UnlockedDeviceRequirementEvidence {
    if (!supportsUnlockedDeviceRequirementInspection(platformVersion)) {
        return UnlockedDeviceRequirementEvidence.NOT_OBSERVABLE
    }
    return observedUnlockedDeviceRequirementEvidence(readUnlockedDeviceRequired())
}

internal fun observedUnlockedDeviceRequirementEvidence(
    unlockedDeviceRequired: Boolean,
): UnlockedDeviceRequirementEvidence =
    if (unlockedDeviceRequired) {
        UnlockedDeviceRequirementEvidence.REQUIRED
    } else {
        UnlockedDeviceRequirementEvidence.NOT_REQUIRED
    }

/** Keeps the API 31 getter behind the production version guard and provides a narrow test seam. */
internal inline fun observeRemainingUsageCountEvidence(
    platformVersion: AndroidPlatformVersion,
    readRemainingUsageCount: () -> Int,
): RemainingUsageCountEvidence {
    if (!supportsRemainingUsageCountInspection(platformVersion)) {
        return RemainingUsageCountEvidence.NOT_OBSERVABLE
    }
    return observedRemainingUsageCountEvidence(readRemainingUsageCount())
}

internal fun observedRemainingUsageCountEvidence(
    remainingUsageCount: Int,
): RemainingUsageCountEvidence =
    if (remainingUsageCount == KeyProperties.UNRESTRICTED_USAGE_COUNT) {
        RemainingUsageCountEvidence.UNRESTRICTED
    } else {
        RemainingUsageCountEvidence.LIMITED
    }

internal class CredentialKeyAliasOccupiedException : Exception()
