package com.wifitestorchestrator.agent.domain.credential.protection

object CredentialProtectionPolicyV1 {
    const val CRYPTO_VERSION_VALUE: Int = 1
    const val KEY_ALIAS_VALUE: String =
        "com.wifitestorchestrator.agent.credential.aead.v1"
    const val KEY_SIZE_BITS: Int = 256
    const val NONCE_SIZE_BYTES: Int = 12
    const val AUTHENTICATION_TAG_SIZE_BITS: Int = 128
    const val AUTHENTICATION_TAG_SIZE_BYTES: Int = 16
    const val PLAINTEXT_SIZE_BYTES: Int = 89
    const val SEALED_CREDENTIAL_SIZE_BYTES: Int =
        PLAINTEXT_SIZE_BYTES + AUTHENTICATION_TAG_SIZE_BYTES
    const val AAD_SIZE_BYTES: Int = 103

    val cryptoVersion: CredentialCryptoVersion = CredentialCryptoVersion.V1
    val keyAlias: CredentialKeyAlias = CredentialKeyAlias.V1
}

enum class CredentialCryptoVersion(val value: Int) {
    V1(CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE),
    ;

    override fun toString(): String = "CredentialCryptoVersion(<redacted>)"

    internal companion object {
        fun fromValue(value: Int): CredentialCryptoVersion? = entries.singleOrNull { it.value == value }
    }
}

enum class CredentialKeyAlias(val value: String) {
    V1(CredentialProtectionPolicyV1.KEY_ALIAS_VALUE),
    ;

    override fun toString(): String = "CredentialKeyAlias(<redacted>)"

    internal companion object {
        fun fromValue(value: String): CredentialKeyAlias? = entries.singleOrNull { it.value == value }
    }
}

enum class CredentialKeySecurityLevel {
    SOFTWARE,
    HARDWARE_BACKED_UNSPECIFIED,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    UNKNOWN_SECURE,
    UNKNOWN,
    ;

    override fun toString(): String = "CredentialKeySecurityLevel(<redacted>)"
}
