package com.wifitestorchestrator.agent.platform.security

import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector

object AndroidCredentialProtectionFactory {
    /** Creates a lazy adapter. This method performs no Keystore access, key creation, or I/O. */
    fun create(): CredentialProtector =
        AndroidKeystoreCredentialProtector(
            keyAccess = AndroidKeystoreKeyAccess(),
            credentialCipher = AesGcmCredentialCipher(),
            operationGuard = AndroidMainThreadGuard,
            bufferCleaner = ZeroizingBufferCleaner,
            lifecycleLock = ProductionCredentialKeyLifecycleLocks.v1,
        )

    internal fun createForTesting(
        keyAccess: CredentialKeyAccess,
        credentialCipher: AesGcmCredentialCipher,
        operationGuard: BlockingOperationGuard,
        bufferCleaner: SensitiveBufferCleaner,
        lifecycleLock: CredentialKeyLifecycleLock,
    ): CredentialProtector =
        AndroidKeystoreCredentialProtector(
            keyAccess = keyAccess,
            credentialCipher = credentialCipher,
            operationGuard = operationGuard,
            bufferCleaner = bufferCleaner,
            lifecycleLock = lifecycleLock,
        )
}
