package com.wifitestorchestrator.agent.platform.security

import android.os.Build
import android.os.Looper
import android.security.KeyStoreException as AndroidKeyStoreException
import android.security.keystore.BackendBusyException
import android.security.keystore.KeyExpiredException
import android.security.keystore.KeyNotYetValidException
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import java.security.InvalidKeyException
import java.security.UnrecoverableKeyException
import java.util.IdentityHashMap
import java.util.concurrent.CancellationException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal fun interface BlockingOperationGuard {
    fun checkOffMainThread()
}

internal object AndroidMainThreadGuard : BlockingOperationGuard {
    override fun checkOffMainThread() {
        if (Looper.getMainLooper().thread === Thread.currentThread()) {
            throw IllegalStateException("Credential protection must run off the main thread.")
        }
    }
}

internal fun interface SensitiveBufferCleaner {
    fun clean(buffer: ByteArray)
}

internal object ZeroizingBufferCleaner : SensitiveBufferCleaner {
    override fun clean(buffer: ByteArray) {
        buffer.fill(0)
    }
}

internal class CredentialKeyLifecycleLock(
    private val lock: ReentrantLock = ReentrantLock(),
) {
    fun <T> withLifecycleLock(block: () -> T): T = lock.withLock(block)
}

internal object ProductionCredentialKeyLifecycleLocks {
    val v1 = CredentialKeyLifecycleLock()
}

internal fun Throwable.rethrowCancellationIfPresent() {
    val visited = IdentityHashMap<Throwable, Unit>()
    var current: Throwable? = this
    while (current != null && visited.put(current, Unit) == null) {
        if (current is CancellationException) throw current
        current = current.cause
    }
}

internal fun Exception.toCredentialProtectionError(
    default: CredentialProtectionError,
    authenticationFailure: Boolean = false,
): CredentialProtectionError {
    rethrowCancellationIfPresent()
    val causes = causesByIdentity()
    if (authenticationFailure && causes.any { it is javax.crypto.AEADBadTagException }) {
        return CredentialProtectionError.AUTHENTICATION_FAILED
    }
    if (causes.any { it is KeyPermanentlyInvalidatedException }) {
        return CredentialProtectionError.KEY_PERMANENTLY_INVALIDATED
    }
    if (causes.any { it is UserNotAuthenticatedException }) {
        return CredentialProtectionError.DEVICE_LOCKED
    }
    if (
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
        causes.any { it is BackendBusyException }
    ) {
        return CredentialProtectionError.KEYSTORE_TEMPORARILY_UNAVAILABLE
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        causes.filterIsInstance<AndroidKeyStoreException>().forEach { keyStoreFailure ->
            when {
                keyStoreFailure.requiresUserAuthentication() ->
                    return CredentialProtectionError.DEVICE_LOCKED
                keyStoreFailure.isTransientFailure ->
                    return CredentialProtectionError.KEYSTORE_TEMPORARILY_UNAVAILABLE
                keyStoreFailure.numericErrorCode == AndroidKeyStoreException.ERROR_KEY_CORRUPTED ->
                    return CredentialProtectionError.KEY_INVALIDATED
                keyStoreFailure.numericErrorCode ==
                    AndroidKeyStoreException.ERROR_KEY_DOES_NOT_EXIST ->
                    return CredentialProtectionError.KEY_MISSING
            }
        }
    }
    if (
        causes.any {
            it is UnrecoverableKeyException ||
                it is KeyExpiredException ||
                it is KeyNotYetValidException ||
                it is InvalidKeyException
        }
    ) {
        return CredentialProtectionError.KEY_INVALIDATED
    }
    if (causes.any { it is InvalidGeneratedNonceException }) {
        return CredentialProtectionError.INVALID_NONCE
    }
    return default
}

internal inline fun <T> withCleanupPreservingPrimaryFailure(
    cleanup: () -> Unit,
    block: () -> T,
): T {
    var primaryFailure: Throwable? = null
    try {
        return block()
    } catch (failure: Throwable) {
        primaryFailure = failure
        throw failure
    } finally {
        try {
            cleanup()
        } catch (cleanupFailure: Throwable) {
            val primary = primaryFailure
            if (primary == null) {
                throw cleanupFailure
            }
            if (primary !== cleanupFailure) {
                primary.addSuppressed(cleanupFailure)
            }
        }
    }
}

internal fun cleanBuffers(
    cleaner: SensitiveBufferCleaner,
    vararg buffers: ByteArray,
) {
    var primaryFailure: Throwable? = null
    buffers.forEach { buffer ->
        try {
            cleaner.clean(buffer)
        } catch (failure: Throwable) {
            val primary = primaryFailure
            if (primary == null) {
                primaryFailure = failure
            } else if (primary !== failure) {
                primary.addSuppressed(failure)
            }
        }
    }
    primaryFailure?.let { throw it }
}

private fun Throwable.causesByIdentity(): List<Throwable> {
    val visited = IdentityHashMap<Throwable, Unit>()
    val causes = mutableListOf<Throwable>()
    var current: Throwable? = this
    while (current != null && visited.put(current, Unit) == null) {
        causes += current
        current = current.cause
    }
    return causes
}
