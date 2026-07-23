package com.wifitestorchestrator.agent.platform.security

import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import java.security.InvalidKeyException
import java.util.concurrent.CancellationException
import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class CredentialProtectionRuntimeTest {
    @Test
    fun directAndNestedCancellationAreRethrownByIdentityBeforeMapping() {
        val direct = CancellationException("synthetic cancellation")
        val nested = CancellationException("nested synthetic cancellation")

        assertSame(
            direct,
            assertFailsWith<CancellationException> {
                direct.toCredentialProtectionError(CredentialProtectionError.PROVIDER_FAILURE)
            },
        )
        assertSame(
            nested,
            assertFailsWith<CancellationException> {
                IllegalStateException("synthetic wrapper", nested)
                    .toCredentialProtectionError(CredentialProtectionError.PROVIDER_FAILURE)
            },
        )
    }

    @Test
    fun cyclicCauseChainTerminatesAndUsesTheDeterministicDefault() {
        val cyclic = CyclicException()

        assertEquals(
            CredentialProtectionError.PROVIDER_FAILURE,
            cyclic.toCredentialProtectionError(CredentialProtectionError.PROVIDER_FAILURE),
        )
    }

    @Test
    fun authenticationAndInvalidKeyMappingsAreClosedAndDeterministic() {
        val authentication = IllegalStateException("sensitive", AEADBadTagException("sensitive"))
        val invalidKey = IllegalStateException("sensitive", InvalidKeyException("sensitive"))

        assertEquals(
            CredentialProtectionError.AUTHENTICATION_FAILED,
            authentication.toCredentialProtectionError(
                default = CredentialProtectionError.DECRYPTION_FAILED,
                authenticationFailure = true,
            ),
        )
        assertEquals(
            CredentialProtectionError.KEY_INVALIDATED,
            invalidKey.toCredentialProtectionError(CredentialProtectionError.PROVIDER_FAILURE),
        )
    }

    @Test
    fun cleanupPreservesPrimaryAddsDistinctFailureAndAvoidsSelfSuppression() {
        val primary = IllegalStateException("primary")
        val cleanup = IllegalArgumentException("cleanup")
        val observed =
            assertFailsWith<IllegalStateException> {
                withCleanupPreservingPrimaryFailure(
                    cleanup = { throw cleanup },
                    block = { throw primary },
                )
            }

        assertSame(primary, observed)
        assertEquals(listOf(cleanup), observed.suppressedExceptions)

        val self = IllegalStateException("same")
        assertSame(
            self,
            assertFailsWith<IllegalStateException> {
                withCleanupPreservingPrimaryFailure(
                    cleanup = { throw self },
                    block = { throw self },
                )
            },
        )
        assertTrue(self.suppressedExceptions.isEmpty())
    }

    @Test
    fun cleanupFailurePropagatesWhenThereIsNoPrimaryFailure() {
        val cleanup = IllegalStateException("cleanup")

        assertSame(
            cleanup,
            assertFailsWith<IllegalStateException> {
                withCleanupPreservingPrimaryFailure(
                    cleanup = { throw cleanup },
                    block = { Unit },
                )
            },
        )
    }

    @Test
    fun multipleBufferCleanupFailuresRetainTheFirstAndSuppressTheRest() {
        val first = IllegalStateException("first")
        val second = IllegalArgumentException("second")
        var invocation = 0
        val cleaner =
            SensitiveBufferCleaner {
                invocation += 1
                if (invocation == 1) throw first else throw second
            }

        val observed =
            assertFailsWith<IllegalStateException> {
                cleanBuffers(cleaner, ByteArray(1), ByteArray(1))
            }

        assertSame(first, observed)
        assertEquals(listOf(second), observed.suppressedExceptions)
    }

    @Test
    fun errorsAreNeverConvertedByCleanupUtilities() {
        val fatal = AssertionError("fatal")

        assertSame(
            fatal,
            assertFailsWith<AssertionError> {
                withCleanupPreservingPrimaryFailure(
                    cleanup = { Unit },
                    block = { throw fatal },
                )
            },
        )
    }
}

private class CyclicException : Exception() {
    override val cause: Throwable
        get() = this
}
