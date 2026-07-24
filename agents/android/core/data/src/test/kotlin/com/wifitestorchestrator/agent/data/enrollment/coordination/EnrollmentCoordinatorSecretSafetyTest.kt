package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.TEST_CREDENTIAL
import com.wifitestorchestrator.agent.data.enrollment.TEST_ENROLLMENT_TOKEN
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class EnrollmentCoordinatorSecretSafetyTest {
    @Test
    fun `token and plaintext never cross the C06 write boundary`() = runTest {
        val fixture = CoordinatorFixture()
        var inspectedInsideCall = false
        fixture.repository.persistAction = { write ->
            inspectedInsideCall = true
            assertFalse(write.toString().contains(TEST_ENROLLMENT_TOKEN))
            assertFalse(write.toString().contains(TEST_CREDENTIAL))
            assertFalse(
                write.javaClass.declaredFields.any {
                    it.name.contains("token", ignoreCase = true) ||
                        it.name.contains("plaintext", ignoreCase = true)
                },
            )
            PersistProtectedEnrollmentResult.Written
        }

        val result = fixture.coordinator().enroll(fixture.attempt)

        assertTrue(inspectedInsideCall)
        assertIs<Enrolled>(result)
        assertFalse(result.toString().contains(TEST_ENROLLMENT_TOKEN))
        assertFalse(result.toString().contains(TEST_CREDENTIAL))
    }

    @Test
    fun `results receipts attempts and events have redacted representations`() = runTest {
        val fixture = CoordinatorFixture()
        val result = fixture.coordinator().enroll(fixture.attempt)
        val rendered =
            listOf(
                fixture.attempt.toString(),
                fixture.attempt.attemptId.toString(),
                result.toString(),
                (result as Enrolled).receipt.toString(),
                fixture.events.snapshot().toString(),
            ).joinToString()

        assertFalse(rendered.contains(TEST_ENROLLMENT_TOKEN))
        assertFalse(rendered.contains(TEST_CREDENTIAL))
        assertTrue(rendered.contains("<redacted>"))
    }

    @Test
    fun `adapter exception messages are discarded from public results`() = runTest {
        val fixture = CoordinatorFixture()
        fixture.call.action = {
            throw IllegalStateException("$TEST_CREDENTIAL $TEST_ENROLLMENT_TOKEN")
        }

        val result = fixture.coordinator().enroll(fixture.attempt)

        assertIs<RemoteOutcomeAmbiguous>(result)
        assertFalse(result.toString().contains(TEST_CREDENTIAL))
        assertFalse(result.toString().contains(TEST_ENROLLMENT_TOKEN))
    }

    @Test
    fun `fake protector does not retain delivered plaintext credential`() = runTest {
        val fixture = CoordinatorFixture()
        var calls = 0
        fixture.protector.protectAction = { credential ->
            credential.useSecret { secret ->
                assertTrue(secret == TEST_CREDENTIAL)
                calls += 1
            }
            com.wifitestorchestrator.agent.domain.credential.protection
                .ProtectCredentialResult.Protected(testEnvelope(credential.metadata))
        }

        assertIs<Enrolled>(fixture.coordinator().enroll(fixture.attempt))

        assertEquals(1, calls)
        assertFalse(
            fixture.protector.javaClass.declaredFields.any {
                it.type.name.contains("DeliveredCredential") ||
                    it.type.name.contains("AgentCredentialSecret")
            },
        )
    }

    @Test
    fun `public result model has no envelope nonce ciphertext AAD token or credential field`() {
        val forbidden =
            setOf(
                "envelope",
                "nonce",
                "ciphertext",
                "aad",
                "token",
                "credential",
            )
        val resultTypes =
            listOf(
                Enrolled::class.java,
                AlreadyEnrolled::class.java,
                MissingPrecondition::class.java,
                InvalidConfiguration::class.java,
                LocalStateBlocked::class.java,
                KeyIncompatible::class.java,
                PlatformFailure::class.java,
                RemoteRejected::class.java,
                KnownTransientFailure::class.java,
                RemoteOutcomeAmbiguous::class.java,
                ResponseIncompatible::class.java,
                ProtectionFailure::class.java,
                PersistenceFailure::class.java,
            )

        resultTypes.forEach { type ->
            type.declaredFields.forEach { field ->
                assertFalse(
                    forbidden.any { fragment ->
                        field.name.contains(fragment, ignoreCase = true)
                    },
                    "${type.simpleName}.${field.name} must not expose secret material",
                )
            }
        }
    }
}
