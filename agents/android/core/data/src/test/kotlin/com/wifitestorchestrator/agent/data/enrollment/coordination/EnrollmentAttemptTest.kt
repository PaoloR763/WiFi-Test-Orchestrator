package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.TEST_ENROLLMENT_TOKEN
import java.io.Serializable
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class EnrollmentAttemptTest {
    @Test
    fun `attempt is ephemeral redacted and not serialization friendly`() {
        val attempt = validAttempt()

        assertEquals("EnrollmentAttempt(<redacted>)", attempt.toString())
        assertFalse((attempt as Any) is Serializable)
        assertFalse(
            attempt.javaClass.interfaces.any {
                it.name == "android.os.Parcelable" ||
                    it.name == "kotlinx.serialization.KSerializer"
            },
        )
        assertFalse(attempt.toString().contains(TEST_ENROLLMENT_TOKEN))
    }

    @Test
    fun `same live attempt freezes every request fact`() {
        val attempt = validAttempt()
        val before = attempt.frozenFingerprint()

        val after = attempt.frozenFingerprint()
        var tokenMatches = false
        attempt.command.enrollmentToken.useSecret {
            tokenMatches = it == TEST_ENROLLMENT_TOKEN
        }

        assertEquals(before, after)
        assertTrue(tokenMatches)
        assertEquals(TEST_REPORTED_AT.toString(), attempt.command.agentReportedAt)
    }

    @Test
    fun `distinct attempt has a distinct opaque identity`() {
        val first = validAttempt()
        val second = validAttempt()

        assertNotEquals(first.attemptId, second.attemptId)
        assertEquals("EnrollmentAttemptId(<opaque>)", first.attemptId.toString())
    }

    @Test
    fun `invalid inputs fail before an attempt exists`() {
        val invalid =
            EnrollmentAttempt.create(
                serverConfiguration = null,
                localIdentity = null,
                idempotencyKey = null,
                correlationId = null,
                enrollmentToken = null,
                displayName = null,
                platformVersion = null,
                agentVersion = null,
                agentReportedAt = Instant.EPOCH,
            )

        val result = assertIs<EnrollmentAttemptCreationResult.Invalid>(invalid)
        assertEquals(EnrollmentAttemptFailure.INVALID_LOCAL_REQUEST, result.reason)
        assertTrue(result.toString().isNotEmpty())
    }
}
