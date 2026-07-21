package com.wifitestorchestrator.agent.data.enrollment

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class EnrollmentWireTimestampTest {
    @Test
    fun fourDigitUtcTimestampsAndRepresentableFractionsAreAccepted() {
        val cases =
            mapOf(
                "0001-01-01T00:00:00Z" to Instant.parse("0001-01-01T00:00:00Z"),
                "2024-02-29T23:59:59.1Z" to Instant.parse("2024-02-29T23:59:59.1Z"),
                "2026-07-21T12:34:56.123456Z" to
                    Instant.parse("2026-07-21T12:34:56.123456Z"),
                "2026-07-21T12:34:56.123456789Z" to
                    Instant.parse("2026-07-21T12:34:56.123456789Z"),
            )

        cases.forEach { (raw, expected) ->
            assertEquals(expected, EnrollmentWireTimestamp.parse(raw))
        }
    }

    @Test
    fun zeroOnlySubnanosecondRemainderIsRemovedWithoutChangingTheInstant() {
        val expected = Instant.parse("2026-07-21T12:34:56.123456789Z")

        assertEquals(
            expected,
            EnrollmentWireTimestamp.parse("2026-07-21T12:34:56.1234567890Z"),
        )
        assertEquals(
            expected,
            EnrollmentWireTimestamp.parse("2026-07-21T12:34:56.12345678900Z"),
        )
    }

    @Test
    fun nonzeroSubnanosecondPrecisionIsRejectedWithoutTruncationOrRounding() {
        listOf(
            "2026-07-21T12:34:56.1234567891Z",
            "2026-07-21T12:34:56.12345678901Z",
        ).forEach { raw ->
            assertNull(EnrollmentWireTimestamp.parse(raw))
        }
    }

    @Test
    fun extendedYearsAndNonContractualUtcFormsAreRejected() {
        listOf(
            "",
            "+10000-01-01T00:00:00Z",
            "-0001-01-01T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00Ztrailing",
            "2026-01-01T00:00:00.123456789000Z",
        ).forEach { raw ->
            assertNull(EnrollmentWireTimestamp.parse(raw))
        }
    }

    @Test
    fun leapSecondTwentyFourHourAndLowercaseZMatchSchemaBackendRejection() {
        listOf(
            "2016-12-31T23:59:60Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00z",
        ).forEach { raw ->
            assertNull(EnrollmentWireTimestamp.parse(raw))
        }
    }

    @Test
    fun lowercaseTIsRejectedWithoutSilentNormalization() {
        assertNull(EnrollmentWireTimestamp.parse("2026-01-01t00:00:00Z"))
    }
}
