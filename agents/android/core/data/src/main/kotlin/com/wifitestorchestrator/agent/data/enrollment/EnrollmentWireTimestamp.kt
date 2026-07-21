package com.wifitestorchestrator.agent.data.enrollment

import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset

private const val UTC_TIMESTAMP_MAX_CODE_POINTS = 32
private const val MAX_SUPPORTED_FRACTION_DIGITS = 11
private const val NANOSECOND_FRACTION_DIGITS = 9

private val utcTimestampPattern =
    Regex(
        "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,$MAX_SUPPORTED_FRACTION_DIGITS}))?Z$",
    )

internal object EnrollmentWireTimestamp {
    fun render(instant: Instant): String? {
        val rendered = instant.toString()
        return rendered.takeIf { parse(it) == instant }
    }

    fun parse(raw: String): Instant? {
        if (raw.codePointLength() !in 1..UTC_TIMESTAMP_MAX_CODE_POINTS) return null
        val match = utcTimestampPattern.matchEntire(raw) ?: return null
        val year = match.groupValues[1].toInt()
        if (year !in 1..9999) return null

        val fraction = match.groupValues[7]
        if (
            fraction.length > NANOSECOND_FRACTION_DIGITS &&
            fraction.drop(NANOSECOND_FRACTION_DIGITS).any { it != '0' }
        ) {
            return null
        }
        val nanosecond =
            fraction
                .take(NANOSECOND_FRACTION_DIGITS)
                .padEnd(NANOSECOND_FRACTION_DIGITS, '0')
                .toIntOrNull()
                ?: 0

        return try {
            LocalDateTime
                .of(
                    year,
                    match.groupValues[2].toInt(),
                    match.groupValues[3].toInt(),
                    match.groupValues[4].toInt(),
                    match.groupValues[5].toInt(),
                    match.groupValues[6].toInt(),
                    nanosecond,
                ).toInstant(ZoneOffset.UTC)
        } catch (_: DateTimeException) {
            null
        }
    }
}
