package com.wifitestorchestrator.agent.data.persistence.room

import java.time.DateTimeException
import java.time.Instant

internal data class PersistedInstant(
    val epochSeconds: Long,
    val nanoseconds: Int,
) {
    fun toInstantOrNull(): Instant? {
        if (nanoseconds !in NANOSECOND_RANGE) return null
        return try {
            Instant.ofEpochSecond(epochSeconds, nanoseconds.toLong())
        } catch (_: DateTimeException) {
            null
        }
    }

    companion object {
        private val NANOSECOND_RANGE = 0..999_999_999

        fun from(value: Instant): PersistedInstant =
            PersistedInstant(
                epochSeconds = value.epochSecond,
                nanoseconds = value.nano,
            )
    }
}
