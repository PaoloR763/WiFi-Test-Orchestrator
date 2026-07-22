package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.data.persistence.room.LOCAL_STATE_SINGLETON_ID
import com.wifitestorchestrator.agent.data.persistence.room.LocalInstallationEntity
import com.wifitestorchestrator.agent.data.persistence.room.PersistedInstant
import com.wifitestorchestrator.agent.data.persistence.room.ServerConfigurationEntity
import com.wifitestorchestrator.agent.data.persistence.room.toEntity
import com.wifitestorchestrator.agent.data.persistence.room.toStoredConfigurationOrNull
import com.wifitestorchestrator.agent.data.persistence.room.toStoredInstallationOrNull
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PersistenceMappersTest {
    @Test
    fun `installation ID and timestamp round trip exactly`() {
        val timestamp = Instant.parse("2026-07-21T12:34:56.123456789Z")
        val entity = localIdentity().toEntity(timestamp)

        val stored = entity.toStoredInstallationOrNull()

        assertEquals(localIdentity(), stored?.localIdentity)
        assertEquals(timestamp, stored?.createdAt)
    }

    @Test
    fun `local entity mapper validates full width SQLite integers before narrowing`() {
        val valid = localIdentity().toEntity(Instant.EPOCH)

        assertNotNull(
            valid.copy(
                singletonId = 1L,
                createdAtNanoseconds = 0L,
            ).toStoredInstallationOrNull(),
        )
        assertNotNull(
            valid.copy(createdAtNanoseconds = 999_999_999L).toStoredInstallationOrNull(),
        )
        listOf(-1L, 1_000_000_000L, 4_294_967_296L, 5_294_967_295L).forEach { rawValue ->
            assertNull(valid.copy(createdAtNanoseconds = rawValue).toStoredInstallationOrNull())
        }
        assertNull(valid.copy(singletonId = 4_294_967_297L).toStoredInstallationOrNull())
    }

    @Test
    fun `pre epoch timestamp round trips exactly`() {
        val timestamp = Instant.ofEpochSecond(-1, 999_999_999)

        assertEquals(timestamp, PersistedInstant.from(timestamp).toInstantOrNull())
    }

    @Test
    fun `nanosecond precision is not reduced to milliseconds`() {
        val timestamp = Instant.ofEpochSecond(123, 123_456_789)

        assertEquals(timestamp, PersistedInstant.from(timestamp).toInstantOrNull())
    }

    @Test
    fun `nanosecond lower boundary is valid`() {
        assertEquals(
            Instant.ofEpochSecond(10, 0),
            PersistedInstant(10, 0).toInstantOrNull(),
        )
    }

    @Test
    fun `nanosecond upper boundary is valid`() {
        assertEquals(
            Instant.ofEpochSecond(10, 999_999_999),
            PersistedInstant(10, 999_999_999).toInstantOrNull(),
        )
    }

    @Test
    fun `negative nanoseconds are rejected`() {
        assertNull(PersistedInstant(10, -1).toInstantOrNull())
    }

    @Test
    fun `one billion nanoseconds are rejected instead of normalized`() {
        assertNull(PersistedInstant(10, 1_000_000_000).toInstantOrNull())
    }

    @Test
    fun `instant outside supported range is rejected`() {
        assertNull(PersistedInstant(Long.MAX_VALUE, 0).toInstantOrNull())
    }

    @Test
    fun `Instant MIN round trips exactly`() {
        assertEquals(
            Instant.MIN,
            PersistedInstant.from(Instant.MIN).toInstantOrNull(),
        )
    }

    @Test
    fun `Instant MAX round trips exactly`() {
        assertEquals(
            Instant.MAX,
            PersistedInstant.from(Instant.MAX).toInstantOrNull(),
        )
    }

    @Test
    fun `seconds and nanoseconds lexicographic order matches Instant order`() {
        val chronological =
            listOf(
                Instant.ofEpochSecond(-2, 999_999_999),
                Instant.ofEpochSecond(-1, 0),
                Instant.ofEpochSecond(-1, 1),
                Instant.ofEpochSecond(-1, 999_999_999),
                Instant.ofEpochSecond(0, 0),
                Instant.ofEpochSecond(0, 1),
            )
        val persistedInReverseOrder = chronological.asReversed().map(PersistedInstant::from)

        val restored =
            persistedInReverseOrder
                .sortedWith(compareBy(PersistedInstant::epochSeconds, PersistedInstant::nanoseconds))
                .map { requireNotNull(it.toInstantOrNull()) }

        assertEquals(chronological, restored)
    }

    @Test
    fun `invalid installation ID is rejected`() {
        val entity =
            LocalInstallationEntity(
                singletonId = LOCAL_STATE_SINGLETON_ID,
                installationId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
                createdAtEpochSeconds = 0,
                createdAtNanoseconds = 0,
            )

        assertNull(entity.toStoredInstallationOrNull())
    }

    @Test
    fun `non singleton installation row is rejected`() {
        val entity = localIdentity().toEntity(Instant.EPOCH).copy(singletonId = 2)

        assertNull(entity.toStoredInstallationOrNull())
    }

    @Test
    fun `canonical HTTPS URL and timestamp round trip exactly`() {
        val timestamp = Instant.parse("2026-07-21T12:34:56.987654321Z")
        val entity = serverConfiguration().toEntity(timestamp)

        val stored = entity.toStoredConfigurationOrNull()

        assertEquals(serverConfiguration(), stored?.configuration)
        assertEquals(timestamp, stored?.updatedAt)
    }

    @Test
    fun `server entity mapper validates full width SQLite integers before narrowing`() {
        val valid = serverConfiguration().toEntity(Instant.EPOCH)

        assertNotNull(
            valid.copy(
                singletonId = 1L,
                updatedAtNanoseconds = 0L,
            ).toStoredConfigurationOrNull(),
        )
        assertNotNull(
            valid.copy(updatedAtNanoseconds = 999_999_999L).toStoredConfigurationOrNull(),
        )
        listOf(-1L, 1_000_000_000L, 4_294_967_296L, 5_294_967_295L).forEach { rawValue ->
            assertNull(valid.copy(updatedAtNanoseconds = rawValue).toStoredConfigurationOrNull())
        }
        assertNull(valid.copy(singletonId = 4_294_967_297L).toStoredConfigurationOrNull())
    }

    @Test
    fun `HTTP URL is rejected on read`() {
        val entity =
            ServerConfigurationEntity(
                singletonId = LOCAL_STATE_SINGLETON_ID,
                baseUrl = "http://lab.invalid/",
                updatedAtEpochSeconds = 0,
                updatedAtNanoseconds = 0,
            )

        assertNull(entity.toStoredConfigurationOrNull())
    }

    @Test
    fun `non canonical HTTPS URL is rejected instead of normalized`() {
        val entity =
            ServerConfigurationEntity(
                singletonId = LOCAL_STATE_SINGLETON_ID,
                baseUrl = "https://LAB.example:443/",
                updatedAtEpochSeconds = 0,
                updatedAtNanoseconds = 0,
            )

        assertNull(entity.toStoredConfigurationOrNull())
    }

    @Test
    fun `non singleton server row is rejected`() {
        val entity = serverConfiguration().toEntity(Instant.EPOCH).copy(singletonId = 2)

        assertNull(entity.toStoredConfigurationOrNull())
    }

    @Test
    fun `invalid server timestamp is rejected`() {
        val entity = serverConfiguration().toEntity(Instant.EPOCH).copy(updatedAtNanoseconds = -1)

        assertNull(entity.toStoredConfigurationOrNull())
    }
}
