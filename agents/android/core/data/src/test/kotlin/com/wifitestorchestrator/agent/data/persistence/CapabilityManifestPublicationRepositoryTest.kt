package com.wifitestorchestrator.agent.data.persistence

import androidx.sqlite.db.SupportSQLiteDatabase
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestAcknowledgement
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestCodec
import com.wifitestorchestrator.agent.data.capability.CanonicalJson
import com.wifitestorchestrator.agent.data.capability.RehashedPersistedManifest
import com.wifitestorchestrator.agent.data.capability.TEST_GENERATED_AT
import com.wifitestorchestrator.agent.data.capability.canonicalFrozenDocument
import com.wifitestorchestrator.agent.data.capability.contractValidHistoricalDocument
import com.wifitestorchestrator.agent.data.capability.frozenManifest
import com.wifitestorchestrator.agent.data.capability.rehashPersistedManifest
import com.wifitestorchestrator.agent.data.capability.validateTestPersisted
import com.wifitestorchestrator.agent.data.capability.withTestProperty
import com.wifitestorchestrator.agent.data.persistence.room.CapabilityManifestPublicationEntity
import com.wifitestorchestrator.agent.data.persistence.room.RoomCapabilityManifestPublicationRepository
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.acceptPending
import com.wifitestorchestrator.agent.data.persistence.room.newPendingPublicationEntity
import java.time.Instant
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class CapabilityManifestPublicationRepositoryTest : RoomPersistenceTestBase() {
    @Test
    fun `sequence zero is reserved durably and retry survives repository recreation`() = runTest {
        val database = enrolledDatabase()
        val firstRepository = publicationRepository(database)
        val initial = enrolled(firstRepository)
        assertEquals(CapabilityManifestPublicationState.Empty, initial.publicationState)
        val pending = frozenManifest(sequence = 0)

        assertEquals(
            ReserveCapabilityManifestResult.Reserved,
            firstRepository.reserve(expectation(initial), pending),
        )
        val afterReservation = enrolled(firstRepository)
        val stored = assertIs<CapabilityManifestPublicationState.Stored>(
            afterReservation.publicationState,
        )
        assertEquals(1L, stored.nextManifestSequence)
        assertTrue(stored.pending!!.isByteIdenticalTo(pending))

        val recreated = publicationRepository(database)
        val ready =
            assertIs<RevalidateCapabilityManifestResult.Ready>(
                recreated.revalidateForSend(
                    initial.enrollmentIdentityFingerprint,
                    pending,
                    TEST_GENERATED_AT.plusSeconds(1),
                ),
            )
        assertTrue(ready.context.pending.isByteIdenticalTo(pending))
    }

    @Test
    fun `valid acknowledgement atomically moves pending to accepted`() = runTest {
        val database = enrolledDatabase()
        val repository = publicationRepository(database)
        val initial = enrolled(repository)
        val pending = frozenManifest()
        assertEquals(
            ReserveCapabilityManifestResult.Reserved,
            repository.reserve(expectation(initial), pending),
        )
        val ready =
            assertIs<RevalidateCapabilityManifestResult.Ready>(
                repository.revalidateForSend(
                    initial.enrollmentIdentityFingerprint,
                    pending,
                    TEST_GENERATED_AT.plusSeconds(1),
                ),
            )
        val acknowledgement =
            CapabilityManifestAcknowledgement(
                manifestId = pending.manifestId,
                manifestDigest = pending.canonicalDigest,
                serverReceivedAt = ACK_TIME,
            )

        assertEquals(
            AcceptCapabilityManifestResult.Accepted,
            repository.accept(
                initial.enrollmentIdentityFingerprint,
                pending,
                CapabilityManifestCredentialUse(
                    ready.context.enrollment.credentialMetadata.credentialId,
                    ready.context.enrollment.credentialMetadata.version.value,
                ),
                acknowledgement,
                TEST_GENERATED_AT.plusSeconds(2),
            ),
        )

        val accepted =
            assertIs<CapabilityManifestPublicationState.Stored>(
                enrolled(repository).publicationState,
            )
        assertEquals(null, accepted.pending)
        assertTrue(accepted.accepted!!.manifest.isByteIdenticalTo(pending))
        assertEquals(ACK_TIME, accepted.accepted.serverReceivedAt)
        assertEquals(1L, accepted.nextManifestSequence)
    }

    @Test
    fun `new reservation rejects historical matrix while current catalog matrix reserves`() =
        runTest {
            val database = enrolledDatabase()
            val repository = publicationRepository(database)
            val initial = enrolled(repository)
            val historicalCandidate =
                rehashPersistedManifest(contractValidHistoricalDocument())
            val historical =
                assertNotNull(
                    CapabilityManifestCodec().validateTestPersisted(historicalCandidate),
                )

            assertEquals(
                ReserveCapabilityManifestResult.Corrupt,
                repository.reserve(expectation(initial), historical),
            )
            assertEquals(
                CapabilityManifestPublicationState.Empty,
                enrolled(repository).publicationState,
            )

            val current = frozenManifest()
            assertEquals(
                ReserveCapabilityManifestResult.Reserved,
                repository.reserve(expectation(initial), current),
            )
            val stored =
                assertIs<CapabilityManifestPublicationState.Stored>(
                    enrolled(repository).publicationState,
                )
            assertTrue(stored.pending!!.isByteIdenticalTo(current))
        }

    @Test
    fun `historical accepted and pending require canonical UUID v4 with matching hashes`() =
        runTest {
            val cases =
                listOf(
                    InvalidStoredUuidCase(
                        label = "accepted UUID v1",
                        manifestId = "aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa",
                        accepted = true,
                    ),
                    InvalidStoredUuidCase(
                        label = "pending UUID v1",
                        manifestId = "aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa",
                        accepted = false,
                    ),
                    InvalidStoredUuidCase(
                        label = "uppercase UUID",
                        manifestId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
                        accepted = false,
                    ),
                    InvalidStoredUuidCase(
                        label = "malformed UUID",
                        manifestId = "not-a-uuid",
                        accepted = true,
                    ),
                )

            cases.forEach { case ->
                val database = enrolledDatabase()
                val repository = publicationRepository(database)
                val initial = enrolled(repository)
                val candidate =
                    rehashPersistedManifest(
                        canonicalFrozenDocument()
                            .withTestProperty(
                                "manifest_id",
                                JsonPrimitive(case.manifestId),
                            ),
                    )
                assertContentEquals(
                    candidate.payload,
                    CanonicalJson.encode(candidate.document),
                    case.label,
                )
                dropPublicationGuards(database.openHelper.writableDatabase)
                database.capabilityManifestPublicationDao().insert(
                    rawStoredManifestEntity(
                        enrollment = initial,
                        manifestId = case.manifestId,
                        candidate = candidate,
                        accepted = case.accepted,
                    ),
                )

                assertEquals(
                    CapabilityPublicationPreflightResult.Corrupt,
                    repository.preflight(),
                    case.label,
                )
            }
        }

    @Test
    fun `two concurrent reservations cannot allocate the same sequence twice`() = runTest {
        val database = enrolledDatabase()
        val repository = publicationRepository(database)
        val initial = enrolled(repository)
        val results =
            listOf(
                async { repository.reserve(expectation(initial), frozenManifest()) },
                async { repository.reserve(expectation(initial), frozenManifest()) },
            ).awaitAll()

        assertEquals(1, results.count { it == ReserveCapabilityManifestResult.Reserved })
        assertEquals(
            1,
            results.count {
                it == ReserveCapabilityManifestResult.PendingAlreadyExists ||
                    it == ReserveCapabilityManifestResult.StateChanged
            },
        )
    }

    @Test
    fun `foreign key restricts deletion of the enrollment parent`() = runTest {
        val database = enrolledDatabase()
        val repository = publicationRepository(database)
        val initial = enrolled(repository)
        assertEquals(
            ReserveCapabilityManifestResult.Reserved,
            repository.reserve(expectation(initial), frozenManifest()),
        )

        assertFails {
            database.openHelper.writableDatabase.execSQL(
                "DELETE FROM protected_enrollment WHERE singleton_id = 1",
            )
        }
    }

    @Test
    fun `raw storage classes tuples ranges digests payloads and binding fail closed`() = runTest {
        val adversarialUpdates =
            listOf(
                "pending_manifest_sequence = 0.5",
                "next_manifest_sequence = 'garbage'",
                "sequence_exhausted = x'00'",
                "pending_manifest_id = NULL",
                "pending_manifest_id = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'",
                "pending_generated_at_nanoseconds = 1000000000",
                "pending_canonical_digest = zeroblob(32)",
                "pending_semantic_fingerprint = zeroblob(32)",
                "enrollment_identity_fingerprint = zeroblob(32)",
                "next_manifest_sequence = 9",
                "pending_canonical_payload = zeroblob(262145)",
            )
        adversarialUpdates.forEach { update ->
            val database = enrolledDatabase()
            val repository = publicationRepository(database)
            val initial = enrolled(repository)
            assertEquals(
                ReserveCapabilityManifestResult.Reserved,
                repository.reserve(expectation(initial), frozenManifest()),
            )
            dropPublicationGuards(database.openHelper.writableDatabase)
            database.openHelper.writableDatabase.execSQL(
                "UPDATE capability_manifest_publication SET $update WHERE singleton_id = 1",
            )

            assertEquals(
                CapabilityPublicationPreflightResult.Corrupt,
                repository.preflight(),
                "raw update did not fail closed: $update",
            )
        }
    }

    @Test
    fun `accepted Long MAX marks exhaustion and cannot coexist with pending`() = runTest {
        val database = enrolledDatabase()
        val repository = publicationRepository(database)
        val initial = enrolled(repository)
        val last = frozenManifest(sequence = Long.MAX_VALUE)
        database.capabilityManifestPublicationDao().insert(
            newPendingPublicationEntity(initial.enrollmentIdentityFingerprint, last)
                .acceptPending(ACK_TIME),
        )

        val stored =
            assertIs<CapabilityManifestPublicationState.Stored>(
                enrolled(repository).publicationState,
            )
        assertTrue(stored.sequenceExhausted)
        assertEquals(Long.MAX_VALUE, stored.nextManifestSequence)
        assertEquals(Long.MAX_VALUE, stored.accepted!!.manifest.manifestSequence)
        assertEquals(null, stored.pending)
    }

    private suspend fun enrolledDatabase(): WtoAgentDatabase {
        val database = openInMemoryDatabase()
        repository(database).ensureLocalInstallation(localIdentity(), SETUP_TIME)
        repository(database).setServerConfiguration(serverConfiguration(), SETUP_TIME)
        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            protectedRepository(database).persist(protectedEnrollmentWrite()),
        )
        return database
    }

    private fun publicationRepository(
        database: WtoAgentDatabase,
    ): CapabilityManifestPublicationRepository =
        RoomCapabilityManifestPublicationRepository(WtoAgentDatabaseProvider { database })

    private suspend fun enrolled(
        repository: CapabilityManifestPublicationRepository,
    ): EnrolledCapabilityPublicationContext =
        assertIs<CapabilityPublicationPreflightResult.Enrolled>(repository.preflight()).context

    private fun expectation(
        context: EnrolledCapabilityPublicationContext,
    ): CapabilityPublicationReservationExpectation {
        val accepted =
            (context.publicationState as? CapabilityManifestPublicationState.Stored)?.accepted
        return CapabilityPublicationReservationExpectation(
            enrollmentIdentityFingerprint = context.enrollmentIdentityFingerprint,
            credentialId = context.enrollment.credentialMetadata.credentialId,
            credentialVersion = context.enrollment.credentialMetadata.version.value,
            expectedAcceptedManifestId = accepted?.manifest?.manifestId,
            expectedAcceptedSequence = accepted?.manifest?.manifestSequence,
        )
    }

    private fun dropPublicationGuards(database: SupportSQLiteDatabase) {
        database.execSQL("DROP TRIGGER IF EXISTS capability_manifest_publication_guard_insert")
        database.execSQL("DROP TRIGGER IF EXISTS capability_manifest_publication_guard_update")
    }

    private fun rawStoredManifestEntity(
        enrollment: EnrolledCapabilityPublicationContext,
        manifestId: String,
        candidate: RehashedPersistedManifest,
        accepted: Boolean,
    ): CapabilityManifestPublicationEntity =
        CapabilityManifestPublicationEntity(
            singletonId = 1L,
            enrollmentIdentityFingerprint =
                enrollment.enrollmentIdentityFingerprint.copyBytes(),
            nextManifestSequence = 1L,
            sequenceExhausted = 0L,
            acceptedManifestId = manifestId.takeIf { accepted },
            acceptedManifestSequence = 0L.takeIf { accepted },
            acceptedManifestDigest =
                candidate.canonicalDigest.copyBytes().takeIf { accepted },
            acceptedServerReceivedAtEpochSeconds =
                ACK_TIME.epochSecond.takeIf { accepted },
            acceptedServerReceivedAtNanoseconds =
                ACK_TIME.nano.toLong().takeIf { accepted },
            acceptedSemanticFingerprint =
                candidate.semanticFingerprint.copyBytes().takeIf { accepted },
            acceptedCanonicalPayload = candidate.payload.copyOf().takeIf { accepted },
            pendingManifestId = manifestId.takeUnless { accepted },
            pendingManifestSequence = 0L.takeUnless { accepted },
            pendingGeneratedAtEpochSeconds =
                TEST_GENERATED_AT.epochSecond.takeUnless { accepted },
            pendingGeneratedAtNanoseconds =
                TEST_GENERATED_AT.nano.toLong().takeUnless { accepted },
            pendingCanonicalPayload = candidate.payload.copyOf().takeUnless { accepted },
            pendingCanonicalDigest =
                candidate.canonicalDigest.copyBytes().takeUnless { accepted },
            pendingSemanticFingerprint =
                candidate.semanticFingerprint.copyBytes().takeUnless { accepted },
        )

    private data class InvalidStoredUuidCase(
        val label: String,
        val manifestId: String,
        val accepted: Boolean,
    )

    private companion object {
        val SETUP_TIME: Instant = Instant.parse("2026-07-25T11:00:00Z")
        val ACK_TIME: Instant = Instant.parse("2026-07-25T12:00:03.456789123Z")
    }
}
