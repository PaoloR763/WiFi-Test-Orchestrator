package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpClient
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpCommand
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestHttpResult
import com.wifitestorchestrator.agent.data.capability.http.CapabilityManifestTransportFailure
import com.wifitestorchestrator.agent.data.capability.http.CredentialScopedHttpCancellation
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationRepository
import com.wifitestorchestrator.agent.data.persistence.CapabilityManifestPublicationState
import com.wifitestorchestrator.agent.data.persistence.CapabilityPublicationPreflightResult
import com.wifitestorchestrator.agent.data.persistence.InitializeLocalStateResult
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.RoomPersistenceTestBase
import com.wifitestorchestrator.agent.data.persistence.backendIdentity
import com.wifitestorchestrator.agent.data.persistence.localIdentity
import com.wifitestorchestrator.agent.data.persistence.protectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.serverConfiguration
import com.wifitestorchestrator.agent.data.persistence.room.RoomCapabilityManifestPublicationRepository
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.acceptPending
import com.wifitestorchestrator.agent.data.persistence.room.newPendingPublicationEntity
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFacts
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFactsProvider
import com.wifitestorchestrator.agent.domain.capability.WifiHardwarePresence
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialKeySecurityLevel
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionError
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.UseDecryptedCredentialResult
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import java.time.Instant
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class C08PublisherTest : RoomPersistenceTestBase() {
    @Test
    fun `not enrolled returns without facts UUID clock credential or network`() = runTest {
        val database = openInMemoryDatabase()
        val fixture = publisherFixture(database)

        assertEquals(CapabilityManifestPublicationResult.NotEnrolled, fixture.publisher.publish())
        assertEquals(0, fixture.facts.calls)
        assertEquals(0, fixture.uuid.calls)
        assertEquals(0, fixture.manifestClock.calls)
        assertEquals(0, fixture.protector.calls)
        assertEquals(0, fixture.http.commands.size)
    }

    @Test
    fun `first publication reserves sequence zero before credential and accepts atomically`() =
        runTest {
            val database = enrolledDatabase()
            val fixture = publisherFixture(database)
            fixture.http.results += HttpAnswer.Accept
            fixture.http.beforeExecute = {
                assertEquals(
                    1L,
                    scalarLong(
                        database,
                        "SELECT COUNT(*) FROM capability_manifest_publication " +
                            "WHERE pending_manifest_sequence = 0",
                    ),
                )
            }

            val result = assertIs<CapabilityManifestPublicationResult.Published>(
                fixture.publisher.publish(),
            )

            assertEquals(0L, result.manifestSequence)
            assertEquals(TEST_MANIFEST_ID, result.manifestId)
            assertEquals(1, fixture.protector.calls)
            assertEquals(1, fixture.http.commands.size)
            assertEquals(
                1L,
                scalarLong(
                    database,
                    "SELECT COUNT(*) FROM capability_manifest_publication " +
                        "WHERE pending_manifest_id IS NULL AND accepted_manifest_sequence = 0",
                ),
            )
        }

    @Test
    fun `already current has no new UUID manifest clock credential or network`() = runTest {
        val database = enrolledDatabase()
        val fixture = publisherFixture(database)
        fixture.http.results += HttpAnswer.Accept
        assertIs<CapabilityManifestPublicationResult.Published>(fixture.publisher.publish())
        val before =
            listOf(
                fixture.uuid.calls,
                fixture.manifestClock.calls,
                fixture.protector.calls,
                fixture.http.commands.size,
            )

        val current =
            assertIs<CapabilityManifestPublicationResult.AlreadyCurrent>(
                fixture.publisher.publish(),
            )

        assertEquals(0L, current.manifestSequence)
        assertEquals(before, listOf(
            fixture.uuid.calls,
            fixture.manifestClock.calls,
            fixture.protector.calls,
            fixture.http.commands.size,
        ))
    }

    @Test
    fun `ambiguous retry preserves frozen snapshot and renews request facts`() = runTest {
        val database = enrolledDatabase()
        val fixture = publisherFixture(database)
        fixture.http.results += HttpAnswer.Ambiguous
        fixture.http.results += HttpAnswer.Accept

        val first =
            assertIs<CapabilityManifestPublicationResult.PendingRetry>(
                fixture.publisher.publish(),
            )
        val second =
            assertIs<CapabilityManifestPublicationResult.Published>(
                fixture.publisher.publish(),
            )

        assertEquals(PendingRetryReason.AMBIGUOUS_TRANSPORT, first.reason)
        assertEquals(first.manifestId, second.manifestId)
        assertEquals(first.manifestSequence, second.manifestSequence)
        assertContentEquals(
            fixture.http.commands[0].canonicalPayload,
            fixture.http.commands[1].canonicalPayload,
        )
        assertTrue(fixture.http.commands[0].timestamp != fixture.http.commands[1].timestamp)
        assertTrue(fixture.http.commands[0].nonce != fixture.http.commands[1].nonce)
        assertTrue(fixture.http.commands[0].correlationId != fixture.http.commands[1].correlationId)
        assertEquals(1, fixture.uuid.calls)
        assertEquals(1, fixture.manifestClock.calls)
        assertEquals(1, fixture.facts.calls)
    }

    @Test
    fun `historical pending survives durable reopen publishes exact bytes and recovers accepted`() =
        runTest {
            val databaseName = newDatabaseName("c08-historical-reopen")
            val initialDatabase = openDatabase(databaseName)
            assertEquals(
                InitializeLocalStateResult.Created,
                repository(initialDatabase).initializeLocalState(
                    localIdentity = localIdentity(),
                    serverConfiguration = serverConfiguration(),
                    installationCreatedAt = SETUP_TIME,
                    serverConfigurationUpdatedAt = SETUP_TIME.plusSeconds(1),
                ),
            )
            assertEquals(
                PersistProtectedEnrollmentResult.Written,
                com.wifitestorchestrator.agent.data.persistence.room
                    .RoomProtectedEnrollmentRepository(
                        WtoAgentDatabaseProvider { initialDatabase },
                    ).persist(protectedEnrollmentWrite()),
            )
            val initialRepository = publicationRepository(initialDatabase)
            val initial =
                assertIs<CapabilityPublicationPreflightResult.Enrolled>(
                    initialRepository.preflight(),
                ).context
            val candidate =
                rehashPersistedManifest(
                    contractValidHistoricalDocument(
                        generatedAt = "2026-07-25t12:00:00.123456789Z",
                    ),
                )
            val historical =
                assertNotNull(CapabilityManifestCodec().validateTestPersisted(candidate))
            assertFalse(
                historical.copyCanonicalPayload().contentEquals(
                    frozenManifest().copyCanonicalPayload(),
                ),
            )
            initialDatabase.capabilityManifestPublicationDao().insert(
                newPendingPublicationEntity(
                    initial.enrollmentIdentityFingerprint,
                    historical,
                ),
            )

            initialDatabase.close()
            assertTrue(databaseFile(databaseName).isFile)
            val reopened = reopenDatabase(databaseName)
            val recoveredPending =
                assertIs<CapabilityPublicationPreflightResult.Enrolled>(
                    publicationRepository(reopened).preflight(),
                ).context
            val pendingState =
                assertIs<CapabilityManifestPublicationState.Stored>(
                    recoveredPending.publicationState,
                )
            assertContentEquals(
                candidate.payload,
                pendingState.pending!!.copyCanonicalPayload(),
            )

            val fixture = publisherFixture(reopened)
            fixture.http.results += HttpAnswer.Accept
            val published =
                assertIs<CapabilityManifestPublicationResult.Published>(
                    fixture.publisher.publish(),
                )

            assertEquals(TEST_MANIFEST_ID, published.manifestId)
            assertEquals(0L, published.manifestSequence)
            assertEquals(0, fixture.facts.calls)
            assertEquals(0, fixture.uuid.calls)
            assertEquals(0, fixture.manifestClock.calls)
            assertContentEquals(candidate.payload, fixture.http.commands.single().canonicalPayload)

            reopened.close()
            val acceptedDatabase = reopenDatabase(databaseName)
            val recoveredAccepted =
                assertIs<CapabilityPublicationPreflightResult.Enrolled>(
                    publicationRepository(acceptedDatabase).preflight(),
                ).context
            val acceptedState =
                assertIs<CapabilityManifestPublicationState.Stored>(
                    recoveredAccepted.publicationState,
                )
            assertEquals(null, acceptedState.pending)
            assertContentEquals(
                candidate.payload,
                acceptedState.accepted!!.manifest.copyCanonicalPayload(),
            )
            assertEquals(ACK_TIME, acceptedState.accepted.serverReceivedAt)
        }

    @Test
    fun `credential rotation for same binding retries pending with active credential`() = runTest {
        val database = enrolledDatabase()
        val fixture = publisherFixture(database)
        fixture.http.results += HttpAnswer.Ambiguous
        fixture.http.results += HttpAnswer.Accept
        assertIs<CapabilityManifestPublicationResult.PendingRetry>(fixture.publisher.publish())
        assertEquals(
            PersistProtectedEnrollmentResult.Replaced,
            com.wifitestorchestrator.agent.data.persistence.room.RoomProtectedEnrollmentRepository(
                WtoAgentDatabaseProvider { database },
            ).persist(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            ),
        )
        fixture.protector.credential = credential(SECOND_CREDENTIAL)

        assertIs<CapabilityManifestPublicationResult.Published>(fixture.publisher.publish())
        assertEquals(
            listOf(FIRST_CREDENTIAL_ID, SECOND_CREDENTIAL_ID),
            fixture.protector.usedCredentialIds,
        )
    }

    @Test
    fun `missing incompatible and invalidated keys retain pending with redacted result`() = runTest {
        listOf(
            CredentialProtectionError.KEY_MISSING,
            CredentialProtectionError.KEY_INCOMPATIBLE,
            CredentialProtectionError.KEY_INVALIDATED,
        ).forEach { protectionFailure ->
            val database = enrolledDatabase()
            val fixture = publisherFixture(database)
            fixture.protector.failure = protectionFailure

            val blocked =
                assertIs<CapabilityManifestPublicationResult.Blocked>(fixture.publisher.publish())

            assertEquals(CapabilityManifestBlockedReason.CREDENTIAL_PROTECTION, blocked.reason)
            assertEquals(0, fixture.http.commands.size)
            assertEquals(
                1L,
                scalarLong(
                    database,
                    "SELECT COUNT(*) FROM capability_manifest_publication " +
                        "WHERE pending_manifest_id IS NOT NULL",
                ),
            )
            assertTrue(!blocked.toString().contains(FIRST_CREDENTIAL))
        }
    }

    @Test
    fun `expired credential is blocked before protector and network with pending durable`() =
        runTest {
            val database =
                enrolledDatabase(
                    protectedEnrollmentWrite(expiresAt = TEST_GENERATED_AT),
                )
            val fixture = publisherFixture(database)

            val blocked =
                assertIs<CapabilityManifestPublicationResult.Blocked>(fixture.publisher.publish())

            assertEquals(CapabilityManifestBlockedReason.CREDENTIAL_UNUSABLE, blocked.reason)
            assertEquals(0, fixture.protector.calls)
            assertEquals(0, fixture.http.commands.size)
            assertEquals(
                1L,
                scalarLong(
                    database,
                    "SELECT COUNT(*) FROM capability_manifest_publication " +
                        "WHERE pending_manifest_id IS NOT NULL",
                ),
            )
        }

    @Test
    fun `transport cancellation maps to CancelledPending and keeps exact pending`() = runTest {
        val database = enrolledDatabase()
        val fixture = publisherFixture(database)
        fixture.http.results += HttpAnswer.Cancelled

        val cancelled =
            assertIs<CapabilityManifestPublicationResult.CancelledPending>(
                fixture.publisher.publish(),
            )

        assertEquals(TEST_MANIFEST_ID, cancelled.manifestId)
        assertEquals(0L, cancelled.manifestSequence)
        assertEquals(
            1L,
            scalarLong(
                database,
                "SELECT COUNT(*) FROM capability_manifest_publication " +
                    "WHERE pending_manifest_id IS NOT NULL",
            ),
        )
    }

    @Test
    fun `credential rotation during request prevents ack commit and retains pending`() = runTest {
        val database = enrolledDatabase()
        val fixture = publisherFixture(database)
        fixture.http.results += HttpAnswer.Accept
        fixture.http.beforeExecute = {
            val rotated =
                runBlocking {
                    com.wifitestorchestrator.agent.data.persistence.room
                        .RoomProtectedEnrollmentRepository(WtoAgentDatabaseProvider { database })
                        .persist(
                            protectedEnrollmentWrite(
                                credentialId = SECOND_CREDENTIAL_ID,
                                credentialVersion = 2,
                            ),
                        )
                }
            assertEquals(PersistProtectedEnrollmentResult.Replaced, rotated)
        }

        val blocked =
            assertIs<CapabilityManifestPublicationResult.Blocked>(fixture.publisher.publish())

        assertEquals(CapabilityManifestBlockedReason.ENROLLMENT_CHANGED, blocked.reason)
        assertEquals(
            1L,
            scalarLong(
                database,
                "SELECT COUNT(*) FROM capability_manifest_publication " +
                    "WHERE pending_manifest_id IS NOT NULL AND accepted_manifest_id IS NULL",
            ),
        )
    }

    @Test
    fun `server binding change during request prevents ack commit and retains pending`() = runTest {
        val database = enrolledDatabase()
        val fixture = publisherFixture(database)
        fixture.http.results += HttpAnswer.Accept
        fixture.http.beforeExecute = {
            database.openHelper.writableDatabase.execSQL(
                "UPDATE server_configuration SET base_url = ? WHERE singleton_id = 1",
                arrayOf<Any?>("https://backup.example/Tenant/"),
            )
            database.openHelper.writableDatabase.execSQL(
                "UPDATE protected_enrollment SET server_base_url = ? WHERE singleton_id = 1",
                arrayOf<Any?>("https://backup.example/Tenant/"),
            )
        }

        val blocked =
            assertIs<CapabilityManifestPublicationResult.Blocked>(fixture.publisher.publish())

        assertEquals(CapabilityManifestBlockedReason.CORRUPT_LOCAL_STATE, blocked.reason)
        assertEquals(
            1L,
            scalarLong(
                database,
                "SELECT COUNT(*) FROM capability_manifest_publication " +
                    "WHERE pending_manifest_id IS NOT NULL AND accepted_manifest_id IS NULL",
            ),
        )
    }

    @Test
    fun `different snapshot at Long MAX exhausts before UUID clock credential and network`() =
        runTest {
            val database = enrolledDatabase()
            val repository = publicationRepository(database)
            val initial =
                assertIs<CapabilityPublicationPreflightResult.Enrolled>(repository.preflight()).context
            database.capabilityManifestPublicationDao().insert(
                newPendingPublicationEntity(
                    initial.enrollmentIdentityFingerprint,
                    frozenManifest(sequence = Long.MAX_VALUE),
                ).acceptPending(ACK_TIME),
            )
            val fixture =
                publisherFixture(
                    database,
                    presence = WifiHardwarePresence.ABSENT,
                )

            assertEquals(
                CapabilityManifestPublicationResult.SequenceExhausted,
                fixture.publisher.publish(),
            )
            assertEquals(0, fixture.uuid.calls)
            assertEquals(0, fixture.manifestClock.calls)
            assertEquals(0, fixture.protector.calls)
            assertEquals(0, fixture.http.commands.size)
        }

    @Test
    fun `one process mutex serializes two independently constructed publishers`() = runTest {
        val database = enrolledDatabase()
        val processMutex = Mutex()
        val first = publisherFixture(database, processMutex = processMutex)
        val second = publisherFixture(database, processMutex = processMutex)
        val enteredHttp = CountDownLatch(1)
        val releaseHttp = CountDownLatch(1)
        first.http.results += HttpAnswer.Accept
        first.http.beforeExecute = {
            enteredHttp.countDown()
            check(releaseHttp.await(5, TimeUnit.SECONDS))
        }

        val firstResult = async(Dispatchers.Default) { first.publisher.publish() }
        assertTrue(
            withContext(Dispatchers.IO) { enteredHttp.await(5, TimeUnit.SECONDS) },
        )
        val secondResult = async(Dispatchers.Default) { second.publisher.publish() }
        delay(100)
        assertEquals(0, second.facts.calls)
        releaseHttp.countDown()

        assertIs<CapabilityManifestPublicationResult.Published>(firstResult.await())
        assertIs<CapabilityManifestPublicationResult.AlreadyCurrent>(secondResult.await())
        assertEquals(0, second.http.commands.size)
    }

    private suspend fun enrolledDatabase(
        enrollmentWrite: ProtectedEnrollmentWrite = protectedEnrollmentWrite(),
    ): WtoAgentDatabase {
        val database = openInMemoryDatabase()
        com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository(
            WtoAgentDatabaseProvider { database },
        ).ensureLocalInstallation(localIdentity(), SETUP_TIME)
        com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository(
            WtoAgentDatabaseProvider { database },
        ).setServerConfiguration(serverConfiguration(), SETUP_TIME)
        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            com.wifitestorchestrator.agent.data.persistence.room.RoomProtectedEnrollmentRepository(
                WtoAgentDatabaseProvider { database },
            ).persist(enrollmentWrite),
        )
        return database
    }

    private fun publisherFixture(
        database: WtoAgentDatabase,
        presence: WifiHardwarePresence = WifiHardwarePresence.PRESENT,
        processMutex: Mutex = Mutex(),
    ): PublisherFixture {
        val repository = publicationRepository(database)
        val facts = CountingFacts(presence)
        val protector = FakeCredentialProtector()
        val http = FakeHttpClient()
        val manifestClock = CountingClock(listOf(TEST_GENERATED_AT))
        val requestClock =
            CountingClock(
                listOf(
                    TEST_GENERATED_AT.plusSeconds(1),
                    TEST_GENERATED_AT.plusSeconds(2),
                    TEST_GENERATED_AT.plusSeconds(3),
                    TEST_GENERATED_AT.plusSeconds(4),
                ),
            )
        val uuid = CountingUuid(listOf(TEST_MANIFEST_ID))
        val random =
            QueueRandom(
                ArrayDeque(
                    listOf(
                        ByteArray(16) { 1 },
                        ByteArray(16) { 2 },
                        ByteArray(16) { 3 },
                    ),
                ),
            )
        val correlation =
            QueueCorrelation(
                ArrayDeque(
                    listOf(
                        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                    ),
                ),
            )
        val agentVersion = AgentVersion.parse("0.1.0")
        check(agentVersion is Valid)
        return PublisherFixture(
            publisher =
                DefaultCapabilityManifestPublisher(
                    repository = repository,
                    credentialProtector = protector,
                    factsProvider = facts,
                    agentVersion = agentVersion.value,
                    httpClient = http,
                    ioDispatcher = ImmediateDispatcher,
                    manifestClock = manifestClock,
                    requestClock = requestClock,
                    uuidSource = uuid,
                    randomSource = random,
                    correlationSource = correlation,
                    processMutex = processMutex,
                ),
            facts = facts,
            protector = protector,
            http = http,
            manifestClock = manifestClock,
            uuid = uuid,
        )
    }

    private fun publicationRepository(
        database: WtoAgentDatabase,
    ): CapabilityManifestPublicationRepository =
        RoomCapabilityManifestPublicationRepository(WtoAgentDatabaseProvider { database })

    private fun scalarLong(
        database: WtoAgentDatabase,
        query: String,
    ): Long =
        database.openHelper.writableDatabase.query(query).use {
            check(it.moveToFirst())
            it.getLong(0)
        }

    private data class PublisherFixture(
        val publisher: CapabilityManifestPublisher,
        val facts: CountingFacts,
        val protector: FakeCredentialProtector,
        val http: FakeHttpClient,
        val manifestClock: CountingClock,
        val uuid: CountingUuid,
    )

    private class CountingFacts(private val presence: WifiHardwarePresence) :
        AndroidCapabilityFactsProvider {
        var calls = 0

        override fun observe(): AndroidCapabilityFacts {
            calls += 1
            return AndroidCapabilityFacts("15", presence)
        }
    }

    private class CountingClock(private val values: List<Instant>) : CapabilityManifestClock {
        var calls = 0

        override fun now(): Instant = values.getOrElse(calls++) { values.last() }
    }

    private class CountingUuid(private val values: List<String>) : CapabilityManifestUuidSource {
        var calls = 0

        override fun next(): String = values.getOrElse(calls++) { values.last() }
    }

    private class QueueRandom(private val values: ArrayDeque<ByteArray>) :
        CapabilityManifestRandomSource {
        override fun nextBytes(size: Int): ByteArray = values.removeFirst().copyOf()
    }

    private class QueueCorrelation(private val values: ArrayDeque<String>) :
        CapabilityManifestCorrelationSource {
        override fun next(): String = values.removeFirst()
    }

    private object ImmediateDispatcher : CoroutineDispatcher() {
        override fun isDispatchNeeded(context: CoroutineContext): Boolean = false

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            block.run()
        }
    }

    private sealed interface HttpAnswer {
        data object Accept : HttpAnswer

        data object Ambiguous : HttpAnswer

        data object Cancelled : HttpAnswer
    }

    private class FakeHttpClient : CapabilityManifestHttpClient {
        val results = ArrayDeque<HttpAnswer>()
        val commands = mutableListOf<CapabilityManifestHttpCommand>()
        var beforeExecute: (() -> Unit)? = null

        override fun execute(
            command: CapabilityManifestHttpCommand,
            credential: AgentCredentialSecret,
            cancellation: CredentialScopedHttpCancellation,
        ): CapabilityManifestHttpResult {
            beforeExecute?.invoke()
            commands += command
            return when (results.removeFirst()) {
                HttpAnswer.Accept ->
                    CapabilityManifestHttpResult.Accepted(
                        CapabilityManifestAcknowledgement(
                            manifestId = command.expectedManifestId,
                            manifestDigest =
                                requireNotNull(command.canonicalPayload.sha256()),
                            serverReceivedAt = ACK_TIME,
                        ),
                    )
                HttpAnswer.Ambiguous ->
                    CapabilityManifestHttpResult.Ambiguous(
                        CapabilityManifestTransportFailure.TIMEOUT,
                    )
                HttpAnswer.Cancelled -> CapabilityManifestHttpResult.Cancelled
            }
        }
    }

    private class FakeCredentialProtector : CredentialProtector {
        var credential = credential(FIRST_CREDENTIAL)
        var failure: CredentialProtectionError? = null
        var calls = 0
        val usedCredentialIds = mutableListOf<String>()

        override fun inspect(): CredentialProtectionInspection =
            CredentialProtectionInspection.Compatible(CredentialKeySecurityLevel.SOFTWARE)

        override fun prepare(): CredentialProtectionPreparation =
            CredentialProtectionPreparation.AlreadyCompatible

        override fun protect(credential: DeliveredCredential): ProtectCredentialResult =
            error("Not used by capability publication")

        override fun useDecryptedCredential(
            envelope: ProtectedCredentialEnvelope,
            block: (AgentCredentialSecret) -> Unit,
        ): UseDecryptedCredentialResult {
            calls += 1
            failure?.let { return UseDecryptedCredentialResult.Failure(it) }
            usedCredentialIds += credential.credentialId.toString()
            block(credential)
            return UseDecryptedCredentialResult.Used
        }
    }

    private companion object {
        const val FIRST_CREDENTIAL =
            "wto_ac_1.77777777-7777-4777-8777-777777777777." +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        const val SECOND_CREDENTIAL =
            "wto_ac_1.88888888-8888-4888-8888-888888888888." +
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        const val FIRST_CREDENTIAL_ID = "77777777-7777-4777-8777-777777777777"
        const val SECOND_CREDENTIAL_ID = "88888888-8888-4888-8888-888888888888"
        val SETUP_TIME: Instant = Instant.parse("2026-07-25T11:00:00Z")
        val ACK_TIME: Instant = Instant.parse("2026-07-25T12:00:03.456789123Z")

        fun credential(raw: String): AgentCredentialSecret {
            val parsed = AgentCredentialSecret.parse(raw)
            check(parsed is Valid)
            return parsed.value
        }
    }
}
