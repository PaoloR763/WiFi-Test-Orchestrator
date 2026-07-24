package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.data.persistence.room.MappedProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.room.ProtectedEnrollmentEntity
import com.wifitestorchestrator.agent.data.persistence.room.RoomProtectedEnrollmentRepository
import com.wifitestorchestrator.agent.data.persistence.room.StorageInitializationException
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.isByteIdenticalTo
import com.wifitestorchestrator.agent.data.persistence.room.toMappedWrite
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import java.time.Instant
import java.util.concurrent.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class RoomProtectedEnrollmentRepositoryTest : RoomPersistenceTestBase() {
    @Test
    fun `read is absent and preflight requires configured matching C04 state`() = runTest {
        val database = openInMemoryDatabase()
        val protectedRepository = protectedRepository(database)

        assertEquals(ReadProtectedEnrollmentResult.Absent, protectedRepository.read())
        assertEquals(
            ProtectedEnrollmentPreflightResult.LocalStateIncomplete,
            protectedRepository.preflight(localIdentity(), serverConfiguration()),
        )

        repository(database).ensureLocalInstallation(localIdentity(), LOCAL_CREATED_AT)
        assertEquals(
            ProtectedEnrollmentPreflightResult.LocalStateIncomplete,
            protectedRepository.preflight(localIdentity(), serverConfiguration()),
        )

        repository(database).setServerConfiguration(serverConfiguration(), SERVER_UPDATED_AT)
        assertEquals(
            ProtectedEnrollmentPreflightResult.Absent,
            protectedRepository.preflight(localIdentity(), serverConfiguration()),
        )
        assertEquals(
            ProtectedEnrollmentPreflightResult.Conflict,
            protectedRepository.preflight(
                localIdentity(SECOND_INSTALLATION_ID),
                serverConfiguration(),
            ),
        )
        assertEquals(
            ProtectedEnrollmentPreflightResult.Conflict,
            protectedRepository.preflight(
                localIdentity(),
                serverConfiguration(SECOND_SERVER_URL),
            ),
        )
    }

    @Test
    fun `first active write is atomic and rereads every fact exactly`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        val write =
            protectedEnrollmentWrite(
                credentialVersion = 17,
                nonceByte = 0x4a,
                sealedByte = 0x5b,
            )

        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            protectedRepository.persist(write),
        )
        val read = assertIs<ReadProtectedEnrollmentResult.Compatible>(protectedRepository.read())
        assertStoredMatches(write, read.enrollment, expectedNonce = 0x4a, expectedSealed = 0x5b)
        val preflight =
            assertIs<ProtectedEnrollmentPreflightResult.Compatible>(
                protectedRepository.preflight(localIdentity(), serverConfiguration()),
            )
        assertStoredMatches(
            write,
            preflight.enrollment,
            expectedNonce = 0x4a,
            expectedSealed = 0x5b,
        )
        assertEquals(1, database.readProtectedEnrollmentEntitiesForTest().size)
    }

    @Test
    fun `equivalent write preserves the original random envelope byte for byte`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        val original =
            protectedEnrollmentWrite(
                credentialVersion = 4,
                nonceByte = 0x11,
                sealedByte = 0x22,
            )
        val equivalent =
            protectedEnrollmentWrite(
                credentialVersion = 4,
                nonceByte = 0x66,
                sealedByte = 0x77,
            )
        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            protectedRepository.persist(original),
        )
        val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()

        assertEquals(
            PersistProtectedEnrollmentResult.ExistingEquivalent,
            protectedRepository.persist(equivalent),
        )

        val after = database.readProtectedEnrollmentEntitiesForTest().single()
        assertTrue(before.isExactly(after))
        assertContentEquals(ByteArray(12) { 0x11 }, after.nonce)
        assertContentEquals(ByteArray(105) { 0x22 }, after.sealedCredential)
    }

    @Test
    fun `higher different credential rotates while lower version rolls back`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)

        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = FIRST_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            ),
        )
        assertEquals(
            PersistProtectedEnrollmentResult.Replaced,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 3,
                ),
            ),
        )
        assertEquals(
            PersistProtectedEnrollmentResult.Rollback,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = THIRD_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            ),
        )

        val read = assertIs<ReadProtectedEnrollmentResult.Compatible>(protectedRepository.read())
        assertEquals(SECOND_CREDENTIAL_ID, read.enrollment.credentialMetadata.credentialId.toString())
        assertEquals(3, read.enrollment.credentialMetadata.version.value)
    }

    @Test
    fun `same ID different version and different ID same version are conflicts`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        protectedRepository.persist(
            protectedEnrollmentWrite(
                credentialId = FIRST_CREDENTIAL_ID,
                credentialVersion = 5,
            ),
        )
        val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()

        assertEquals(
            PersistProtectedEnrollmentResult.Conflict,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = FIRST_CREDENTIAL_ID,
                    credentialVersion = 6,
                ),
            ),
        )
        assertEquals(
            PersistProtectedEnrollmentResult.Conflict,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 5,
                ),
            ),
        )
        assertTrue(before.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()))
    }

    @Test
    fun `backend identity installation and server mismatches conflict without writing`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        protectedRepository.persist(
            protectedEnrollmentWrite(
                credentialId = FIRST_CREDENTIAL_ID,
                credentialVersion = 1,
            ),
        )
        val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()
        val candidates =
            listOf(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                    backendIdentity =
                        backendIdentity(
                            agentId = SECOND_AGENT_ID,
                            deviceId = FIRST_DEVICE_ID,
                        ),
                ),
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                    backendIdentity =
                        backendIdentity(
                            agentId = FIRST_AGENT_ID,
                            deviceId = SECOND_DEVICE_ID,
                        ),
                ),
                protectedEnrollmentWrite(
                    expectedLocalIdentity = localIdentity(SECOND_INSTALLATION_ID),
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
                protectedEnrollmentWrite(
                    expectedServerConfiguration = serverConfiguration(SECOND_SERVER_URL),
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            )

        candidates.forEach { candidate ->
            assertEquals(
                PersistProtectedEnrollmentResult.Conflict,
                protectedRepository.persist(candidate),
            )
            assertTrue(before.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()))
        }
    }

    @Test
    fun `pending is rejected both initially and during replacement`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        val pending =
            protectedEnrollmentWrite(
                credentialId = FIRST_CREDENTIAL_ID,
                credentialVersion = 1,
                deliveryState = CredentialDeliveryState.PENDING,
            )

        assertEquals(
            PersistProtectedEnrollmentResult.PendingRejected,
            protectedRepository.persist(pending),
        )
        assertEquals(ReadProtectedEnrollmentResult.Absent, protectedRepository.read())

        protectedRepository.persist(
            protectedEnrollmentWrite(
                credentialId = FIRST_CREDENTIAL_ID,
                credentialVersion = 1,
            ),
        )
        val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()
        assertEquals(
            PersistProtectedEnrollmentResult.PendingRejected,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                    deliveryState = CredentialDeliveryState.PENDING,
                ),
            ),
        )
        assertTrue(before.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()))
    }

    @Test
    fun `invalid candidate is rejected without creating partial state`() = runTest {
        val database = configuredDatabase()
        val original = protectedEnrollmentWrite()
        val mismatchedEnvelope =
            ProtectedEnrollmentWrite(
                expectedLocalIdentity = original.expectedLocalIdentity,
                expectedServerConfiguration = original.expectedServerConfiguration,
                backendIdentity = original.backendIdentity,
                protocolVersion = original.protocolVersion,
                serverReceivedAt = original.serverReceivedAt,
                credentialMetadata = original.credentialMetadata,
                protectedCredential =
                    requireValidEnvelope(
                        credentialId =
                            validValue(
                                com.wifitestorchestrator.agent.domain.identity.CredentialId
                                    .parse(SECOND_CREDENTIAL_ID),
                            ),
                    ),
            )

        assertEquals(
            PersistProtectedEnrollmentResult.InvalidCandidate,
            protectedRepository(database).persist(mismatchedEnvelope),
        )
        assertEquals(0, database.readProtectedEnrollmentEntitiesForTest().size)
        assertEquals(
            ReadProtectedEnrollmentResult.Absent,
            protectedRepository(database).read(),
        )
    }

    @Test
    fun `stored pending row is unsupported and cannot be auto activated or replaced`() =
        runTest {
            val database = configuredDatabase()
            val pending = validEntity().copy(credentialDeliveryState = "PENDING")
            database.protectedEnrollmentDao().insert(pending)
            val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()
            val protectedRepository = protectedRepository(database)

            assertEquals(ReadProtectedEnrollmentResult.Unsupported, protectedRepository.read())
            assertEquals(
                ProtectedEnrollmentPreflightResult.Unsupported,
                protectedRepository.preflight(localIdentity(), serverConfiguration()),
            )
            assertEquals(
                PersistProtectedEnrollmentResult.Unsupported,
                protectedRepository.persist(
                    protectedEnrollmentWrite(
                        credentialId = SECOND_CREDENTIAL_ID,
                        credentialVersion = 2,
                    ),
                ),
            )
            assertTrue(before.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()))
        }

    @Test
    fun `unsupported row blocks read preflight persist and server changes without mutation`() =
        runTest {
            val database = configuredDatabase()
            val unsupported =
                validEntity().copy(
                    cryptoVersion = 2,
                    keyAlias = "com.wifitestorchestrator.agent.credential.aead.v2",
                )
            database.protectedEnrollmentDao().insert(unsupported)
            val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()
            val protectedRepository = protectedRepository(database)

            assertEquals(ReadProtectedEnrollmentResult.Unsupported, protectedRepository.read())
            assertEquals(
                ProtectedEnrollmentPreflightResult.Unsupported,
                protectedRepository.preflight(localIdentity(), serverConfiguration()),
            )
            assertEquals(
                PersistProtectedEnrollmentResult.Unsupported,
                protectedRepository.persist(protectedEnrollmentWrite()),
            )
            assertEquals(
                SetServerConfigurationResult.Unsupported,
                repository(database).setServerConfiguration(
                    serverConfiguration(SECOND_SERVER_URL),
                    Instant.EPOCH,
                ),
            )
            assertTrue(before.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()))
            assertServerUnchanged(database)
        }

    @Test
    fun `corrupt row blocks read preflight persist and server changes without mutation`() =
        runTest {
            val database = configuredDatabase()
            val corrupt = validEntity().copy(credentialDeliveryState = "UNKNOWN")
            database.protectedEnrollmentDao().insert(corrupt)
            val before = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()
            val protectedRepository = protectedRepository(database)

            assertEquals(ReadProtectedEnrollmentResult.Corrupt, protectedRepository.read())
            assertEquals(
                ProtectedEnrollmentPreflightResult.Corrupt,
                protectedRepository.preflight(localIdentity(), serverConfiguration()),
            )
            assertEquals(
                PersistProtectedEnrollmentResult.Corrupt,
                protectedRepository.persist(protectedEnrollmentWrite()),
            )
            assertEquals(
                SetServerConfigurationResult.Corrupt,
                repository(database).setServerConfiguration(
                    serverConfiguration(SECOND_SERVER_URL),
                    Instant.EPOCH,
                ),
            )
            assertTrue(before.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()))
            assertServerUnchanged(database)
        }

    @Test
    fun `durable compatible enrollment freezes server except exact idempotence`() = runTest {
        val database = configuredDatabase()
        protectedRepository(database).persist(protectedEnrollmentWrite())
        val localRepository = repository(database)
        val beforeEnrollment = database.readProtectedEnrollmentEntitiesForTest().single().deepCopy()

        assertEquals(
            SetServerConfigurationResult.Unchanged,
            localRepository.setServerConfiguration(serverConfiguration(), Instant.EPOCH),
        )
        assertEquals(
            SetServerConfigurationResult.Conflict,
            localRepository.setServerConfiguration(
                serverConfiguration(SECOND_SERVER_URL),
                Instant.EPOCH,
            ),
        )

        assertServerUnchanged(database)
        assertTrue(
            beforeEnrollment.isExactly(database.readProtectedEnrollmentEntitiesForTest().single()),
        )
    }

    @Test
    fun `storage initialization failure is closed and cancellation is rethrown`() = runTest {
        val failedRepository =
            RoomProtectedEnrollmentRepository(
                WtoAgentDatabaseProvider { throw StorageInitializationException() },
            )
        assertEquals(
            ReadProtectedEnrollmentResult.Failure(
                LocalPersistenceError.INITIALIZATION_FAILED,
            ),
            failedRepository.read(),
        )
        assertEquals(
            ProtectedEnrollmentPreflightResult.Failure(
                LocalPersistenceError.INITIALIZATION_FAILED,
            ),
            failedRepository.preflight(localIdentity(), serverConfiguration()),
        )
        assertEquals(
            PersistProtectedEnrollmentResult.Failure(
                LocalPersistenceError.INITIALIZATION_FAILED,
            ),
            failedRepository.persist(protectedEnrollmentWrite()),
        )

        val cancellation = CancellationException("synthetic cancellation")
        val cancellingRepository =
            RoomProtectedEnrollmentRepository(WtoAgentDatabaseProvider { throw cancellation })
        assertEquals(
            cancellation,
            assertFailsWith<CancellationException> { cancellingRepository.read() },
        )
    }

    @Test
    fun `storage failure does not fabricate success or partial enrollment`() = runTest {
        val database = configuredDatabase()
        database.openHelper.writableDatabase.execSQL("DROP TABLE protected_enrollment")

        val result = protectedRepository(database).persist(protectedEnrollmentWrite())

        val failure = assertIs<PersistProtectedEnrollmentResult.Failure>(result)
        assertEquals(LocalPersistenceError.UNKNOWN, failure.error)
        val configured = assertIs<ReadLocalStateResult.Configured>(repository(database).readLocalState())
        assertEquals(localIdentity(), configured.installation.localIdentity)
        assertEquals(serverConfiguration(), configured.serverConfiguration.configuration)
    }

    @Test
    fun `v2 then v3 replaces and v3 then v2 never downgrades`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = FIRST_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            ),
        )
        assertEquals(
            PersistProtectedEnrollmentResult.Replaced,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 3,
                ),
            ),
        )
        assertEquals(
            PersistProtectedEnrollmentResult.Rollback,
            protectedRepository.persist(
                protectedEnrollmentWrite(
                    credentialId = THIRD_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            ),
        )
        assertEquals(
            3L,
            database.readProtectedEnrollmentEntitiesForTest().single().credentialVersion,
        )
    }

    @Test
    fun `concurrent equivalent initial writes have one writer and preserve its envelope`() =
        runTest {
            val database = configuredDatabase()
            val protectedRepository = protectedRepository(database)
            val first =
                protectedEnrollmentWrite(
                    credentialVersion = 4,
                    nonceByte = 0x12,
                    sealedByte = 0x23,
                )
            val second =
                protectedEnrollmentWrite(
                    credentialVersion = 4,
                    nonceByte = 0x34,
                    sealedByte = 0x45,
                )

            val results =
                listOf(first, second)
                    .map { write ->
                        async(Dispatchers.Default) { protectedRepository.persist(write) }
                    }.awaitAll()

            assertEquals(1, results.count { it == PersistProtectedEnrollmentResult.Written })
            assertEquals(
                1,
                results.count {
                    it == PersistProtectedEnrollmentResult.ExistingEquivalent
                },
            )
            val stored = database.readProtectedEnrollmentEntitiesForTest().single()
            val firstEnvelope =
                stored.nonce.all { it == 0x12.toByte() } &&
                    stored.sealedCredential.all { it == 0x23.toByte() }
            val secondEnvelope =
                stored.nonce.all { it == 0x34.toByte() } &&
                    stored.sealedCredential.all { it == 0x45.toByte() }
            assertTrue(firstEnvelope.xor(secondEnvelope))
        }

    @Test
    fun `concurrent different IDs at same version have no false second success`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        val writes =
            listOf(
                protectedEnrollmentWrite(
                    credentialId = FIRST_CREDENTIAL_ID,
                    credentialVersion = 6,
                ),
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 6,
                ),
            )

        val results =
            writes
                .map { write ->
                    async(Dispatchers.Default) { protectedRepository.persist(write) }
                }.awaitAll()

        assertEquals(1, results.count { it == PersistProtectedEnrollmentResult.Written })
        assertEquals(1, results.count { it == PersistProtectedEnrollmentResult.Conflict })
        assertEquals(1, database.readProtectedEnrollmentEntitiesForTest().size)
        assertEquals(
            6L,
            database.readProtectedEnrollmentEntitiesForTest().single().credentialVersion,
        )
    }

    @Test
    fun `concurrent rotations converge on highest version in either scheduling order`() =
        runTest {
            repeat(8) { iteration ->
                val database = configuredDatabase()
                val protectedRepository = protectedRepository(database)
                protectedRepository.persist(
                    protectedEnrollmentWrite(
                        credentialId = FIRST_CREDENTIAL_ID,
                        credentialVersion = 1,
                    ),
                )
                val lower =
                    protectedEnrollmentWrite(
                        credentialId = SECOND_CREDENTIAL_ID,
                        credentialVersion = 2,
                    )
                val higher =
                    protectedEnrollmentWrite(
                        credentialId = THIRD_CREDENTIAL_ID,
                        credentialVersion = 3,
                    )
                val ordered = if (iteration % 2 == 0) listOf(lower, higher) else listOf(higher, lower)

                val results =
                    ordered
                        .map { write ->
                            async(Dispatchers.Default) {
                                protectedRepository.persist(write)
                            }
                        }.awaitAll()

                assertTrue(
                    results.all {
                        it == PersistProtectedEnrollmentResult.Replaced ||
                            it == PersistProtectedEnrollmentResult.Rollback
                    },
                )
                val stored = database.readProtectedEnrollmentEntitiesForTest().single()
                assertEquals(3L, stored.credentialVersion)
                assertEquals(THIRD_CREDENTIAL_ID, stored.credentialId)
            }
        }

    @Test
    fun `concurrent conflicting rotations leave one complete winner`() = runTest {
        val database = configuredDatabase()
        val protectedRepository = protectedRepository(database)
        protectedRepository.persist(
            protectedEnrollmentWrite(
                credentialId = FIRST_CREDENTIAL_ID,
                credentialVersion = 1,
            ),
        )
        val rotations =
            listOf(
                protectedEnrollmentWrite(
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                    nonceByte = 0x51,
                    sealedByte = 0x61,
                ),
                protectedEnrollmentWrite(
                    credentialId = THIRD_CREDENTIAL_ID,
                    credentialVersion = 2,
                    nonceByte = 0x52,
                    sealedByte = 0x62,
                ),
            )

        val results =
            rotations
                .map { write ->
                    async(Dispatchers.Default) { protectedRepository.persist(write) }
                }.awaitAll()

        assertEquals(1, results.count { it == PersistProtectedEnrollmentResult.Replaced })
        assertEquals(1, results.count { it == PersistProtectedEnrollmentResult.Conflict })
        val stored = database.readProtectedEnrollmentEntitiesForTest().single()
        assertEquals(2L, stored.credentialVersion)
        val secondWinner =
            stored.credentialId == SECOND_CREDENTIAL_ID &&
                stored.nonce.all { it == 0x51.toByte() } &&
                stored.sealedCredential.all { it == 0x61.toByte() }
        val thirdWinner =
            stored.credentialId == THIRD_CREDENTIAL_ID &&
                stored.nonce.all { it == 0x52.toByte() } &&
                stored.sealedCredential.all { it == 0x62.toByte() }
        assertTrue(secondWinner.xor(thirdWinner))
    }

    private suspend fun configuredDatabase(): WtoAgentDatabase {
        val database = openInMemoryDatabase()
        assertEquals(
            InitializeLocalStateResult.Created,
            repository(database).initializeLocalState(
                localIdentity = localIdentity(),
                serverConfiguration = serverConfiguration(),
                installationCreatedAt = LOCAL_CREATED_AT,
                serverConfigurationUpdatedAt = SERVER_UPDATED_AT,
            ),
        )
        return database
    }

    private fun validEntity(): ProtectedEnrollmentEntity =
        assertIs<MappedProtectedEnrollmentWrite.Active>(
            protectedEnrollmentWrite().toMappedWrite(),
        ).entity

    private suspend fun assertServerUnchanged(database: WtoAgentDatabase) {
        val local = assertIs<ReadLocalStateResult.Configured>(repository(database).readLocalState())
        assertEquals(serverConfiguration(), local.serverConfiguration.configuration)
        assertEquals(SERVER_UPDATED_AT, local.serverConfiguration.updatedAt)
    }

    private fun assertStoredMatches(
        write: ProtectedEnrollmentWrite,
        stored: StoredProtectedEnrollment,
        expectedNonce: Byte,
        expectedSealed: Byte,
    ) {
        assertEquals(write.expectedLocalIdentity, stored.localIdentity)
        assertEquals(write.expectedServerConfiguration, stored.serverConfiguration)
        assertEquals(write.backendIdentity, stored.backendIdentity)
        assertEquals(write.protocolVersion, stored.protocolVersion)
        assertEquals(write.serverReceivedAt, stored.serverReceivedAt)
        assertEquals(write.credentialMetadata, stored.credentialMetadata)
        stored.protectedCredential.useNonce { nonce ->
            assertContentEquals(ByteArray(12) { expectedNonce }, nonce)
        }
        stored.protectedCredential.useSealedCredential { sealed ->
            assertContentEquals(ByteArray(105) { expectedSealed }, sealed)
        }
    }

    private fun ProtectedEnrollmentEntity.deepCopy(): ProtectedEnrollmentEntity =
        copy(nonce = nonce.copyOf(), sealedCredential = sealedCredential.copyOf())

    private fun ProtectedEnrollmentEntity.isExactly(
        other: ProtectedEnrollmentEntity,
    ): Boolean = isByteIdenticalTo(other)

    private companion object {
        val LOCAL_CREATED_AT: Instant = Instant.parse("2026-07-21T12:00:00.123456789Z")
        val SERVER_UPDATED_AT: Instant = Instant.parse("2026-07-21T12:01:00.987654321Z")
    }
}
