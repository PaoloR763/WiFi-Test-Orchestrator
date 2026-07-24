package com.wifitestorchestrator.agent.data.persistence

import android.database.Cursor
import com.wifitestorchestrator.agent.data.persistence.room.LOCAL_STATE_SINGLETON_ID
import com.wifitestorchestrator.agent.data.persistence.room.MappedProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.room.ProtectedEnrollmentEntity
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.toMappedWrite
import java.time.Instant
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class ProtectedEnrollmentRawSqlTest : RoomPersistenceTestBase() {
    @Test
    fun `raw SQL integer versions are range checked before narrowing`() = runTest {
        val fixture = rawFixture()
        listOf(
            fixture.entity.copy(credentialVersion = 0),
            fixture.entity.copy(credentialVersion = -1),
            fixture.entity.copy(credentialVersion = Int.MAX_VALUE.toLong() + 1),
            fixture.entity.copy(credentialVersion = 4_294_967_297L),
            fixture.entity.copy(cryptoVersion = 0),
            fixture.entity.copy(cryptoVersion = -1),
            fixture.entity.copy(cryptoVersion = Int.MAX_VALUE.toLong() + 1),
            fixture.entity.copy(cryptoVersion = 4_294_967_297L),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `raw SQL future policy aliases cover ten digit Int versions without overflow`() = runTest {
        val fixture = rawFixture()
        fun alias(version: String) =
            "com.wifitestorchestrator.agent.credential.aead.v$version"

        listOf(999_999_999L, 1_000_000_000L, Int.MAX_VALUE.toLong()).forEach { version ->
            fixture.assertRaw(
                fixture.entity.copy(
                    cryptoVersion = version,
                    keyAlias = alias(version.toString()),
                ),
                ReadProtectedEnrollmentResult.Unsupported,
            )
        }

        listOf(
            fixture.entity.copy(
                cryptoVersion = Int.MAX_VALUE.toLong() + 1L,
                keyAlias = alias("2147483648"),
            ),
            fixture.entity.copy(
                cryptoVersion = 9_999_999_999L,
                keyAlias = alias("9999999999"),
            ),
            fixture.entity.copy(
                cryptoVersion = 1_000_000_000L,
                keyAlias = alias("1000000001"),
            ),
            fixture.entity.copy(
                cryptoVersion = 100_000_000L,
                keyAlias = alias("0100000000"),
            ),
            fixture.entity.copy(
                cryptoVersion = 2L,
                keyAlias = alias("10000000000"),
            ),
            fixture.entity.copy(cryptoVersion = 0L, keyAlias = alias("0")),
            fixture.entity.copy(cryptoVersion = -1L, keyAlias = alias("-1")),
            fixture.entity.copy(cryptoVersion = 2L, keyAlias = alias("2x")),
            fixture.entity.copy(
                cryptoVersion = 1_000_000_000L,
                keyAlias = alias("1000000000"),
                nonce = ByteArray(0),
            ),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `raw SQL rejects REAL TEXT and BLOB storage for INTEGER columns`() = runTest {
        val fixture = rawFixture()
        listOf(
            StorageClassCase("credential_version", 1.9, "real"),
            StorageClassCase("credential_version", "1x", "text"),
            StorageClassCase("credential_version", byteArrayOf(0x31), "blob"),
            StorageClassCase("server_received_at_nanoseconds", 1.9, "real"),
            StorageClassCase(
                "issued_at_epoch_seconds",
                "${fixture.entity.issuedAtEpochSeconds}x",
                "text",
            ),
            StorageClassCase("expires_at_epoch_seconds", byteArrayOf(0x31), "blob"),
            StorageClassCase("crypto_version", 1.9, "real"),
        ).forEach { candidate ->
            fixture.assertStorageClassCorrupt(candidate)
        }
    }

    @Test
    fun `raw SQL rejects BLOB storage for every security relevant TEXT family`() = runTest {
        val fixture = rawFixture()
        listOf(
            StorageClassCase(
                "installation_id",
                fixture.entity.installationId.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase(
                "server_base_url",
                fixture.entity.serverBaseUrl.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase(
                "credential_delivery_state",
                fixture.entity.credentialDeliveryState.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase(
                "protocol_version",
                fixture.entity.protocolVersion.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase(
                "key_alias",
                fixture.entity.keyAlias.encodeToByteArray(),
                "blob",
            ),
        ).forEach { candidate ->
            fixture.assertStorageClassCorrupt(candidate)
        }
    }

    @Test
    fun `raw SQL rejects TEXT INTEGER and REAL storage for BLOB columns`() = runTest {
        val fixture = rawFixture()
        listOf(
            StorageClassCase("nonce", "N".repeat(12), "text"),
            StorageClassCase("nonce", 12L, "integer"),
            StorageClassCase("nonce", 12.5, "real"),
            StorageClassCase(
                "sealed_credential",
                SECRET_STORAGE_MARKER.padEnd(105, 'S'),
                "text",
            ),
            StorageClassCase("sealed_credential", 105L, "integer"),
            StorageClassCase("sealed_credential", 105.5, "real"),
        ).forEach { candidate ->
            fixture.assertStorageClassCorrupt(candidate)
        }
    }

    @Test
    fun `all nineteen columns enforce or validate their exact SQLite storage class`() = runTest {
        val fixture = rawFixture()
        assertFailsWith<android.database.sqlite.SQLiteException> {
            fixture.insertRaw(
                fixture.entity,
                mapOf("singleton_id" to "1x"),
            )
        }
        assertEquals(0L, fixture.scalarLong("SELECT COUNT(*) FROM protected_enrollment"))

        listOf(
            StorageClassCase(
                "installation_id",
                fixture.entity.installationId.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase(
                "server_base_url",
                fixture.entity.serverBaseUrl.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase("agent_id", fixture.entity.agentId.encodeToByteArray(), "blob"),
            StorageClassCase("device_id", fixture.entity.deviceId.encodeToByteArray(), "blob"),
            StorageClassCase(
                "protocol_version",
                fixture.entity.protocolVersion.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase("server_received_at_epoch_seconds", 1.9, "real"),
            StorageClassCase("server_received_at_nanoseconds", 1.9, "real"),
            StorageClassCase(
                "credential_id",
                fixture.entity.credentialId.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase("credential_version", 1.9, "real"),
            StorageClassCase("issued_at_epoch_seconds", 1.9, "real"),
            StorageClassCase("issued_at_nanoseconds", 1.9, "real"),
            StorageClassCase("expires_at_epoch_seconds", 1.9, "real"),
            StorageClassCase("expires_at_nanoseconds", 1.9, "real"),
            StorageClassCase(
                "credential_delivery_state",
                fixture.entity.credentialDeliveryState.encodeToByteArray(),
                "blob",
            ),
            StorageClassCase("crypto_version", 1.9, "real"),
            StorageClassCase("key_alias", fixture.entity.keyAlias.encodeToByteArray(), "blob"),
            StorageClassCase("nonce", "N".repeat(12), "text"),
            StorageClassCase("sealed_credential", "S".repeat(105), "text"),
        ).forEach { candidate ->
            fixture.assertStorageClassCorrupt(candidate)
        }
    }

    @Test
    fun `raw SQL nanoseconds are range checked without modulo truncation`() = runTest {
        val fixture = rawFixture()
        listOf(
            fixture.entity.copy(serverReceivedAtNanoseconds = -1),
            fixture.entity.copy(serverReceivedAtNanoseconds = 1_000_000_000),
            fixture.entity.copy(serverReceivedAtNanoseconds = 4_294_967_296L),
            fixture.entity.copy(issuedAtNanoseconds = -1),
            fixture.entity.copy(issuedAtNanoseconds = 1_000_000_000),
            fixture.entity.copy(expiresAtNanoseconds = -1),
            fixture.entity.copy(expiresAtNanoseconds = 1_000_000_000),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `raw SQL rejects impossible timestamp windows and seconds`() = runTest {
        val fixture = rawFixture()
        listOf(
            fixture.entity.copy(
                serverReceivedAtEpochSeconds = fixture.entity.issuedAtEpochSeconds - 1,
            ),
            fixture.entity.copy(
                serverReceivedAtEpochSeconds = fixture.entity.expiresAtEpochSeconds,
                serverReceivedAtNanoseconds = fixture.entity.expiresAtNanoseconds,
            ),
            fixture.entity.copy(
                expiresAtEpochSeconds = fixture.entity.issuedAtEpochSeconds,
                expiresAtNanoseconds = fixture.entity.issuedAtNanoseconds,
            ),
            fixture.entity.copy(serverReceivedAtEpochSeconds = Long.MAX_VALUE),
            fixture.entity.copy(expiresAtEpochSeconds = Long.MIN_VALUE),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `raw SQL gives known v1 corruption precedence over unsupported dimensions`() = runTest {
        val fixture = rawFixture()
        val futureAlias = "com.wifitestorchestrator.agent.credential.aead.v2"
        listOf(
            fixture.entity.copy(
                credentialDeliveryState = "PENDING",
                nonce = ByteArray(13),
            ) to ReadProtectedEnrollmentResult.Corrupt,
            fixture.entity.copy(
                credentialDeliveryState = "PENDING",
                sealedCredential = ByteArray(106),
            ) to ReadProtectedEnrollmentResult.Corrupt,
            fixture.entity.copy(
                credentialDeliveryState = "PENDING",
            ) to ReadProtectedEnrollmentResult.Unsupported,
            fixture.entity.copy(
                protocolVersion = "2.0.0",
                nonce = ByteArray(13),
            ) to ReadProtectedEnrollmentResult.Corrupt,
            fixture.entity.copy(
                protocolVersion = "2.0.0",
                sealedCredential = ByteArray(106),
            ) to ReadProtectedEnrollmentResult.Corrupt,
            fixture.entity.copy(
                protocolVersion = "2.0.0",
            ) to ReadProtectedEnrollmentResult.Unsupported,
            fixture.entity.copy(
                cryptoVersion = 2,
                keyAlias = futureAlias,
                nonce = ByteArray(13),
                sealedCredential = ByteArray(106),
            ) to ReadProtectedEnrollmentResult.Unsupported,
            fixture.entity.copy(
                cryptoVersion = 2,
                keyAlias = futureAlias,
                nonce = ByteArray(0),
            ) to ReadProtectedEnrollmentResult.Corrupt,
            fixture.entity.copy(
                keyAlias = futureAlias,
                nonce = ByteArray(13),
                sealedCredential = ByteArray(106),
            ) to ReadProtectedEnrollmentResult.Corrupt,
            fixture.entity.copy(
                keyAlias = "unrecognized.future.alias",
            ) to ReadProtectedEnrollmentResult.Corrupt,
        ).forEach { (entity, expected) ->
            fixture.assertRaw(entity, expected)
        }
    }

    @Test
    fun `raw SQL rejects malformed state alias and protocol representations`() = runTest {
        val fixture = rawFixture()
        listOf(
            fixture.entity.copy(credentialDeliveryState = "active"),
            fixture.entity.copy(credentialDeliveryState = "UNKNOWN"),
            fixture.entity.copy(credentialDeliveryState = ""),
            fixture.entity.copy(keyAlias = ""),
            fixture.entity.copy(
                keyAlias = "com.wifitestorchestrator.agent.credential.aead.v0",
            ),
            fixture.entity.copy(protocolVersion = "01.0.0"),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `raw SQL rejects invalid current nonce and ciphertext lengths`() = runTest {
        val fixture = rawFixture()
        listOf(
            fixture.entity.copy(nonce = ByteArray(0)),
            fixture.entity.copy(nonce = ByteArray(11)),
            fixture.entity.copy(nonce = ByteArray(13)),
            fixture.entity.copy(sealedCredential = ByteArray(0)),
            fixture.entity.copy(sealedCredential = ByteArray(104)),
            fixture.entity.copy(sealedCredential = ByteArray(106)),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `raw SQL rejects empty excessive noncanonical and inconsistent identities`() = runTest {
        val fixture = rawFixture()
        listOf(
            fixture.entity.copy(installationId = ""),
            fixture.entity.copy(installationId = "x".repeat(512)),
            fixture.entity.copy(installationId = SECOND_INSTALLATION_ID),
            fixture.entity.copy(serverBaseUrl = "https://LAB.example:443/"),
            fixture.entity.copy(serverBaseUrl = SECOND_SERVER_URL),
            fixture.entity.copy(agentId = ""),
            fixture.entity.copy(agentId = "x".repeat(512)),
            fixture.entity.copy(agentId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
            fixture.entity.copy(deviceId = ""),
            fixture.entity.copy(deviceId = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"),
            fixture.entity.copy(credentialId = ""),
            fixture.entity.copy(credentialId = "x".repeat(512)),
            fixture.entity.copy(credentialId = "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC"),
        ).forEach { entity ->
            fixture.assertRaw(entity, ReadProtectedEnrollmentResult.Corrupt)
        }
    }

    @Test
    fun `foreign keys reject ordinary orphan and disabled FK orphan is read corrupt`() = runTest {
        val fixture = rawFixture()
        val orphan = fixture.entity.copy(singletonId = 2)

        assertFailsWith<android.database.sqlite.SQLiteConstraintException> {
            fixture.insertRaw(orphan)
        }
        fixture.withForeignKeysDisabled {
            fixture.insertRaw(orphan)
        }
        assertEquals(1L, fixture.scalarLong("PRAGMA foreign_keys"))
        assertEquals(ReadProtectedEnrollmentResult.Corrupt, fixture.repository.read())
        assertEquals(1L, fixture.scalarLong("SELECT COUNT(*) FROM protected_enrollment"))
    }

    @Test
    fun `matching orphan cannot create either missing C04 parent`() = runTest {
        OrphanParentState.entries.forEach { parentState ->
            val fixture = orphanFixture(parentState)

            fixture.assertC04ParentMutationsBlocked(
                expectedRead = ReadProtectedEnrollmentResult.Corrupt,
                expectedFailure = LocalPersistenceError.CORRUPTION,
                expectedSetServer = SetServerConfigurationResult.Corrupt,
            )
        }
    }

    @Test
    fun `corrupt pending and future orphans cannot be legitimized by C04 writes`() = runTest {
        protectedRepresentationCases().forEach { candidate ->
            val fixture =
                orphanFixture(
                    parentState = OrphanParentState.BOTH_MISSING,
                    candidate = candidate.entity,
                    overrides = candidate.overrides,
                )
            candidate.expectedStorageClass?.let { expected ->
                assertEquals(expected, fixture.storageClass("crypto_version"))
            }

            fixture.assertC04ParentMutationsBlocked(
                expectedRead = ReadProtectedEnrollmentResult.Corrupt,
                expectedFailure = LocalPersistenceError.CORRUPTION,
                expectedSetServer = SetServerConfigurationResult.Corrupt,
            )
        }
    }

    @Test
    fun `complete corrupt or unsupported enrollment blocks every C04 mutation`() = runTest {
        protectedRepresentationCases().forEach { candidate ->
            val fixture = rawFixture()
            fixture.insertRaw(candidate.entity, candidate.overrides)
            candidate.expectedStorageClass?.let { expected ->
                assertEquals(expected, fixture.storageClass("crypto_version"))
            }

            fixture.assertC04ParentMutationsBlocked(
                expectedRead = candidate.expectedRead,
                expectedFailure = candidate.expectedFailure,
                expectedSetServer = candidate.expectedSetServer,
            )
        }
    }

    @Test
    fun `complete compatible enrollment permits only exact C04 idempotence`() = runTest {
        val fixture = rawFixture()
        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            fixture.repository.persist(protectedEnrollmentWrite()),
        )
        val before = fixture.durableSnapshot()

        assertEquals(
            EnsureLocalInstallationResult.Existing,
            fixture.localRepository.ensureLocalInstallation(localIdentity(), Instant.EPOCH),
        )
        assertEquals(
            InitializeLocalStateResult.ExistingEquivalent,
            fixture.localRepository.initializeLocalState(
                localIdentity = localIdentity(),
                serverConfiguration = serverConfiguration(),
                installationCreatedAt = Instant.EPOCH,
                serverConfigurationUpdatedAt = Instant.EPOCH,
            ),
        )
        assertEquals(
            SetServerConfigurationResult.Unchanged,
            fixture.localRepository.setServerConfiguration(
                serverConfiguration(),
                Instant.EPOCH,
            ),
        )
        assertEquals(
            EnsureLocalInstallationResult.Conflict,
            fixture.localRepository.ensureLocalInstallation(
                localIdentity(SECOND_INSTALLATION_ID),
                Instant.EPOCH,
            ),
        )
        assertEquals(
            InitializeLocalStateResult.Conflict,
            fixture.localRepository.initializeLocalState(
                localIdentity = localIdentity(SECOND_INSTALLATION_ID),
                serverConfiguration = serverConfiguration(),
                installationCreatedAt = Instant.EPOCH,
                serverConfigurationUpdatedAt = Instant.EPOCH,
            ),
        )
        assertEquals(
            InitializeLocalStateResult.Conflict,
            fixture.localRepository.initializeLocalState(
                localIdentity = localIdentity(),
                serverConfiguration = serverConfiguration(SECOND_SERVER_URL),
                installationCreatedAt = Instant.EPOCH,
                serverConfigurationUpdatedAt = Instant.EPOCH,
            ),
        )
        assertEquals(
            SetServerConfigurationResult.Conflict,
            fixture.localRepository.setServerConfiguration(
                serverConfiguration(SECOND_SERVER_URL),
                Instant.EPOCH,
            ),
        )

        assertTrue(before == fixture.durableSnapshot(), "C04 idempotence changed durable rows")
        assertIs<ReadProtectedEnrollmentResult.Compatible>(fixture.repository.read())
    }

    @Test
    fun `multiple raw singleton candidates are corrupt and remain intact`() = runTest {
        val fixture = rawFixture()
        fixture.withForeignKeysDisabled {
            fixture.insertRaw(fixture.entity)
            fixture.insertRaw(
                fixture.entity.copy(
                    singletonId = 2,
                    credentialId = SECOND_CREDENTIAL_ID,
                    credentialVersion = 2,
                ),
            )
        }

        assertEquals(ReadProtectedEnrollmentResult.Corrupt, fixture.repository.read())
        assertEquals(2L, fixture.scalarLong("SELECT COUNT(*) FROM protected_enrollment"))
    }

    @Test
    fun `FK restoration preserves primary failure and suppresses distinct cleanup only`() =
        runTest {
            val fixture = rawFixture()
            val primary = IllegalStateException("primary")

            val observed =
                assertFailsWith<IllegalStateException> {
                    fixture.withForeignKeysDisabled {
                        assertEquals(0L, fixture.scalarLong("PRAGMA foreign_keys"))
                        throw primary
                    }
                }

            assertSame(primary, observed)
            assertTrue(observed.suppressed.isEmpty())
            assertEquals(1L, fixture.scalarLong("PRAGMA foreign_keys"))

            val cleanup = IllegalArgumentException("cleanup")
            val observedWithCleanup =
                assertFailsWith<IllegalStateException> {
                    withCleanupPreservingPrimaryFailure(
                        cleanup = { throw cleanup },
                        block = { throw primary },
                    )
                }
            assertSame(primary, observedWithCleanup)
            assertEquals(listOf(cleanup), observedWithCleanup.suppressed.toList())

            val shared = IllegalStateException("shared")
            val observedShared =
                assertFailsWith<IllegalStateException> {
                    withCleanupPreservingPrimaryFailure(
                        cleanup = { throw shared },
                        block = { throw shared },
                    )
                }
            assertSame(shared, observedShared)
            assertTrue(observedShared.suppressed.isEmpty())
        }

    private data class StorageClassCase(
        val column: String,
        val value: Any,
        val expectedStorageClass: String,
    )

    private data class ProtectedRepresentationCase(
        val entity: ProtectedEnrollmentEntity,
        val overrides: Map<String, Any> = emptyMap(),
        val expectedStorageClass: String? = null,
        val expectedRead: ReadProtectedEnrollmentResult,
        val expectedFailure: LocalPersistenceError,
        val expectedSetServer: SetServerConfigurationResult,
    )

    private enum class OrphanParentState {
        BOTH_MISSING,
        SERVER_MISSING,
        INSTALLATION_MISSING,
    }

    private fun protectedRepresentationCases(): List<ProtectedRepresentationCase> {
        val entity = validEntity()
        return listOf(
            ProtectedRepresentationCase(
                entity = entity,
                overrides = mapOf("crypto_version" to 1.9),
                expectedStorageClass = "real",
                expectedRead = ReadProtectedEnrollmentResult.Corrupt,
                expectedFailure = LocalPersistenceError.CORRUPTION,
                expectedSetServer = SetServerConfigurationResult.Corrupt,
            ),
            ProtectedRepresentationCase(
                entity =
                    entity.copy(
                        cryptoVersion = 2,
                        keyAlias = "com.wifitestorchestrator.agent.credential.aead.v2",
                        nonce = ByteArray(13),
                        sealedCredential = ByteArray(106),
                    ),
                expectedRead = ReadProtectedEnrollmentResult.Unsupported,
                expectedFailure = LocalPersistenceError.STATE_CONFLICT,
                expectedSetServer = SetServerConfigurationResult.Unsupported,
            ),
            ProtectedRepresentationCase(
                entity = entity.copy(credentialDeliveryState = "PENDING"),
                expectedRead = ReadProtectedEnrollmentResult.Unsupported,
                expectedFailure = LocalPersistenceError.STATE_CONFLICT,
                expectedSetServer = SetServerConfigurationResult.Unsupported,
            ),
            ProtectedRepresentationCase(
                entity = entity.copy(nonce = ByteArray(13)),
                expectedRead = ReadProtectedEnrollmentResult.Corrupt,
                expectedFailure = LocalPersistenceError.CORRUPTION,
                expectedSetServer = SetServerConfigurationResult.Corrupt,
            ),
        )
    }

    private fun validEntity(): ProtectedEnrollmentEntity =
        (protectedEnrollmentWrite().toMappedWrite() as MappedProtectedEnrollmentWrite.Active)
            .entity

    private suspend fun orphanFixture(
        parentState: OrphanParentState,
        candidate: ProtectedEnrollmentEntity = validEntity(),
        overrides: Map<String, Any> = emptyMap(),
    ): RawFixture {
        val database = openInMemoryDatabase()
        val fixture =
            RawFixture(
                database = database,
                repository = protectedRepository(database),
                localRepository = repository(database),
                entity = candidate,
            )
        when (parentState) {
            OrphanParentState.BOTH_MISSING -> Unit
            OrphanParentState.SERVER_MISSING ->
                assertEquals(
                    EnsureLocalInstallationResult.Created,
                    fixture.localRepository.ensureLocalInstallation(
                        localIdentity(),
                        LOCAL_CREATED_AT,
                    ),
                )
            OrphanParentState.INSTALLATION_MISSING -> Unit
        }
        fixture.withForeignKeysDisabled {
            if (parentState == OrphanParentState.INSTALLATION_MISSING) {
                fixture.insertRawServerConfiguration()
            }
            fixture.insertRaw(candidate, overrides)
        }
        assertEquals(1L, fixture.scalarLong("PRAGMA foreign_keys"))
        assertEquals(
            if (parentState == OrphanParentState.SERVER_MISSING) 1L else 0L,
            fixture.scalarLong("SELECT COUNT(*) FROM local_installation"),
        )
        assertEquals(
            if (parentState == OrphanParentState.INSTALLATION_MISSING) 1L else 0L,
            fixture.scalarLong("SELECT COUNT(*) FROM server_configuration"),
        )
        assertEquals(1L, fixture.scalarLong("SELECT COUNT(*) FROM protected_enrollment"))
        return fixture
    }

    private suspend fun rawFixture(): RawFixture {
        val database = openInMemoryDatabase()
        assertEquals(
            InitializeLocalStateResult.Created,
            repository(database).initializeLocalState(
                localIdentity(),
                serverConfiguration(),
                installationCreatedAt = LOCAL_CREATED_AT,
                serverConfigurationUpdatedAt = SERVER_UPDATED_AT,
            ),
        )
        return RawFixture(
            database = database,
            repository = protectedRepository(database),
            localRepository = repository(database),
            entity = validEntity(),
        )
    }

    private class RawFixture(
        val database: WtoAgentDatabase,
        val repository: ProtectedEnrollmentRepository,
        val localRepository: LocalStateRepository,
        val entity: ProtectedEnrollmentEntity,
    ) {
        suspend fun assertRaw(
            candidate: ProtectedEnrollmentEntity,
            expected: ReadProtectedEnrollmentResult,
        ) {
            database.openHelper.writableDatabase.execSQL("DELETE FROM protected_enrollment")
            insertRaw(candidate)
            assertBlockedAndPreserved(expected)
        }

        suspend fun assertStorageClassCorrupt(candidate: StorageClassCase) {
            database.openHelper.writableDatabase.execSQL("DELETE FROM protected_enrollment")
            insertRaw(entity, mapOf(candidate.column to candidate.value))
            assertEquals(candidate.expectedStorageClass, storageClass(candidate.column))
            assertBlockedAndPreserved(ReadProtectedEnrollmentResult.Corrupt)
        }

        private suspend fun assertBlockedAndPreserved(
            expected: ReadProtectedEnrollmentResult,
        ) {
            val enrollmentBefore = rawSnapshot("SELECT * FROM protected_enrollment ORDER BY singleton_id")
            val serverBefore = rawSnapshot("SELECT * FROM server_configuration ORDER BY singleton_id")
            val read = repository.read()
            val preflight = repository.preflight(localIdentity(), serverConfiguration())
            val persist = repository.persist(protectedEnrollmentWrite())
            val setServer =
                localRepository.setServerConfiguration(
                    serverConfiguration(SECOND_SERVER_URL),
                    Instant.EPOCH,
                )

            assertEquals(expected, read)
            when (expected) {
                ReadProtectedEnrollmentResult.Corrupt -> {
                    assertEquals(ProtectedEnrollmentPreflightResult.Corrupt, preflight)
                    assertEquals(PersistProtectedEnrollmentResult.Corrupt, persist)
                    assertEquals(SetServerConfigurationResult.Corrupt, setServer)
                }
                ReadProtectedEnrollmentResult.Unsupported -> {
                    assertEquals(ProtectedEnrollmentPreflightResult.Unsupported, preflight)
                    assertEquals(PersistProtectedEnrollmentResult.Unsupported, persist)
                    assertEquals(SetServerConfigurationResult.Unsupported, setServer)
                }
                else -> error("Raw blocking fixture must be corrupt or unsupported")
            }

            assertEquals(
                enrollmentBefore,
                rawSnapshot("SELECT * FROM protected_enrollment ORDER BY singleton_id"),
            )
            assertEquals(
                serverBefore,
                rawSnapshot("SELECT * FROM server_configuration ORDER BY singleton_id"),
            )
            listOf(read, preflight, persist, setServer).forEach { result ->
                assertFalse(SECRET_STORAGE_MARKER in result.toString())
            }
        }

        suspend fun assertC04ParentMutationsBlocked(
            expectedRead: ReadProtectedEnrollmentResult,
            expectedFailure: LocalPersistenceError,
            expectedSetServer: SetServerConfigurationResult,
        ) {
            val before = durableSnapshot()
            assertEquals(expectedRead, repository.read())

            assertEquals(
                EnsureLocalInstallationResult.Failure(expectedFailure),
                localRepository.ensureLocalInstallation(localIdentity(), Instant.EPOCH),
            )
            assertDurableStateUnchanged(before, expectedRead)

            assertEquals(
                InitializeLocalStateResult.Failure(expectedFailure),
                localRepository.initializeLocalState(
                    localIdentity = localIdentity(),
                    serverConfiguration = serverConfiguration(),
                    installationCreatedAt = Instant.EPOCH,
                    serverConfigurationUpdatedAt = Instant.EPOCH,
                ),
            )
            assertDurableStateUnchanged(before, expectedRead)

            assertEquals(
                expectedSetServer,
                localRepository.setServerConfiguration(
                    serverConfiguration(),
                    Instant.EPOCH,
                ),
            )
            assertDurableStateUnchanged(before, expectedRead)
        }

        fun insertRaw(
            candidate: ProtectedEnrollmentEntity,
            overrides: Map<String, Any> = emptyMap(),
        ) {
            val values = candidate.toRawValues().toMutableList()
            overrides.forEach { (column, value) ->
                val index = PROTECTED_ENROLLMENT_COLUMNS.indexOf(column)
                require(index >= 0) { "Unknown synthetic protected enrollment column" }
                values[index] = value
            }
            database.openHelper.writableDatabase.execSQL(
                INSERT_PROTECTED_ENROLLMENT,
                values.toTypedArray(),
            )
        }

        fun insertRawServerConfiguration() {
            database.openHelper.writableDatabase.execSQL(
                INSERT_RAW_SERVER_CONFIGURATION,
                arrayOf<Any?>(
                    LOCAL_STATE_SINGLETON_ID,
                    FIRST_SERVER_URL,
                    SERVER_UPDATED_AT.epochSecond,
                    SERVER_UPDATED_AT.nano.toLong(),
                ),
            )
        }

        fun <T> withForeignKeysDisabled(block: () -> T): T {
            val writable = database.openHelper.writableDatabase
            writable.execSQL("PRAGMA foreign_keys = OFF")
            return withCleanupPreservingPrimaryFailure(
                cleanup = { writable.execSQL("PRAGMA foreign_keys = ON") },
                block = block,
            )
        }

        fun scalarLong(query: String): Long =
            database.openHelper.writableDatabase.query(query).use { cursor ->
                assertTrue(cursor.moveToFirst())
                cursor.getLong(0)
            }

        fun storageClass(column: String): String =
            database.openHelper.writableDatabase
                .query("SELECT typeof($column) FROM protected_enrollment")
                .use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    cursor.getString(0)
                }

        fun durableSnapshot(): RawDurableState =
            RawDurableState(
                installations = rawSnapshot("SELECT * FROM local_installation ORDER BY singleton_id"),
                servers = rawSnapshot("SELECT * FROM server_configuration ORDER BY singleton_id"),
                enrollment = rawSnapshot("SELECT * FROM protected_enrollment ORDER BY singleton_id"),
            )

        private suspend fun assertDurableStateUnchanged(
            expected: RawDurableState,
            expectedRead: ReadProtectedEnrollmentResult,
        ) {
            assertTrue(expected == durableSnapshot(), "C04 mutation changed durable rows")
            assertEquals(expectedRead, repository.read())
        }

        private fun rawSnapshot(query: String): List<List<RawCell>> =
            database.openHelper.writableDatabase.query(query).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) {
                        add(
                            List(cursor.columnCount) { index ->
                                cursor.rawCell(index)
                            },
                        )
                    }
                }
            }
    }

    private companion object {
        const val SECRET_STORAGE_MARKER =
            "C06_CORRUPT_STORAGE_VALUE_MUST_NOT_ESCAPE_4D8C13A7"
        val LOCAL_CREATED_AT: Instant = Instant.parse("2026-07-23T10:00:00Z")
        val SERVER_UPDATED_AT: Instant = Instant.parse("2026-07-23T10:01:00Z")

        val PROTECTED_ENROLLMENT_COLUMNS =
            listOf(
                "singleton_id",
                "installation_id",
                "server_base_url",
                "agent_id",
                "device_id",
                "protocol_version",
                "server_received_at_epoch_seconds",
                "server_received_at_nanoseconds",
                "credential_id",
                "credential_version",
                "issued_at_epoch_seconds",
                "issued_at_nanoseconds",
                "expires_at_epoch_seconds",
                "expires_at_nanoseconds",
                "credential_delivery_state",
                "crypto_version",
                "key_alias",
                "nonce",
                "sealed_credential",
            )

        const val INSERT_PROTECTED_ENROLLMENT =
            "INSERT INTO protected_enrollment (" +
                "singleton_id, installation_id, server_base_url, agent_id, device_id, " +
                "protocol_version, server_received_at_epoch_seconds, " +
                "server_received_at_nanoseconds, credential_id, credential_version, " +
                "issued_at_epoch_seconds, issued_at_nanoseconds, " +
                "expires_at_epoch_seconds, expires_at_nanoseconds, " +
                "credential_delivery_state, crypto_version, key_alias, nonce, " +
                "sealed_credential) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
                "?, ?, ?, ?, ?)"

        const val INSERT_RAW_SERVER_CONFIGURATION =
            "INSERT INTO server_configuration " +
                "(singleton_id, base_url, updated_at_epoch_seconds, " +
                "updated_at_nanoseconds) VALUES (?, ?, ?, ?)"
    }
}

private data class RawDurableState(
    val installations: List<List<RawCell>>,
    val servers: List<List<RawCell>>,
    val enrollment: List<List<RawCell>>,
)

private data class RawCell(
    val storageClass: Int,
    val value: String,
)

private fun Cursor.rawCell(index: Int): RawCell =
    when (val type = getType(index)) {
        Cursor.FIELD_TYPE_NULL -> RawCell(type, "<null>")
        Cursor.FIELD_TYPE_INTEGER -> RawCell(type, getLong(index).toString())
        Cursor.FIELD_TYPE_FLOAT ->
            RawCell(type, java.lang.Double.doubleToRawLongBits(getDouble(index)).toString())
        Cursor.FIELD_TYPE_STRING -> RawCell(type, getString(index))
        Cursor.FIELD_TYPE_BLOB ->
            RawCell(
                type,
                getBlob(index).joinToString(separator = "") { byte ->
                    "%02x".format(byte.toInt() and 0xff)
                },
            )
        else -> error("Unexpected Cursor field type")
    }

private fun ProtectedEnrollmentEntity.toRawValues(): List<Any> =
    listOf(
        singletonId,
        installationId,
        serverBaseUrl,
        agentId,
        deviceId,
        protocolVersion,
        serverReceivedAtEpochSeconds,
        serverReceivedAtNanoseconds,
        credentialId,
        credentialVersion,
        issuedAtEpochSeconds,
        issuedAtNanoseconds,
        expiresAtEpochSeconds,
        expiresAtNanoseconds,
        credentialDeliveryState,
        cryptoVersion,
        keyAlias,
        nonce,
        sealedCredential,
    )

private fun <T> withCleanupPreservingPrimaryFailure(
    cleanup: () -> Unit,
    block: () -> T,
): T {
    var primaryFailure: Throwable? = null
    try {
        return block()
    } catch (failure: Throwable) {
        primaryFailure = failure
        throw failure
    } finally {
        try {
            cleanup()
        } catch (cleanupFailure: Throwable) {
            val failure = primaryFailure
            if (failure == null) {
                throw cleanupFailure
            }
            if (failure !== cleanupFailure) {
                failure.addSuppressed(cleanupFailure)
            }
        }
    }
}
