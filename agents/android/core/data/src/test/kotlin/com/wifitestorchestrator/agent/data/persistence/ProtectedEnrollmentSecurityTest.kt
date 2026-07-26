package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.io.File
import java.lang.reflect.Constructor
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.Type
import java.nio.file.Files
import java.time.Instant
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
internal class ProtectedEnrollmentSecurityTest : RoomPersistenceTestBase() {
    @Test
    fun `exercised plaintext stays outside database WAL and SHM while envelope is present`() =
        runTest {
            val name = newDatabaseName("security-files")
            val database = openDatabase(name)
            repository(database).initializeLocalState(
                localIdentity(),
                serverConfiguration(),
                installationCreatedAt = Instant.parse("2026-07-23T10:00:00Z"),
                serverConfigurationUpdatedAt = Instant.parse("2026-07-23T10:01:00Z"),
            )
            val nonce = "C06-NONCE-V1".encodeToByteArray()
            val sealed = ByteArray(CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) {
                0x5a
            }
            SEALED_ENVELOPE_MARKER.encodeToByteArray().copyInto(sealed)
            val envelope =
                TestBoundaryProtector.protect(
                    plaintextCredential = PLAINTEXT_CREDENTIAL_MARKER,
                    credentialId = validValue(CredentialId.parse(FIRST_CREDENTIAL_ID)),
                    credentialVersion = validValue(CredentialVersion.from(1)),
                    nonce = nonce,
                    sealedCredential = sealed,
                )
            val write = writeWithEnvelope(envelope)

            assertEquals(
                PersistProtectedEnrollmentResult.Written,
                protectedRepository(database).persist(write),
            )
            database.openHelper.writableDatabase
                .query(
                    "SELECT credential_id, nonce, sealed_credential " +
                        "FROM protected_enrollment",
                ).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertEquals(FIRST_CREDENTIAL_ID, cursor.getString(0))
                    assertContentEquals(nonce, cursor.getBlob(1))
                    assertContentEquals(sealed, cursor.getBlob(2))
                    assertFalse(cursor.moveToNext())
                }

            val snapshots =
                listOf(name, "$name-wal", "$name-shm")
                    .map { fileName -> File(context.noBackupFilesDir, fileName) }
                    .filter(File::exists)
                    .map { file -> StorageFileSnapshot(file.name, file.readBytes()) }
            assertTrue(snapshots.any { it.name == name })

            listOf(
                FIRST_CREDENTIAL_ID.encodeToByteArray(),
                nonce,
                sealed,
            ).forEach { expected ->
                assertTrue(snapshots.any { snapshot -> snapshot.bytes.containsSubsequence(expected) })
            }
            val plaintext = PLAINTEXT_CREDENTIAL_MARKER.encodeToByteArray()
            snapshots.forEach { snapshot ->
                assertFalse(
                    snapshot.bytes.containsSubsequence(plaintext),
                    "${snapshot.name} contains the exercised plaintext marker",
                )
            }
        }

    @Test
    fun `only nonce and ciphertext bytes are persisted and arrays cannot mutate them`() = runTest {
        val database = configuredDatabase()
        val nonce = ByteArray(CredentialProtectionPolicyV1.NONCE_SIZE_BYTES) { 0x41 }
        val sealed =
            ByteArray(CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) { 0x52 }
        val envelope =
            requireValidEnvelope(
                nonce = nonce,
                sealedCredential = sealed,
            )
        nonce.fill(0x7f)
        sealed.fill(0x7f)
        val write = writeWithEnvelope(envelope)

        assertEquals(
            PersistProtectedEnrollmentResult.Written,
            protectedRepository(database).persist(write),
        )
        val row =
            database.openHelper.writableDatabase
                .query("SELECT nonce, sealed_credential FROM protected_enrollment")
                .use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    cursor.getBlob(0) to cursor.getBlob(1)
                }
        assertContentEquals(ByteArray(12) { 0x41 }, row.first)
        assertContentEquals(ByteArray(105) { 0x52 }, row.second)

        val firstRead =
            assertIs<ReadProtectedEnrollmentResult.Compatible>(
                protectedRepository(database).read(),
            )
        firstRead.enrollment.protectedCredential.useNonce { copy -> copy.fill(0x11) }
        firstRead.enrollment.protectedCredential.useSealedCredential { copy -> copy.fill(0x22) }
        val secondRead =
            assertIs<ReadProtectedEnrollmentResult.Compatible>(
                protectedRepository(database).read(),
            )
        secondRead.enrollment.protectedCredential.useNonce { copy ->
            assertContentEquals(ByteArray(12) { 0x41 }, copy)
        }
        secondRead.enrollment.protectedCredential.useSealedCredential { copy ->
            assertContentEquals(ByteArray(105) { 0x52 }, copy)
        }
    }

    @Test
    fun `known C06 public API snapshot matches current JVM members`() {
        val projectDir =
            File(requireNotNull(System.getProperty("wto.android.data.projectDir")))
        val declaredTypes =
            KNOWN_C06_PUBLIC_API_SOURCE_PATHS
                .flatMap { relativePath ->
                    publicTypeDeclarations(File(projectDir, relativePath).readText())
                }.groupingBy { it }
                .eachCount()
        assertEquals(KNOWN_C06_PUBLIC_TYPE_DECLARATIONS, declaredTypes)
        KNOWN_C06_DEFAULT_FILE_FACADES.forEach { facadeName ->
            val loaded =
                try {
                    Class.forName(
                        facadeName,
                        false,
                        ProtectedEnrollmentWrite::class.java.classLoader,
                    )
                } catch (_: ClassNotFoundException) {
                    null
                }
            assertEquals(
                null,
                loaded,
                "$facadeName unexpectedly exposes a top-level JVM member in a known source",
            )
        }

        assertEquals(28, KNOWN_C06_PUBLIC_API_SNAPSHOT.size)
        KNOWN_C06_PUBLIC_API_SNAPSHOT.forEach { (type, expected) ->
            val actual = declaredJvmApi(type)
            assertEquals(
                emptySet(),
                exactApiViolations(expected, actual),
                type.name,
            )
            assertEquals(
                emptySet(),
                exactApiViolations(expected, actual.reversed()),
                "${type.name} depends on reflection order",
            )
            val rendered = actual.joinToString("\n")
            FORBIDDEN_API_REFERENCES.forEach { forbidden ->
                assertFalse(
                    forbidden in rendered,
                    "${type.name} exposes $forbidden",
                )
            }
        }

        assertEquals(
            emptySet(),
            exactApiViolations(NEUTRAL_FIXTURE_API, declaredJvmApi(ExactApiFixture::class.java)),
        )
        assertUnexpectedApiMember(AdditionalMethodFixture::class.java, "acceptMaterial")
        assertUnexpectedApiMember(AdditionalConstructorFixture::class.java, "<init>")
        assertUnexpectedApiMember(AdditionalPropertyFixture::class.java, "material")
        assertUnexpectedApiMember(AdditionalGenericParameterFixture::class.java, "acceptValues")
        assertUnexpectedApiMember(AdditionalReturnFixture::class.java, "reveal")

        assertEquals(
            emptySet(),
            exactApiViolations(
                GENERATED_DATA_CLASS_FIXTURE_API,
                declaredJvmApi(GeneratedMembersFixture::class.java),
            ),
        )
        assertEquals(
            emptySet(),
            exactApiViolations(
                GENERATED_DEFAULT_CONSTRUCTOR_FIXTURE_API,
                declaredJvmApi(GeneratedDefaultConstructorFixture::class.java),
            ),
        )
        assertEquals(
            emptySet(),
            exactApiViolations(
                GENERATED_BRIDGE_FIXTURE_API,
                declaredJvmApi(GeneratedBridgeFixture::class.java),
            ),
        )
        assertEquals(
            emptySet(),
            exactApiViolations(
                SUSPEND_FIXTURE_API,
                declaredJvmApi(SuspendFixture::class.java),
            ),
        )
    }

    @Test
    fun `persistence source inventory is closed and checks inventoried files`() {
        val persistenceRoot =
            File(
                requireNotNull(System.getProperty("wto.android.data.projectDir")),
                "src/main/kotlin/com/wifitestorchestrator/agent/data/persistence",
            )
        assertEquals(
            emptySet(),
            sourceInventoryViolations(persistenceRoot, PERSISTENCE_SOURCE_INVENTORY),
        )
        assertEquals(29, PERSISTENCE_SOURCE_INVENTORY.size)
        assertEquals(
            mapOf(
                SourceCategory.C04 to 11,
                SourceCategory.C06 to 6,
                SourceCategory.C08 to 7,
                SourceCategory.SHARED_C04_C06 to 2,
                SourceCategory.SHARED_C04_C06_C08 to 2,
                SourceCategory.SHARED_C06_C08 to 1,
            ),
            PERSISTENCE_SOURCE_INVENTORY
                .groupingBy(ClassifiedSource::category)
                .eachCount(),
        )
        PERSISTENCE_SOURCE_INVENTORY.map { it.relativePath }.sorted().forEach { relativePath ->
            val sourceFile = File(persistenceRoot, relativePath)
            assertTrue(sourceFile.isFile)
            assertTrue(
                findForbiddenSourceReferences(sourceFile.readText()).isEmpty(),
                "$relativePath contains a forbidden production dependency",
            )
            assertTrue(
                findDisallowedLocalProductImports(sourceFile.readText()).isEmpty(),
                "$relativePath imports an unapproved local product package",
            )
            assertTrue(
                findDisallowedLocalProductReferences(sourceFile.readText()).isEmpty(),
                "$relativePath directly references an unapproved local product package",
            )
        }

        withTemporarySourceTree { syntheticRoot ->
            writeSyntheticSource(
                syntheticRoot,
                "RoomBoundary.kt",
                """
                package synthetic.persistence
                internal class RoomBoundary {
                    private val sink = SecretSink()
                }
                """.trimIndent(),
            )
            writeSyntheticSource(
                syntheticRoot,
                "SecretSink.kt",
                """
                package synthetic.persistence
                import okhttp3.OkHttpClient as NeutralClient
                internal class SecretSink(private val client: NeutralClient)
                """.trimIndent(),
            )
            val knownOnly =
                listOf(
                    ClassifiedSource(SourceCategory.C06, "RoomBoundary.kt"),
                )
            assertTrue(
                "unclassified:SecretSink.kt" in
                    sourceInventoryViolations(syntheticRoot, knownOnly),
            )

            val helperClassified =
                knownOnly + ClassifiedSource(SourceCategory.C06, "SecretSink.kt")
            assertEquals(
                emptySet(),
                sourceInventoryViolations(syntheticRoot, helperClassified),
            )
            assertTrue(
                "http-client" in
                    findForbiddenSourceReferences(
                        File(syntheticRoot, "SecretSink.kt").readText(),
                    ),
            )

            writeSyntheticSource(
                syntheticRoot,
                "SecretSink.kt",
                """
                package synthetic.persistence
                internal class SecretSink
                """.trimIndent(),
            )
            assertEquals(
                emptySet(),
                sourceInventoryViolations(syntheticRoot, helperClassified),
            )
            helperClassified.forEach { classified ->
                assertEquals(
                    emptySet(),
                    findForbiddenSourceReferences(
                        File(syntheticRoot, classified.relativePath).readText(),
                    ),
                )
            }

            assertTrue(
                "listed-but-missing:Missing.kt" in
                    sourceInventoryViolations(
                        syntheticRoot,
                        helperClassified +
                            ClassifiedSource(SourceCategory.C06, "Missing.kt"),
                    ),
            )
            assertTrue(
                sourceInventoryViolations(
                    syntheticRoot,
                    helperClassified +
                        ClassifiedSource(SourceCategory.SHARED_C04_C06, "RoomBoundary.kt"),
                ).any { it.startsWith("multiply-classified:RoomBoundary.kt:") },
            )
        }
    }

    @Test
    fun `maintenance source checks cover documented direct forms`() {
        FORBIDDEN_SOURCE_REFERENCES.forEach { forbidden ->
            assertTrue(
                forbidden.label in findForbiddenSourceReferences(forbidden.syntheticSource),
                "Scanner did not detect ${forbidden.label}",
            )
            val runtimeReference =
                "val runtimeReference = \"${forbidden.syntheticSource.escapeForString()}\""
            assertTrue(
                forbidden.label in findForbiddenSourceReferences(runtimeReference),
                "Scanner did not detect runtime string ${forbidden.label}",
            )
        }
        val nonCodeMentions =
            buildString {
                FORBIDDEN_SOURCE_REFERENCES.forEach { forbidden ->
                    appendLine("// ${forbidden.syntheticSource}")
                    appendLine("/* ${forbidden.syntheticSource} */")
                }
        }
        assertTrue(findForbiddenSourceReferences(nonCodeMentions).isEmpty())

        assertTrue(
            "http-client" in
                findForbiddenSourceReferences(
                    "import okhttp3.OkHttpClient as NeutralClient",
                ),
        )
        assertTrue(
            "http-client" in
                findForbiddenSourceReferences(
                    "val client = okhttp3.OkHttpClient()",
                ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.SecretSink"),
            findDisallowedLocalProductImports(
                "import com.wifitestorchestrator.agent.data.secret.SecretSink as Sink",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.SecretSink"),
            findDisallowedLocalProductImports(
                "import com.wifitestorchestrator.agent.data.secret.SecretSink",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.*"),
            findDisallowedLocalProductImports(
                "import com.wifitestorchestrator.agent.data.secret.*",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.*"),
            findDisallowedLocalProductImports(
                "import com . wifitestorchestrator . agent . data . secret . *",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.*"),
            findDisallowedLocalProductImports(
                "import com /* local root */ . wifitestorchestrator . " +
                    "agent . data . secret . *",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.*"),
            findDisallowedLocalProductImports(
                "import com.wifitestorchestrator.agent.data.secret.* // external helper",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.domain.identity.*"),
            findDisallowedLocalProductImports(
                "import com.wifitestorchestrator.agent.domain.identity.*",
            ),
        )
        assertEquals(
            emptySet(),
            findDisallowedLocalProductImports(
                "import com.wifitestorchestrator.agent.domain.identity.AgentId as Id",
            ),
        )
        assertEquals(
            setOf("com.wifitestorchestrator.agent.data.secret.SecretSink"),
            findDisallowedLocalProductReferences(
                "val sink = com.wifitestorchestrator.agent.data.secret.SecretSink()",
            ),
        )
        assertEquals(
            emptySet(),
            findDisallowedLocalProductReferences(
                "val id: com.wifitestorchestrator.agent.domain.identity.AgentId",
            ),
        )
    }

    @Test
    fun `results and storage failures never render exercised envelope bytes`() = runTest {
        val database = configuredDatabase()
        val sealed = ByteArray(CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) { 0x62 }
        SEALED_ENVELOPE_MARKER.encodeToByteArray().copyInto(sealed)
        val write =
            writeWithEnvelope(
                requireValidEnvelope(
                    nonce = ByteArray(CredentialProtectionPolicyV1.NONCE_SIZE_BYTES) { 0x61 },
                    sealedCredential = sealed,
                ),
            )
        val values =
            mutableListOf<Any>(
                write,
                PersistProtectedEnrollmentResult.PendingRejected,
                ReadProtectedEnrollmentResult.Corrupt,
                ProtectedEnrollmentPreflightResult.Unsupported,
            )
        database.openHelper.writableDatabase.execSQL("DROP TABLE protected_enrollment")
        values += protectedRepository(database).persist(write)

        values.forEach { value ->
            assertFalse(SEALED_ENVELOPE_MARKER in value.toString())
        }
    }

    private suspend fun configuredDatabase() =
        openInMemoryDatabase().also { database ->
            repository(database).initializeLocalState(
                localIdentity(),
                serverConfiguration(),
                installationCreatedAt = Instant.parse("2026-07-23T10:00:00Z"),
                serverConfigurationUpdatedAt = Instant.parse("2026-07-23T10:01:00Z"),
            )
        }

    private fun writeWithEnvelope(
        envelope: ProtectedCredentialEnvelope,
    ): ProtectedEnrollmentWrite {
        val metadata =
            validValue(
                CredentialMetadata.create(
                    credentialId = validValue(CredentialId.parse(FIRST_CREDENTIAL_ID)),
                    version = validValue(CredentialVersion.from(1)),
                    issuedAt = DEFAULT_ISSUED_AT,
                    expiresAt = DEFAULT_EXPIRES_AT,
                    deliveryState = CredentialDeliveryState.ACTIVE,
                ),
            )
        return ProtectedEnrollmentWrite(
            expectedLocalIdentity = localIdentity(),
            expectedServerConfiguration = serverConfiguration(),
            backendIdentity = backendIdentity(),
            protocolVersion = ProtocolVersion.CURRENT,
            serverReceivedAt = DEFAULT_SERVER_RECEIVED_AT,
            credentialMetadata = metadata,
            protectedCredential = envelope,
        )
    }

    private object TestBoundaryProtector {
        fun protect(
            plaintextCredential: String,
            credentialId: CredentialId,
            credentialVersion: CredentialVersion,
            nonce: ByteArray,
            sealedCredential: ByteArray,
        ): ProtectedCredentialEnvelope {
            check(plaintextCredential == PLAINTEXT_CREDENTIAL_MARKER)
            return requireValidEnvelope(
                credentialId = credentialId,
                credentialVersion = credentialVersion,
                nonce = nonce,
                sealedCredential = sealedCredential,
            )
        }
    }

    private data class StorageFileSnapshot(
        val name: String,
        val bytes: ByteArray,
    ) {
        override fun toString(): String = "StorageFileSnapshot(name=$name, bytes=<redacted>)"
    }

    private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) return false
        return (0..size - candidate.size).any { start ->
            candidate.indices.all { offset -> this[start + offset] == candidate[offset] }
        }
    }

    private fun findForbiddenSourceReferences(source: String): Set<String> {
        val codeOnly = source.withCommentsRemoved()
        return FORBIDDEN_SOURCE_REFERENCES
            .filter { it.pattern.containsMatchIn(codeOnly) }
            .mapTo(linkedSetOf()) { it.label }
    }

    private companion object {
        const val PLAINTEXT_CREDENTIAL_MARKER =
            "C06_EXERCISED_PLAINTEXT_MUST_NEVER_REACH_ROOM_91A74F20"
        const val SEALED_ENVELOPE_MARKER =
            "C06_SEALED_ENVELOPE_BYTES_ARE_EXPECTED_IN_SQLITE_7B13E4F6"

        val FORBIDDEN_API_REFERENCES =
            setOf(
                "EnrollmentToken",
                "AgentCredentialSecret",
                "DeliveredCredential",
                "BackendEnrollmentAcceptance",
                "AgentRegistrationRequestDto",
                "AgentRegistrationResponseDto",
                "CredentialProtector",
                "java.security",
                "javax.crypto",
                "okhttp3",
                "retrofit2",
            )

        val FORBIDDEN_SOURCE_REFERENCES =
            listOf(
                ForbiddenSourceReference(
                    "enrollment-token-type",
                    Regex("""\bEnrollmentToken\b"""),
                    "val token: EnrollmentToken",
                ),
                ForbiddenSourceReference(
                    "enrollment-token-value",
                    Regex(
                        """(?i)\b(?:token|enrollment_?token|""" +
                            """bearer_?(?:token|credential)|authorization)\b""",
                    ),
                    "val token: String",
                ),
                ForbiddenSourceReference(
                    "plaintext-credential-value",
                    Regex(
                        """(?i)\b(?:plaintext(?:_?credential)?|""" +
                            """credential_?plaintext|raw_?credential)\b""",
                    ),
                    "fun persist(plaintextCredential: String) = Unit",
                ),
                ForbiddenSourceReference(
                    "credential-secret",
                    Regex("""\bAgentCredentialSecret\b"""),
                    "val secret: AgentCredentialSecret",
                ),
                ForbiddenSourceReference(
                    "delivered-credential",
                    Regex("""\bDeliveredCredential\b"""),
                    "val delivered: DeliveredCredential",
                ),
                ForbiddenSourceReference(
                    "enrollment-acceptance",
                    Regex("""\bBackendEnrollmentAcceptance\b"""),
                    "val acceptance: BackendEnrollmentAcceptance",
                ),
                ForbiddenSourceReference(
                    "registration-request",
                    Regex("""\bAgentRegistrationRequestDto\b"""),
                    "val request: AgentRegistrationRequestDto",
                ),
                ForbiddenSourceReference(
                    "registration-response",
                    Regex("""\bAgentRegistrationResponseDto\b"""),
                    "val response: AgentRegistrationResponseDto",
                ),
                ForbiddenSourceReference(
                    "credential-protector",
                    Regex("""\bCredentialProtector\b"""),
                    "val protector: CredentialProtector",
                ),
                ForbiddenSourceReference(
                    "keystore-jca",
                    Regex(
                        """\b(?:KeyStore|Cipher|SecretKey)\b|""" +
                            """\b(?:java\.security|javax\.crypto)\b""",
                    ),
                    "import javax.crypto.Cipher",
                ),
                ForbiddenSourceReference(
                    "http-client",
                    Regex(
                        """\b(?:OkHttpClient|Retrofit|HttpURLConnection)\b|""" +
                            """\b(?:okhttp3|retrofit2|java\.net\.http)\b|""" +
                            """\bopenConnection\s*\(""",
                    ),
                    "val client: OkHttpClient",
                ),
                ForbiddenSourceReference(
                    "logging",
                    Regex(
                        """\bandroid\.util\.Log\b|\bLog\.(?:d|e|i|v|w|wtf)\s*\(|""" +
                            """\bprintln\s*\(|\bprintStackTrace\s*\(|\bTimber\.""",
                    ),
                    "println(secret)",
                ),
            )
    }
}

private enum class SourceCategory {
    C04,
    C06,
    C08,
    SHARED_C04_C06,
    SHARED_C04_C06_C08,
    SHARED_C06_C08,
}

private data class ClassifiedSource(
    val category: SourceCategory,
    val relativePath: String,
)

private val PERSISTENCE_SOURCE_INVENTORY =
    listOf(
        ClassifiedSource(
            SourceCategory.SHARED_C04_C06_C08,
            "AndroidLocalPersistenceFactory.kt",
        ),
        ClassifiedSource(SourceCategory.C08, "CapabilityManifestPublicationModels.kt"),
        ClassifiedSource(SourceCategory.C04, "LocalPersistenceError.kt"),
        ClassifiedSource(SourceCategory.SHARED_C04_C06, "LocalPersistenceModels.kt"),
        ClassifiedSource(SourceCategory.C04, "LocalStateRepository.kt"),
        ClassifiedSource(SourceCategory.C06, "ProtectedEnrollmentPersistenceModels.kt"),
        ClassifiedSource(SourceCategory.C06, "ProtectedEnrollmentRepository.kt"),
        ClassifiedSource(SourceCategory.C04, "room/FailClosedRoomOpenHelperFactory.kt"),
        ClassifiedSource(SourceCategory.C04, "room/LocalInstallationEntity.kt"),
        ClassifiedSource(SourceCategory.C04, "room/LocalStateDao.kt"),
        ClassifiedSource(SourceCategory.C04, "room/PersistedInstant.kt"),
        ClassifiedSource(SourceCategory.C04, "room/PersistenceFailureMapper.kt"),
        ClassifiedSource(SourceCategory.C04, "room/PersistenceMappers.kt"),
        ClassifiedSource(SourceCategory.C04, "room/ProcessRoomDatabaseProvider.kt"),
        ClassifiedSource(SourceCategory.C06, "room/ProtectedEnrollmentDao.kt"),
        ClassifiedSource(SourceCategory.C06, "room/ProtectedEnrollmentEntity.kt"),
        ClassifiedSource(SourceCategory.C06, "room/ProtectedEnrollmentMappers.kt"),
        ClassifiedSource(SourceCategory.SHARED_C04_C06, "room/RoomLocalStateRepository.kt"),
        ClassifiedSource(SourceCategory.C06, "room/RoomProtectedEnrollmentRepository.kt"),
        ClassifiedSource(SourceCategory.C08, "room/CapabilityManifestPublicationDao.kt"),
        ClassifiedSource(SourceCategory.C08, "room/CapabilityManifestPublicationEntity.kt"),
        ClassifiedSource(SourceCategory.C08, "room/CapabilityManifestPublicationMappers.kt"),
        ClassifiedSource(SourceCategory.C08, "room/CapabilityManifestPublicationObservation.kt"),
        ClassifiedSource(SourceCategory.C08, "room/CapabilityManifestPublicationSchema.kt"),
        ClassifiedSource(SourceCategory.C08, "room/RoomCapabilityManifestPublicationRepository.kt"),
        ClassifiedSource(SourceCategory.C04, "room/ServerConfigurationEntity.kt"),
        ClassifiedSource(SourceCategory.C04, "room/StorageExceptions.kt"),
        ClassifiedSource(SourceCategory.SHARED_C04_C06_C08, "room/WtoAgentDatabase.kt"),
        ClassifiedSource(SourceCategory.SHARED_C06_C08, "room/WtoAgentDatabaseMigrations.kt"),
    )

private fun sourceInventoryViolations(
    root: File,
    inventory: List<ClassifiedSource>,
): Set<String> {
    val discovered =
        if (root.isDirectory) {
            root.walkTopDown()
                .filter(File::isFile)
                .filter { it.extension == "kt" }
                .map { it.relativeTo(root).invariantSeparatorsPath }
                .toSet()
        } else {
            emptySet()
        }
    val grouped = inventory.groupBy(ClassifiedSource::relativePath)
    val classified = grouped.keys
    return buildSet {
        (discovered - classified).sorted().forEach { add("unclassified:$it") }
        (classified - discovered).sorted().forEach { add("listed-but-missing:$it") }
        grouped
            .filterValues { it.size != 1 }
            .toSortedMap()
            .forEach { (path, entries) ->
                val categories =
                    entries.joinToString(",") { it.category.name }
                add("multiply-classified:$path:$categories")
            }
    }
}

private inline fun <T> withTemporarySourceTree(block: (File) -> T): T {
    val root = Files.createTempDirectory("c06-source-inventory-").toFile()
    var primary: Throwable? = null
    try {
        return block(root)
    } catch (failure: Throwable) {
        primary = failure
        throw failure
    } finally {
        try {
            check(!root.exists() || root.deleteRecursively()) {
                "Could not delete synthetic source tree"
            }
        } catch (cleanupFailure: Throwable) {
            val primaryFailure = primary
            if (primaryFailure == null) {
                throw cleanupFailure
            }
            if (cleanupFailure !== primaryFailure) {
                primaryFailure.addSuppressed(cleanupFailure)
            }
        }
    }
}

private fun writeSyntheticSource(
    root: File,
    relativePath: String,
    source: String,
) {
    val target = File(root, relativePath)
    val parent = requireNotNull(target.parentFile)
    check(parent.mkdirs() || parent.isDirectory)
    target.writeText(source)
}

private val ALLOWED_LOCAL_PRODUCT_PREFIXES =
    setOf(
        "com.wifitestorchestrator.agent.data.capability.",
        "com.wifitestorchestrator.agent.data.persistence.",
        "com.wifitestorchestrator.agent.domain.configuration.",
        "com.wifitestorchestrator.agent.domain.credential.protection.",
        "com.wifitestorchestrator.agent.domain.enrollment.",
        "com.wifitestorchestrator.agent.domain.error.",
        "com.wifitestorchestrator.agent.domain.identity.",
        "com.wifitestorchestrator.agent.domain.version.",
    )

/*
 * Deliberately small lexical recognizer for ordinary Kotlin import directives. It is a
 * maintenance check, not a parser or security boundary.
 */
private val KOTLIN_IMPORT_DIRECT_FORM =
    Regex(
        """(?m)^\s*import\s+(""" +
            """[A-Za-z_][A-Za-z0-9_]*""" +
            """(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*""" +
            """(?:\s*\.\s*\*)?""" +
            """)\s*(?:as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*$""",
    )

private fun findDisallowedLocalProductImports(source: String): Set<String> =
    KOTLIN_IMPORT_DIRECT_FORM
        .findAll(source.withCommentsRemoved())
        .map { it.groupValues[1].withoutWhitespace() }
        .filter { it.startsWith("com.wifitestorchestrator.agent.") }
        .filter { imported ->
            imported.endsWith(".*") ||
                ALLOWED_LOCAL_PRODUCT_PREFIXES.none(imported::startsWith)
        }.toCollection(linkedSetOf())

private val LOCAL_PRODUCT_REFERENCE_DIRECT_FORM =
    Regex(
        """\bcom\s*\.\s*wifitestorchestrator\s*\.\s*agent""" +
            """(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+""",
    )

private fun findDisallowedLocalProductReferences(source: String): Set<String> {
    val codeWithoutDeclarations =
        source
            .withCommentsRemoved(preserveLiterals = false)
            .lineSequence()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("package ") || trimmed.startsWith("import ")
            }.joinToString("\n")
    return LOCAL_PRODUCT_REFERENCE_DIRECT_FORM
        .findAll(codeWithoutDeclarations)
        .map { it.value.withoutWhitespace() }
        .filter { reference ->
            ALLOWED_LOCAL_PRODUCT_PREFIXES.none(reference::startsWith)
        }.toCollection(linkedSetOf())
}

private fun String.withoutWhitespace(): String =
    filterNot(Char::isWhitespace)

/*
 * Explicitly known source and binary names only. This snapshot detects drift in the currently
 * enumerated API; it does not discover new classes or renamed file facades.
 */
private val KNOWN_C06_PUBLIC_API_SOURCE_PATHS =
    listOf(
        "src/main/kotlin/com/wifitestorchestrator/agent/data/persistence/" +
            "ProtectedEnrollmentPersistenceModels.kt",
        "src/main/kotlin/com/wifitestorchestrator/agent/data/persistence/" +
            "ProtectedEnrollmentRepository.kt",
    )

private val KNOWN_C06_DEFAULT_FILE_FACADES =
    setOf(
        "com.wifitestorchestrator.agent.data.persistence." +
            "ProtectedEnrollmentPersistenceModelsKt",
        "com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentRepositoryKt",
    )

private val KNOWN_C06_PUBLIC_TYPE_DECLARATIONS =
    mapOf(
        "ProtectedEnrollmentWrite" to 1,
        "StoredProtectedEnrollment" to 1,
        "ProtectedEnrollmentPreflightResult" to 1,
        "Absent" to 2,
        "Compatible" to 2,
        "Conflict" to 2,
        "LocalStateIncomplete" to 1,
        "Corrupt" to 3,
        "Unsupported" to 3,
        "Failure" to 3,
        "ReadProtectedEnrollmentResult" to 1,
        "PersistProtectedEnrollmentResult" to 1,
        "Written" to 1,
        "ExistingEquivalent" to 1,
        "Replaced" to 1,
        "Rollback" to 1,
        "PendingRejected" to 1,
        "InvalidCandidate" to 1,
        "ProtectedEnrollmentRepository" to 1,
    )

private val PUBLIC_TYPE_DECLARATION =
    Regex(
        """(?m)^\s*((?:(?:public|internal|private|protected|sealed|data|enum|""" +
            """value|annotation|open|abstract|final)\s+)*)""" +
            """(?:class|interface|object)\s+([A-Za-z_][A-Za-z0-9_]*)\b""",
    )

private fun publicTypeDeclarations(source: String): List<String> =
    PUBLIC_TYPE_DECLARATION
        .findAll(source.withCommentsRemoved(preserveLiterals = false))
        .filter { match ->
            val modifiers = match.groupValues[1].split(Regex("""\s+"""))
            modifiers.none { it in setOf("private", "internal", "protected") }
        }.map { it.groupValues[2] }
        .toList()

private data class JvmApiType(
    val descriptor: String,
    val genericName: String,
)

private data class ApiProperty(
    val name: String,
    val getterName: String,
    val type: JvmApiType,
)

private val LOCAL_INSTALLATION_IDENTITY =
    jvmObjectType(
        "com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity",
    )
private val SERVER_CONFIGURATION =
    jvmObjectType(
        "com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration",
    )
private val BACKEND_AGENT_IDENTITY =
    jvmObjectType(
        "com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity",
    )
private val PROTOCOL_VERSION =
    jvmObjectType("com.wifitestorchestrator.agent.domain.version.ProtocolVersion")
private val INSTANT = jvmObjectType("java.time.Instant")
private val CREDENTIAL_METADATA =
    jvmObjectType("com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata")
private val PROTECTED_CREDENTIAL_ENVELOPE =
    jvmObjectType(
        "com.wifitestorchestrator.agent.domain.credential.protection." +
            "ProtectedCredentialEnvelope",
    )
private val STORED_PROTECTED_ENROLLMENT =
    jvmObjectType(
        "com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment",
    )
private val PROTECTED_ENROLLMENT_WRITE =
    jvmObjectType(
        "com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentWrite",
    )
private val LOCAL_PERSISTENCE_ERROR =
    jvmObjectType("com.wifitestorchestrator.agent.data.persistence.LocalPersistenceError")
private val JAVA_STRING = jvmObjectType("java.lang.String")
private val JAVA_OBJECT = jvmObjectType("java.lang.Object")
private val JAVA_LIST_OF_STRING =
    JvmApiType(
        descriptor = "Ljava/util/List;",
        genericName = "java.util.List<java.lang.String>",
    )
private val BYTE_ARRAY = JvmApiType(descriptor = "[B", genericName = "byte[]")
private val JVM_INT = JvmApiType(descriptor = "I", genericName = "int")
private val JVM_BOOLEAN = JvmApiType(descriptor = "Z", genericName = "boolean")
private val JVM_VOID = JvmApiType(descriptor = "V", genericName = "void")
private val JVM_SELF = JvmApiType(descriptor = "L<self>;", genericName = "<self>")
private val DEFAULT_CONSTRUCTOR_MARKER =
    jvmObjectType("kotlin.jvm.internal.DefaultConstructorMarker")

private fun jvmObjectType(name: String): JvmApiType =
    JvmApiType(
        descriptor = "L${name.replace('.', '/')};",
        genericName = name,
    )

private fun continuationOf(resultType: String): JvmApiType =
    JvmApiType(
        descriptor = "Lkotlin/coroutines/Continuation;",
        genericName = "kotlin.coroutines.Continuation<? super $resultType>",
    )

private fun expectedField(
    name: String,
    flags: String,
    type: JvmApiType,
): String =
    "field|$name|flags=$flags|descriptor=${type.descriptor}|generic=${type.genericName}"

private fun expectedConstructor(
    flags: String,
    parameters: List<JvmApiType>,
): String =
    "constructor|<init>|flags=$flags|descriptor=" +
        "(${parameters.joinToString("") { it.descriptor }})V|generic=" +
        "(${parameters.joinToString(",") { it.genericName }})"

private fun expectedMethod(
    name: String,
    flags: String,
    parameters: List<JvmApiType>,
    returnType: JvmApiType,
): String =
    "method|$name|flags=$flags|descriptor=" +
        "(${parameters.joinToString("") { it.descriptor }})${returnType.descriptor}|generic=" +
        "(${parameters.joinToString(",") { it.genericName }})->${returnType.genericName}"

private fun plainHolderApi(properties: List<ApiProperty>): Set<String> =
    buildSet {
        properties.forEach { property ->
            add(expectedField(property.name, "private,final", property.type))
        }
        add(expectedConstructor("public", properties.map(ApiProperty::type)))
        properties.forEach { property ->
            add(
                expectedMethod(
                    property.getterName,
                    "public,final",
                    emptyList(),
                    property.type,
                ),
            )
        }
        add(expectedMethod("toString", "public", emptyList(), JAVA_STRING))
    }

private fun sealedInterfaceApi(): Set<String> = emptySet()

private fun dataObjectApi(): Set<String> =
    setOf(
        expectedField("INSTANCE", "public,static,final", JVM_SELF),
        expectedConstructor("private", emptyList()),
        expectedMethod("toString", "public", emptyList(), JAVA_STRING),
        expectedMethod("hashCode", "public", emptyList(), JVM_INT),
        expectedMethod("equals", "public", listOf(JAVA_OBJECT), JVM_BOOLEAN),
    )

private fun compatibleResultApi(): Set<String> =
    setOf(
        expectedField("enrollment", "private,final", STORED_PROTECTED_ENROLLMENT),
        expectedConstructor("public", listOf(STORED_PROTECTED_ENROLLMENT)),
        expectedMethod(
            "getEnrollment",
            "public,final",
            emptyList(),
            STORED_PROTECTED_ENROLLMENT,
        ),
        expectedMethod("toString", "public", emptyList(), JAVA_STRING),
    )

private fun dataClassApi(property: ApiProperty): Set<String> =
    setOf(
        expectedField(property.name, "private,final", property.type),
        expectedConstructor("public", listOf(property.type)),
        expectedMethod(
            property.getterName,
            "public,final",
            emptyList(),
            property.type,
        ),
        expectedMethod("component1", "public,final", emptyList(), property.type),
        expectedMethod("copy", "public,final", listOf(property.type), JVM_SELF),
        expectedMethod(
            "copy\$default",
            "public,static,synthetic",
            listOf(JVM_SELF, property.type, JVM_INT, JAVA_OBJECT),
            JVM_SELF,
        ),
        expectedMethod("toString", "public", emptyList(), JAVA_STRING),
        expectedMethod("hashCode", "public", emptyList(), JVM_INT),
        expectedMethod("equals", "public", listOf(JAVA_OBJECT), JVM_BOOLEAN),
    )

private val WRITE_PROPERTIES =
    listOf(
        ApiProperty(
            "expectedLocalIdentity",
            "getExpectedLocalIdentity",
            LOCAL_INSTALLATION_IDENTITY,
        ),
        ApiProperty(
            "expectedServerConfiguration",
            "getExpectedServerConfiguration",
            SERVER_CONFIGURATION,
        ),
        ApiProperty("backendIdentity", "getBackendIdentity", BACKEND_AGENT_IDENTITY),
        ApiProperty("protocolVersion", "getProtocolVersion", PROTOCOL_VERSION),
        ApiProperty("serverReceivedAt", "getServerReceivedAt", INSTANT),
        ApiProperty("credentialMetadata", "getCredentialMetadata", CREDENTIAL_METADATA),
        ApiProperty(
            "protectedCredential",
            "getProtectedCredential",
            PROTECTED_CREDENTIAL_ENVELOPE,
        ),
    )

private val STORED_PROPERTIES =
    listOf(
        ApiProperty("localIdentity", "getLocalIdentity", LOCAL_INSTALLATION_IDENTITY),
        ApiProperty(
            "serverConfiguration",
            "getServerConfiguration",
            SERVER_CONFIGURATION,
        ),
        ApiProperty("backendIdentity", "getBackendIdentity", BACKEND_AGENT_IDENTITY),
        ApiProperty("protocolVersion", "getProtocolVersion", PROTOCOL_VERSION),
        ApiProperty("serverReceivedAt", "getServerReceivedAt", INSTANT),
        ApiProperty("credentialMetadata", "getCredentialMetadata", CREDENTIAL_METADATA),
        ApiProperty(
            "protectedCredential",
            "getProtectedCredential",
            PROTECTED_CREDENTIAL_ENVELOPE,
        ),
    )

private val PROTECTED_ENROLLMENT_REPOSITORY_API =
    setOf(
        expectedMethod(
            "preflight",
            "public,abstract",
            listOf(
                LOCAL_INSTALLATION_IDENTITY,
                SERVER_CONFIGURATION,
                continuationOf(
                    "com.wifitestorchestrator.agent.data.persistence." +
                        "ProtectedEnrollmentPreflightResult",
                ),
            ),
            JAVA_OBJECT,
        ),
        expectedMethod(
            "read",
            "public,abstract",
            listOf(
                continuationOf(
                    "com.wifitestorchestrator.agent.data.persistence." +
                        "ReadProtectedEnrollmentResult",
                ),
            ),
            JAVA_OBJECT,
        ),
        expectedMethod(
            "persist",
            "public,abstract",
            listOf(
                PROTECTED_ENROLLMENT_WRITE,
                continuationOf(
                    "com.wifitestorchestrator.agent.data.persistence." +
                        "PersistProtectedEnrollmentResult",
                ),
            ),
            JAVA_OBJECT,
        ),
    )

private val FAILURE_API =
    dataClassApi(
        ApiProperty("error", "getError", LOCAL_PERSISTENCE_ERROR),
    )

private val KNOWN_C06_PUBLIC_API_SNAPSHOT: Map<Class<*>, Set<String>> =
    linkedMapOf<Class<*>, Set<String>>().apply {
        put(ProtectedEnrollmentWrite::class.java, plainHolderApi(WRITE_PROPERTIES))
        put(StoredProtectedEnrollment::class.java, plainHolderApi(STORED_PROPERTIES))
        put(ProtectedEnrollmentPreflightResult::class.java, sealedInterfaceApi())
        put(ProtectedEnrollmentPreflightResult.Absent::class.java, dataObjectApi())
        put(ProtectedEnrollmentPreflightResult.Compatible::class.java, compatibleResultApi())
        put(ProtectedEnrollmentPreflightResult.Conflict::class.java, dataObjectApi())
        put(
            ProtectedEnrollmentPreflightResult.LocalStateIncomplete::class.java,
            dataObjectApi(),
        )
        put(ProtectedEnrollmentPreflightResult.Corrupt::class.java, dataObjectApi())
        put(ProtectedEnrollmentPreflightResult.Unsupported::class.java, dataObjectApi())
        put(ProtectedEnrollmentPreflightResult.Failure::class.java, FAILURE_API)
        put(ReadProtectedEnrollmentResult::class.java, sealedInterfaceApi())
        put(ReadProtectedEnrollmentResult.Absent::class.java, dataObjectApi())
        put(ReadProtectedEnrollmentResult.Compatible::class.java, compatibleResultApi())
        put(ReadProtectedEnrollmentResult.Corrupt::class.java, dataObjectApi())
        put(ReadProtectedEnrollmentResult.Unsupported::class.java, dataObjectApi())
        put(ReadProtectedEnrollmentResult.Failure::class.java, FAILURE_API)
        put(PersistProtectedEnrollmentResult::class.java, sealedInterfaceApi())
        put(PersistProtectedEnrollmentResult.Written::class.java, dataObjectApi())
        put(
            PersistProtectedEnrollmentResult.ExistingEquivalent::class.java,
            dataObjectApi(),
        )
        put(PersistProtectedEnrollmentResult.Replaced::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.Conflict::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.Rollback::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.PendingRejected::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.InvalidCandidate::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.Corrupt::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.Unsupported::class.java, dataObjectApi())
        put(PersistProtectedEnrollmentResult.Failure::class.java, FAILURE_API)
        put(ProtectedEnrollmentRepository::class.java, PROTECTED_ENROLLMENT_REPOSITORY_API)
    }

private fun declaredJvmApi(type: Class<*>): List<String> =
    buildList {
        type.declaredFields.forEach { add(it.toApiDescriptor(type)) }
        type.declaredConstructors.forEach { add(it.toApiDescriptor(type)) }
        type.declaredMethods.forEach { add(it.toApiDescriptor(type)) }
    }.sorted()

private fun Field.toApiDescriptor(owner: Class<*>): String =
    expectedField(
        name = name,
        flags = memberFlags(modifiers, isSynthetic),
        type =
            JvmApiType(
                type.jvmDescriptor(owner),
                genericType.normalizedGenericName(owner),
            ),
    )

private fun Constructor<*>.toApiDescriptor(owner: Class<*>): String =
    expectedConstructor(
        flags = memberFlags(modifiers, isSynthetic, isVarArgs = isVarArgs),
        parameters =
            parameterTypes.zip(genericParameterTypes).map { (raw, generic) ->
                JvmApiType(
                    raw.jvmDescriptor(owner),
                    generic.normalizedGenericName(owner),
                )
            },
    )

private fun Method.toApiDescriptor(owner: Class<*>): String =
    expectedMethod(
        name = name,
        flags =
            memberFlags(
                modifiers = modifiers,
                isSynthetic = isSynthetic,
                isBridge = isBridge,
                isVarArgs = isVarArgs,
            ),
        parameters =
            parameterTypes.zip(genericParameterTypes).map { (raw, generic) ->
                JvmApiType(
                    raw.jvmDescriptor(owner),
                    generic.normalizedGenericName(owner),
                )
            },
        returnType =
            JvmApiType(
                returnType.jvmDescriptor(owner),
                genericReturnType.normalizedGenericName(owner),
            ),
    )

private fun memberFlags(
    modifiers: Int,
    isSynthetic: Boolean,
    isBridge: Boolean = false,
    isVarArgs: Boolean = false,
): String =
    buildList {
        when {
            Modifier.isPublic(modifiers) -> add("public")
            Modifier.isProtected(modifiers) -> add("protected")
            Modifier.isPrivate(modifiers) -> add("private")
        }
        if (Modifier.isStatic(modifiers)) add("static")
        if (Modifier.isAbstract(modifiers)) add("abstract")
        if (Modifier.isFinal(modifiers)) add("final")
        if (isBridge) add("bridge")
        if (isSynthetic) add("synthetic")
        if (isVarArgs) add("varargs")
    }.joinToString(",")

private fun Class<*>.jvmDescriptor(owner: Class<*>): String {
    val descriptor =
        when {
            this == java.lang.Void.TYPE -> "V"
            this == java.lang.Boolean.TYPE -> "Z"
            this == java.lang.Byte.TYPE -> "B"
            this == java.lang.Character.TYPE -> "C"
            this == java.lang.Short.TYPE -> "S"
            this == java.lang.Integer.TYPE -> "I"
            this == java.lang.Long.TYPE -> "J"
            this == java.lang.Float.TYPE -> "F"
            this == java.lang.Double.TYPE -> "D"
            isArray -> "[${requireNotNull(componentType).jvmDescriptor(owner)}"
            else -> "L${name.replace('.', '/')};"
        }
    return descriptor.replace(owner.name.replace('.', '/'), "<self>")
}

private fun Type.normalizedGenericName(owner: Class<*>): String =
    typeName.replace(owner.name, "<self>")

private fun exactApiViolations(
    expected: Set<String>,
    actual: List<String>,
): Set<String> =
    buildSet {
        val actualSet = actual.toSet()
        (expected - actualSet).sorted().forEach { add("missing:$it") }
        (actualSet - expected).sorted().forEach { add("unexpected:$it") }
        actual
            .groupingBy { it }
            .eachCount()
            .filterValues { it > 1 }
            .toSortedMap()
            .forEach { (member, count) -> add("duplicate:$count:$member") }
    }

private fun assertUnexpectedApiMember(
    type: Class<*>,
    marker: String,
) {
    val violations = exactApiViolations(NEUTRAL_FIXTURE_API, declaredJvmApi(type))
    assertTrue(
        violations.any { it.startsWith("unexpected:") && marker in it },
        "$marker was not rejected for ${type.name}: $violations",
    )
}

private val NEUTRAL_FIXTURE_PROPERTIES =
    listOf(ApiProperty("value", "getValue", JAVA_STRING))

private val NEUTRAL_FIXTURE_API =
    plainHolderApi(NEUTRAL_FIXTURE_PROPERTIES) -
        expectedMethod("toString", "public", emptyList(), JAVA_STRING) +
        expectedMethod(
            "allowed",
            "public,final",
            listOf(JAVA_STRING),
            JAVA_STRING,
        )

private val GENERATED_DATA_CLASS_FIXTURE_API =
    dataClassApi(ApiProperty("value", "getValue", JAVA_STRING))

private val GENERATED_DEFAULT_CONSTRUCTOR_FIXTURE_API =
    setOf(
        expectedField("value", "private,final", JAVA_STRING),
        expectedConstructor("public", listOf(JAVA_STRING)),
        expectedConstructor(
            "public,synthetic",
            listOf(JAVA_STRING, JVM_INT, DEFAULT_CONSTRUCTOR_MARKER),
        ),
        expectedConstructor("public", emptyList()),
        expectedMethod("getValue", "public,final", emptyList(), JAVA_STRING),
    )

private val GENERATED_BRIDGE_FIXTURE_API =
    setOf(
        expectedConstructor("public", emptyList()),
        expectedMethod("value", "public", emptyList(), JAVA_STRING),
        expectedMethod(
            "value",
            "public,bridge,synthetic",
            emptyList(),
            JAVA_OBJECT,
        ),
    )

private val SUSPEND_FIXTURE_API =
    setOf(
        expectedMethod(
            "accept",
            "public,abstract",
            listOf(JAVA_STRING, continuationOf("java.lang.String")),
            JAVA_OBJECT,
        ),
    )

private class ExactApiFixture(
    val value: String,
) {
    fun allowed(input: String): String = input
}

private class AdditionalMethodFixture(
    val value: String,
) {
    fun allowed(input: String): String = input

    fun acceptMaterial(material: String) = Unit
}

private class AdditionalConstructorFixture(
    val value: String,
) {
    constructor(
        value: String,
        marker: Int,
    ) : this(value) {
        require(marker >= 0)
    }

    fun allowed(input: String): String = input
}

private class AdditionalPropertyFixture(
    val value: String,
) {
    val material: ByteArray = byteArrayOf()

    fun allowed(input: String): String = input
}

private class AdditionalGenericParameterFixture(
    val value: String,
) {
    fun allowed(input: String): String = input

    fun acceptValues(values: List<String>) = Unit
}

private class AdditionalReturnFixture(
    val value: String,
) {
    fun allowed(input: String): String = input

    fun reveal(): Any = value
}

private data class GeneratedMembersFixture(
    val value: String,
)

private class GeneratedDefaultConstructorFixture(
    val value: String = "default",
)

private interface GeneratedBridgeContract<T> {
    fun value(): T
}

private class GeneratedBridgeFixture : GeneratedBridgeContract<String> {
    override fun value(): String = "value"
}

private interface SuspendFixture {
    suspend fun accept(value: String): String
}

private data class ForbiddenSourceReference(
    val label: String,
    val pattern: Regex,
    val syntheticSource: String,
)

private fun String.escapeForString(): String =
    replace("\\", "\\\\").replace("\"", "\\\"")

private fun String.withCommentsRemoved(preserveLiterals: Boolean = true): String {
    val result = StringBuilder(length)
    var index = 0
    var state = KotlinLexicalState.CODE
    var blockDepth = 0
    while (index < length) {
        val current = this[index]
        val next = getOrNull(index + 1)
        val third = getOrNull(index + 2)
        when (state) {
            KotlinLexicalState.CODE ->
                when {
                    current == '/' && next == '/' -> {
                        result.append("  ")
                        index += 2
                        state = KotlinLexicalState.LINE_COMMENT
                    }
                    current == '/' && next == '*' -> {
                        result.append("  ")
                        index += 2
                        blockDepth = 1
                        state = KotlinLexicalState.BLOCK_COMMENT
                    }
                    current == '"' && next == '"' && third == '"' -> {
                        result.append(if (preserveLiterals) "\"\"\"" else "   ")
                        index += 3
                        state = KotlinLexicalState.TRIPLE_STRING
                    }
                    current == '"' -> {
                        result.append(if (preserveLiterals) current else ' ')
                        index += 1
                        state = KotlinLexicalState.STRING
                    }
                    current == '\'' -> {
                        result.append(if (preserveLiterals) current else ' ')
                        index += 1
                        state = KotlinLexicalState.CHAR
                    }
                    else -> {
                        result.append(current)
                        index += 1
                    }
                }
            KotlinLexicalState.LINE_COMMENT -> {
                result.append(if (current == '\n') '\n' else ' ')
                index += 1
                if (current == '\n') state = KotlinLexicalState.CODE
            }
            KotlinLexicalState.BLOCK_COMMENT ->
                when {
                    current == '/' && next == '*' -> {
                        result.append("  ")
                        index += 2
                        blockDepth += 1
                    }
                    current == '*' && next == '/' -> {
                        result.append("  ")
                        index += 2
                        blockDepth -= 1
                        if (blockDepth == 0) state = KotlinLexicalState.CODE
                    }
                    else -> {
                        result.append(if (current == '\n') '\n' else ' ')
                        index += 1
                    }
                }
            KotlinLexicalState.STRING,
            KotlinLexicalState.CHAR,
            -> {
                val terminator =
                    if (state == KotlinLexicalState.STRING) {
                        '"'
                    } else {
                        '\''
                    }
                when {
                    current == '\\' && next != null -> {
                        if (preserveLiterals) {
                            result.append(current)
                            result.append(next)
                        } else {
                            result.append("  ")
                        }
                        index += 2
                    }
                    current == terminator -> {
                        result.append(if (preserveLiterals) current else ' ')
                        index += 1
                        state = KotlinLexicalState.CODE
                    }
                    else -> {
                        result.append(
                            if (preserveLiterals || current == '\n') current else ' ',
                        )
                        index += 1
                    }
                }
            }
            KotlinLexicalState.TRIPLE_STRING -> {
                if (current == '"' && next == '"' && third == '"') {
                    result.append(if (preserveLiterals) "\"\"\"" else "   ")
                    index += 3
                    state = KotlinLexicalState.CODE
                } else {
                    result.append(
                        if (preserveLiterals || current == '\n') current else ' ',
                    )
                    index += 1
                }
            }
        }
    }
    return result.toString()
}

private enum class KotlinLexicalState {
    CODE,
    LINE_COMMENT,
    BLOCK_COMMENT,
    STRING,
    TRIPLE_STRING,
    CHAR,
}
