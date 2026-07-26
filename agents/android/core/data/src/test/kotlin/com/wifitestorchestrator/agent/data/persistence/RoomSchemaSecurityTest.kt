package com.wifitestorchestrator.agent.data.persistence

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RoomSchemaSecurityTest {
    private val projectDirectory =
        File(requireNotNull(System.getProperty("wto.android.data.projectDir")))
    private val schemaV1File =
        File(
            projectDirectory,
            "schemas/com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase/1.json",
        )
    private val schemaV2File =
        File(
            projectDirectory,
            "schemas/com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase/2.json",
        )
    private val schemaV3File =
        File(
            projectDirectory,
            "schemas/com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase/3.json",
        )

    @Test
    fun `v1 schema remains the exact C04 shape and identity`() {
        val database = exportedDatabase(schemaV1File)
        val columnsByTable = columnsByTable(database)

        assertEquals(setOf("local_installation", "server_configuration"), columnsByTable.keys)
        assertEquals(8, columnsByTable.values.sumOf { it.size })
        assertEquals(
            "2a33bf103f9927f13a8246f20d09ad8e",
            database.getValue("identityHash").jsonPrimitive.content,
        )
    }

    @Test
    fun `v2 schema contains exactly the three authorized tables and columns`() {
        val database = exportedDatabase(schemaV2File)
        val columnsByTable = columnsByTable(database)

        assertEquals(
            mapOf(
                "local_installation" to
                    setOf(
                        "singleton_id",
                        "installation_id",
                        "created_at_epoch_seconds",
                        "created_at_nanoseconds",
                    ),
                "server_configuration" to
                    setOf(
                        "singleton_id",
                        "base_url",
                        "updated_at_epoch_seconds",
                        "updated_at_nanoseconds",
                    ),
                "protected_enrollment" to protectedEnrollmentColumns,
            ),
            columnsByTable,
        )
        assertEquals(27, columnsByTable.values.sumOf { it.size })
    }

    @Test
    fun `v2 SQL has two restrictive enrollment foreign keys and only approved blobs`() {
        val database = exportedDatabase(schemaV2File)
        val entities = database.getValue("entities").jsonArray.map { it.jsonObject }
        val protectedEnrollment =
            entities.single {
                it.getValue("tableName").jsonPrimitive.content == "protected_enrollment"
            }
        val createSql = protectedEnrollment.getValue("createSql").jsonPrimitive.content
        val normalized = createSql.lowercase()
        val blobColumns =
            protectedEnrollment.getValue("fields").jsonArray
                .map { it.jsonObject }
                .filter { it.getValue("affinity").jsonPrimitive.content == "BLOB" }
                .map { it.getValue("columnName").jsonPrimitive.content }
                .toSet()

        assertTrue("primary key(`singleton_id`)" in normalized)
        assertEquals(2, normalized.countOccurrences("foreign key(`singleton_id`)"))
        assertEquals(
            2,
            normalized.countOccurrences("on update no action on delete restrict"),
        )
        assertEquals(setOf("nonce", "sealed_credential"), blobColumns)
        forbiddenStorageNames.forEach { forbidden ->
            assertFalse(Regex("[`_a-z]$forbidden[`_a-z]").containsMatchIn(normalized))
        }
    }

    @Test
    fun `installation ID index remains unique and v2 identity is generated`() {
        val database = exportedDatabase(schemaV2File)
        val installation =
            database.getValue("entities").jsonArray
                .map { it.jsonObject }
                .single { it.getValue("tableName").jsonPrimitive.content == "local_installation" }
        val index = installation.getValue("indices").jsonArray.single().jsonObject

        assertEquals(
            "index_local_installation_installation_id",
            index.getValue("name").jsonPrimitive.content,
        )
        assertTrue(index.getValue("unique").jsonPrimitive.content.toBoolean())
        assertEquals(
            "412e402cf0ccad7079c1d70488cbea1b",
            database.getValue("identityHash").jsonPrimitive.content,
        )
    }

    @Test
    fun `v3 adds only the capability publication singleton with the approved columns`() {
        val database = exportedDatabase(schemaV3File)
        val columnsByTable = columnsByTable(database)

        assertEquals(
            setOf(
                "local_installation",
                "server_configuration",
                "protected_enrollment",
                "capability_manifest_publication",
            ),
            columnsByTable.keys,
        )
        assertEquals(capabilityPublicationColumns, columnsByTable["capability_manifest_publication"])
        assertEquals(45, columnsByTable.values.sumOf { it.size })
        assertEquals(
            "fc6ae10689d928ae79814722274f529e",
            database.getValue("identityHash").jsonPrimitive.content,
        )
    }

    @Test
    fun `v3 publication SQL has one restrictive enrollment FK and only approved blobs`() {
        val database = exportedDatabase(schemaV3File)
        val publication =
            database.getValue("entities").jsonArray
                .map { it.jsonObject }
                .single {
                    it.getValue("tableName").jsonPrimitive.content ==
                        "capability_manifest_publication"
                }
        val createSql = publication.getValue("createSql").jsonPrimitive.content.lowercase()
        val blobColumns =
            publication.getValue("fields").jsonArray
                .map { it.jsonObject }
                .filter { it.getValue("affinity").jsonPrimitive.content == "BLOB" }
                .map { it.getValue("columnName").jsonPrimitive.content }
                .toSet()

        assertEquals(1, createSql.countOccurrences("foreign key(`singleton_id`)"))
        assertEquals(1, createSql.countOccurrences("on update no action on delete restrict"))
        assertEquals(
            setOf(
                "enrollment_identity_fingerprint",
                "accepted_manifest_digest",
                "accepted_semantic_fingerprint",
                "accepted_canonical_payload",
                "pending_canonical_payload",
                "pending_canonical_digest",
                "pending_semantic_fingerprint",
            ),
            blobColumns,
        )
        setOf("token", "secret", "authorization", "headers", "exception", "message")
            .forEach { forbidden -> assertFalse(forbidden in createSql) }
    }

    @Test
    fun `public persistence ports exclude plaintext protector transport and Room types`() {
        val signature =
            listOf(
                LocalStateRepository::class.java,
                ProtectedEnrollmentRepository::class.java,
                CapabilityManifestPublicationRepository::class.java,
            )
                .flatMap { type -> type.declaredMethods.toList() }
                .joinToString("\n") { method -> method.toGenericString() }
                .lowercase()

        forbiddenApiTypeNames.forEach { forbidden ->
            assertFalse(
                forbidden in signature,
                "Public persistence API contains a forbidden type category.",
            )
        }
        setOf("delete", "clear", "reset", "rawquery", "export", "close").forEach {
            forbidden -> assertFalse(forbidden in signature)
        }
    }

    @Test
    fun `C06 production source has no protector plaintext token or networking dependency`() {
        val productionDirectory = File(projectDirectory, "src/main/kotlin")
        val c06Sources =
            productionDirectory
                .walkTopDown()
                .filter(File::isFile)
                .filter { file ->
                    file.name.contains("ProtectedEnrollment") ||
                        file.name == "AndroidLocalPersistenceFactory.kt" ||
                        file.name == "WtoAgentDatabaseMigrations.kt"
                }.toList()
        val source = c06Sources.joinToString("\n") { it.readText() }

        forbiddenProductionSymbols.forEach { forbidden ->
            assertFalse(forbidden in source, "C06 production source references $forbidden.")
        }
    }

    @Test
    fun `DAOs and builder contain no destructive or permissive operations`() {
        val daoSource =
            listOf("LocalStateDao.kt", "ProtectedEnrollmentDao.kt")
                .joinToString("\n") { name ->
                    File(
                        projectDirectory,
                        "src/main/kotlin/com/wifitestorchestrator/agent/data/persistence/room/$name",
                    ).readText()
                }
        val databaseSource =
            File(
                projectDirectory,
                "src/main/kotlin/com/wifitestorchestrator/agent/data/persistence/room/WtoAgentDatabase.kt",
            ).readText()

        assertFalse("OnConflictStrategy.REPLACE" in daoSource)
        assertFalse("@Delete" in daoSource)
        assertFalse("@Upsert" in daoSource)
        assertFalse("DELETE FROM" in daoSource)
        assertFalse("fallbackToDestructiveMigration" in databaseSource)
        assertFalse("allowMainThreadQueries" in databaseSource)
        assertFalse("enableMultiInstanceInvalidation" in databaseSource)
        assertFalse("setAutoCloseTimeout" in databaseSource)
    }

    @Test
    fun `failure results expose only closed errors`() {
        val failures =
            listOf(
                ReadLocalStateResult.Failure(LocalPersistenceError.CORRUPTION),
                ReadProtectedEnrollmentResult.Failure(LocalPersistenceError.CORRUPTION),
                PersistProtectedEnrollmentResult.Failure(LocalPersistenceError.CORRUPTION),
            )

        failures.forEach { failure ->
            val rendered = failure.toString().lowercase()
            assertTrue("corruption" in rendered)
            forbiddenDiagnosticNames.forEach { forbidden -> assertFalse(forbidden in rendered) }
        }
    }

    private fun columnsByTable(database: JsonObject): Map<String, Set<String>> {
        val entities = database.getValue("entities").jsonArray
        return entities.associate { entityElement ->
            val entity = entityElement.jsonObject
            entity.getValue("tableName").jsonPrimitive.content to
                entity.getValue("fields").jsonArray.map { field ->
                    field.jsonObject.getValue("columnName").jsonPrimitive.content
                }.toSet()
        }
    }

    private fun String.countOccurrences(value: String): Int =
        windowed(value.length).count { it == value }

    private fun exportedDatabase(schemaFile: File): JsonObject {
        assertTrue(schemaFile.isFile)
        return Json
            .parseToJsonElement(schemaFile.readText())
            .jsonObject
            .getValue("database")
            .jsonObject
    }

    private companion object {
        val protectedEnrollmentColumns =
            setOf(
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
        val capabilityPublicationColumns =
            setOf(
                "singleton_id",
                "enrollment_identity_fingerprint",
                "next_manifest_sequence",
                "sequence_exhausted",
                "accepted_manifest_id",
                "accepted_manifest_sequence",
                "accepted_manifest_digest",
                "accepted_server_received_at_epoch_seconds",
                "accepted_server_received_at_nanoseconds",
                "accepted_semantic_fingerprint",
                "accepted_canonical_payload",
                "pending_manifest_id",
                "pending_manifest_sequence",
                "pending_generated_at_epoch_seconds",
                "pending_generated_at_nanoseconds",
                "pending_canonical_payload",
                "pending_canonical_digest",
                "pending_semantic_fingerprint",
            )
        val forbiddenStorageNames =
            setOf(
                "token",
                "secret",
                "authorization",
                "body",
                "payload",
                "headers",
                "request",
                "response",
                "exception",
                "message",
                "details",
            )
        val forbiddenApiTypeNames =
            setOf(
                "deliveredcredential",
                "credentialprotector",
                "agentcredentialsecret",
                "enrollmenttoken",
                "backendenrollmentacceptance",
                "dto",
                "roomdatabase",
                "supportsqlitedatabase",
                ".persistence.room.",
                "android.content.context",
                "androidx.room",
                "androidx.sqlite",
            )
        val forbiddenProductionSymbols =
            setOf(
                "CredentialProtector",
                "DeliveredCredential",
                "AgentCredentialSecret",
                "EnrollmentToken",
                "BackendEnrollmentAcceptance",
                "OkHttp",
                "Retrofit",
                "HttpUrl",
            )
        val forbiddenDiagnosticNames =
            setOf("path", "select", "insert", "https", "exception", "cause", "stack")
    }
}
