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
    private val schemaFile =
        File(
            projectDirectory,
            "schemas/com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase/1.json",
        )

    @Test
    fun `exported schema contains exactly two tables and eight authorized columns`() {
        val database = exportedDatabase()
        val entities = database.getValue("entities").jsonArray
        val columnsByTable =
            entities.associate { entityElement ->
                val entity = entityElement.jsonObject
                entity.getValue("tableName").jsonPrimitive.content to
                    entity.getValue("fields").jsonArray.map { field ->
                        field.jsonObject.getValue("columnName").jsonPrimitive.content
                    }.toSet()
            }

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
            ),
            columnsByTable,
        )
        assertEquals(8, columnsByTable.values.sumOf { it.size })
    }

    @Test
    fun `schema SQL has required constraints and no blob or generic storage column`() {
        val database = exportedDatabase()
        val entities = database.getValue("entities").jsonArray.map { it.jsonObject }
        val createSql = entities.joinToString("\n") { it.getValue("createSql").jsonPrimitive.content }
        val normalized = createSql.lowercase()

        assertTrue("primary key(`singleton_id`)" in normalized)
        assertTrue("foreign key(`singleton_id`)" in normalized)
        assertTrue("on update no action on delete restrict" in normalized)
        assertFalse("blob" in normalized)
        forbiddenStorageNames.forEach { forbidden ->
            assertFalse(Regex("[`_a-z]$forbidden[`_a-z]").containsMatchIn(normalized))
        }
    }

    @Test
    fun `installation ID index is unique and schema identity is stable`() {
        val database = exportedDatabase()
        val installation =
            database.getValue("entities").jsonArray
                .map { it.jsonObject }
                .single { it.getValue("tableName").jsonPrimitive.content == "local_installation" }
        val index = installation.getValue("indices").jsonArray.single().jsonObject

        assertEquals("index_local_installation_installation_id", index.getValue("name").jsonPrimitive.content)
        assertTrue(index.getValue("unique").jsonPrimitive.content.toBoolean())
        assertEquals("2a33bf103f9927f13a8246f20d09ad8e", database.getValue("identityHash").jsonPrimitive.content)
    }

    @Test
    fun `public persistence API cannot accept enrollment or storage implementation types`() {
        val signature =
            LocalStateRepository::class.java.declaredMethods
                .joinToString("\n") { method -> method.toGenericString() }
                .lowercase()

        forbiddenApiTypeNames.forEach { forbidden ->
            assertFalse(forbidden in signature, "Public persistence API contains a forbidden type category.")
        }
        setOf("delete", "clear", "reset", "replace", "rawquery", "export", "close").forEach {
            forbidden -> assertFalse(forbidden in signature)
        }
    }

    @Test
    fun `DAO and builder contain no destructive or permissive operations`() {
        val daoSource =
            File(
                projectDirectory,
                "src/main/kotlin/com/wifitestorchestrator/agent/data/persistence/room/LocalStateDao.kt",
            ).readText()
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
        val failure = ReadLocalStateResult.Failure(LocalPersistenceError.CORRUPTION)
        val rendered = failure.toString().lowercase()

        assertTrue("corruption" in rendered)
        forbiddenDiagnosticNames.forEach { forbidden -> assertFalse(forbidden in rendered) }
    }

    private fun exportedDatabase(): JsonObject {
        assertTrue(schemaFile.isFile)
        return Json.parseToJsonElement(schemaFile.readText()).jsonObject.getValue("database").jsonObject
    }

    private companion object {
        val forbiddenStorageNames =
            setOf(
                "token",
                "secret",
                "credential",
                "authorization",
                "body",
                "payload",
                "headers",
                "exception",
                "message",
                "details",
            )
        val forbiddenApiTypeNames =
            setOf(
                "enrollment",
                "credential",
                "token",
                "deliveredcredential",
                "backendenrollmentacceptance",
                "dto",
                "roomdatabase",
                "supportsqlitedatabase",
                ".persistence.room.",
                "android.content.context",
                "androidx.room",
                "androidx.sqlite",
            )
        val forbiddenDiagnosticNames =
            setOf("path", "select", "insert", "https", "exception", "cause", "stack")
    }
}
