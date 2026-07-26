package com.wifitestorchestrator.agent.contracts.capability

import com.wifitestorchestrator.agent.contracts.CanonicalContractFixtures
import com.wifitestorchestrator.agent.contracts.strictJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class CapabilityManifestDtosTest {
    @Test
    fun `mobile fixture is structural evidence and round trips exactly as JSON`() {
        val source = CanonicalContractFixtures.read("valid/capability-manifest-mobile.json")
        val decoded = strictJson.decodeFromString<CapabilityManifestDto>(source)

        assertEquals(15, decoded.capabilities.size)
        assertEquals("wifi.connection.read", decoded.capabilities.first().id)
        assertEquals("execution.background.continuous", decoded.capabilities.last().id)
        assertEquals(
            ImplementationStatusValueDto.IMPLEMENTED,
            decoded.capabilities.single { it.id == "network.http.probe" }
                .implementationStatus.status,
        )
        assertTrue(
            strictJson.parseToJsonElement(source) ==
                strictJson.parseToJsonElement(strictJson.encodeToString(decoded)),
        )
    }

    @Test
    fun `required fields have no decoding defaults`() {
        val source = CanonicalContractFixtures.read("valid/capability-manifest-mobile.json")
        val root = strictJson.parseToJsonElement(source).jsonObject.toMutableMap()
        root.remove("agent_version")

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<CapabilityManifestDto>(
                strictJson.encodeToString(
                    kotlinx.serialization.json.JsonObject.serializer(),
                    kotlinx.serialization.json.JsonObject(root),
                ),
            )
        }
    }

    @Test
    fun `unknown manifest fields and enum values are rejected`() {
        val source = CanonicalContractFixtures.read("valid/capability-manifest-mobile.json")
        val root = strictJson.parseToJsonElement(source).jsonObject
        val unknownField =
            kotlinx.serialization.json.JsonObject(
                root + ("unexpected" to kotlinx.serialization.json.JsonPrimitive(true)),
            )
        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<CapabilityManifestDto>(unknownField.toString())
        }

        val capabilities = root.getValue("capabilities").jsonArray.toMutableList()
        val first = capabilities.first().jsonObject
        val technical = first.getValue("technical_support").jsonObject
        capabilities[0] =
            kotlinx.serialization.json.JsonObject(
                first +
                    (
                        "technical_support" to
                            kotlinx.serialization.json.JsonObject(
                                technical +
                                    (
                                        "status" to
                                            kotlinx.serialization.json.JsonPrimitive(
                                                "invented",
                                            )
                                    ),
                            )
                    ),
            )
        val unknownEnum =
            kotlinx.serialization.json.JsonObject(
                root + ("capabilities" to kotlinx.serialization.json.JsonArray(capabilities)),
            )
        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<CapabilityManifestDto>(unknownEnum.toString())
        }
    }

    @Test
    fun `ack is strict and requires exactly the normative fields`() {
        val valid =
            """
            {
              "schema_version":"1.0.0",
              "manifest_id":"30000000-0000-4000-8000-000000000004",
              "manifest_digest":"${"ab".repeat(32)}",
              "server_received_at":"2026-07-25T12:00:00Z"
            }
            """.trimIndent()
        val decoded = strictJson.decodeFromString<CapabilityManifestAcceptedDto>(valid)
        assertEquals("1.0.0", decoded.schemaVersion)
        assertEquals("ab".repeat(32), decoded.manifestDigest)

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<CapabilityManifestAcceptedDto>(
                valid.replace(
                    "\"server_received_at\":\"2026-07-25T12:00:00Z\"",
                    "\"server_received_at\":\"2026-07-25T12:00:00Z\",\"extra\":1",
                ),
            )
        }
        val missing = strictJson.parseToJsonElement(valid).jsonObject.toMutableMap()
        missing.remove("manifest_digest")
        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<CapabilityManifestAcceptedDto>(
                kotlinx.serialization.json.JsonObject(missing).toString(),
            )
        }
    }

    @Test
    fun `contract constants freeze endpoint limits and catalog version`() {
        assertEquals("/api/v1/agents/self/capability-manifest", CapabilityManifestContract.PATH)
        assertEquals(262_144, CapabilityManifestContract.MAX_REQUEST_BYTES)
        assertEquals(65_536, CapabilityManifestContract.MAX_RESPONSE_BYTES)
        assertEquals("1.0.0", CapabilityManifestContract.CATALOG_VERSION)
        assertEquals(
            "1.0.0",
            strictJson.parseToJsonElement(
                CanonicalContractFixtures.read("valid/capability-manifest-mobile.json"),
            ).jsonObject.getValue("capability_catalog_version").jsonPrimitive.content,
        )
    }
}
