package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.domain.identity.AgentId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CapabilityManifestV1ValidatorTest {
    private val codec = CapabilityManifestCodec()

    @Test
    fun `historical profile rejects missing duplicate and malformed capabilities`() {
        val base = canonicalFrozenDocument()
        val capabilities = base.testCapabilities()
        val duplicate =
            capabilities.toMutableList().apply {
                this[1] = this[0]
            }
        val cases =
            listOf(
                "missing capability" to
                    base.withTestCapabilities(capabilities.dropLast(1)),
                "duplicate capability" to
                    base.withTestCapabilities(duplicate),
                "unknown capability id" to
                    base.mutateTestCapability {
                        it.withTestProperty("id", JsonPrimitive("wifi.unknown"))
                    },
                "wrong capability version" to
                    base.mutateTestCapability {
                        it.withTestProperty("version", JsonPrimitive("1.0.1"))
                    },
                "missing dimension" to
                    base.mutateTestCapability {
                        it.withoutTestProperty("provider")
                    },
                "wrong dimension type" to
                    base.mutateTestCapability {
                        it.withTestProperty("provider", JsonNull)
                    },
                "additional capability property" to
                    base.mutateTestCapability {
                        it.withTestProperty("unexpected", JsonPrimitive("value"))
                    },
            )

        cases.forEach { (label, document) -> assertRejected(label, document) }
    }

    @Test
    fun `historical profile rejects incompatible envelope versions and identity`() {
        val base = canonicalFrozenDocument()
        val cases =
            listOf(
                "unknown schema" to
                    base.withTestProperty("schema_version", JsonPrimitive("2.0.0")),
                "unknown catalog" to
                    base.withTestProperty(
                        "capability_catalog_version",
                        JsonPrimitive("2.0.0"),
                    ),
                "unknown protocol" to
                    base.withTestProperty("protocol_version", JsonPrimitive("2.0.0")),
                "wrong platform" to
                    base.withTestProperty("platform", JsonPrimitive("ios")),
                "invalid agent version" to
                    base.withTestProperty("agent_version", JsonPrimitive("01.0.0")),
                "empty platform version" to
                    base.withTestProperty("platform_version", JsonPrimitive("")),
                "long platform version" to
                    base.withTestProperty("platform_version", JsonPrimitive("x".repeat(65))),
                "invalid timestamp" to
                    base.withTestProperty(
                        "generated_at",
                        JsonPrimitive("2026-02-30T12:00:00Z"),
                    ),
                "missing required envelope field" to
                    base.withoutTestProperty("generated_at"),
                "additional envelope property" to
                    base.withTestProperty("unexpected", JsonPrimitive("value")),
                "mismatched agent identity" to
                    base.withTestProperty(
                        "agent_id",
                        JsonPrimitive("44444444-4444-4444-8444-444444444444"),
                    ),
                "mismatched manifest identity" to
                    base.withTestProperty("manifest_id", JsonPrimitive(SECOND_TEST_MANIFEST_ID)),
                "mismatched sequence" to
                    base.withTestProperty("manifest_sequence", JsonPrimitive(1)),
            )

        cases.forEach { (label, document) -> assertRejected(label, document) }
    }

    @Test
    fun `historical timestamp accepts uppercase or lowercase separator and exact fraction bounds`() {
        val cases =
            linkedMapOf(
                "uppercase separator" to "2026-07-25T12:00:00Z",
                "lowercase separator" to "2026-07-25t12:00:00Z",
                "one fractional digit" to "2026-07-25T12:00:00.1Z",
                "nanosecond precision" to "2026-07-25T12:00:00.123456789Z",
                "32 code point boundary" to "2026-07-25t12:00:00.12345678900Z",
            )

        cases.forEach { (label, timestamp) ->
            assertAccepted(
                label,
                canonicalFrozenDocument()
                    .withTestProperty("generated_at", JsonPrimitive(timestamp)),
            )
        }
    }

    @Test
    fun `historical timestamp rejects invalid UTC calendar precision and trailing forms`() {
        val cases =
            linkedMapOf(
                "lowercase z" to "2026-07-25T12:00:00z",
                "impossible date" to "2026-02-30T12:00:00Z",
                "24 hour" to "2026-07-25T24:00:00Z",
                "leap second" to "2026-07-25T12:00:60Z",
                "UTC offset" to "2026-07-25T12:00:00+00:00",
                "trailing content" to "2026-07-25T12:00:00Ztail",
                "empty fraction" to "2026-07-25T12:00:00.Z",
                "tenth nonzero fraction" to "2026-07-25T12:00:00.1234567891Z",
                "eleventh nonzero fraction" to "2026-07-25T12:00:00.12345678901Z",
                "overlong fraction" to "2026-07-25T12:00:00.123456789000Z",
                "year zero" to "0000-07-25T12:00:00Z",
            )

        cases.forEach { (label, timestamp) ->
            assertRejected(
                label,
                canonicalFrozenDocument()
                    .withTestProperty("generated_at", JsonPrimitive(timestamp)),
            )
        }
    }

    @Test
    fun `historical profile enforces enums reasons and permission constraints`() {
        val base = canonicalFrozenDocument()
        val permission =
            (base
                    .testCapabilities()
                    .first() as JsonObject)
                .testObject("permission_requirement")
                .testArray("permissions")
                .first()
        val cases =
            listOf(
                "unknown status" to
                    base.mutateTestDimension("technical_support") {
                        it.withTestProperty("status", JsonPrimitive("magical"))
                    },
                "unknown reason code" to
                    base.mutateTestDimension("implementation_status") {
                        it.withTestProperty(
                            "reason",
                            JsonObject(mapOf("code" to JsonPrimitive("magical"))),
                        )
                    },
                "empty reason detail" to
                    base.mutateTestDimension("implementation_status") {
                        it.withTestReasonDetail(JsonPrimitive(""))
                    },
                "long reason detail" to
                    base.mutateTestDimension("implementation_status") {
                        it.withTestReasonDetail(JsonPrimitive("x".repeat(257)))
                    },
                "additional reason property" to
                    base.mutateTestDimension("implementation_status") {
                        val reason = it.testObject("reason")
                        it.withTestProperty(
                            "reason",
                            reason.withTestProperty("unexpected", JsonPrimitive("value")),
                        )
                    },
                "invalid permission pattern" to
                    base.mutateTestDimension("permission_requirement") {
                        it.withTestProperty(
                            "permissions",
                            JsonArray(listOf(JsonPrimitive("Nearby WiFi"))),
                        )
                    },
                "permission too short for pattern" to
                    base.mutateTestDimension("permission_requirement") {
                        it.withTestProperty(
                            "permissions",
                            JsonArray(listOf(JsonPrimitive("a"))),
                        )
                    },
                "duplicate permissions" to
                    base.mutateTestDimension("permission_requirement") {
                        it.withTestProperty("permissions", JsonArray(listOf(permission, permission)))
                    },
                "too many permissions" to
                    base.mutateTestDimension("permission_requirement") {
                        it.withTestProperty(
                            "permissions",
                            JsonArray(
                                (0..16).map { index ->
                                    JsonPrimitive("permission.$index")
                                },
                            ),
                        )
                    },
                "permission wrong type" to
                    base.mutateTestDimension("permission_requirement") {
                        it.withTestProperty(
                            "permissions",
                            JsonArray(listOf(JsonPrimitive(1))),
                        )
                    },
            )

        cases.forEach { (label, document) -> assertRejected(label, document) }
    }

    @Test
    fun `historical profile enforces provider shape patterns semver limits and uniqueness`() {
        val base = canonicalFrozenDocument()
        val implementation = providerImplementation()
        val cases =
            listOf(
                "duplicate providers" to
                    base.withProviderImplementations(listOf(implementation, implementation)),
                "too many providers" to
                    base.withProviderImplementations(
                        (0..8).map { index ->
                            providerImplementation(providerId = "provider-$index")
                        },
                    ),
                "provider id pattern" to
                    base.withProviderImplementations(
                        listOf(providerImplementation(providerId = "Native Provider")),
                    ),
                "provider id length" to
                    base.withProviderImplementations(
                        listOf(providerImplementation(providerId = "ab")),
                    ),
                "provider semver" to
                    base.withProviderImplementations(
                        listOf(providerImplementation(providerVersion = "01.0.0")),
                    ),
                "provider method pattern" to
                    base.withProviderImplementations(
                        listOf(providerImplementation(method = "native method")),
                    ),
                "provider method length" to
                    base.withProviderImplementations(
                        listOf(providerImplementation(method = "x".repeat(65))),
                    ),
                "missing provider field" to
                    base.withProviderImplementations(
                        listOf(implementation.withoutTestProperty("method")),
                    ),
                "additional provider field" to
                    base.withProviderImplementations(
                        listOf(
                            implementation.withTestProperty(
                                "unexpected",
                                JsonPrimitive("value"),
                            ),
                        ),
                    ),
                "additional provider dimension property" to
                    base.mutateTestDimension("provider") {
                        it.withTestProperty("unexpected", JsonPrimitive("value"))
                    },
            )

        cases.forEach { (label, document) -> assertRejected(label, document) }
    }

    @Test
    fun `historical profile enforces every limitation integer type and exact range`() {
        val base = canonicalFrozenDocument()
        val maxima =
            linkedMapOf(
                "max_duration_seconds" to 86_400L,
                "max_throughput_bps" to 1_000_000_000_000L,
                "max_payload_bytes" to 1_073_741_824L,
                "max_concurrency" to 1_024L,
                "max_streams" to 128L,
            )

        maxima.forEach { (field, maximum) ->
            listOf(0L, -1L, maximum + 1L).forEach { invalid ->
                assertRejected(
                    "$field=$invalid",
                    base.withLimitation(field, JsonPrimitive(invalid)),
                )
            }
            assertRejected(
                "$field has string type",
                base.withLimitation(field, JsonPrimitive("1")),
            )
        }
        assertRejected(
            "additional limitation property",
            base.mutateTestDimension("limitations") {
                it.withTestProperty("unexpected", JsonPrimitive(1))
            },
        )
    }

    @Test
    fun `explicit null is rejected for detail and each optional limitation`() {
        val base = canonicalFrozenDocument()
        assertRejected(
            "detail null",
            base.mutateTestDimension("implementation_status") {
                it.withTestReasonDetail(JsonNull)
            },
        )
        listOf(
            "max_duration_seconds",
            "max_throughput_bps",
            "max_payload_bytes",
            "max_concurrency",
            "max_streams",
        ).forEach { field ->
            assertRejected(
                "$field null",
                base.withLimitation(field, JsonNull),
            )
        }
    }

    @Test
    fun `omitted optionals valid detail required null reasons and range boundaries are accepted`() {
        val base = canonicalFrozenDocument()
        val technicalSupport =
            (base.testCapabilities().first() as JsonObject).testObject("technical_support")
        assertTrue(technicalSupport["reason"] === JsonNull)
        assertTrue(
            base
                .testCapabilities()
                .map { it as JsonObject }
                .all {
                    val limitations = it.testObject("limitations")
                    LIMITATION_FIELDS.none(limitations::containsKey)
                },
        )
        assertAccepted("omitted optionals and required reason null", base)

        val validDetail =
            base.mutateTestDimension("implementation_status") {
                it.withTestReasonDetail(JsonPrimitive("historical policy decision"))
            }
        assertAccepted("valid detail", validDetail)

        val boundaries =
            linkedMapOf(
                "max_duration_seconds" to 86_400L,
                "max_throughput_bps" to 1_000_000_000_000L,
                "max_payload_bytes" to 1_073_741_824L,
                "max_concurrency" to 1_024L,
                "max_streams" to 128L,
            ).entries.fold(base) { document, (field, maximum) ->
                document.withLimitation(field, JsonPrimitive(maximum))
            }
        assertAccepted("valid limitation maxima", boundaries)
    }

    private fun assertRejected(
        label: String,
        document: JsonObject,
    ) {
        val candidate = rehashPersistedManifest(document)
        assertEquals(candidate.canonicalDigest, assertNotNull(candidate.payload.sha256()), label)
        assertNull(codec.validateTestPersisted(candidate), label)
    }

    private fun assertAccepted(
        label: String,
        document: JsonObject,
    ) {
        val candidate = rehashPersistedManifest(document)
        val validated = assertNotNull(codec.validateTestPersisted(candidate), label)
        assertContentEquals(candidate.payload, validated.copyCanonicalPayload(), label)
        assertEquals(candidate.canonicalDigest, validated.canonicalDigest, label)
        assertEquals(candidate.semanticFingerprint, validated.semanticFingerprint, label)
    }
}

internal data class RehashedPersistedManifest(
    val document: JsonObject,
    val payload: ByteArray,
    val canonicalDigest: Sha256Value,
    val semanticFingerprint: Sha256Value,
)

internal fun canonicalFrozenDocument(): JsonObject {
    val element = CanonicalJson.parseCanonical(frozenManifest().copyCanonicalPayload())
    return checkNotNull(element as? JsonObject)
}

internal fun rehashPersistedManifest(
    document: JsonObject,
    payloadOverride: ByteArray? = null,
): RehashedPersistedManifest {
    val payload = payloadOverride ?: checkNotNull(CanonicalJson.encode(document))
    val semantic =
        JsonObject(
            document.filterKeys {
                it != "manifest_id" &&
                    it != "manifest_sequence" &&
                    it != "generated_at"
            },
        )
    return RehashedPersistedManifest(
        document = document,
        payload = payload,
        canonicalDigest = checkNotNull(payload.sha256()),
        semanticFingerprint =
            checkNotNull(checkNotNull(CanonicalJson.encode(semantic)).sha256()),
    )
}

internal fun CapabilityManifestCodec.validateTestPersisted(
    candidate: RehashedPersistedManifest,
    expectedAgentId: AgentId = capabilitySemanticInput().agentId,
    expectedManifestId: String = TEST_MANIFEST_ID,
    expectedSequence: Long = 0L,
): FrozenCapabilityManifest? =
    validatePersisted(
        canonicalPayload = candidate.payload,
        canonicalDigest = candidate.canonicalDigest,
        semanticFingerprint = candidate.semanticFingerprint,
        expectedAgentId = expectedAgentId,
        expectedManifestId = expectedManifestId,
        expectedSequence = expectedSequence,
    )

internal fun JsonObject.withTestProperty(
    key: String,
    value: JsonElement,
): JsonObject =
    JsonObject(
        toMutableMap().apply {
            this[key] = value
        },
    )

internal fun JsonObject.withoutTestProperty(key: String): JsonObject =
    JsonObject(
        toMutableMap().apply {
            remove(key)
        },
    )

internal fun JsonObject.testObject(key: String): JsonObject =
    checkNotNull(this[key] as? JsonObject)

internal fun JsonObject.testArray(key: String): JsonArray =
    checkNotNull(this[key] as? JsonArray)

internal fun JsonObject.testCapabilities(): List<JsonElement> =
    testArray("capabilities").toList()

internal fun JsonObject.withTestCapabilities(capabilities: List<JsonElement>): JsonObject =
    withTestProperty("capabilities", JsonArray(capabilities))

internal fun JsonObject.mutateTestCapability(
    index: Int = 0,
    transform: (JsonObject) -> JsonObject,
): JsonObject {
    val capabilities = testCapabilities().toMutableList()
    capabilities[index] = transform(checkNotNull(capabilities[index] as? JsonObject))
    return withTestCapabilities(capabilities)
}

internal fun JsonObject.mutateTestDimension(
    name: String,
    index: Int = 0,
    transform: (JsonObject) -> JsonObject,
): JsonObject =
    mutateTestCapability(index) { capability ->
        capability.withTestProperty(
            name,
            transform(capability.testObject(name)),
        )
    }

private fun JsonObject.withProviderImplementations(
    implementations: List<JsonElement>,
): JsonObject =
    mutateTestDimension("provider") {
        it.withTestProperty("implementations", JsonArray(implementations))
    }

private fun JsonObject.withLimitation(
    field: String,
    value: JsonElement,
): JsonObject =
    mutateTestDimension("limitations") {
        it.withTestProperty(field, value)
    }

private fun JsonObject.withTestReasonDetail(detail: JsonElement): JsonObject {
    val reason = testObject("reason")
    return withTestProperty("reason", reason.withTestProperty("detail", detail))
}

private fun providerImplementation(
    providerId: String = "android-native",
    providerVersion: String = "1.2.3",
    method: String = "http.download",
): JsonObject =
    JsonObject(
        mapOf(
            "provider_id" to JsonPrimitive(providerId),
            "provider_version" to JsonPrimitive(providerVersion),
            "method" to JsonPrimitive(method),
        ),
    )

private val LIMITATION_FIELDS =
    setOf(
        "max_duration_seconds",
        "max_throughput_bps",
        "max_payload_bytes",
        "max_concurrency",
        "max_streams",
    )

internal fun contractValidHistoricalDocument(
    manifestId: String = TEST_MANIFEST_ID,
    manifestSequence: Long = 0L,
    generatedAt: String = "2026-07-25T12:00:00.123456789Z",
): JsonObject =
    canonicalFrozenDocument()
        .withTestProperty("manifest_id", JsonPrimitive(manifestId))
        .withTestProperty("manifest_sequence", JsonPrimitive(manifestSequence))
        .withTestProperty("generated_at", JsonPrimitive(generatedAt))
        .mutateTestDimension("implementation_status") {
            it
                .withTestProperty("status", JsonPrimitive("implemented"))
                .withTestProperty("reason", JsonNull)
        }.mutateTestDimension("permission_requirement") {
            it
                .withTestProperty("status", JsonPrimitive("denied"))
                .withTestProperty(
                    "reason",
                    JsonObject(
                        mapOf(
                            "code" to JsonPrimitive("permission_denied"),
                            "detail" to JsonPrimitive("historical user decision"),
                        ),
                    ),
                )
        }.mutateTestDimension("provider") {
            it
                .withTestProperty("status", JsonPrimitive("available"))
                .withTestProperty(
                    "implementations",
                    JsonArray(
                        listOf(
                            JsonObject(
                                mapOf(
                                    "provider_id" to JsonPrimitive("android-native"),
                                    "provider_version" to JsonPrimitive("1.2.3"),
                                    "method" to JsonPrimitive("http.download"),
                                ),
                            ),
                        ),
                    ),
                ).withTestProperty("reason", JsonNull)
        }.mutateTestDimension("limitations") {
            it
                .withTestProperty("status", JsonPrimitive("known"))
                .withTestProperty("max_duration_seconds", JsonPrimitive(300))
                .withTestProperty("max_throughput_bps", JsonPrimitive(100_000_000L))
                .withTestProperty("reason", JsonNull)
        }
