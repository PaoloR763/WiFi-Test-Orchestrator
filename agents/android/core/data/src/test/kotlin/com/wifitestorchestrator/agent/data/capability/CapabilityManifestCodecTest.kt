package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.domain.capability.ImplementationStatus
import com.wifitestorchestrator.agent.domain.capability.LimitationsStatus
import com.wifitestorchestrator.agent.domain.capability.ProviderImplementation
import com.wifitestorchestrator.agent.domain.capability.ProviderStatus
import com.wifitestorchestrator.agent.domain.capability.WifiHardwarePresence
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class CapabilityManifestCodecTest {
    private val codec = CapabilityManifestCodec()

    @Test
    fun `canonical JSON matches backend profile for ordering unicode escapes and integers`() {
        val document =
            JsonObject(
                linkedMapOf(
                    "z" to JsonPrimitive("β\n"),
                    "a" to JsonArray(listOf(JsonPrimitive(2), JsonPrimitive(1), JsonNull)),
                ),
            )
        val expected = """{"a":[2,1,null],"z":"β\n"}""".encodeToByteArray()

        val actual = assertNotNull(CanonicalJson.encode(document))

        assertContentEquals(expected, actual)
        assertEquals(
            "8a5dd18a64165f3b617cbd09dfafc7b73f18bd80b81a5d154d387653ad8feb0c",
            assertNotNull(actual.sha256()).lowercaseHex(),
        )
    }

    @Test
    fun `negative zero encodes as zero and is never accepted as canonical input`() {
        val negativeZero = CapabilityJson.strict.parseToJsonElement("-0")

        assertContentEquals("0".encodeToByteArray(), assertNotNull(CanonicalJson.encode(negativeZero)))
        assertNull(CanonicalJson.parseCanonical("-0".encodeToByteArray()))
        assertNull(
            CanonicalJson.parseCanonical(
                """{"max_duration_seconds":-0}""".encodeToByteArray(),
            ),
        )
        listOf("01", "-01", "1.0", "1e3", "NaN", "Infinity", "-Infinity").forEach {
            assertNull(CanonicalJson.parseCanonical(it.encodeToByteArray()), it)
        }
        listOf("0", "1", "-1", "9223372036854775807").forEach {
            assertNotNull(CanonicalJson.parseCanonical(it.encodeToByteArray()), it)
        }
        assertNotNull(
            CanonicalJson.parseCanonical(
                """{"max_duration_seconds":1}""".encodeToByteArray(),
            ),
        )
    }

    @Test
    fun `freeze is deterministic and semantic fingerprint excludes only frozen envelope fields`() {
        val input = capabilitySemanticInput()
        val first =
            assertFrozen(
                codec.freeze(input, TEST_MANIFEST_ID, 0, TEST_GENERATED_AT),
            )
        val retry =
            assertFrozen(
                codec.freeze(input, TEST_MANIFEST_ID, 0, TEST_GENERATED_AT),
            )
        val next =
            assertFrozen(
                codec.freeze(
                    input,
                    SECOND_TEST_MANIFEST_ID,
                    1,
                    TEST_GENERATED_AT.plusSeconds(1),
                ),
            )

        assertTrue(first.isByteIdenticalTo(retry))
        assertEquals(first.semanticFingerprint, next.semanticFingerprint)
        assertNotEquals(first.canonicalDigest, next.canonicalDigest)
        assertFalse(first.copyCanonicalPayload().contentEquals(next.copyCanonicalPayload()))
    }

    @Test
    fun `semantic changes in agent OS hardware or dimensions produce new fingerprint`() {
        val nominal = assertNotNull(codec.semanticFingerprint(capabilitySemanticInput()))
        val changedAgent =
            assertNotNull(
                codec.semanticFingerprint(capabilitySemanticInput(agentVersion = "0.2.0")),
            )
        val changedOs =
            assertNotNull(
                codec.semanticFingerprint(capabilitySemanticInput(platformVersion = "16")),
            )
        val absentWifi =
            assertNotNull(
                codec.semanticFingerprint(
                    capabilitySemanticInput(presence = WifiHardwarePresence.ABSENT),
                ),
            )
        val unknownWifi =
            assertNotNull(
                codec.semanticFingerprint(
                    capabilitySemanticInput(presence = WifiHardwarePresence.UNKNOWN),
                ),
            )

        assertEquals(5, setOf(nominal, changedAgent, changedOs, absentWifi, unknownWifi).size)
    }

    @Test
    fun `persisted validation requires canonical bytes digest fingerprint and exact identity`() {
        val frozen = frozenManifest()
        val validated =
            codec.validatePersisted(
                canonicalPayload = frozen.copyCanonicalPayload(),
                canonicalDigest = frozen.canonicalDigest,
                semanticFingerprint = frozen.semanticFingerprint,
                expectedAgentId = capabilitySemanticInput().agentId,
                expectedManifestId = frozen.manifestId,
                expectedSequence = frozen.manifestSequence,
            )

        assertNotNull(validated)
        assertTrue(frozen.isByteIdenticalTo(validated))
        assertNull(
            codec.validatePersisted(
                canonicalPayload = frozen.copyCanonicalPayload() + byteArrayOf(' '.code.toByte()),
                canonicalDigest = frozen.canonicalDigest,
                semanticFingerprint = frozen.semanticFingerprint,
                expectedAgentId = capabilitySemanticInput().agentId,
                expectedManifestId = frozen.manifestId,
                expectedSequence = frozen.manifestSequence,
            ),
        )
        assertNull(
            codec.validatePersisted(
                canonicalPayload = frozen.copyCanonicalPayload(),
                canonicalDigest = Sha256Value.from(ByteArray(32) { 7 })!!,
                semanticFingerprint = frozen.semanticFingerprint,
                expectedAgentId = capabilitySemanticInput().agentId,
                expectedManifestId = frozen.manifestId,
                expectedSequence = frozen.manifestSequence,
            ),
        )
        val nonV4ManifestId = "aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa"
        val nonV4 =
            rehashPersistedManifest(
                canonicalFrozenDocument()
                    .withTestProperty("manifest_id", JsonPrimitive(nonV4ManifestId)),
            )
        assertNull(
            codec.validatePersisted(
                canonicalPayload = nonV4.payload,
                canonicalDigest = nonV4.canonicalDigest,
                semanticFingerprint = nonV4.semanticFingerprint,
                expectedAgentId = capabilitySemanticInput().agentId,
                expectedManifestId = nonV4ManifestId,
                expectedSequence = 0L,
            ),
        )
    }

    @Test
    fun `historical contract manifest rehydrates byte identically as accepted and pending`() {
        val historical = contractValidHistoricalDocument()
        val acceptedCandidate = rehashPersistedManifest(historical)
        val accepted =
            assertNotNull(
                codec.validateTestPersisted(acceptedCandidate),
            )
        assertContentEquals(acceptedCandidate.payload, accepted.copyCanonicalPayload())
        assertFalse(
            frozenManifest().copyCanonicalPayload().contentEquals(accepted.copyCanonicalPayload()),
        )

        val pendingDocument =
            historical
                .withTestProperty("manifest_id", JsonPrimitive(SECOND_TEST_MANIFEST_ID))
                .withTestProperty("manifest_sequence", JsonPrimitive(1))
                .withTestProperty(
                    "generated_at",
                    JsonPrimitive("2026-07-25T12:00:01.123456789Z"),
                )
        val pendingCandidate = rehashPersistedManifest(pendingDocument)
        val pending =
            assertNotNull(
                codec.validateTestPersisted(
                    candidate = pendingCandidate,
                    expectedManifestId = SECOND_TEST_MANIFEST_ID,
                    expectedSequence = 1L,
                ),
            )

        assertContentEquals(pendingCandidate.payload, pending.copyCanonicalPayload())
        assertEquals(acceptedCandidate.semanticFingerprint, pending.semanticFingerprint)
        assertEquals(pendingCandidate.canonicalDigest, pending.canonicalDigest)
    }

    @Test
    fun `new fingerprints and freezes still reject snapshots outside current Android catalog`() {
        val snapshot = capabilitySnapshot()
        val current = snapshot.capabilities.first()
        val foreign =
            current.copy(
                implementationStatus =
                    current.implementationStatus.copy(
                        status = ImplementationStatus.IMPLEMENTED,
                        reason = null,
                    ),
                provider =
                    current.provider.copy(
                        status = ProviderStatus.AVAILABLE,
                        implementations =
                            listOf(
                                ProviderImplementation(
                                    providerId = "android-native",
                                    providerVersion = "1.2.3",
                                    method = "http.download",
                                ),
                            ),
                        reason = null,
                    ),
                limitations =
                    current.limitations.copy(
                        status = LimitationsStatus.KNOWN,
                        maxDurationSeconds = 300L,
                        reason = null,
                    ),
            )
        val foreignInput =
            capabilitySemanticInput().copy(
                snapshot =
                    snapshot.copy(
                        capabilities =
                            snapshot.capabilities.toMutableList().apply {
                                this[0] = foreign
                            },
                    ),
            )

        assertNull(codec.semanticFingerprint(foreignInput))
        assertEquals(
            CapabilityManifestFreezeResult.Invalid,
            codec.freeze(
                input = foreignInput,
                manifestId = TEST_MANIFEST_ID,
                manifestSequence = 0L,
                generatedAt = TEST_GENERATED_AT,
            ),
        )
    }

    @Test
    fun `persisted negative zero is corrupt even when local digest and fingerprint match`() {
        val zeroCandidate = rehashPersistedManifest(canonicalFrozenDocument())
        val zero =
            assertNotNull(
                codec.validateTestPersisted(zeroCandidate),
            )
        val zeroRaw = zeroCandidate.payload.decodeToString()
        assertTrue(zeroRaw.contains("\"manifest_sequence\":0"))
        assertContentEquals(zeroCandidate.payload, zero.copyCanonicalPayload())

        val sequenceNegativeZeroRaw =
            zeroRaw
                .replace("\"manifest_sequence\":0", "\"manifest_sequence\":-0")
                .encodeToByteArray()
        val sequenceNegativeZeroDocument =
            CapabilityJson.strict.parseToJsonElement(
                sequenceNegativeZeroRaw.decodeToString(),
            ) as JsonObject
        val sequenceNegativeZero =
            rehashPersistedManifest(
                document = sequenceNegativeZeroDocument,
                payloadOverride = sequenceNegativeZeroRaw,
            )
        assertEquals(
            assertNotNull(sequenceNegativeZeroRaw.sha256()),
            sequenceNegativeZero.canonicalDigest,
        )
        assertNull(codec.validateTestPersisted(sequenceNegativeZero))

        val limitationOne =
            canonicalFrozenDocument().mutateTestDimension("limitations") {
                it.withTestProperty("max_duration_seconds", JsonPrimitive(1))
            }
        val limitationOneRaw = assertNotNull(CanonicalJson.encode(limitationOne)).decodeToString()
        val limitationNegativeZeroRaw =
            limitationOneRaw
                .replace("\"max_duration_seconds\":1", "\"max_duration_seconds\":-0")
                .encodeToByteArray()
        val limitationNegativeZeroDocument =
            CapabilityJson.strict.parseToJsonElement(
                limitationNegativeZeroRaw.decodeToString(),
            ) as JsonObject
        val limitationNegativeZero =
            rehashPersistedManifest(
                document = limitationNegativeZeroDocument,
                payloadOverride = limitationNegativeZeroRaw,
            )
        assertEquals(
            assertNotNull(limitationNegativeZeroRaw.sha256()),
            limitationNegativeZero.canonicalDigest,
        )
        assertNull(codec.validateTestPersisted(limitationNegativeZero))
    }

    @Test
    fun `invalid platform UUID sequence and generated timestamp fail closed`() {
        assertNull(
            codec.semanticFingerprint(
                capabilitySemanticInput().copy(
                    snapshot = capabilitySnapshot().copy(platformVersion = ""),
                ),
            ),
        )
        assertEquals(
            CapabilityManifestFreezeResult.Invalid,
            codec.freeze(
                capabilitySemanticInput(),
                "not-a-uuid",
                0,
                TEST_GENERATED_AT,
            ),
        )
        assertEquals(
            CapabilityManifestFreezeResult.Invalid,
            codec.freeze(
                capabilitySemanticInput(),
                TEST_MANIFEST_ID,
                -1,
                TEST_GENERATED_AT,
            ),
        )
        assertEquals(
            CapabilityManifestFreezeResult.Invalid,
            codec.freeze(
                capabilitySemanticInput(),
                TEST_MANIFEST_ID,
                0,
                Instant.MAX,
            ),
        )
    }

    private fun assertFrozen(result: CapabilityManifestFreezeResult): FrozenCapabilityManifest {
        check(result is CapabilityManifestFreezeResult.Frozen)
        return result.manifest
    }
}
