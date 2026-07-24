package com.wifitestorchestrator.agent.data.persistence

import com.wifitestorchestrator.agent.data.persistence.room.LocalStateRows
import com.wifitestorchestrator.agent.data.persistence.room.MappedProtectedEnrollment
import com.wifitestorchestrator.agent.data.persistence.room.MappedProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.room.ObservedProtectedEnrollmentRows
import com.wifitestorchestrator.agent.data.persistence.room.ProtectedEnrollmentEntity
import com.wifitestorchestrator.agent.data.persistence.room.mapProtectedEnrollment
import com.wifitestorchestrator.agent.data.persistence.room.toEntity
import com.wifitestorchestrator.agent.data.persistence.room.toMappedLocalState
import com.wifitestorchestrator.agent.data.persistence.room.toMappedWrite
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ProtectedEnrollmentMappersTest {
    @Test
    fun `active write maps every field and compatible row reconstructs exactly`() {
        val write =
            protectedEnrollmentWrite(
                credentialVersion = 7,
                nonceByte = 0x31,
                sealedByte = 0x42,
            )
        val entity = assertIs<MappedProtectedEnrollmentWrite.Active>(write.toMappedWrite()).entity

        val mapped =
            assertIs<MappedProtectedEnrollment.Compatible>(
                mapProtectedEnrollment(configuredLocalState(), observed(entity)),
            )

        assertEquals(write.expectedLocalIdentity, mapped.enrollment.localIdentity)
        assertEquals(
            write.expectedServerConfiguration,
            mapped.enrollment.serverConfiguration,
        )
        assertEquals(write.backendIdentity, mapped.enrollment.backendIdentity)
        assertEquals(write.protocolVersion, mapped.enrollment.protocolVersion)
        assertEquals(write.serverReceivedAt, mapped.enrollment.serverReceivedAt)
        assertEquals(write.credentialMetadata, mapped.enrollment.credentialMetadata)
        mapped.enrollment.protectedCredential.useNonce { nonce ->
            assertContentEquals(ByteArray(12) { 0x31 }, nonce)
        }
        mapped.enrollment.protectedCredential.useSealedCredential { sealed ->
            assertContentEquals(ByteArray(105) { 0x42 }, sealed)
        }
    }

    @Test
    fun `all SQLite integers are validated as Long before Int narrowing`() {
        val entity = validEntity()
        val invalidVersions =
            listOf(
                entity.copy(credentialVersion = 0L),
                entity.copy(credentialVersion = -1L),
                entity.copy(credentialVersion = Int.MAX_VALUE.toLong() + 1L),
                entity.copy(credentialVersion = 4_294_967_297L),
                entity.copy(cryptoVersion = 0L),
                entity.copy(cryptoVersion = -1L),
                entity.copy(cryptoVersion = Int.MAX_VALUE.toLong() + 1L),
                entity.copy(cryptoVersion = 4_294_967_297L),
            )

        invalidVersions.forEach { invalid ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(invalid)),
            )
        }
    }

    @Test
    fun `nanoseconds outside the closed range are corrupt without normalization`() {
        val entity = validEntity()
        val invalidRows =
            listOf(
                entity.copy(serverReceivedAtNanoseconds = -1),
                entity.copy(serverReceivedAtNanoseconds = 1_000_000_000),
                entity.copy(serverReceivedAtNanoseconds = 4_294_967_296L),
                entity.copy(issuedAtNanoseconds = -1),
                entity.copy(issuedAtNanoseconds = 1_000_000_000),
                entity.copy(expiresAtNanoseconds = -1),
                entity.copy(expiresAtNanoseconds = 1_000_000_000),
            )

        invalidRows.forEach { invalid ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(invalid)),
            )
        }
    }

    @Test
    fun `temporal incoherence and unrepresentable instants are corrupt`() {
        val entity = validEntity()
        val invalidRows =
            listOf(
                entity.copy(serverReceivedAtEpochSeconds = entity.issuedAtEpochSeconds - 1),
                entity.copy(
                    serverReceivedAtEpochSeconds = entity.expiresAtEpochSeconds,
                    serverReceivedAtNanoseconds = entity.expiresAtNanoseconds,
                ),
                entity.copy(
                    expiresAtEpochSeconds = entity.issuedAtEpochSeconds,
                    expiresAtNanoseconds = entity.issuedAtNanoseconds,
                ),
                entity.copy(serverReceivedAtEpochSeconds = Long.MAX_VALUE),
                entity.copy(issuedAtEpochSeconds = Long.MIN_VALUE),
            )

        invalidRows.forEach { invalid ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(invalid)),
            )
        }
    }

    @Test
    fun `pending and recognizable future policies are unsupported not corrupt`() {
        val entity = validEntity()
        val unsupportedRows =
            listOf(
                entity.copy(credentialDeliveryState = "PENDING"),
                entity.copy(
                    cryptoVersion = 2,
                    keyAlias = versionedAlias("2"),
                    nonce = ByteArray(32),
                    sealedCredential = ByteArray(256),
                ),
                entity.copy(protocolVersion = "2.0.0"),
            )

        unsupportedRows.forEach { unsupported ->
            assertEquals(
                MappedProtectedEnrollment.Unsupported,
                mapProtectedEnrollment(configuredLocalState(), observed(unsupported)),
            )
        }
    }

    @Test
    fun `future alias versions cover the positive Int range and reject malformed values`() {
        val entity = validEntity()
        listOf(999_999_999L, 1_000_000_000L, Int.MAX_VALUE.toLong()).forEach { version ->
            assertEquals(
                MappedProtectedEnrollment.Unsupported,
                mapProtectedEnrollment(
                    configuredLocalState(),
                    observed(
                        entity.copy(
                            cryptoVersion = version,
                            keyAlias = versionedAlias(version.toString()),
                        ),
                    ),
                ),
            )
        }

        listOf(
            entity.copy(
                cryptoVersion = Int.MAX_VALUE.toLong() + 1L,
                keyAlias = versionedAlias("2147483648"),
            ),
            entity.copy(
                cryptoVersion = 9_999_999_999L,
                keyAlias = versionedAlias("9999999999"),
            ),
            entity.copy(
                cryptoVersion = 1_000_000_000L,
                keyAlias = versionedAlias("1000000001"),
            ),
            entity.copy(
                cryptoVersion = 100_000_000L,
                keyAlias = versionedAlias("0100000000"),
            ),
            entity.copy(
                cryptoVersion = 2L,
                keyAlias = versionedAlias("10000000000"),
            ),
            entity.copy(cryptoVersion = 0L, keyAlias = versionedAlias("0")),
            entity.copy(cryptoVersion = -1L, keyAlias = versionedAlias("-1")),
            entity.copy(cryptoVersion = 2L, keyAlias = versionedAlias("2x")),
            entity.copy(
                cryptoVersion = 1_000_000_000L,
                keyAlias = versionedAlias("1000000000"),
                nonce = ByteArray(0),
            ),
        ).forEach { corrupt ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(corrupt)),
            )
        }
    }

    @Test
    fun `known v1 envelope corruption precedes pending and future protocol`() {
        val entity = validEntity()
        listOf(
            entity.copy(
                credentialDeliveryState = "PENDING",
                nonce = ByteArray(13),
            ),
            entity.copy(
                credentialDeliveryState = "PENDING",
                sealedCredential = ByteArray(106),
            ),
            entity.copy(
                protocolVersion = "2.0.0",
                nonce = ByteArray(13),
            ),
            entity.copy(
                protocolVersion = "2.0.0",
                sealedCredential = ByteArray(106),
            ),
        ).forEach { corrupt ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(corrupt)),
            )
        }
        assertEquals(
            MappedProtectedEnrollment.Unsupported,
            mapProtectedEnrollment(
                configuredLocalState(),
                observed(
                    entity.copy(
                        cryptoVersion = 2,
                        keyAlias =
                            "com.wifitestorchestrator.agent.credential.aead.v2",
                        nonce = ByteArray(13),
                        sealedCredential = ByteArray(106),
                    ),
                ),
            ),
        )
    }

    @Test
    fun `unknown state and malformed or unrecognized aliases are corrupt`() {
        val entity = validEntity()
        val corruptRows =
            listOf(
                entity.copy(credentialDeliveryState = "active"),
                entity.copy(credentialDeliveryState = "UNKNOWN"),
                entity.copy(credentialDeliveryState = ""),
                entity.copy(keyAlias = ""),
                entity.copy(keyAlias = "future.alias.v2"),
                entity.copy(
                    keyAlias =
                        "com.wifitestorchestrator.agent.credential.aead.v0",
                ),
                entity.copy(protocolVersion = "02.0.0"),
            )

        corruptRows.forEach { corrupt ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(corrupt)),
            )
        }
    }

    @Test
    fun `current policy rejects invalid nonce and ciphertext sizes`() {
        val entity = validEntity()
        val corruptRows =
            listOf(
                entity.copy(nonce = ByteArray(0)),
                entity.copy(nonce = ByteArray(11)),
                entity.copy(nonce = ByteArray(13)),
                entity.copy(sealedCredential = ByteArray(0)),
                entity.copy(sealedCredential = ByteArray(104)),
                entity.copy(sealedCredential = ByteArray(106)),
            )

        corruptRows.forEach { corrupt ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(corrupt)),
            )
        }
    }

    @Test
    fun `invalid identifiers URL singleton and relationship are corrupt`() {
        val entity = validEntity()
        val corruptRows =
            listOf(
                entity.copy(singletonId = 2),
                entity.copy(installationId = ""),
                entity.copy(installationId = SECOND_INSTALLATION_ID),
                entity.copy(serverBaseUrl = "https://LAB.example:443/"),
                entity.copy(serverBaseUrl = SECOND_SERVER_URL),
                entity.copy(agentId = ""),
                entity.copy(deviceId = "not-a-device"),
                entity.copy(credentialId = "x".repeat(256)),
            )

        corruptRows.forEach { corrupt ->
            assertEquals(
                MappedProtectedEnrollment.Corrupt,
                mapProtectedEnrollment(configuredLocalState(), observed(corrupt)),
            )
        }
    }

    @Test
    fun `cardinality and missing parent state are corrupt`() {
        val entity = validEntity()

        assertEquals(
            MappedProtectedEnrollment.Corrupt,
            mapProtectedEnrollment(
                configuredLocalState(),
                observed(entity, entity.copy(singletonId = 2)),
            ),
        )
        assertEquals(
            MappedProtectedEnrollment.Corrupt,
            mapProtectedEnrollment(
                LocalStateRows(emptyList(), emptyList()).toMappedLocalState(),
                observed(entity),
            ),
        )
    }

    @Test
    fun `candidate pending is rejected before an entity exists`() {
        val pending =
            protectedEnrollmentWrite(
                deliveryState = CredentialDeliveryState.PENDING,
            )

        assertEquals(MappedProtectedEnrollmentWrite.Pending, pending.toMappedWrite())
    }

    @Test
    fun `candidate validates timeline and envelope metadata coherence`() {
        val mismatchedEnvelope =
            protectedEnrollmentWrite().let { original ->
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
            }
        val lateServerReceipt =
            protectedEnrollmentWrite(
                serverReceivedAt = DEFAULT_EXPIRES_AT,
            )

        assertEquals(
            MappedProtectedEnrollmentWrite.Invalid,
            mismatchedEnvelope.toMappedWrite(),
        )
        assertEquals(
            MappedProtectedEnrollmentWrite.Invalid,
            lateServerReceipt.toMappedWrite(),
        )
    }

    private fun validEntity() =
        assertIs<MappedProtectedEnrollmentWrite.Active>(
            protectedEnrollmentWrite().toMappedWrite(),
        ).entity

    private fun versionedAlias(version: String): String =
        "com.wifitestorchestrator.agent.credential.aead.v$version"

    private fun observed(
        vararg rows: ProtectedEnrollmentEntity,
    ): ObservedProtectedEnrollmentRows =
        ObservedProtectedEnrollmentRows.Valid(rows.toList())

    private fun configuredLocalState() =
        LocalStateRows(
            installations =
                listOf(
                    localIdentity().toEntity(Instant.parse("2026-07-21T12:00:00Z")),
                ),
            serverConfigurations =
                listOf(
                    serverConfiguration().toEntity(
                        Instant.parse("2026-07-21T12:01:00Z"),
                    ),
                ),
        ).toMappedLocalState()
}
