package com.wifitestorchestrator.agent.data.persistence

import android.content.Context
import androidx.room.Room
import androidx.room.withTransaction
import androidx.test.core.app.ApplicationProvider
import com.wifitestorchestrator.agent.data.persistence.room.ObservedProtectedEnrollmentRows
import com.wifitestorchestrator.agent.data.persistence.room.ProtectedEnrollmentEntity
import com.wifitestorchestrator.agent.data.persistence.room.RoomLocalStateRepository
import com.wifitestorchestrator.agent.data.persistence.room.RoomProtectedEnrollmentRepository
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabase
import com.wifitestorchestrator.agent.data.persistence.room.WtoAgentDatabaseProvider
import com.wifitestorchestrator.agent.data.persistence.room.observeProtectedEnrollmentRows
import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPolicyV1
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeCreationResult
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.DeviceId
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.io.File
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Before

internal const val FIRST_INSTALLATION_ID = "11111111-1111-4111-8111-111111111111"
internal const val SECOND_INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
internal const val FIRST_SERVER_URL = "https://lab.example/"
internal const val SECOND_SERVER_URL = "https://backup.example/Tenant/"
internal const val FIRST_AGENT_ID = "33333333-3333-4333-8333-333333333333"
internal const val SECOND_AGENT_ID = "44444444-4444-4444-8444-444444444444"
internal const val FIRST_DEVICE_ID = "55555555-5555-4555-8555-555555555555"
internal const val SECOND_DEVICE_ID = "66666666-6666-4666-8666-666666666666"
internal const val FIRST_CREDENTIAL_ID = "77777777-7777-4777-8777-777777777777"
internal const val SECOND_CREDENTIAL_ID = "88888888-8888-4888-8888-888888888888"
internal const val THIRD_CREDENTIAL_ID = "99999999-9999-4999-8999-999999999999"
internal val DEFAULT_SERVER_RECEIVED_AT: Instant =
    Instant.parse("2026-07-23T12:00:00.123456789Z")
internal val DEFAULT_ISSUED_AT: Instant =
    Instant.parse("2026-07-23T12:00:00.123456789Z")
internal val DEFAULT_EXPIRES_AT: Instant =
    Instant.parse("2026-10-21T12:00:00.987654321Z")

internal fun localIdentity(raw: String = FIRST_INSTALLATION_ID): LocalInstallationIdentity {
    val parsed = InstallationId.parse(raw)
    check(parsed is Valid)
    return LocalInstallationIdentity(parsed.value)
}

internal fun serverConfiguration(raw: String = FIRST_SERVER_URL): ServerConfiguration {
    val parsed = ServerBaseUrl.parse(raw)
    check(parsed is Valid)
    return ServerConfiguration(parsed.value)
}

internal fun backendIdentity(
    agentId: String = FIRST_AGENT_ID,
    deviceId: String = FIRST_DEVICE_ID,
): BackendAgentIdentity =
    BackendAgentIdentity(
        agentId = validValue(AgentId.parse(agentId)),
        deviceId = validValue(DeviceId.parse(deviceId)),
    )

internal fun protectedEnrollmentWrite(
    expectedLocalIdentity: LocalInstallationIdentity = localIdentity(),
    expectedServerConfiguration: ServerConfiguration = serverConfiguration(),
    backendIdentity: BackendAgentIdentity = backendIdentity(),
    credentialId: String = FIRST_CREDENTIAL_ID,
    credentialVersion: Int = 1,
    deliveryState: CredentialDeliveryState = CredentialDeliveryState.ACTIVE,
    serverReceivedAt: Instant = DEFAULT_SERVER_RECEIVED_AT,
    issuedAt: Instant = DEFAULT_ISSUED_AT,
    expiresAt: Instant = DEFAULT_EXPIRES_AT,
    nonceByte: Byte = 0x11,
    sealedByte: Byte = 0x22,
): ProtectedEnrollmentWrite {
    val typedCredentialId = validValue(CredentialId.parse(credentialId))
    val typedCredentialVersion = validValue(CredentialVersion.from(credentialVersion))
    val metadata =
        validValue(
            CredentialMetadata.create(
                credentialId = typedCredentialId,
                version = typedCredentialVersion,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                deliveryState = deliveryState,
            ),
        )
    val envelope =
        requireValidEnvelope(
            credentialId = typedCredentialId,
            credentialVersion = typedCredentialVersion,
            nonce = ByteArray(CredentialProtectionPolicyV1.NONCE_SIZE_BYTES) { nonceByte },
            sealedCredential =
                ByteArray(CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) {
                    sealedByte
                },
        )
    return ProtectedEnrollmentWrite(
        expectedLocalIdentity = expectedLocalIdentity,
        expectedServerConfiguration = expectedServerConfiguration,
        backendIdentity = backendIdentity,
        protocolVersion = ProtocolVersion.CURRENT,
        serverReceivedAt = serverReceivedAt,
        credentialMetadata = metadata,
        protectedCredential = envelope,
    )
}

internal fun requireValidEnvelope(
    credentialId: CredentialId = validValue(CredentialId.parse(FIRST_CREDENTIAL_ID)),
    credentialVersion: CredentialVersion = validValue(CredentialVersion.from(1)),
    nonce: ByteArray = ByteArray(CredentialProtectionPolicyV1.NONCE_SIZE_BYTES) { 0x11 },
    sealedCredential: ByteArray =
        ByteArray(CredentialProtectionPolicyV1.SEALED_CREDENTIAL_SIZE_BYTES) { 0x22 },
): ProtectedCredentialEnvelope =
    when (
        val created =
            ProtectedCredentialEnvelope.create(
                cryptoVersion = CredentialProtectionPolicyV1.CRYPTO_VERSION_VALUE,
                keyAlias = CredentialProtectionPolicyV1.KEY_ALIAS_VALUE,
                credentialId = credentialId,
                credentialVersion = credentialVersion,
                nonce = nonce,
                sealedCredential = sealedCredential,
            )
    ) {
        is ProtectedCredentialEnvelopeCreationResult.Valid -> created.envelope
        is ProtectedCredentialEnvelopeCreationResult.Invalid ->
            error("Synthetic protected credential envelope is invalid")
    }

internal fun <T : Any> validValue(
    result: com.wifitestorchestrator.agent.domain.error.ValidationResult<T>,
): T {
    check(result is Valid)
    return result.value
}

internal suspend fun WtoAgentDatabase.readProtectedEnrollmentEntitiesForTest():
    List<ProtectedEnrollmentEntity> =
    withTransaction {
        when (val observed = observeProtectedEnrollmentRows()) {
            ObservedProtectedEnrollmentRows.Corrupt ->
                error("Protected enrollment fixture is not structurally readable")
            is ObservedProtectedEnrollmentRows.Valid -> observed.rows
        }
    }

internal abstract class RoomPersistenceTestBase {
    protected lateinit var context: Context

    private val databases = mutableListOf<WtoAgentDatabase>()
    private val databaseNames = mutableSetOf<String>()

    @Before
    fun configureRoomTestContext() {
        context = ApplicationProvider.getApplicationContext()
    }

    @After
    fun closeRoomTestDatabases() {
        databases.asReversed().forEach { database ->
            try {
                database.close()
            } catch (_: Exception) {
                // Tests still remove only their own generated database files.
            }
        }
        databaseNames.forEach(::removeTestDatabaseFiles)
        databases.clear()
        databaseNames.clear()
    }

    protected fun newDatabaseName(@Suppress("UNUSED_PARAMETER") prefix: String): String =
        "r${databaseSequence.incrementAndGet()}.db"

    protected fun openDatabase(name: String = newDatabaseName("wto-room-test")): WtoAgentDatabase {
        databaseNames += name
        return WtoAgentDatabase.build(context, name).also(databases::add)
    }

    protected fun openInMemoryDatabase(): WtoAgentDatabase =
        Room
            .inMemoryDatabaseBuilder(context, WtoAgentDatabase::class.java)
            .build()
            .also(databases::add)

    protected fun reopenDatabase(name: String): WtoAgentDatabase =
        WtoAgentDatabase.build(context, name).also(databases::add)

    protected fun repository(database: WtoAgentDatabase): LocalStateRepository =
        RoomLocalStateRepository(WtoAgentDatabaseProvider { database })

    protected fun protectedRepository(
        database: WtoAgentDatabase,
    ): ProtectedEnrollmentRepository =
        RoomProtectedEnrollmentRepository(WtoAgentDatabaseProvider { database })

    protected fun databaseFile(name: String): File = File(context.noBackupFilesDir, name)

    protected fun removeTestDatabaseFiles(name: String) {
        listOf(name, "$name-wal", "$name-shm", "$name-journal").forEach { fileName ->
            try {
                File(context.noBackupFilesDir, fileName).delete()
            } catch (_: SecurityException) {
                // Test cleanup must not hide the preceding assertion result.
            }
        }
    }

    private companion object {
        val databaseSequence = AtomicInteger()
    }
}
