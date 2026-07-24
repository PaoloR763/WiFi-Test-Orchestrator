package com.wifitestorchestrator.agent.data.enrollment.coordination

import com.wifitestorchestrator.agent.data.enrollment.EnrollmentCall
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentClient
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentResult
import com.wifitestorchestrator.agent.data.enrollment.TEST_CORRELATION_ID
import com.wifitestorchestrator.agent.data.enrollment.TEST_CREDENTIAL
import com.wifitestorchestrator.agent.data.enrollment.TEST_ENROLLMENT_TOKEN
import com.wifitestorchestrator.agent.data.enrollment.TEST_IDEMPOTENCY_KEY
import com.wifitestorchestrator.agent.data.enrollment.TEST_INSTALLATION_ID
import com.wifitestorchestrator.agent.data.enrollment.validValue
import com.wifitestorchestrator.agent.data.persistence.PersistProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentPreflightResult
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentRepository
import com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentWrite
import com.wifitestorchestrator.agent.data.persistence.ReadProtectedEnrollmentResult
import com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment
import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionInspection
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtectionPreparation
import com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectCredentialResult
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelope
import com.wifitestorchestrator.agent.domain.credential.protection.ProtectedCredentialEnvelopeCreationResult
import com.wifitestorchestrator.agent.domain.credential.protection.UseDecryptedCredentialResult
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.enrollment.BackendEnrollmentAcceptance
import com.wifitestorchestrator.agent.domain.enrollment.CredentialDeliveryState
import com.wifitestorchestrator.agent.domain.enrollment.CredentialMetadata
import com.wifitestorchestrator.agent.domain.enrollment.CredentialVersion
import com.wifitestorchestrator.agent.domain.enrollment.DeliveredCredential
import com.wifitestorchestrator.agent.domain.enrollment.EnrollmentToken
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.identity.BackendAgentIdentity
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.DeviceId
import com.wifitestorchestrator.agent.domain.identity.IdempotencyKey
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

internal const val SECOND_ATTEMPT_TOKEN =
    "wto_enr_1.30000000-0000-4000-8000-000000000002." +
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
internal const val SECOND_IDEMPOTENCY_KEY = "30000000-0000-4000-8000-000000000001"
internal const val SECOND_CORRELATION_ID = "corr-c07-second"
internal const val TEST_AGENT_ID = "20000000-0000-4000-8000-000000000005"
internal const val TEST_DEVICE_ID = "20000000-0000-4000-8000-000000000004"
internal const val TEST_CREDENTIAL_ID = "10000000-0000-4000-8000-000000000001"
internal val TEST_REPORTED_AT: Instant = Instant.parse("2026-07-12T12:00:00Z")
internal val TEST_SERVER_RECEIVED_AT: Instant = Instant.parse("2026-07-12T12:00:01Z")
internal val TEST_EXPIRES_AT: Instant = Instant.parse("2026-10-10T12:00:01Z")

internal fun validAttempt(
    token: String = TEST_ENROLLMENT_TOKEN,
    idempotencyKey: String = TEST_IDEMPOTENCY_KEY,
    correlationId: String = TEST_CORRELATION_ID,
    reportedAt: Instant = TEST_REPORTED_AT,
): EnrollmentAttempt {
    val result =
        EnrollmentAttempt.create(
            serverConfiguration = testServerConfiguration(),
            localIdentity = testLocalIdentity(),
            idempotencyKey = validValue(IdempotencyKey.parse(idempotencyKey)),
            correlationId = validValue(CorrelationId.parse(correlationId)),
            enrollmentToken = validValue(EnrollmentToken.parse(token)),
            displayName = "Synthetic C07 agent",
            platformVersion = "36",
            agentVersion = validValue(AgentVersion.parse("0.1.0")),
            agentReportedAt = reportedAt,
        )
    return (result as EnrollmentAttemptCreationResult.Ready).attempt
}

internal fun secondAttempt(): EnrollmentAttempt =
    validAttempt(
        token = SECOND_ATTEMPT_TOKEN,
        idempotencyKey = SECOND_IDEMPOTENCY_KEY,
        correlationId = SECOND_CORRELATION_ID,
    )

internal fun testLocalIdentity(): LocalInstallationIdentity =
    LocalInstallationIdentity(validValue(InstallationId.parse(TEST_INSTALLATION_ID)))

internal fun testServerConfiguration(): ServerConfiguration =
    ServerConfiguration(validValue(ServerBaseUrl.parse("https://example.test/Tenant/")))

internal fun testBackendIdentity(): BackendAgentIdentity =
    BackendAgentIdentity(
        agentId = validValue(AgentId.parse(TEST_AGENT_ID)),
        deviceId = validValue(DeviceId.parse(TEST_DEVICE_ID)),
    )

internal fun testCredentialMetadata(
    issuedAt: Instant = TEST_SERVER_RECEIVED_AT,
    expiresAt: Instant = TEST_EXPIRES_AT,
    state: CredentialDeliveryState = CredentialDeliveryState.ACTIVE,
): CredentialMetadata =
    validValue(
        CredentialMetadata.create(
            credentialId = validValue(CredentialId.parse(TEST_CREDENTIAL_ID)),
            version = validValue(CredentialVersion.from(1)),
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            deliveryState = state,
        ),
    )

internal fun testDeliveredCredential(
    metadata: CredentialMetadata = testCredentialMetadata(),
): DeliveredCredential =
    validValue(
        DeliveredCredential.create(
            metadata = metadata,
            secret = validValue(AgentCredentialSecret.parse(TEST_CREDENTIAL)),
        ),
    )

internal fun testAcceptance(
    attempt: EnrollmentAttempt,
    localIdentity: LocalInstallationIdentity = attempt.expectedLocalIdentity,
    metadata: CredentialMetadata = testCredentialMetadata(),
    serverReceivedAt: Instant = TEST_SERVER_RECEIVED_AT,
    protocolVersion: ProtocolVersion = ProtocolVersion.CURRENT,
): BackendEnrollmentAcceptance =
    BackendEnrollmentAcceptance(
        localIdentity = localIdentity,
        backendIdentity = testBackendIdentity(),
        deliveredCredential = testDeliveredCredential(metadata),
        serverReceivedAt = serverReceivedAt,
        protocolVersion = protocolVersion,
    )

internal fun acceptedResult(
    attempt: EnrollmentAttempt,
    acceptance: BackendEnrollmentAcceptance = testAcceptance(attempt),
): EnrollmentResult =
    EnrollmentResult.Accepted(
        acceptance = acceptance,
        correlationId = attempt.command.correlationId,
    )

internal fun testEnvelope(
    metadata: CredentialMetadata = testCredentialMetadata(),
    nonceByte: Byte = 0x31,
    sealedByte: Byte = 0x42,
): ProtectedCredentialEnvelope {
    val result =
        ProtectedCredentialEnvelope.create(
            cryptoVersion = 1,
            keyAlias = "com.wifitestorchestrator.agent.credential.aead.v1",
            credentialId = metadata.credentialId,
            credentialVersion = metadata.version,
            nonce = ByteArray(12) { nonceByte },
            sealedCredential = ByteArray(105) { sealedByte },
        )
    return (result as ProtectedCredentialEnvelopeCreationResult.Valid).envelope
}

internal fun storedEnrollment(
    attempt: EnrollmentAttempt,
    metadata: CredentialMetadata = testCredentialMetadata(),
    envelope: ProtectedCredentialEnvelope = testEnvelope(metadata),
): StoredProtectedEnrollment =
    StoredProtectedEnrollment(
        localIdentity = attempt.expectedLocalIdentity,
        serverConfiguration = attempt.expectedServerConfiguration,
        backendIdentity = testBackendIdentity(),
        protocolVersion = ProtocolVersion.CURRENT,
        serverReceivedAt = TEST_SERVER_RECEIVED_AT,
        credentialMetadata = metadata,
        protectedCredential = envelope,
    )

internal class EventLog {
    private val events = Collections.synchronizedList(mutableListOf<String>())

    fun add(event: String) {
        events += event
    }

    fun snapshot(): List<String> = synchronized(events) { events.toList() }
}

internal class FakeEnrollmentCall(
    private val events: EventLog,
    var action: () -> EnrollmentResult,
) : EnrollmentCall {
    val executeCount = AtomicInteger(0)
    val cancelCount = AtomicInteger(0)
    var cancelAction: () -> Unit = {}

    override val isCanceled: Boolean
        get() = cancelCount.get() > 0

    override fun execute(): EnrollmentResult {
        executeCount.incrementAndGet()
        events.add("execute")
        return action()
    }

    override fun cancel() {
        cancelCount.incrementAndGet()
        events.add("cancel")
        cancelAction()
    }
}

internal class FakeEnrollmentClient(
    private val events: EventLog,
    var call: FakeEnrollmentCall,
) : EnrollmentClient {
    val newCallCount = AtomicInteger(0)

    override fun newCall(
        command: com.wifitestorchestrator.agent.data.enrollment.EnrollmentCommand,
    ): EnrollmentCall {
        newCallCount.incrementAndGet()
        events.add("newCall")
        return call
    }
}

internal class FakeProtectedEnrollmentRepository(
    private val events: EventLog,
) : ProtectedEnrollmentRepository {
    val preflightCount = AtomicInteger(0)
    val readCount = AtomicInteger(0)
    val persistCount = AtomicInteger(0)
    var preflightAction: suspend () -> ProtectedEnrollmentPreflightResult = {
        ProtectedEnrollmentPreflightResult.Absent
    }
    var readAction: suspend () -> ReadProtectedEnrollmentResult = {
        ReadProtectedEnrollmentResult.Absent
    }
    var persistAction: suspend (ProtectedEnrollmentWrite) ->
        PersistProtectedEnrollmentResult = {
            PersistProtectedEnrollmentResult.Written
        }

    override suspend fun preflight(
        expectedLocalIdentity: LocalInstallationIdentity,
        expectedServerConfiguration: ServerConfiguration,
    ): ProtectedEnrollmentPreflightResult {
        preflightCount.incrementAndGet()
        events.add("preflight")
        return preflightAction()
    }

    override suspend fun read(): ReadProtectedEnrollmentResult {
        readCount.incrementAndGet()
        events.add("read")
        return readAction()
    }

    override suspend fun persist(
        write: ProtectedEnrollmentWrite,
    ): PersistProtectedEnrollmentResult {
        persistCount.incrementAndGet()
        events.add("persist")
        return persistAction(write)
    }
}

internal class FakeCredentialProtector(
    private val events: EventLog,
) : CredentialProtector {
    val inspectCount = AtomicInteger(0)
    val prepareCount = AtomicInteger(0)
    val protectCount = AtomicInteger(0)
    var inspectAction: () -> CredentialProtectionInspection = {
        CredentialProtectionInspection.Compatible(
            com.wifitestorchestrator.agent.domain.credential.protection
                .CredentialKeySecurityLevel.TRUSTED_ENVIRONMENT,
        )
    }
    var prepareAction: () -> CredentialProtectionPreparation = {
        CredentialProtectionPreparation.AlreadyCompatible
    }
    var protectAction: (DeliveredCredential) -> ProtectCredentialResult = {
        ProtectCredentialResult.Protected(testEnvelope(it.metadata))
    }

    override fun inspect(): CredentialProtectionInspection {
        inspectCount.incrementAndGet()
        events.add("inspect")
        return inspectAction()
    }

    override fun prepare(): CredentialProtectionPreparation {
        prepareCount.incrementAndGet()
        events.add("prepare")
        return prepareAction()
    }

    override fun protect(credential: DeliveredCredential): ProtectCredentialResult {
        protectCount.incrementAndGet()
        events.add("protect")
        return protectAction(credential)
    }

    override fun useDecryptedCredential(
        envelope: ProtectedCredentialEnvelope,
        block: (AgentCredentialSecret) -> Unit,
    ): UseDecryptedCredentialResult =
        error("C07 never decrypts an existing credential")
}

internal class CoordinatorFixture(
    val dispatcher: CoroutineDispatcher = Dispatchers.Default,
    val guard: ProcessEnrollmentGuard = ProcessEnrollmentGuard(),
) {
    val events = EventLog()
    val attempt = validAttempt()
    val call =
        FakeEnrollmentCall(events) {
            acceptedResult(attempt)
        }
    val client = FakeEnrollmentClient(events, call)
    val repository = FakeProtectedEnrollmentRepository(events)
    val protector = FakeCredentialProtector(events)

    fun coordinator(): EnrollmentCoordinator =
        EnrollmentCoordinatorFactory.createForTesting(
            enrollmentClient = client,
            protectedEnrollmentRepository = repository,
            credentialProtector = protector,
            blockingDispatcher = dispatcher,
            processGuard = guard,
        )
}

internal fun EnrollmentAttempt.frozenFingerprint(): List<String> {
    return listOf(
        attemptId.toString(),
        System.identityHashCode(command).toString(),
        System.identityHashCode(command.enrollmentToken).toString(),
        command.idempotencyKey.toString(),
        command.correlationId.toString(),
        command.agentReportedAt,
        command.localIdentity.toString(),
        expectedServerConfiguration.toString(),
    )
}
