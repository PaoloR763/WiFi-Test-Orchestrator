package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.enrollment.EnrollmentToken
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.identity.IdempotencyKey
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import java.io.Closeable
import java.time.Instant
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Headers.Companion.headersOf
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate

internal const val TEST_CORRELATION_ID = "corr-c03-123"
internal const val TEST_IDEMPOTENCY_KEY = "20000000-0000-4000-8000-000000000001"
internal const val TEST_INSTALLATION_ID = "20000000-0000-4000-8000-000000000003"
internal const val TEST_ENROLLMENT_TOKEN =
    "wto_enr_1.20000000-0000-4000-8000-000000000002." +
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
internal const val TEST_CREDENTIAL =
    "wto_ac_1.10000000-0000-4000-8000-000000000001." +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

internal val validSuccessJson =
    """
    {
      "schema_version": "1.0.0",
      "device_id": "20000000-0000-4000-8000-000000000004",
      "agent_id": "20000000-0000-4000-8000-000000000005",
      "protocol_version": "1.0.0",
      "server_received_at": "2026-07-12T12:00:01Z",
      "credential": {
        "schema_version": "1.0.0",
        "credential_id": "10000000-0000-4000-8000-000000000001",
        "credential_version": 1,
        "credential": "$TEST_CREDENTIAL",
        "issued_at": "2026-07-12T12:00:01Z",
        "expires_at": "2026-10-10T12:00:01Z",
        "state": "active"
      }
    }
    """.trimIndent()

internal fun validErrorJson(
    correlationId: String = TEST_CORRELATION_ID,
    code: String = "enrollment_failed",
    details: String = "null",
): String =
    """
    {
      "schema_version": "1.0.0",
      "error": {
        "code": "$code",
        "message": "Synthetic failure.",
        "details": $details,
        "correlation_id": "$correlationId"
      }
    }
    """.trimIndent()

internal fun readyCommand(
    baseUrl: String = "https://example.test/Tenant/",
    displayName: String? = "Synthetic Android agent",
    platformVersion: String? = "36",
    agentVersion: AgentVersion? = validValue(AgentVersion.parse("0.1.0")),
    reportedAt: Instant? = Instant.parse("2026-07-12T12:00:00Z"),
): EnrollmentCommand {
    val result = commandCreationResult(baseUrl, displayName, platformVersion, agentVersion, reportedAt)
    return when (result) {
        is EnrollmentCommandCreationResult.Ready -> result.command
        is EnrollmentCommandCreationResult.Invalid -> error("Synthetic command is invalid")
    }
}

internal fun commandCreationResult(
    baseUrl: String = "https://example.test/Tenant/",
    displayName: String? = "Synthetic Android agent",
    platformVersion: String? = "36",
    agentVersion: AgentVersion? = validValue(AgentVersion.parse("0.1.0")),
    reportedAt: Instant? = Instant.parse("2026-07-12T12:00:00Z"),
): EnrollmentCommandCreationResult =
    EnrollmentCommand.create(
        serverConfiguration = ServerConfiguration(validValue(ServerBaseUrl.parse(baseUrl))),
        localIdentity =
            LocalInstallationIdentity(validValue(InstallationId.parse(TEST_INSTALLATION_ID))),
        idempotencyKey = validValue(IdempotencyKey.parse(TEST_IDEMPOTENCY_KEY)),
        correlationId = validValue(CorrelationId.parse(TEST_CORRELATION_ID)),
        enrollmentToken = validValue(EnrollmentToken.parse(TEST_ENROLLMENT_TOKEN)),
        displayName = displayName,
        platformVersion = platformVersion,
        agentVersion = agentVersion,
        agentReportedAt = reportedAt,
    )

internal fun jsonResponse(
    statusCode: Int,
    body: String,
    correlationId: String = TEST_CORRELATION_ID,
    contentType: String = "application/json",
): MockResponse =
    MockResponse(
        code = statusCode,
        headers =
            headersOf(
                "Content-Type",
                contentType,
                "X-Correlation-ID",
                correlationId,
            ),
        body = body,
    )

internal class TlsMockServer : Closeable {
    private val heldCertificate =
        HeldCertificate
            .Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .build()
    private val serverCertificates =
        HandshakeCertificates.Builder().heldCertificate(heldCertificate).build()
    private val clientCertificates =
        HandshakeCertificates
            .Builder()
            .addTrustedCertificate(heldCertificate.certificate)
            .build()

    val server = MockWebServer()

    init {
        server.useHttps(serverCertificates.sslSocketFactory())
        server.start()
    }

    fun client(base: OkHttpClient = EnrollmentHttpClientPolicy.build()): EnrollmentClient =
        OkHttpEnrollmentClient(
            base
                .newBuilder()
                .sslSocketFactory(
                    clientCertificates.sslSocketFactory(),
                    clientCertificates.trustManager,
                ).build(),
        )

    fun command(path: String = "/Tenant/"): EnrollmentCommand =
        readyCommand(server.url(path).toString())

    override fun close() {
        server.close()
    }
}

internal fun <T : Any> validValue(result: ValidationResult<T>): T =
    when (result) {
        is Valid -> result.value
        is Invalid -> error("Synthetic fixture is invalid")
    }
