package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentCredentialDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentPlatformDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import com.wifitestorchestrator.agent.contracts.enrollment.CredentialDeliveryStateDto
import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.enrollment.EnrollmentToken
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import com.wifitestorchestrator.agent.domain.identity.IdempotencyKey
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import java.security.MessageDigest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import okhttp3.HttpUrl.Companion.toHttpUrl

class EnrollmentMappingTest {
    @Test
    fun validCommandMapsToExactAndroidWireRequest() {
        val command = readyCommand()
        val dto = EnrollmentRequestMapper.map(command)
        val encoded = requireNotNull(EnrollmentJson.encodeRequest(dto))
        val validated = requireNotNull(EnrollmentJson.encodeValidatedRequest(command))
        val expected =
            "{" +
                "\"schema_version\":\"1.0.0\"," +
                "\"idempotency_key\":\"$TEST_IDEMPOTENCY_KEY\"," +
                "\"enrollment_token\":\"$TEST_ENROLLMENT_TOKEN\"," +
                "\"installation_id\":\"$TEST_INSTALLATION_ID\"," +
                "\"display_name\":\"Synthetic Android agent\"," +
                "\"platform\":\"android\"," +
                "\"platform_version\":\"36\"," +
                "\"agent_version\":\"0.1.0\"," +
                "\"protocol_min_version\":\"1.0.0\"," +
                "\"protocol_max_version\":\"1.0.0\"," +
                "\"agent_reported_at\":\"2026-07-12T12:00:00Z\"}"

        assertTrue(encoded.sha256().contentEquals(expected.encodeToByteArray().sha256()))
        assertTrue(validated.sha256().contentEquals(expected.encodeToByteArray().sha256()))
        assertTrue(validated.size <= 32 * 1024)
        assertEquals(AgentPlatformDto.ANDROID, dto.platform)
        assertEquals(dto.idempotencyKey, TEST_IDEMPOTENCY_KEY)
    }

    @Test
    fun unknownRequiredValuesFailBeforeACommandExists() {
        val values =
            listOf(
                commandResult(serverConfiguration = null),
                commandResult(localIdentity = null),
                commandResult(idempotencyKey = null),
                commandResult(correlationId = null),
                commandResult(enrollmentToken = null),
                commandResult(displayName = null),
                commandResult(platformVersion = null),
                commandResult(agentVersion = null),
                commandResult(reportedAt = null),
            )

        values.forEach { value ->
            val invalid = assertIs<EnrollmentCommandCreationResult.Invalid>(value)
            assertEquals(EnrollmentCommandFailure.INVALID_LOCAL_REQUEST, invalid.reason)
        }
    }

    @Test
    fun callerProvidedContractLiteralsAndWhitespaceArePreserved() {
        val cases =
            listOf(
                Triple("unknown", "0", Instant.EPOCH),
                Triple("UNKNOWN", "unknown", Instant.parse("2026-07-12T12:00:00Z")),
                Triple(" ", " ", Instant.parse("2026-07-12T12:00:00Z")),
            )

        cases.forEach { (displayName, platformVersion, reportedAt) ->
            val ready =
                assertIs<EnrollmentCommandCreationResult.Ready>(
                    commandResult(
                        displayName = displayName,
                        platformVersion = platformVersion,
                        reportedAt = reportedAt,
                    ),
                )
            val dto = EnrollmentRequestMapper.map(ready.command)

            assertEquals(displayName, dto.displayName)
            assertEquals(platformVersion, dto.platformVersion)
            assertEquals(reportedAt.toString(), dto.agentReportedAt)
        }
    }

    @Test
    fun emptyAndOverlongStringsFailWithoutFallback() {
        listOf(
            commandResult(displayName = ""),
            commandResult(displayName = "x".repeat(129)),
            commandResult(platformVersion = ""),
            commandResult(platformVersion = "x".repeat(65)),
        ).forEach { value ->
            val invalid = assertIs<EnrollmentCommandCreationResult.Invalid>(value)
            assertEquals(EnrollmentCommandFailure.INVALID_LOCAL_REQUEST, invalid.reason)
        }
    }

    @Test
    fun requestTimestampRenderingRejectsExtendedYears() {
        listOf(
            Instant.parse("+10000-01-01T00:00:00Z"),
            Instant.parse("-0001-01-01T00:00:00Z"),
        ).forEach { reportedAt ->
            val invalid =
                assertIs<EnrollmentCommandCreationResult.Invalid>(
                    commandResult(reportedAt = reportedAt),
                )
            assertEquals(EnrollmentCommandFailure.INVALID_LOCAL_REQUEST, invalid.reason)
        }
    }

    @Test
    fun endpointPreservesRootNestedPathCaseAndPort() {
        assertEquals(
            "https://example.test/api/v1/agent-enrollments",
            readyCommand("https://example.test/").endpointUrl,
        )
        assertEquals(
            "https://example.test:8443/Tenant/Lab/api/v1/agent-enrollments",
            readyCommand("https://example.test:8443/Tenant/Lab/").endpointUrl,
        )
    }

    @Test
    fun exactEnrollmentEndpointSuffixIsRejected() {
        listOf(
            "https://example.test/api/v1/agent-enrollments",
            "https://example.test/api/v1/agent-enrollments/",
            "https://example.test/Tenant/api/v1/agent-enrollments/",
        ).forEach { baseUrl ->
            val invalid =
                assertIs<EnrollmentCommandCreationResult.Invalid>(
                    commandResult(serverConfiguration = configuration(baseUrl)),
                )
            assertEquals(EnrollmentCommandFailure.INVALID_ENDPOINT, invalid.reason)
        }
    }

    @Test
    fun effectiveEndpointSuffixRecognizesLiteralAndPercentEncodedSegments() {
        listOf(
            "https://example.test/api/v1/agent-enrollments",
            "https://example.test/api/v1/agent-enrollments/",
            "https://example.test/Tenant/api/v1/agent-enrollments/",
            "https://example.test/%61pi/v1/agent-enrollments/",
            "https://example.test/api/%76%31/agent-enrollments/",
            "https://example.test/api/v1/agent%2Denrollments/",
            "https://example.test/api/v1/agent%2denrollments/",
            "https://example.test/api/v1/age%6Et-enrollments/",
            "https://example.test/api/v1/age%6et-enrollments/",
            "https://example.test/%61pi/%76%31/age%6et%2Denrollments/",
            "https://example.test/prefix//api/v1/agent-enrollments/",
        ).forEach { rawUrl ->
            assertTrue(rawUrl.toHttpUrl().hasEnrollmentEndpointSuffix(), rawUrl)
        }
    }

    @Test
    fun effectiveEndpointSuffixPreservesBoundariesAndAvoidsFalsePositives() {
        listOf(
            "https://example.test/api/v1/agent-enrollments-extra/",
            "https://example.test/api/v1/prefix-agent-enrollments/",
            "https://example.test/api/v1/",
            "https://example.test/v1/agent-enrollments/",
            "https://example.test/API/v1/agent-enrollments/",
            "https://example.test/root-api/v1/agent-enrollments/",
            "https://example.test/api/v1/agent%2Fenrollments/",
            "https://example.test/api/v1/agent%2fenrollments/",
            "https://example.test/api//v1/agent-enrollments/",
            "https://example.test/api/v1/agent-enrollments/extra/",
        ).forEach { rawUrl ->
            assertFalse(rawUrl.toHttpUrl().hasEnrollmentEndpointSuffix(), rawUrl)
        }
    }

    @Test
    fun partialSubstringAndDifferentCasePathsStillAppendTheEndpoint() {
        val cases =
            mapOf(
                "https://example.test/prefix/api/v1/" to
                    "https://example.test/prefix/api/v1/api/v1/agent-enrollments",
                "https://example.test/api/v1/agent-enrollments-extra/" to
                    "https://example.test/api/v1/agent-enrollments-extra/api/v1/agent-enrollments",
                "https://example.test/API/v1/agent-enrollments/" to
                    "https://example.test/API/v1/agent-enrollments/api/v1/agent-enrollments",
            )

        cases.forEach { (baseUrl, expected) ->
            val ready =
                assertIs<EnrollmentCommandCreationResult.Ready>(
                    commandResult(serverConfiguration = configuration(baseUrl)),
                )
            assertEquals(expected, ready.command.endpointUrl)
        }
    }

    @Test
    fun serverBaseUrlContinuesToRejectPercentEncoding() {
        assertIs<Invalid>(
            ServerBaseUrl.parse("https://example.test/%61pi/v1/agent-enrollments/"),
        )
    }

    @Test
    fun successfulDtoMapsToDomainAndPreservesLocalIdentity() {
        val localIdentity =
            LocalInstallationIdentity(validValue(InstallationId.parse(TEST_INSTALLATION_ID)))
        val mapped = EnrollmentResponseMapper.map(validResponse(), localIdentity)
        val acceptance = assertIs<EnrollmentDomainMappingResult.Valid>(mapped).value

        assertEquals(localIdentity, acceptance.localIdentity)
        assertEquals("20000000-0000-4000-8000-000000000004", acceptance.backendIdentity.deviceId.toString())
        assertEquals("20000000-0000-4000-8000-000000000005", acceptance.backendIdentity.agentId.toString())
        assertEquals("1.0.0", acceptance.protocolVersion.toString())
        assertEquals(Instant.parse("2026-07-12T12:00:01Z"), acceptance.serverReceivedAt)
        assertFalse(acceptance.toString().contains(TEST_CREDENTIAL))
    }

    @Test
    fun invalidCredentialWindowAndLocatorMismatchFailMapping() {
        val localIdentity =
            LocalInstallationIdentity(validValue(InstallationId.parse(TEST_INSTALLATION_ID)))
        val invalidWindow =
            validResponse(
                credential = validCredential(expiresAt = "2026-07-12T12:00:01Z"),
            )
        val mismatch =
            validResponse(
                credential =
                    validCredential(
                        credentialId = "20000000-0000-4000-8000-000000000011",
                    ),
            )

        assertIs<EnrollmentDomainMappingResult.Invalid>(
            EnrollmentResponseMapper.map(invalidWindow, localIdentity),
        )
        assertIs<EnrollmentDomainMappingResult.Invalid>(
            EnrollmentResponseMapper.map(mismatch, localIdentity),
        )
    }

    @Test
    fun credentialWindowUsesExactRepresentableFractionalInstants() {
        val localIdentity =
            LocalInstallationIdentity(validValue(InstallationId.parse(TEST_INSTALLATION_ID)))
        val equalAfterExactConversion =
            validResponse(
                credential =
                    validCredential(
                        issuedAt = "2026-07-12T12:00:01.1234567890Z",
                        expiresAt = "2026-07-12T12:00:01.12345678900Z",
                    ),
            )
        assertIs<EnrollmentDomainMappingResult.Invalid>(
            EnrollmentResponseMapper.map(equalAfterExactConversion, localIdentity),
        )

        val valid =
            validResponse(
                serverReceivedAt = "2026-07-12T12:00:01.12345678900Z",
                credential =
                    validCredential(
                        issuedAt = "2026-07-12T12:00:01.12345678900Z",
                        expiresAt = "2026-07-12T12:00:01.12345679000Z",
                    ),
            )
        val acceptance =
            assertIs<EnrollmentDomainMappingResult.Valid>(
                EnrollmentResponseMapper.map(valid, localIdentity),
            ).value

        assertEquals(
            Instant.parse("2026-07-12T12:00:01.123456789Z"),
            acceptance.serverReceivedAt,
        )
        assertEquals(
            Instant.parse("2026-07-12T12:00:01.123456789Z"),
            acceptance.deliveredCredential.metadata.issuedAt,
        )
        assertEquals(
            Instant.parse("2026-07-12T12:00:01.123456790Z"),
            acceptance.deliveredCredential.metadata.expiresAt,
        )
    }

    @Test
    fun sensitiveCommandAndCreationResultRemainRedacted() {
        val command = readyCommand()
        val rendered = command.toString()
        val ready = EnrollmentCommandCreationResult.Ready(command).toString()

        assertFalse(rendered.contains(TEST_ENROLLMENT_TOKEN))
        assertFalse(rendered.contains("example.test"))
        assertFalse(ready.contains(TEST_ENROLLMENT_TOKEN))
        assertTrue(rendered.contains("<redacted>"))
    }

    private fun commandResult(
        serverConfiguration: ServerConfiguration? =
            ServerConfiguration(
                validValue(ServerBaseUrl.parse("https://example.test/Tenant/")),
            ),
        localIdentity: LocalInstallationIdentity? =
            LocalInstallationIdentity(validValue(InstallationId.parse(TEST_INSTALLATION_ID))),
        idempotencyKey: IdempotencyKey? = validValue(IdempotencyKey.parse(TEST_IDEMPOTENCY_KEY)),
        correlationId: CorrelationId? = validValue(CorrelationId.parse(TEST_CORRELATION_ID)),
        enrollmentToken: EnrollmentToken? =
            validValue(EnrollmentToken.parse(TEST_ENROLLMENT_TOKEN)),
        displayName: String? = "Synthetic Android agent",
        platformVersion: String? = "36",
        agentVersion: AgentVersion? = validValue(AgentVersion.parse("0.1.0")),
        reportedAt: Instant? = Instant.parse("2026-07-12T12:00:00Z"),
    ): EnrollmentCommandCreationResult =
        EnrollmentCommand.create(
            serverConfiguration = serverConfiguration,
            localIdentity = localIdentity,
            idempotencyKey = idempotencyKey,
            correlationId = correlationId,
            enrollmentToken = enrollmentToken,
            displayName = displayName,
            platformVersion = platformVersion,
            agentVersion = agentVersion,
            agentReportedAt = reportedAt,
        )

    private fun validResponse(
        serverReceivedAt: String = "2026-07-12T12:00:01Z",
        credential: AgentCredentialDto = validCredential(),
    ): AgentRegistrationResponseDto =
        AgentRegistrationResponseDto(
            schemaVersion = "1.0.0",
            deviceId = "20000000-0000-4000-8000-000000000004",
            agentId = "20000000-0000-4000-8000-000000000005",
            protocolVersion = "1.0.0",
            serverReceivedAt = serverReceivedAt,
            credential = credential,
        )

    private fun validCredential(
        credentialId: String = "10000000-0000-4000-8000-000000000001",
        issuedAt: String = "2026-07-12T12:00:01Z",
        expiresAt: String = "2026-10-10T12:00:01Z",
    ): AgentCredentialDto =
        AgentCredentialDto(
            schemaVersion = "1.0.0",
            credentialId = credentialId,
            credentialVersion = 1,
            credential = TEST_CREDENTIAL,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            state = CredentialDeliveryStateDto.ACTIVE,
        )

    private fun configuration(baseUrl: String): ServerConfiguration =
        ServerConfiguration(validValue(ServerBaseUrl.parse(baseUrl)))
}

private fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)
