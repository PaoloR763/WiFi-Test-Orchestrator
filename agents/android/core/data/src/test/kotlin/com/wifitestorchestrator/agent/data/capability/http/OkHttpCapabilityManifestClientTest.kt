package com.wifitestorchestrator.agent.data.capability.http

import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestContract
import com.wifitestorchestrator.agent.data.capability.frozenManifest
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentHttpClientPolicy
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import com.wifitestorchestrator.agent.domain.error.Valid
import java.io.Closeable
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Handshake
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal class OkHttpCapabilityManifestClientTest {
    @Test
    fun `put sends exact pending bytes authenticated headers and no idempotency key`() {
        ManifestTlsServer().use { fixture ->
            val command = fixture.command()
            fixture.server.enqueue(fixture.validAck())

            val result =
                fixture.client.execute(
                    command,
                    credential(),
                    CredentialScopedHttpCancellation(),
                )
            val request = fixture.server.takeRequest()

            assertIs<CapabilityManifestHttpResult.Accepted>(result)
            assertEquals("PUT", request.method)
            assertEquals("/Tenant/api/v1/agents/self/capability-manifest", request.url.encodedPath)
            assertContentEquals(
                command.canonicalPayload,
                requireNotNull(request.body).utf8().encodeToByteArray(),
            )
            assertEquals("application/json", request.headers["Content-Type"])
            assertEquals("application/json", request.headers["Accept"])
            assertEquals("Bearer $CREDENTIAL", request.headers["Authorization"])
            assertEquals(COMMAND_TIMESTAMP, request.headers["X-WTO-Agent-Timestamp"])
            assertEquals(COMMAND_NONCE, request.headers["X-WTO-Agent-Nonce"])
            assertEquals("1.0.0", request.headers["X-WTO-Agent-Protocol"])
            assertEquals(CORRELATION_ID, request.headers["X-Correlation-ID"])
            assertNull(request.headers["Idempotency-Key"])
            assertNull(request.headers["Cookie"])
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun `all specified non 200 statuses retain pending outcome without automatic retry`() {
        ManifestTlsServer().use { fixture ->
            val expected =
                linkedMapOf(
                    401 to CapabilityManifestRejection.AUTHENTICATION_BLOCKED,
                    409 to CapabilityManifestRejection.CONFLICT,
                    413 to CapabilityManifestRejection.REQUEST_TOO_LARGE,
                    422 to CapabilityManifestRejection.CONTRACT_INCOMPATIBLE,
                    426 to CapabilityManifestRejection.CONTRACT_INCOMPATIBLE,
                    429 to CapabilityManifestRejection.RATE_LIMITED,
                    503 to CapabilityManifestRejection.SERVICE_UNAVAILABLE,
                )
            expected.keys.forEach { status ->
                fixture.server.enqueue(MockResponse.Builder().code(status).body("secret").build())
            }

            expected.values.forEach { reason ->
                val rejected =
                    assertIs<CapabilityManifestHttpResult.Rejected>(
                        fixture.client.execute(
                            fixture.command(),
                            credential(),
                            CredentialScopedHttpCancellation(),
                        ),
                    )
                assertEquals(reason, rejected.reason)
            }
            assertEquals(expected.size, fixture.server.requestCount)
        }
    }

    @Test
    fun `redirects are rejected and never followed`() {
        ManifestTlsServer().use { fixture ->
            fixture.server.enqueue(
                MockResponse
                    .Builder()
                    .code(307)
                    .addHeader("Location", fixture.server.url("/elsewhere"))
                    .build(),
            )

            val result =
                fixture.client.execute(
                    fixture.command(),
                    credential(),
                    CredentialScopedHttpCancellation(),
                )

            assertEquals(
                CapabilityManifestHttpResult.Rejected(CapabilityManifestRejection.REDIRECT),
                result,
            )
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun `ack correlation content type shape identity digest and timestamp are strict`() {
        ManifestTlsServer().use { fixture ->
            val invalidResponses =
                listOf(
                    fixture.validAck(correlation = "wrong"),
                    fixture.validAck(contentType = "text/plain"),
                    fixture.validAck(body = "{"),
                    fixture.validAck(
                        body = fixture.ackJson().replaceFirst(
                            "\"manifest_id\"",
                            "\"manifest_id\":\"${frozenManifest().manifestId}\",\"manifest_id_2\"",
                        ),
                    ),
                    fixture.validAck(body = fixture.ackJson().dropLast(1) + ",\"extra\":1}"),
                    fixture.validAck(
                        body = fixture.ackJson().replace("1.0.0", "2.0.0"),
                    ),
                    fixture.validAck(
                        body = fixture.ackJson().replace(
                            frozenManifest().manifestId,
                            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                        ),
                    ),
                    fixture.validAck(
                        body = fixture.ackJson().replace(
                            frozenManifest().canonicalDigest.lowercaseHex(),
                            "0".repeat(64),
                        ),
                    ),
                    fixture.validAck(
                        body = fixture.ackJson().replace(
                            "2026-07-25T12:00:03.456789123Z",
                            "not-a-timestamp",
                        ),
                    ),
                )
            invalidResponses.forEach(fixture.server::enqueue)
            fixture.server.enqueue(
                fixture.validAck().newBuilder()
                    .addHeader("X-Correlation-ID", CORRELATION_ID)
                    .build(),
            )

            repeat(invalidResponses.size + 1) {
                assertIs<CapabilityManifestHttpResult.InvalidAcknowledgement>(
                    fixture.client.execute(
                        fixture.command(),
                        credential(),
                        CredentialScopedHttpCancellation(),
                    ),
                )
            }
        }
    }

    @Test
    fun `duplicate ack key and oversized body fail closed`() {
        ManifestTlsServer().use { fixture ->
            val duplicate =
                fixture.ackJson().replace(
                    "\"schema_version\":\"1.0.0\"",
                    "\"schema_version\":\"1.0.0\",\"schema_version\":\"1.0.0\"",
                )
            fixture.server.enqueue(fixture.validAck(body = duplicate))
            fixture.server.enqueue(fixture.validAck(body = "x".repeat(65_537)))

            val duplicateResult =
                assertIs<CapabilityManifestHttpResult.InvalidAcknowledgement>(
                    fixture.client.execute(
                        fixture.command(),
                        credential(),
                        CredentialScopedHttpCancellation(),
                    ),
                )
            assertEquals(InvalidAcknowledgementReason.DUPLICATE_KEY, duplicateResult.reason)
            val oversized =
                assertIs<CapabilityManifestHttpResult.InvalidAcknowledgement>(
                    fixture.client.execute(
                        fixture.command(),
                        credential(),
                        CredentialScopedHttpCancellation(),
                    ),
                )
            assertEquals(InvalidAcknowledgementReason.BODY_TOO_LARGE, oversized.reason)
        }
    }

    @Test
    fun `cancellation relay forwards once clears references and suppresses cleanup`() {
        val relay = CredentialScopedHttpCancellation()
        var calls = 0
        val cleanup = IllegalStateException("cleanup")
        relay.register {
            calls += 1
            throw cleanup
        }

        relay.requestCancellation()
        relay.requestCancellation()
        val primary = IllegalArgumentException("primary")
        relay.attachCleanupFailure(primary)
        relay.clear()

        assertEquals(1, calls)
        assertTrue(relay.isCancellationRequested())
        assertContentEquals(arrayOf(cleanup), primary.suppressed)
        assertFalse(relay.toString().contains(CREDENTIAL))
    }

    private class ManifestTlsServer : Closeable {
        private val certificate =
            HeldCertificate.Builder()
                .commonName("localhost")
                .addSubjectAlternativeName("localhost")
                .build()
        private val serverCertificates =
            HandshakeCertificates.Builder().heldCertificate(certificate).build()
        private val clientCertificates =
            HandshakeCertificates.Builder()
                .addTrustedCertificate(certificate.certificate)
                .build()
        val server = MockWebServer()
        val client: OkHttpCapabilityManifestClient

        init {
            server.useHttps(serverCertificates.sslSocketFactory())
            server.start()
            val transport: OkHttpClient =
                EnrollmentHttpClientPolicy.shared
                    .newBuilder()
                    .sslSocketFactory(
                        clientCertificates.sslSocketFactory(),
                        clientCertificates.trustManager,
                    ).build()
            client = OkHttpCapabilityManifestClient(transport)
        }

        fun command(): CapabilityManifestHttpCommand {
            val frozen = frozenManifest()
            return CapabilityManifestHttpCommand(
                endpointUrl =
                    server.url("/Tenant/api/v1/agents/self/capability-manifest").toString(),
                expectedManifestId = frozen.manifestId,
                canonicalPayload = frozen.copyCanonicalPayload(),
                timestamp = COMMAND_TIMESTAMP,
                nonce = COMMAND_NONCE,
                correlationId = CORRELATION_ID,
            )
        }

        fun ackJson(): String {
            val frozen = frozenManifest()
            return """{"schema_version":"1.0.0","manifest_id":"${frozen.manifestId}","manifest_digest":"${frozen.canonicalDigest.lowercaseHex()}","server_received_at":"2026-07-25T12:00:03.456789123Z"}"""
        }

        fun validAck(
            body: String = ackJson(),
            correlation: String = CORRELATION_ID,
            contentType: String = "application/json",
        ): MockResponse =
            MockResponse
                .Builder()
                .code(200)
                .addHeader("Content-Type", contentType)
                .addHeader("X-Correlation-ID", correlation)
                .body(body)
                .build()

        override fun close() {
            server.close()
        }
    }

    private companion object {
        const val CREDENTIAL =
            "wto_ac_1.77777777-7777-4777-8777-777777777777." +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        const val COMMAND_TIMESTAMP = "2026-07-25T12:00:02.123456789Z"
        const val COMMAND_NONCE = "AAECAwQFBgcICQoLDA0ODw"
        const val CORRELATION_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

        fun credential(): AgentCredentialSecret {
            val parsed = AgentCredentialSecret.parse(CREDENTIAL)
            check(parsed is Valid)
            return parsed.value
        }
    }
}
