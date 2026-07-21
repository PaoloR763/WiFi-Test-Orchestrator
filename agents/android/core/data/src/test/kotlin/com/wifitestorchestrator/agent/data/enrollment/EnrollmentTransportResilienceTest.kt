package com.wifitestorchestrator.agent.data.enrollment

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.UnknownHostException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.SocketEffect
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer

class EnrollmentTransportResilienceTest {
    @Test
    fun validGzipIsLimitedAfterTransparentDecompression() {
        TlsMockServer().use { fixture ->
            val exact = validSuccessJson + " ".repeat(65_536 - validSuccessJson.encodeToByteArray().size)
            val oversized = exact + " "
            fixture.server.enqueue(gzipResponse(gzip(exact.encodeToByteArray())))
            fixture.server.enqueue(gzipResponse(gzip(oversized.encodeToByteArray())))

            assertIs<EnrollmentResult.Accepted>(
                fixture.client().newCall(fixture.command()).execute(),
            )
            val failed =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            assertEquals(EnrollmentFailureReason.RESPONSE_TOO_LARGE, failed.reason)
            assertEquals(2, fixture.server.requestCount)
        }
    }

    @Test
    fun corruptAndTruncatedGzipFailClosedWithoutRetry() {
        TlsMockServer().use { fixture ->
            val encoded = gzip(validSuccessJson.encodeToByteArray())
            val corrupt =
                encoded.copyOf().also { bytes ->
                    bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
                }
            val truncated = encoded.copyOf(encoded.size - 5)
            fixture.server.enqueue(gzipResponse(corrupt))
            fixture.server.enqueue(gzipResponse(truncated))

            repeat(2) {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.INCOMPLETE_RESPONSE, failed.reason)
            }
            assertEquals(2, fixture.server.requestCount)
        }
    }

    @Test
    fun disconnectDuringBodyIsIncompleteAndNeverRetried() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(
                MockResponse
                    .Builder()
                    .code(201)
                    .addHeader("Content-Type", "application/json")
                    .addHeader("X-Correlation-ID", TEST_CORRELATION_ID)
                    .body(validSuccessJson + " ".repeat(8_192))
                    .onResponseBody(SocketEffect.CloseSocket())
                    .build(),
            )

            val failed =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            assertTrue(
                failed.reason in
                    setOf(
                        EnrollmentFailureReason.INCOMPLETE_RESPONSE,
                        EnrollmentFailureReason.IO,
                    ),
            )
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun readAndWholeCallTimeoutsAreClassifiedWithoutRetry() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(
                jsonResponse(201, validSuccessJson)
                    .newBuilder()
                    .bodyDelay(750, TimeUnit.MILLISECONDS)
                    .build(),
            )
            fixture.server.enqueue(
                jsonResponse(201, validSuccessJson)
                    .newBuilder()
                    .headersDelay(750, TimeUnit.MILLISECONDS)
                    .build(),
            )
            val readTimeoutClient =
                EnrollmentHttpClientPolicy
                    .build()
                    .newBuilder()
                    .readTimeout(100, TimeUnit.MILLISECONDS)
                    .callTimeout(2, TimeUnit.SECONDS)
                    .build()
            val callTimeoutClient =
                EnrollmentHttpClientPolicy
                    .build()
                    .newBuilder()
                    .readTimeout(2, TimeUnit.SECONDS)
                    .callTimeout(100, TimeUnit.MILLISECONDS)
                    .build()

            val readFailure =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client(readTimeoutClient).newCall(fixture.command()).execute(),
                )
            val callFailure =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client(callTimeoutClient).newCall(fixture.command()).execute(),
                )

            assertEquals(EnrollmentFailureReason.TIMEOUT, readFailure.reason)
            assertEquals(EnrollmentFailureReason.TIMEOUT, callFailure.reason)
            assertTrue(fixture.server.requestCount <= 2)
        }
    }

    @Test
    fun cancellationDelegatesToTheRealCallAndDoesNotClaimNonProcessing() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(
                jsonResponse(201, validSuccessJson)
                    .newBuilder()
                    .bodyDelay(5, TimeUnit.SECONDS)
                    .build(),
            )
            val call = fixture.client().newCall(fixture.command())
            val executor = Executors.newSingleThreadExecutor()
            try {
                val result = executor.submit<EnrollmentResult> { call.execute() }
                assertNotNull(fixture.server.takeRequest(2, TimeUnit.SECONDS))
                call.cancel()

                val failed = assertIs<EnrollmentResult.Failed>(result.get(2, TimeUnit.SECONDS))
                assertEquals(EnrollmentFailureReason.CANCELLED, failed.reason)
                assertTrue(call.isCanceled)
                assertTrue(fixture.server.requestCount <= 1)
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test
    fun dnsConnectionAndGenericIoFailuresHaveClosedCategories() {
        val dnsClient =
            EnrollmentHttpClientPolicy
                .build()
                .newBuilder()
                .dns(Dns { throw UnknownHostException() })
                .build()
        val dnsFailure =
            assertIs<EnrollmentResult.Failed>(
                OkHttpEnrollmentClient(dnsClient)
                    .newCall(readyCommand("https://dns.invalid/"))
                    .execute(),
            )
        assertEquals(EnrollmentFailureReason.DNS, dnsFailure.reason)

        val closedPort = ServerSocket(0).use { it.localPort }
        val connectionClient =
            EnrollmentHttpClientPolicy
                .build()
                .newBuilder()
                .connectTimeout(500, TimeUnit.MILLISECONDS)
                .callTimeout(1, TimeUnit.SECONDS)
                .build()
        val connectionFailure =
            assertIs<EnrollmentResult.Failed>(
                OkHttpEnrollmentClient(connectionClient)
                    .newCall(readyCommand("https://localhost:$closedPort/"))
                    .execute(),
            )
        assertEquals(EnrollmentFailureReason.CONNECTION, connectionFailure.reason)

        val ioClient =
            EnrollmentHttpClientPolicy
                .build()
                .newBuilder()
                .addInterceptor { throw IOException() }
                .build()
        val ioFailure =
            assertIs<EnrollmentResult.Failed>(
                OkHttpEnrollmentClient(ioClient)
                    .newCall(readyCommand("https://io.invalid/"))
                    .execute(),
            )
        assertEquals(EnrollmentFailureReason.IO, ioFailure.reason)
    }

    @Test
    fun systemTrustRejectsTheEphemeralTestCertificate() {
        val heldCertificate =
            HeldCertificate
                .Builder()
                .commonName("localhost")
                .addSubjectAlternativeName("localhost")
                .build()
        val serverCertificates =
            HandshakeCertificates.Builder().heldCertificate(heldCertificate).build()
        MockWebServer().use { server ->
            server.useHttps(serverCertificates.sslSocketFactory())
            server.start()
            server.enqueue(jsonResponse(201, validSuccessJson))

            val failed =
                assertIs<EnrollmentResult.Failed>(
                    OkHttpEnrollmentClient(EnrollmentHttpClientPolicy.build())
                        .newCall(readyCommand(server.url("/").toString()))
                        .execute(),
                )
            assertEquals(EnrollmentFailureReason.TLS, failed.reason)
            assertTrue(server.requestCount <= 1)
        }
    }

    @Test
    fun defaultHostnameVerifierRejectsATrustedCertificateForAnotherHost() {
        val heldCertificate =
            HeldCertificate
                .Builder()
                .commonName("wrong.example")
                .addSubjectAlternativeName("wrong.example")
                .build()
        val serverCertificates =
            HandshakeCertificates.Builder().heldCertificate(heldCertificate).build()
        val clientCertificates =
            HandshakeCertificates
                .Builder()
                .addTrustedCertificate(heldCertificate.certificate)
                .build()
        MockWebServer().use { server ->
            server.useHttps(serverCertificates.sslSocketFactory())
            server.start()
            server.enqueue(jsonResponse(201, validSuccessJson))
            val client =
                EnrollmentHttpClientPolicy
                    .build()
                    .newBuilder()
                    .sslSocketFactory(
                        clientCertificates.sslSocketFactory(),
                        clientCertificates.trustManager,
                    ).build()

            val failed =
                assertIs<EnrollmentResult.Failed>(
                    OkHttpEnrollmentClient(client)
                        .newCall(readyCommand(server.url("/").toString()))
                        .execute(),
                )
            assertEquals(EnrollmentFailureReason.TLS, failed.reason)
            assertTrue(server.requestCount <= 1)
        }
    }

    private fun gzipResponse(bytes: ByteArray): MockResponse =
        MockResponse
            .Builder()
            .code(201)
            .addHeader("Content-Type", "application/json")
            .addHeader("Content-Encoding", "gzip")
            .addHeader("X-Correlation-ID", TEST_CORRELATION_ID)
            .body(Buffer().write(bytes))
            .build()

    private fun gzip(bytes: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        GZIPOutputStream(output).use { it.write(bytes) }
        return output.toByteArray()
    }
}
