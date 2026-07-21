package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentEnrollmentContract
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mockwebserver3.MockResponse

class EnrollmentHttpTransportTest {
    @Test
    fun postUsesExactPathHeadersAndAndroidPayloadWithoutCredentials() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(jsonResponse(201, validSuccessJson))

            val result = fixture.client().newCall(fixture.command()).execute()
            val recorded = fixture.server.takeRequest()
            val body =
                EnrollmentJson.instance
                    .parseToJsonElement(requireNotNull(recorded.body).utf8())
                    .jsonObject

            assertIs<EnrollmentResult.Accepted>(result)
            assertEquals("POST", recorded.method)
            assertEquals("/Tenant/api/v1/agent-enrollments", recorded.url.encodedPath)
            assertEquals("application/json", recorded.headers["Content-Type"])
            assertEquals("application/json", recorded.headers["Accept"])
            assertTrue(recorded.headers[AgentEnrollmentContract.IDEMPOTENCY_HEADER] == TEST_IDEMPOTENCY_KEY)
            assertTrue(recorded.headers[AgentEnrollmentContract.CORRELATION_HEADER] == TEST_CORRELATION_ID)
            assertNull(recorded.headers["Authorization"])
            assertNull(recorded.headers["Cookie"])
            assertNull(recorded.headers["Proxy-Authorization"])
            assertEquals("android", body.getValue("platform").jsonPrimitive.content)
            assertEquals("1.0.0", body.getValue("schema_version").jsonPrimitive.content)
            assertTrue(
                body.getValue("idempotency_key").jsonPrimitive.content == TEST_IDEMPOTENCY_KEY,
            )
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun invalidTimestampIn201ResponseIsFailedNeverAccepted() {
        TlsMockServer().use { fixture ->
            val invalidResponse =
                validSuccessJson.replace(
                    "\"server_received_at\": \"2026-07-12T12:00:01Z\"",
                    "\"server_received_at\": \"+10000-01-01T00:00:00Z\"",
                )
            fixture.server.enqueue(jsonResponse(201, invalidResponse))

            val failed =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            assertEquals(EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS, failed.reason)
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun duplicateEndpointFailsBeforeAnHttpCallCanBeCreatedOrExecuted() {
        TlsMockServer().use { fixture ->
            val result =
                commandCreationResult(
                    fixture.server.url("/Tenant/api/v1/agent-enrollments/").toString(),
                )

            val invalid = assertIs<EnrollmentCommandCreationResult.Invalid>(result)
            assertEquals(EnrollmentCommandFailure.INVALID_ENDPOINT, invalid.reason)
            assertEquals(0, fixture.server.requestCount)
        }
    }

    @Test
    fun allNormativeErrorsMapByStatusOnlyWhenEnvelopeIsValid() {
        TlsMockServer().use { fixture ->
            val expected =
                listOf(
                    Triple(
                        401,
                        EnrollmentRejectionReason.AUTHENTICATION_TOKEN_OR_CLOCK_REJECTED,
                        "enrollment_failed",
                    ),
                    Triple(409, EnrollmentRejectionReason.CONFLICT, "resource_conflict"),
                    Triple(413, EnrollmentRejectionReason.REQUEST_TOO_LARGE, "payload_too_large"),
                    Triple(422, EnrollmentRejectionReason.CONTRACT_REJECTED, "validation_error"),
                    Triple(429, EnrollmentRejectionReason.RATE_LIMITED, "login_rate_limited"),
                    Triple(
                        503,
                        EnrollmentRejectionReason.SERVICE_UNAVAILABLE,
                        "dependency_unavailable",
                    ),
                )
            expected.forEach { (status, _, code) ->
                fixture.server.enqueue(jsonResponse(status, validErrorJson(code = code)))
            }

            expected.forEach { (status, reason, _) ->
                val result = fixture.client().newCall(fixture.command()).execute()
                val rejected = assertIs<EnrollmentResult.Rejected>(result)
                assertEquals(status, rejected.statusCode)
                assertEquals(reason, rejected.reason)
                assertEquals(TEST_CORRELATION_ID, rejected.correlationId.toString())
            }
            assertEquals(expected.size, fixture.server.requestCount)
        }
    }

    @Test
    fun invalidNormativeErrorBodyIsFailedNeverRejected() {
        TlsMockServer().use { fixture ->
            listOf(401, 409, 413, 422, 429, 503).forEach { status ->
                fixture.server.enqueue(jsonResponse(status, "{"))
            }

            repeat(6) {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.MALFORMED_JSON, failed.reason)
            }
            assertEquals(6, fixture.server.requestCount)
        }
    }

    @Test
    fun allUnspecifiedStatusesAreUnexpectedAndBodiesAreNotTrusted() {
        TlsMockServer().use { fixture ->
            val statuses = listOf(200, 202, 204, 400, 403, 404, 426, 500, 502, 504)
            statuses.forEach { status ->
                val response = MockResponse.Builder().code(status)
                if (status != 204) response.body("sensitive")
                fixture.server.enqueue(response.build())
            }

            statuses.forEach {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.UNEXPECTED_STATUS, failed.reason)
            }
            assertEquals(statuses.size, fixture.server.requestCount)
        }
    }

    @Test
    fun redirectsAreRejectedWithoutAFollowUpRequest() {
        TlsMockServer().use { fixture ->
            listOf(301, 302, 307, 308).forEach { status ->
                fixture.server.enqueue(
                    MockResponse
                        .Builder()
                        .code(status)
                        .addHeader("Location", fixture.server.url("/other"))
                        .build(),
                )
            }

            repeat(4) {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.REDIRECT, failed.reason)
            }
            assertEquals(4, fixture.server.requestCount)
        }
    }

    @Test
    fun mimeAcceptsOnlyJsonWithNoCharsetOrUtf8() {
        TlsMockServer().use { fixture ->
            listOf(
                "application/json",
                "Application/JSON; CHARSET=UTF-8",
                "application/json;charset=utf-8",
            ).forEach { contentType ->
                fixture.server.enqueue(
                    jsonResponse(201, validSuccessJson, contentType = contentType),
                )
            }

            repeat(3) {
                assertIs<EnrollmentResult.Accepted>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            }
        }
    }

    @Test
    fun absentWrongOrAmbiguousMimeIsRejected() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(
                MockResponse
                    .Builder()
                    .code(201)
                    .addHeader("X-Correlation-ID", TEST_CORRELATION_ID)
                    .body(validSuccessJson)
                    .build(),
            )
            listOf(
                "text/plain",
                "application/problem+json",
                "application/json; charset=iso-8859-1",
                "application/json; charset=utf-8; charset=utf-8",
                "application/json; profile=synthetic",
            ).forEach { contentType ->
                fixture.server.enqueue(
                    jsonResponse(201, validSuccessJson, contentType = contentType),
                )
            }
            fixture.server.enqueue(
                MockResponse
                    .Builder()
                    .code(201)
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Content-Type", "application/json; charset=utf-8")
                    .addHeader("X-Correlation-ID", TEST_CORRELATION_ID)
                    .body(validSuccessJson)
                    .build(),
            )

            repeat(7) {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.INVALID_CONTENT_TYPE, failed.reason)
            }
        }
    }

    @Test
    fun correlationHeaderMustBeSingleValidAndMatchTheRequest() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(
                MockResponse
                    .Builder()
                    .code(201)
                    .addHeader("Content-Type", "application/json")
                    .body(validSuccessJson)
                    .build(),
            )
            fixture.server.enqueue(jsonResponse(201, validSuccessJson, correlationId = ""))
            fixture.server.enqueue(
                MockResponse
                    .Builder()
                    .code(201)
                    .addHeader("Content-Type", "application/json")
                    .addHeader("X-Correlation-ID", TEST_CORRELATION_ID)
                    .addHeader("X-Correlation-ID", TEST_CORRELATION_ID)
                    .body(validSuccessJson)
                    .build(),
            )
            fixture.server.enqueue(jsonResponse(201, validSuccessJson, correlationId = "invalid value"))
            fixture.server.enqueue(jsonResponse(201, validSuccessJson, correlationId = "corr-other"))

            repeat(4) {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.MISSING_CORRELATION, failed.reason)
            }
            val mismatch =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            assertEquals(EnrollmentFailureReason.CORRELATION_MISMATCH, mismatch.reason)
        }
    }

    @Test
    fun errorBodyCorrelationMustMatchHeaderAndRequest() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(
                jsonResponse(401, validErrorJson(correlationId = "corr-other")),
            )

            val failed =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            assertEquals(EnrollmentFailureReason.CORRELATION_MISMATCH, failed.reason)
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun emptyBodyAndDecompressedSizeBoundaryAreEnforced() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(jsonResponse(201, ""))
            fixture.server.enqueue(jsonResponse(201, " \t\r\n"))
            val exact = validSuccessJson + " ".repeat(65_536 - validSuccessJson.encodeToByteArray().size)
            val oversized = exact + " "
            fixture.server.enqueue(jsonResponse(201, exact))
            fixture.server.enqueue(jsonResponse(201, oversized))

            repeat(2) {
                val failed =
                    assertIs<EnrollmentResult.Failed>(
                        fixture.client().newCall(fixture.command()).execute(),
                    )
                assertEquals(EnrollmentFailureReason.EMPTY_BODY, failed.reason)
            }
            assertIs<EnrollmentResult.Accepted>(
                fixture.client().newCall(fixture.command()).execute(),
            )
            val tooLarge =
                assertIs<EnrollmentResult.Failed>(
                    fixture.client().newCall(fixture.command()).execute(),
                )
            assertEquals(EnrollmentFailureReason.RESPONSE_TOO_LARGE, tooLarge.reason)
            assertEquals(4, fixture.server.requestCount)
        }
    }

    @Test
    fun aCallExecutesAtMostOnce() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(jsonResponse(201, validSuccessJson))
            val call = fixture.client().newCall(fixture.command())

            assertIs<EnrollmentResult.Accepted>(call.execute())
            val second = assertIs<EnrollmentResult.Failed>(call.execute())
            assertEquals(EnrollmentFailureReason.INVALID_LOCAL_REQUEST, second.reason)
            assertEquals(1, fixture.server.requestCount)
        }
    }

    @Test
    fun acceptedAndFailedResultsDoNotRevealCredentialsOrBodies() {
        TlsMockServer().use { fixture ->
            fixture.server.enqueue(jsonResponse(201, validSuccessJson))
            fixture.server.enqueue(jsonResponse(201, "{"))

            val accepted = fixture.client().newCall(fixture.command()).execute().toString()
            val failed = fixture.client().newCall(fixture.command()).execute().toString()

            assertFalse(accepted.contains(TEST_CREDENTIAL))
            assertFalse(accepted.contains("device_id"))
            assertFalse(accepted.contains(TEST_CORRELATION_ID))
            assertFalse(failed.contains("{"))
            assertFalse(failed.contains("http"))
        }
    }
}
