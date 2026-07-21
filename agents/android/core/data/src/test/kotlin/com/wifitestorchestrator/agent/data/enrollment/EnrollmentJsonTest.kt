package com.wifitestorchestrator.agent.data.enrollment

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class EnrollmentJsonTest {
    @Test
    fun productionJsonConfigurationIsFailClosed() {
        val configuration = EnrollmentJson.instance.configuration

        assertEquals(false, configuration.ignoreUnknownKeys)
        assertEquals(false, configuration.isLenient)
        assertEquals(false, configuration.coerceInputValues)
        assertEquals(true, configuration.explicitNulls)
        assertEquals(false, configuration.decodeEnumsCaseInsensitive)
        assertEquals(false, configuration.useAlternativeNames)
        assertEquals(false, configuration.allowSpecialFloatingPointValues)
        assertEquals(false, configuration.allowStructuredMapKeys)
    }

    @Test
    fun validSuccessAndNormativeErrorDecode() {
        assertIs<DecodedPayload.Success<*>>(
            EnrollmentPayloadDecoder.decodeSuccess(validSuccessJson.encodeToByteArray()),
        )
        assertIs<DecodedPayload.Success<*>>(
            EnrollmentPayloadDecoder.decodeError(validErrorJson().encodeToByteArray()),
        )
        assertIs<DecodedPayload.Success<*>>(
            EnrollmentPayloadDecoder.decodeError(
                validErrorJson(
                    details = "[{\"location\":[\"body\",\"platform\"],\"type\":\"enum\"}]",
                ).encodeToByteArray(),
            ),
        )
    }

    @Test
    fun malformedTrailingBomEmptyAndWhitespaceBodiesFailClosed() {
        assertSuccessFailure("{", EnrollmentFailureReason.MALFORMED_JSON)
        assertSuccessFailure(validSuccessJson + "{}", EnrollmentFailureReason.MALFORMED_JSON)
        assertSuccessFailure("\uFEFF$validSuccessJson", EnrollmentFailureReason.MALFORMED_JSON)
        assertSuccessFailure("", EnrollmentFailureReason.EMPTY_BODY)
        assertSuccessFailure(" \t\r\n", EnrollmentFailureReason.EMPTY_BODY)
    }

    @Test
    fun unknownMissingNullAndWrongTypeFieldsAreRejected() {
        val unknown = validSuccessJson.replace("\"device_id\":", "\"unknown\":true,\"device_id\":")
        val missing = validSuccessJson.replace("\"device_id\": \"20000000-0000-4000-8000-000000000004\",", "")
        val explicitNull =
            validSuccessJson.replace(
                "\"device_id\": \"20000000-0000-4000-8000-000000000004\"",
                "\"device_id\": null",
            )
        val wrongType =
            validSuccessJson.replace(
                "\"device_id\": \"20000000-0000-4000-8000-000000000004\"",
                "\"device_id\": true",
            )

        listOf(unknown, missing, explicitNull, wrongType).forEach { raw ->
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SHAPE)
        }
    }

    @Test
    fun duplicatePropertiesAtRootNestedAndEscapedNamesAreRejected() {
        val rootDuplicate =
            validSuccessJson.replace(
                "\"schema_version\": \"1.0.0\",",
                "\"schema_version\": \"1.0.0\",\"schema_version\":\"1.0.0\",",
            )
        val nestedDuplicate =
            validSuccessJson.replace(
                "\"credential_id\": \"10000000-0000-4000-8000-000000000001\",",
                "\"credential_id\": \"10000000-0000-4000-8000-000000000001\"," +
                    "\"credential_id\":\"10000000-0000-4000-8000-000000000001\",",
            )
        val escapedDuplicate = "{\"a\":1,\"\\u0061\":2}"

        assertEquals(
            "2",
            EnrollmentJson.instance
                .parseToJsonElement("{\"a\":1,\"a\":2}")
                .jsonObject["a"]
                ?.jsonPrimitive
                ?.content,
        )

        assertSuccessFailure(rootDuplicate, EnrollmentFailureReason.INVALID_RESPONSE_SHAPE)
        assertSuccessFailure(nestedDuplicate, EnrollmentFailureReason.INVALID_RESPONSE_SHAPE)
        assertEquals(
            RawJsonValidation.DUPLICATE_PROPERTY,
            JsonDuplicateKeyDetector.validate(escapedDuplicate),
        )
    }

    @Test
    fun credentialVersionRequiresAnExactBoundedJsonInteger() {
        listOf("\"1\"", "1.0", "1e0", "true").forEach { replacement ->
            val raw = validSuccessJson.replace("\"credential_version\": 1", "\"credential_version\": $replacement")
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SHAPE)
        }
        listOf("0", "2147483648").forEach { replacement ->
            val raw = validSuccessJson.replace("\"credential_version\": 1", "\"credential_version\": $replacement")
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
    }

    @Test
    fun unknownEnumsAndVersionsAreRejectedWithoutFallback() {
        val state = validSuccessJson.replace("\"state\": \"active\"", "\"state\": \"ACTIVE\"")
        val schema = validSuccessJson.replaceFirst("\"schema_version\": \"1.0.0\"", "\"schema_version\": \"2.0.0\"")
        val protocol = validSuccessJson.replace("\"protocol_version\": \"1.0.0\"", "\"protocol_version\": \"2.0.0\"")

        listOf(state, schema, protocol).forEach { raw ->
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
    }

    @Test
    fun invalidNonCanonicalAndNilUuidsAreRejected() {
        val invalid = validSuccessJson.replace("20000000-0000-4000-8000-000000000004", "not-a-uuid")
        val uppercase = validSuccessJson.replace("20000000-0000-4000-8000-000000000004", "20000000-0000-4000-8000-00000000000A")
        val nil = validSuccessJson.replace("20000000-0000-4000-8000-000000000004", "00000000-0000-0000-0000-000000000000")

        listOf(invalid, uppercase, nil).forEach { raw ->
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
    }

    @Test
    fun timestampsCredentialShapeAndCrossFieldSemanticsAreRejected() {
        val offsetTimestamp =
            validSuccessJson.replace("2026-07-12T12:00:01Z", "2026-07-12T09:00:01-03:00")
        val malformedSecret = validSuccessJson.replace(TEST_CREDENTIAL, "not-a-credential")
        val expiredAtIssue =
            validSuccessJson.replace("2026-10-10T12:00:01Z", "2026-07-12T12:00:01Z")
        val mismatchedCredentialId =
            validSuccessJson.replace(
                "\"credential_id\": \"10000000-0000-4000-8000-000000000001\"",
                "\"credential_id\": \"20000000-0000-4000-8000-000000000011\"",
            )

        listOf(offsetTimestamp, malformedSecret, expiredAtIssue, mismatchedCredentialId).forEach { raw ->
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
    }

    @Test
    fun responseTimestampsAcceptRepresentableContractFractions() {
        listOf(
            "2026-07-12T12:00:01.1Z",
            "2026-07-12T12:00:01.123456Z",
            "2026-07-12T12:00:01.123456789Z",
            "2026-07-12T12:00:01.1234567890Z",
            "2026-07-12T12:00:01.12345678900Z",
        ).forEach { timestamp ->
            val raw =
                validSuccessJson.replace(
                    "\"server_received_at\": \"2026-07-12T12:00:01Z\"",
                    "\"server_received_at\": \"$timestamp\"",
                )
            assertIs<DecodedPayload.Success<*>>(
                EnrollmentPayloadDecoder.decodeSuccess(raw.encodeToByteArray()),
            )
        }
    }

    @Test
    fun responseTimestampProfileRejectsNonContractualOrUnrepresentableValues() {
        listOf(
            "+10000-01-01T00:00:00Z",
            "-0001-01-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2016-12-31T23:59:60Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00z",
            "2026-01-01T00:00:00.1234567891Z",
            "2026-01-01T00:00:00.12345678901Z",
            "2026-01-01T00:00:00.123456789000Z",
        ).forEach { timestamp ->
            val raw =
                validSuccessJson.replace(
                    "\"server_received_at\": \"2026-07-12T12:00:01Z\"",
                    "\"server_received_at\": \"$timestamp\"",
                )
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
    }

    @Test
    fun invalidCredentialTimestampsFailClosed() {
        val invalidIssued =
            validSuccessJson.replace(
                "\"issued_at\": \"2026-07-12T12:00:01Z\"",
                "\"issued_at\": \"+10000-01-01T00:00:00Z\"",
            )
        val invalidExpiry =
            validSuccessJson.replace(
                "\"expires_at\": \"2026-10-10T12:00:01Z\"",
                "\"expires_at\": \"2026-10-10T12:00:01.1234567891Z\"",
            )

        listOf(invalidIssued, invalidExpiry).forEach { raw ->
            assertSuccessFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
    }

    @Test
    fun errorDetailsNullValidAndContractLimitsAreEnforced() {
        val oversizedDetails =
            (0 until 33).joinToString(prefix = "[", postfix = "]") {
                "{\"location\":[],\"type\":\"synthetic\"}"
            }
        val tooDeepLocation =
            "[{\"location\":[" +
                (0 until 9).joinToString(",") { "\"x\"" } +
                "],\"type\":\"synthetic\"}]"
        val unknownDetail =
            "[{\"location\":[],\"type\":\"synthetic\",\"unknown\":true}]"

        assertIs<DecodedPayload.Success<*>>(
            EnrollmentPayloadDecoder.decodeError(validErrorJson(details = "null").encodeToByteArray()),
        )
        assertErrorFailure(
            validErrorJson(details = oversizedDetails),
            EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS,
        )
        assertErrorFailure(
            validErrorJson(details = tooDeepLocation),
            EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS,
        )
        assertErrorFailure(
            validErrorJson(details = unknownDetail),
            EnrollmentFailureReason.INVALID_RESPONSE_SHAPE,
        )
    }

    @Test
    fun errorCodeMessageCorrelationAndTypesAreValidated() {
        val invalidCode = validErrorJson(code = "Bad-Code")
        val emptyMessage = validErrorJson().replace("Synthetic failure.", "")
        val invalidCorrelation = validErrorJson(correlationId = "invalid value")
        val missingDetails = validErrorJson().replace("\"details\": null,", "")
        val wrongDetailsType = validErrorJson(details = "{}")

        listOf(invalidCode, emptyMessage, invalidCorrelation).forEach { raw ->
            assertErrorFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS)
        }
        listOf(missingDetails, wrongDetailsType).forEach { raw ->
            assertErrorFailure(raw, EnrollmentFailureReason.INVALID_RESPONSE_SHAPE)
        }
    }

    @Test
    fun rawScannerRejectsMalformedEscapesAndExcessiveNesting() {
        assertEquals(RawJsonValidation.MALFORMED, JsonDuplicateKeyDetector.validate("{\"a\":\"\\x\"}"))
        val nested = "[".repeat(66) + "0" + "]".repeat(66)
        assertEquals(RawJsonValidation.MALFORMED, JsonDuplicateKeyDetector.validate(nested))
    }

    private fun assertSuccessFailure(raw: String, expected: EnrollmentFailureReason) {
        val result = EnrollmentPayloadDecoder.decodeSuccess(raw.encodeToByteArray())
        assertEquals(expected, assertIs<DecodedPayload.Failure>(result).reason)
    }

    private fun assertErrorFailure(raw: String, expected: EnrollmentFailureReason) {
        val result = EnrollmentPayloadDecoder.decodeError(raw.encodeToByteArray())
        assertEquals(expected, assertIs<DecodedPayload.Failure>(result).reason)
    }
}
