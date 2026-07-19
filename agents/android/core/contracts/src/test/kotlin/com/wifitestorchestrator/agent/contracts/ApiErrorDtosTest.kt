package com.wifitestorchestrator.agent.contracts

import com.wifitestorchestrator.agent.contracts.error.ErrorEnvelopeDto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

class ApiErrorDtosTest {
    @Test
    fun detailsListDecodes() {
        val decoded = strictJson.decodeFromString<ErrorEnvelopeDto>(errorWithDetails)

        assertEquals(1, decoded.error.details?.size)
        assertEquals(listOf("body", "platform"), decoded.error.details?.single()?.location)
        assertEquals("enum", decoded.error.details?.single()?.type)
    }

    @Test
    fun explicitNullDetailsDecodes() {
        val decoded = strictJson.decodeFromString<ErrorEnvelopeDto>(errorWithNullDetails)

        assertNull(decoded.error.details)
    }

    @Test
    fun absentDetailsIsRejectedEvenThoughItsValueIsNullable() {
        val envelope = strictJson.parseToJsonElement(errorWithNullDetails).jsonObject
        val error = envelope.getValue("error").jsonObject
        val payload = JsonObject(envelope + ("error" to JsonObject(error - "details")))

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<ErrorEnvelopeDto>(payload.toString())
        }
    }

    @Test
    fun unknownErrorEnvelopeFieldIsRejected() {
        val payload =
            JsonObject(
                strictJson.parseToJsonElement(errorWithNullDetails).jsonObject +
                    ("unknown" to JsonPrimitive(true)),
            )

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<ErrorEnvelopeDto>(payload.toString())
        }
    }

    @Test
    fun missingRequiredEnvelopeFieldIsRejected() {
        val envelope = strictJson.parseToJsonElement(errorWithNullDetails).jsonObject

        assertFailsWith<SerializationException> {
            strictJson.decodeFromString<ErrorEnvelopeDto>(JsonObject(envelope - "error").toString())
        }
    }

    @Test
    fun errorCodeRemainsAnOpenString() {
        val decoded =
            strictJson.decodeFromString<ErrorEnvelopeDto>(
                errorWithNullDetails.replace("enrollment_failed", "future_public_code"),
            )

        assertEquals("future_public_code", decoded.error.code)
    }

    @Test
    fun errorEncodingUsesExactlyThePublishedFields() {
        val decoded = strictJson.decodeFromString<ErrorEnvelopeDto>(errorWithDetails)
        val encoded = strictJson.parseToJsonElement(strictJson.encodeToString(decoded)).jsonObject
        val error = encoded.getValue("error").jsonObject

        assertEquals(setOf("schema_version", "error"), encoded.keys)
        assertEquals(setOf("code", "message", "details", "correlation_id"), error.keys)
        assertEquals(setOf("location", "type"), error.getValue("details").jsonArray.single().jsonObject.keys)
    }

    private companion object {
        val errorWithNullDetails =
            """
            {
              "schema_version": "1.0.0",
              "error": {
                "code": "enrollment_failed",
                "message": "Agent enrollment failed.",
                "details": null,
                "correlation_id": "corr-123"
              }
            }
            """.trimIndent()

        val errorWithDetails =
            """
            {
              "schema_version": "1.0.0",
              "error": {
                "code": "request_validation_failed",
                "message": "Request validation failed.",
                "details": [
                  {"location": ["body", "platform"], "type": "enum"}
                ],
                "correlation_id": "corr-456"
              }
            }
            """.trimIndent()
    }
}
