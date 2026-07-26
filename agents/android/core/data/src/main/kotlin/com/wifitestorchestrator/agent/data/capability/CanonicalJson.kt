package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.data.enrollment.JsonDuplicateKeyDetector
import com.wifitestorchestrator.agent.data.enrollment.RawJsonValidation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@OptIn(ExperimentalSerializationApi::class)
internal object CapabilityJson {
    val strict: Json =
        Json {
            ignoreUnknownKeys = false
            isLenient = false
            coerceInputValues = false
            explicitNulls = true
            exceptionsWithDebugInfo = false
            decodeEnumsCaseInsensitive = false
            useAlternativeNames = false
            allowSpecialFloatingPointValues = false
            allowStructuredMapKeys = false
            encodeDefaults = false
        }
}

internal object CanonicalJson {
    private val integerPattern = Regex("-?(?:0|[1-9][0-9]*)")

    fun encode(element: JsonElement): ByteArray? =
        try {
            buildString { appendElement(element) }.encodeToByteArray()
        } catch (_: IllegalArgumentException) {
            null
        }

    fun parseCanonical(bytes: ByteArray): JsonElement? {
        val raw = decodeUtf8Strict(bytes) ?: return null
        if (JsonDuplicateKeyDetector.validate(raw) != RawJsonValidation.VALID) return null
        val element =
            try {
                CapabilityJson.strict.parseToJsonElement(raw)
            } catch (_: SerializationException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            } ?: return null
        val canonical = encode(element) ?: return null
        return element.takeIf { canonical.contentEquals(bytes) }
    }

    fun decodeUtf8Strict(bytes: ByteArray): String? =
        try {
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: java.nio.charset.CharacterCodingException) {
            null
        }

    private fun StringBuilder.appendElement(element: JsonElement) {
        when (element) {
            is JsonObject -> {
                append('{')
                element.entries.sortedBy(Map.Entry<String, JsonElement>::key)
                    .forEachIndexed { index, (key, value) ->
                        if (index > 0) append(',')
                        appendString(key)
                        append(':')
                        appendElement(value)
                    }
                append('}')
            }
            is JsonArray -> {
                append('[')
                element.forEachIndexed { index, value ->
                    if (index > 0) append(',')
                    appendElement(value)
                }
                append(']')
            }
            JsonNull -> append("null")
            is JsonPrimitive -> {
                if (element.isString) {
                    appendString(element.content)
                } else {
                    val content = element.content
                    require(
                        content == "true" ||
                            content == "false" ||
                            integerPattern.matches(content),
                    )
                    append(if (content == "-0") "0" else content)
                }
            }
        }
    }

    private fun StringBuilder.appendString(value: String) {
        append('"')
        var index = 0
        while (index < value.length) {
            val character = value[index]
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> {
                    when {
                        character.code < 0x20 -> {
                            append("\\u")
                            append(character.code.toString(16).padStart(4, '0'))
                        }
                        character.isHighSurrogate() -> {
                            require(index + 1 < value.length && value[index + 1].isLowSurrogate())
                            append(character)
                            append(value[index + 1])
                            index += 1
                        }
                        character.isLowSurrogate() -> throw IllegalArgumentException()
                        else -> append(character)
                    }
                }
            }
            index += 1
        }
        append('"')
    }
}
