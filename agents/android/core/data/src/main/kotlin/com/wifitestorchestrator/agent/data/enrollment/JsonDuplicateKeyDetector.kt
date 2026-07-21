package com.wifitestorchestrator.agent.data.enrollment

private const val MAX_JSON_NESTING_DEPTH = 64

internal enum class RawJsonValidation {
    VALID,
    MALFORMED,
    DUPLICATE_PROPERTY,
}

internal object JsonDuplicateKeyDetector {
    fun validate(raw: String): RawJsonValidation =
        try {
            StrictJsonScanner(raw).scan()
            RawJsonValidation.VALID
        } catch (_: DuplicatePropertyException) {
            RawJsonValidation.DUPLICATE_PROPERTY
        } catch (_: MalformedJsonException) {
            RawJsonValidation.MALFORMED
        }
}

private class StrictJsonScanner(private val raw: String) {
    private var index: Int = 0

    fun scan() {
        skipWhitespace()
        parseValue(depth = 0)
        skipWhitespace()
        if (index != raw.length) malformed()
    }

    private fun parseValue(depth: Int) {
        if (depth > MAX_JSON_NESTING_DEPTH || index >= raw.length) malformed()
        when (raw[index]) {
            '{' -> parseObject(depth + 1)
            '[' -> parseArray(depth + 1)
            '"' -> parseString()
            't' -> parseLiteral("true")
            'f' -> parseLiteral("false")
            'n' -> parseLiteral("null")
            '-', in '0'..'9' -> parseNumber()
            else -> malformed()
        }
    }

    private fun parseObject(depth: Int) {
        consume('{')
        skipWhitespace()
        if (consumeIf('}')) return
        val keys = mutableSetOf<String>()
        while (true) {
            if (index >= raw.length || raw[index] != '"') malformed()
            val key = parseString()
            if (!keys.add(key)) duplicate()
            skipWhitespace()
            consume(':')
            skipWhitespace()
            parseValue(depth)
            skipWhitespace()
            when {
                consumeIf('}') -> return
                consumeIf(',') -> skipWhitespace()
                else -> malformed()
            }
        }
    }

    private fun parseArray(depth: Int) {
        consume('[')
        skipWhitespace()
        if (consumeIf(']')) return
        while (true) {
            parseValue(depth)
            skipWhitespace()
            when {
                consumeIf(']') -> return
                consumeIf(',') -> skipWhitespace()
                else -> malformed()
            }
        }
    }

    private fun parseString(): String {
        consume('"')
        val decoded = StringBuilder()
        while (index < raw.length) {
            val character = raw[index++]
            when {
                character == '"' -> return decoded.toString()
                character == '\\' -> parseEscape(decoded)
                character.code < 0x20 -> malformed()
                character.isHighSurrogate() -> {
                    if (index >= raw.length || !raw[index].isLowSurrogate()) malformed()
                    decoded.append(character)
                    decoded.append(raw[index++])
                }
                character.isLowSurrogate() -> malformed()
                else -> decoded.append(character)
            }
        }
        malformed()
    }

    private fun parseEscape(decoded: StringBuilder) {
        if (index >= raw.length) malformed()
        when (val escaped = raw[index++]) {
            '"', '\\', '/' -> decoded.append(escaped)
            'b' -> decoded.append('\b')
            'f' -> decoded.append('\u000c')
            'n' -> decoded.append('\n')
            'r' -> decoded.append('\r')
            't' -> decoded.append('\t')
            'u' -> {
                val character = parseUnicodeEscape()
                when {
                    character.isHighSurrogate() -> {
                        if (
                            index + 1 >= raw.length ||
                            raw[index] != '\\' ||
                            raw[index + 1] != 'u'
                        ) {
                            malformed()
                        }
                        index += 2
                        val low = parseUnicodeEscape()
                        if (!low.isLowSurrogate()) malformed()
                        decoded.append(character)
                        decoded.append(low)
                    }
                    character.isLowSurrogate() -> malformed()
                    else -> decoded.append(character)
                }
            }
            else -> malformed()
        }
    }

    private fun parseUnicodeEscape(): Char {
        if (index + 4 > raw.length) malformed()
        var value = 0
        repeat(4) {
            value = (value shl 4) or hexValue(raw[index++])
        }
        return value.toChar()
    }

    private fun parseNumber() {
        consumeIf('-')
        if (index >= raw.length) malformed()
        when (raw[index]) {
            '0' -> index += 1
            in '1'..'9' -> {
                index += 1
                while (index < raw.length && raw[index] in '0'..'9') index += 1
            }
            else -> malformed()
        }
        if (consumeIf('.')) {
            if (index >= raw.length || raw[index] !in '0'..'9') malformed()
            while (index < raw.length && raw[index] in '0'..'9') index += 1
        }
        if (index < raw.length && raw[index] in charArrayOf('e', 'E')) {
            index += 1
            if (index < raw.length && raw[index] in charArrayOf('+', '-')) index += 1
            if (index >= raw.length || raw[index] !in '0'..'9') malformed()
            while (index < raw.length && raw[index] in '0'..'9') index += 1
        }
    }

    private fun parseLiteral(expected: String) {
        if (!raw.regionMatches(index, expected, 0, expected.length)) malformed()
        index += expected.length
    }

    private fun skipWhitespace() {
        while (index < raw.length && raw[index] in charArrayOf(' ', '\t', '\r', '\n')) {
            index += 1
        }
    }

    private fun consume(expected: Char) {
        if (!consumeIf(expected)) malformed()
    }

    private fun consumeIf(expected: Char): Boolean {
        if (index >= raw.length || raw[index] != expected) return false
        index += 1
        return true
    }

    private fun hexValue(character: Char): Int =
        when (character) {
            in '0'..'9' -> character - '0'
            in 'a'..'f' -> character - 'a' + 10
            in 'A'..'F' -> character - 'A' + 10
            else -> malformed()
        }

    private fun malformed(): Nothing = throw MalformedJsonException()

    private fun duplicate(): Nothing = throw DuplicatePropertyException()
}

private class MalformedJsonException : RuntimeException()

private class DuplicatePropertyException : RuntimeException()
