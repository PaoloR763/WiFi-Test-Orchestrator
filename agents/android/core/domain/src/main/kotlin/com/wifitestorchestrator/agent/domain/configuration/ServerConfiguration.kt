package com.wifitestorchestrator.agent.domain.configuration

import com.wifitestorchestrator.agent.domain.error.ConfigurationIssue
import com.wifitestorchestrator.agent.domain.error.ConfigurationKind
import com.wifitestorchestrator.agent.domain.error.ConfigurationViolation
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidConfiguration
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import java.net.IDN
import java.net.URI
import java.net.URISyntaxException

private const val HTTPS_PORT = 443
private val pathSegmentPattern = Regex("[A-Za-z0-9._~-]+")
private val idna2003DeviationCharacters =
    setOf(
        '\u00DF', // U+00DF LATIN SMALL LETTER SHARP S
        '\u03C2', // U+03C2 GREEK SMALL LETTER FINAL SIGMA
        '\u200C', // U+200C ZERO WIDTH NON-JOINER
        '\u200D', // U+200D ZERO WIDTH JOINER
    )

class ServerBaseUrl private constructor(private val canonicalAscii: String) {
    override fun equals(other: Any?): Boolean =
        other is ServerBaseUrl && canonicalAscii == other.canonicalAscii

    override fun hashCode(): Int = canonicalAscii.hashCode()

    override fun toString(): String = canonicalAscii

    companion object {
        fun parse(raw: String): ValidationResult<ServerBaseUrl> {
            when (val characters = validateRawCharacters(raw)) {
                is Valid -> Unit
                is Invalid -> return characters
            }
            val uri =
                try {
                    URI(raw)
                } catch (_: URISyntaxException) {
                    return invalid(ConfigurationIssue.URI_SYNTAX)
                }
            if (!uri.isAbsolute) return invalid(ConfigurationIssue.RELATIVE_URI)
            if (uri.isOpaque) return invalid(ConfigurationIssue.OPAQUE_URI)
            val scheme = uri.scheme.lowercase()
            if (scheme != "https") {
                return if (scheme == "http") {
                    invalid(
                        ConfigurationIssue.INSECURE_SCHEME,
                        ConfigurationViolation.INSECURE,
                    )
                } else {
                    invalid(ConfigurationIssue.UNSUPPORTED_SCHEME)
                }
            }
            if (uri.rawQuery != null) return invalid(ConfigurationIssue.QUERY)
            if (uri.rawFragment != null) return invalid(ConfigurationIssue.FRAGMENT)
            val authority = uri.rawAuthority ?: return invalid(ConfigurationIssue.MISSING_AUTHORITY)
            if (uri.rawUserInfo != null || '@' in authority) {
                return invalid(ConfigurationIssue.USER_INFO)
            }
            val canonicalAuthority =
                when (val parsed = parseAuthority(authority)) {
                    is Valid -> parsed.value
                    is Invalid -> return parsed
                }
            val canonicalPath =
                when (val parsed = canonicalizePath(uri.rawPath.orEmpty())) {
                    is Valid -> parsed.value
                    is Invalid -> return parsed
                }
            return Valid(
                ServerBaseUrl(
                    "https://${canonicalAuthority.render()}$canonicalPath",
                ),
            )
        }
    }
}

data class ServerConfiguration(val baseUrl: ServerBaseUrl)

private fun validateRawCharacters(raw: String): ValidationResult<Unit> {
    if (raw != raw.trim()) {
        return invalid(ConfigurationIssue.LEADING_OR_TRAILING_WHITESPACE)
    }
    if (raw.any { Character.isWhitespace(it) || Character.isSpaceChar(it) }) {
        return invalid(ConfigurationIssue.WHITESPACE)
    }
    if (raw.any(Character::isISOControl)) {
        return invalid(ConfigurationIssue.CONTROL_CHARACTER)
    }
    if ('\\' in raw) return invalid(ConfigurationIssue.BACKSLASH)
    if ('%' in raw) {
        val openingBracket = raw.indexOf('[')
        val closingBracket = raw.indexOf(']', startIndex = openingBracket + 1)
        val percent = raw.indexOf('%')
        if (openingBracket >= 0 && closingBracket > openingBracket && percent in openingBracket..closingBracket) {
            return invalid(ConfigurationIssue.IPV6_SCOPE)
        }
        return invalid(ConfigurationIssue.PERCENT_ENCODING)
    }
    return Valid(Unit)
}

private enum class HostKind {
    DNS_OR_IPV4,
    IPV6,
}

private data class CanonicalAuthority(
    val host: String,
    val port: Int,
    val hostKind: HostKind,
) {
    fun render(): String {
        val renderedHost = if (hostKind == HostKind.IPV6) "[$host]" else host
        return if (port == HTTPS_PORT) renderedHost else "$renderedHost:$port"
    }
}

private fun parseAuthority(raw: String): ValidationResult<CanonicalAuthority> {
    if (raw.isEmpty()) return invalid(ConfigurationIssue.MISSING_HOST)
    if (raw.startsWith('[')) {
        val closing = raw.indexOf(']')
        if (closing <= 1) return invalid(ConfigurationIssue.INVALID_IPV6)
        val host = raw.substring(1, closing)
        val suffix = raw.substring(closing + 1)
        if ('%' in host) return invalid(ConfigurationIssue.IPV6_SCOPE)
        val port =
            when {
                suffix.isEmpty() -> HTTPS_PORT
                suffix.startsWith(':') ->
                    when (val parsed = parsePort(suffix.substring(1))) {
                        is Valid -> parsed.value
                        is Invalid -> return parsed
                    }
                else -> return invalid(ConfigurationIssue.INVALID_HOST)
            }
        val words =
            when (val parsed = parseIpv6(host)) {
                is Ipv6Parse.Valid -> parsed.words
                Ipv6Parse.Invalid -> return invalid(ConfigurationIssue.INVALID_IPV6)
            }
        return Valid(CanonicalAuthority(renderIpv6(words), port, HostKind.IPV6))
    }
    if ('[' in raw || ']' in raw) return invalid(ConfigurationIssue.INVALID_HOST)
    if (raw.count { it == ':' } > 1) {
        return invalid(ConfigurationIssue.UNBRACKETED_IPV6)
    }
    val separator = raw.lastIndexOf(':')
    val host = if (separator >= 0) raw.substring(0, separator) else raw
    val port =
        if (separator >= 0) {
            when (val parsed = parsePort(raw.substring(separator + 1))) {
                is Valid -> parsed.value
                is Invalid -> return parsed
            }
        } else {
            HTTPS_PORT
        }
    if (host.isEmpty()) return invalid(ConfigurationIssue.MISSING_HOST)
    val canonicalHost =
        when (val parsed = canonicalizeDnsOrIpv4(host)) {
            is Valid -> parsed.value
            is Invalid -> return parsed
        }
    return Valid(CanonicalAuthority(canonicalHost, port, HostKind.DNS_OR_IPV4))
}

private fun parsePort(raw: String): ValidationResult<Int> {
    if (raw.isEmpty() || !raw.all { it in '0'..'9' }) {
        return invalid(ConfigurationIssue.INVALID_PORT)
    }
    if (raw.length > 5) return invalid(ConfigurationIssue.INVALID_PORT)
    val value = raw.toInt()
    return if (value in 1..65535) Valid(value) else invalid(ConfigurationIssue.INVALID_PORT)
}

private fun canonicalizeDnsOrIpv4(raw: String): ValidationResult<String> {
    val originalHost = raw
    if (originalHost.any { it in idna2003DeviationCharacters }) {
        return invalid(ConfigurationIssue.INVALID_HOST)
    }
    if (originalHost.endsWith('.')) return invalid(ConfigurationIssue.TRAILING_DOT)
    val originalIsAscii = originalHost.all { it.code <= 0x7f }
    when (val classification = classifyDnsOrIpv4(originalHost)) {
        is DnsOrIpv4Classification.Ipv4 -> return classification.result.asValidationResult()
        DnsOrIpv4Classification.AmbiguousNumeric -> {
            return invalid(ConfigurationIssue.AMBIGUOUS_IPV4)
        }
        DnsOrIpv4Classification.Dns -> Unit
    }
    val ascii =
        try {
            IDN.toASCII(originalHost, IDN.USE_STD3_ASCII_RULES).lowercase()
        } catch (_: IllegalArgumentException) {
            return invalid(ConfigurationIssue.INVALID_HOST)
    }
    if (ascii.isEmpty()) return invalid(ConfigurationIssue.MISSING_HOST)
    if (ascii.endsWith('.')) return invalid(ConfigurationIssue.TRAILING_DOT)
    val asciiClassification = classifyDnsOrIpv4(ascii)
    val unicodeNumericCandidate =
        !originalIsAscii && originalHost.all { it == '.' || it.isDigit() }
    if (
        !originalIsAscii &&
        (asciiClassification != DnsOrIpv4Classification.Dns || unicodeNumericCandidate)
    ) {
        return invalid(ConfigurationIssue.AMBIGUOUS_IPV4)
    }
    when (asciiClassification) {
        is DnsOrIpv4Classification.Ipv4 -> return asciiClassification.result.asValidationResult()
        DnsOrIpv4Classification.AmbiguousNumeric -> {
            return invalid(ConfigurationIssue.AMBIGUOUS_IPV4)
        }
        DnsOrIpv4Classification.Dns -> Unit
    }
    if (ascii.length > 253 || ascii.split('.').any { it.isEmpty() || it.length > 63 }) {
        return invalid(ConfigurationIssue.INVALID_HOST)
    }
    return Valid(ascii)
}

private sealed interface Ipv4Result {
    data class Valid(val canonical: String, val octets: IntArray) : Ipv4Result

    data object Ambiguous : Ipv4Result

    data object Invalid : Ipv4Result
}

private sealed interface DnsOrIpv4Classification {
    data class Ipv4(val result: Ipv4Result) : DnsOrIpv4Classification

    data object AmbiguousNumeric : DnsOrIpv4Classification

    data object Dns : DnsOrIpv4Classification
}

private fun classifyDnsOrIpv4(raw: String): DnsOrIpv4Classification {
    if (raw.isNotEmpty() && raw.all { it == '.' || it in '0'..'9' }) {
        return DnsOrIpv4Classification.Ipv4(parseIpv4(raw))
    }
    val components = raw.split('.')
    return if (components.all(::isNumericHostComponent)) {
        DnsOrIpv4Classification.AmbiguousNumeric
    } else {
        DnsOrIpv4Classification.Dns
    }
}

private fun isNumericHostComponent(raw: String): Boolean {
    if (raw.isEmpty()) return false
    if (raw.all { it in '0'..'9' }) return true
    return raw.length > 2 &&
        raw.startsWith("0x", ignoreCase = true) &&
        raw.substring(2).all(::isAsciiHexDigit)
}

private fun isAsciiHexDigit(value: Char): Boolean =
    value in '0'..'9' || value in 'a'..'f' || value in 'A'..'F'

private fun Ipv4Result.asValidationResult(): ValidationResult<String> =
    when (this) {
        is Ipv4Result.Valid -> Valid(canonical)
        Ipv4Result.Ambiguous -> invalid(ConfigurationIssue.AMBIGUOUS_IPV4)
        Ipv4Result.Invalid -> invalid(ConfigurationIssue.INVALID_IPV4)
    }

private fun parseIpv4(raw: String): Ipv4Result {
    val parts = raw.split('.')
    if (
        parts.size != 4 ||
        parts.any {
            it.isEmpty() ||
                !it.all { character -> character in '0'..'9' }
        }
    ) {
        return Ipv4Result.Invalid
    }
    if (parts.any { it.length > 1 && it.startsWith('0') }) return Ipv4Result.Ambiguous
    if (parts.any { it.length > 3 }) return Ipv4Result.Invalid
    val octets = IntArray(4)
    for (index in parts.indices) {
        val value = parts[index].toInt()
        if (value !in 0..255) return Ipv4Result.Invalid
        octets[index] = value
    }
    return Ipv4Result.Valid(octets.joinToString("."), octets)
}

private fun canonicalizePath(raw: String): ValidationResult<String> {
    if (raw.isEmpty() || raw == "/") return Valid("/")
    if (!raw.startsWith('/')) return invalid(ConfigurationIssue.INVALID_PATH_SEGMENT)
    if ("//" in raw) return invalid(ConfigurationIssue.DOUBLE_SLASH_PATH)
    val withoutEdges = raw.removePrefix("/").removeSuffix("/")
    val segments = withoutEdges.split('/')
    if (segments.any { it == "." || it == ".." }) {
        return invalid(ConfigurationIssue.DOT_SEGMENT)
    }
    if (segments.any { !pathSegmentPattern.matches(it) }) {
        return invalid(ConfigurationIssue.INVALID_PATH_SEGMENT)
    }
    return Valid("/${segments.joinToString("/")}/")
}

private sealed interface Ipv6Parse {
    data class Valid(val words: IntArray) : Ipv6Parse

    data object Invalid : Ipv6Parse
}

private sealed interface HextetParse {
    data class Valid(val words: List<Int>) : HextetParse

    data object Invalid : HextetParse
}

private fun parseIpv6(raw: String): Ipv6Parse {
    if (raw.isEmpty() || '%' in raw) return Ipv6Parse.Invalid
    var value = raw
    if ('.' in value) {
        val separator = value.lastIndexOf(':')
        if (separator < 0) return Ipv6Parse.Invalid
        val ipv4 = parseIpv4(value.substring(separator + 1))
        if (ipv4 !is Ipv4Result.Valid) return Ipv6Parse.Invalid
        val high = (ipv4.octets[0] shl 8) or ipv4.octets[1]
        val low = (ipv4.octets[2] shl 8) or ipv4.octets[3]
        value = value.substring(0, separator + 1) + high.toString(16) + ":" + low.toString(16)
    }
    val compression = value.indexOf("::")
    if (compression >= 0 && compression != value.lastIndexOf("::")) {
        return Ipv6Parse.Invalid
    }
    val hasCompression = compression >= 0
    val leftText = if (hasCompression) value.substring(0, compression) else value
    val rightText = if (hasCompression) value.substring(compression + 2) else ""
    val left =
        when (val parsed = parseHextets(leftText)) {
            is HextetParse.Valid -> parsed.words
            HextetParse.Invalid -> return Ipv6Parse.Invalid
        }
    val right =
        when (val parsed = parseHextets(rightText)) {
            is HextetParse.Valid -> parsed.words
            HextetParse.Invalid -> return Ipv6Parse.Invalid
        }
    val represented = left.size + right.size
    if ((!hasCompression && represented != 8) || (hasCompression && represented >= 8)) {
        return Ipv6Parse.Invalid
    }
    val words = IntArray(8)
    left.forEachIndexed { index, word -> words[index] = word }
    right.forEachIndexed { index, word -> words[8 - right.size + index] = word }
    return Ipv6Parse.Valid(words)
}

private fun parseHextets(raw: String): HextetParse {
    if (raw.isEmpty()) return HextetParse.Valid(emptyList())
    val parts = raw.split(':')
    if (parts.any { part ->
            part.isEmpty() ||
                part.length > 4 ||
                part.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }
        }
    ) {
        return HextetParse.Invalid
    }
    return HextetParse.Valid(parts.map { it.toInt(16) })
}

private fun renderIpv6(words: IntArray): String {
    var bestStart = -1
    var bestLength = 0
    var index = 0
    while (index < words.size) {
        if (words[index] != 0) {
            index += 1
            continue
        }
        val start = index
        while (index < words.size && words[index] == 0) index += 1
        val length = index - start
        if (length >= 2 && length > bestLength) {
            bestStart = start
            bestLength = length
        }
    }
    if (bestStart < 0) return words.joinToString(":") { it.toString(16) }
    val left = words.take(bestStart).joinToString(":") { it.toString(16) }
    val right = words.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
    return when {
        left.isEmpty() && right.isEmpty() -> "::"
        left.isEmpty() -> "::$right"
        right.isEmpty() -> "$left::"
        else -> "$left::$right"
    }
}

private fun invalid(
    issue: ConfigurationIssue,
    violation: ConfigurationViolation = ConfigurationViolation.SYNTAX,
): Invalid =
    Invalid(
        InvalidConfiguration(
            kind = ConfigurationKind.SERVER_BASE_URL,
            violation = violation,
            issue = issue,
        ),
    )
