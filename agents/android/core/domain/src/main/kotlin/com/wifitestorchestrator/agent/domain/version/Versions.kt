package com.wifitestorchestrator.agent.domain.version

import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidVersion
import com.wifitestorchestrator.agent.domain.error.UnsupportedProtocolVersion
import com.wifitestorchestrator.agent.domain.error.UnsupportedSchemaVersion
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.error.VersionKind
import com.wifitestorchestrator.agent.domain.error.VersionViolation
import com.wifitestorchestrator.agent.domain.error.flatMap
import com.wifitestorchestrator.agent.domain.error.map
import java.math.BigInteger

class SemanticVersion private constructor(
    val major: BigInteger,
    val minor: BigInteger,
    val patch: BigInteger,
    val preRelease: String?,
) : Comparable<SemanticVersion> {
    override fun compareTo(other: SemanticVersion): Int {
        val majorComparison = major.compareTo(other.major)
        if (majorComparison != 0) return majorComparison
        val minorComparison = minor.compareTo(other.minor)
        if (minorComparison != 0) return minorComparison
        val patchComparison = patch.compareTo(other.patch)
        if (patchComparison != 0) return patchComparison
        val left = preRelease
        val right = other.preRelease
        if (left == null && right == null) return 0
        if (left == null) return 1
        if (right == null) return -1
        val leftIdentifiers = left.split('.')
        val rightIdentifiers = right.split('.')
        val commonSize = minOf(leftIdentifiers.size, rightIdentifiers.size)
        for (index in 0 until commonSize) {
            val comparison = comparePreReleaseIdentifier(leftIdentifiers[index], rightIdentifiers[index])
            if (comparison != 0) return comparison
        }
        return leftIdentifiers.size.compareTo(rightIdentifiers.size)
    }

    override fun equals(other: Any?): Boolean =
        other is SemanticVersion &&
            major == other.major &&
            minor == other.minor &&
            patch == other.patch &&
            preRelease == other.preRelease

    override fun hashCode(): Int {
        var result = major.hashCode()
        result = 31 * result + minor.hashCode()
        result = 31 * result + patch.hashCode()
        result = 31 * result + (preRelease?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String =
        buildString {
            append(major)
            append('.')
            append(minor)
            append('.')
            append(patch)
            preRelease?.let {
                append('-')
                append(it)
            }
        }

    companion object {
        private const val MIN_LENGTH = 5
        private const val MAX_LENGTH = 32
        private const val MAX_PRERELEASE_LENGTH = 16

        fun parse(raw: String): ValidationResult<SemanticVersion> {
            if (raw.length !in MIN_LENGTH..MAX_LENGTH) {
                return invalid(VersionViolation.INVALID_LENGTH)
            }
            if ('+' in raw) {
                return invalid(VersionViolation.BUILD_METADATA_NOT_ALLOWED)
            }
            val separator = raw.indexOf('-')
            val core = if (separator >= 0) raw.substring(0, separator) else raw
            val preRelease = if (separator >= 0) raw.substring(separator + 1) else null
            val parts = core.split('.')
            if (parts.size != 3 || parts.any { it.isEmpty() || !it.all(Char::isAsciiDigit) }) {
                return invalid(VersionViolation.INVALID_FORMAT)
            }
            if (parts.any { it.length > 1 && it.startsWith('0') }) {
                return invalid(VersionViolation.LEADING_ZERO)
            }
            if (preRelease != null) {
                if (preRelease.length > MAX_PRERELEASE_LENGTH) {
                    return invalid(VersionViolation.PRERELEASE_TOO_LONG)
                }
                val identifiers = preRelease.split('.')
                if (identifiers.any(String::isEmpty)) {
                    return invalid(VersionViolation.PRERELEASE_EMPTY_IDENTIFIER)
                }
                if (identifiers.any { identifier ->
                        identifier.any { character ->
                            !character.isAsciiDigit() &&
                                character !in 'A'..'Z' &&
                                character !in 'a'..'z' &&
                                character != '-'
                        }
                    }
                ) {
                    return invalid(VersionViolation.PRERELEASE_INVALID_CHARACTER)
                }
                if (identifiers.any { identifier ->
                        identifier.all(Char::isAsciiDigit) &&
                            identifier.length > 1 &&
                            identifier.startsWith('0')
                    }
                ) {
                    return invalid(VersionViolation.PRERELEASE_NUMERIC_LEADING_ZERO)
                }
            }
            return Valid(
                SemanticVersion(
                    major = BigInteger(parts[0]),
                    minor = BigInteger(parts[1]),
                    patch = BigInteger(parts[2]),
                    preRelease = preRelease,
                ),
            )
        }

        private fun invalid(violation: VersionViolation): Invalid =
            Invalid(InvalidVersion(VersionKind.SEMANTIC, violation))

        internal fun supported(): SemanticVersion =
            SemanticVersion(
                major = BigInteger.ONE,
                minor = BigInteger.ZERO,
                patch = BigInteger.ZERO,
                preRelease = null,
            )
    }
}

class SchemaVersion private constructor(val value: SemanticVersion) {
    override fun equals(other: Any?): Boolean = other is SchemaVersion && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        val CURRENT: SchemaVersion = SchemaVersion(SemanticVersion.supported())

        fun parse(raw: String): ValidationResult<SchemaVersion> =
            parseSemanticVersion(raw, VersionKind.SCHEMA).flatMap { parsed ->
                if (parsed == CURRENT.value) Valid(CURRENT) else Invalid(UnsupportedSchemaVersion)
            }
    }
}

class ProtocolVersion private constructor(val value: SemanticVersion) {
    override fun equals(other: Any?): Boolean = other is ProtocolVersion && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        val CURRENT: ProtocolVersion = ProtocolVersion(SemanticVersion.supported())

        fun parse(raw: String): ValidationResult<ProtocolVersion> =
            parseSemanticVersion(raw, VersionKind.PROTOCOL).flatMap { parsed ->
                if (parsed == CURRENT.value) Valid(CURRENT) else Invalid(UnsupportedProtocolVersion)
            }
    }
}

class AgentVersion private constructor(val value: SemanticVersion) {
    override fun equals(other: Any?): Boolean = other is AgentVersion && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        fun parse(raw: String): ValidationResult<AgentVersion> =
            parseSemanticVersion(raw, VersionKind.AGENT).map(::AgentVersion)
    }
}

private fun parseSemanticVersion(
    raw: String,
    kind: VersionKind,
): ValidationResult<SemanticVersion> =
    when (val parsed = SemanticVersion.parse(raw)) {
        is Valid -> parsed
        is Invalid -> {
            val error = parsed.error
            if (error is InvalidVersion) {
                Invalid(InvalidVersion(kind, error.violation))
            } else {
                parsed
            }
        }
    }

private fun Char.isAsciiDigit(): Boolean = this in '0'..'9'

private fun comparePreReleaseIdentifier(left: String, right: String): Int {
    val leftNumeric = left.all(Char::isAsciiDigit)
    val rightNumeric = right.all(Char::isAsciiDigit)
    return when {
        leftNumeric && rightNumeric -> BigInteger(left).compareTo(BigInteger(right))
        leftNumeric -> -1
        rightNumeric -> 1
        else -> left.compareTo(right)
    }
}
