package com.wifitestorchestrator.agent.domain.identity

import com.wifitestorchestrator.agent.domain.error.IdentifierKind
import com.wifitestorchestrator.agent.domain.error.IdentifierViolation
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidIdentifier
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.error.map
import java.util.UUID

private val nilUuid: UUID = UUID(0L, 0L)
private val correlationIdPattern = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

internal fun parseCanonicalUuid(
    raw: String,
    kind: IdentifierKind,
    versionRequirement: UuidVersionRequirement = UuidVersionRequirement.ONE_THROUGH_EIGHT,
): ValidationResult<UUID> {
    val parsed =
        try {
            UUID.fromString(raw)
        } catch (_: IllegalArgumentException) {
            return Invalid(InvalidIdentifier(kind, IdentifierViolation.INVALID_FORMAT))
        }
    if (parsed.toString() != raw) {
        return Invalid(InvalidIdentifier(kind, IdentifierViolation.NON_CANONICAL))
    }
    if (parsed == nilUuid) {
        return Invalid(InvalidIdentifier(kind, IdentifierViolation.NIL_UUID))
    }
    if (parsed.variant() != 2) {
        return Invalid(InvalidIdentifier(kind, IdentifierViolation.INVALID_VARIANT))
    }
    if (parsed.version() !in 1..8) {
        return Invalid(InvalidIdentifier(kind, IdentifierViolation.UNSUPPORTED_VERSION))
    }
    if (versionRequirement == UuidVersionRequirement.VERSION_FOUR && parsed.version() != 4) {
        return Invalid(InvalidIdentifier(kind, IdentifierViolation.UUID_V4_REQUIRED))
    }
    return Valid(parsed)
}

internal enum class UuidVersionRequirement {
    ONE_THROUGH_EIGHT,
    VERSION_FOUR,
}

class InstallationId private constructor(private val value: UUID) {
    override fun equals(other: Any?): Boolean =
        other is InstallationId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        fun parse(raw: String): ValidationResult<InstallationId> =
            parseCanonicalUuid(raw, IdentifierKind.INSTALLATION_ID).map(::InstallationId)

        fun fromUuid(value: UUID): ValidationResult<InstallationId> =
            parseCanonicalUuid(value.toString(), IdentifierKind.INSTALLATION_ID)
                .map(::InstallationId)

        fun generate(): InstallationId = InstallationId(UUID.randomUUID())
    }
}

class AgentId private constructor(private val value: UUID) {
    override fun equals(other: Any?): Boolean = other is AgentId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        fun parse(raw: String): ValidationResult<AgentId> =
            parseCanonicalUuid(raw, IdentifierKind.AGENT_ID).map(::AgentId)
    }
}

class DeviceId private constructor(private val value: UUID) {
    override fun equals(other: Any?): Boolean = other is DeviceId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        fun parse(raw: String): ValidationResult<DeviceId> =
            parseCanonicalUuid(raw, IdentifierKind.DEVICE_ID).map(::DeviceId)
    }
}

class CredentialId private constructor(private val value: UUID) {
    override fun equals(other: Any?): Boolean = other is CredentialId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        fun parse(raw: String): ValidationResult<CredentialId> =
            parseCanonicalUuid(raw, IdentifierKind.CREDENTIAL_ID).map(::CredentialId)
    }
}

class IdempotencyKey private constructor(private val value: UUID) {
    override fun equals(other: Any?): Boolean =
        other is IdempotencyKey && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value.toString()

    companion object {
        fun parse(raw: String): ValidationResult<IdempotencyKey> =
            parseCanonicalUuid(
                raw,
                IdentifierKind.IDEMPOTENCY_KEY,
                versionRequirement = UuidVersionRequirement.VERSION_FOUR,
            )
                .map(::IdempotencyKey)

        fun generate(): IdempotencyKey = IdempotencyKey(UUID.randomUUID())
    }
}

class CorrelationId private constructor(private val value: String) {
    override fun equals(other: Any?): Boolean =
        other is CorrelationId && value == other.value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value

    companion object {
        fun parse(raw: String): ValidationResult<CorrelationId> {
            if (raw.length !in 1..128) {
                return Invalid(
                    InvalidIdentifier(
                        IdentifierKind.CORRELATION_ID,
                        IdentifierViolation.INVALID_LENGTH,
                    ),
                )
            }
            if (!correlationIdPattern.matches(raw)) {
                return Invalid(
                    InvalidIdentifier(
                        IdentifierKind.CORRELATION_ID,
                        IdentifierViolation.INVALID_CHARACTERS,
                    ),
                )
            }
            return Valid(CorrelationId(raw))
        }
    }
}
