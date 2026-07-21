package com.wifitestorchestrator.agent.domain.enrollment

import com.wifitestorchestrator.agent.domain.error.IdentifierKind
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.InvalidSecretFormat
import com.wifitestorchestrator.agent.domain.error.SecretKind
import com.wifitestorchestrator.agent.domain.error.SecretViolation
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.error.ValidationResult
import com.wifitestorchestrator.agent.domain.identity.CredentialId
import com.wifitestorchestrator.agent.domain.identity.parseCanonicalUuid

private const val ENROLLMENT_TOKEN_PREFIX = "wto_enr_1"
private const val ENROLLMENT_TOKEN_LENGTH = 90
private const val AGENT_CREDENTIAL_PREFIX = "wto_ac_1"
private const val AGENT_CREDENTIAL_LENGTH = 89
private const val SECRET_SEGMENT_LENGTH = 43
private val base64UrlSegmentPattern = Regex("[A-Za-z0-9_-]{$SECRET_SEGMENT_LENGTH}")

class EnrollmentToken private constructor(private val raw: String) {
    fun <T> useSecret(block: (String) -> T): T = block(raw)

    override fun toString(): String = "EnrollmentToken(<redacted>)"

    companion object {
        fun parse(raw: String): ValidationResult<EnrollmentToken> {
            when (
                val shape =
                    validateSecretShape(
                        raw = raw,
                        expectedLength = ENROLLMENT_TOKEN_LENGTH,
                        expectedPrefix = ENROLLMENT_TOKEN_PREFIX,
                        kind = SecretKind.ENROLLMENT_TOKEN,
                    )
            ) {
                is Valid -> Unit
                is Invalid -> return shape
            }
            val locator = raw.split('.')[1]
            if (
                parseCanonicalUuid(locator, IdentifierKind.ENROLLMENT_TOKEN_LOCATOR) is Invalid
            ) {
                return invalidSecret(SecretKind.ENROLLMENT_TOKEN, SecretViolation.INVALID_LOCATOR)
            }
            return Valid(EnrollmentToken(raw))
        }
    }
}

class AgentCredentialSecret private constructor(
    private val raw: String,
    val credentialId: CredentialId,
) {
    fun <T> useSecret(block: (String) -> T): T = block(raw)

    override fun toString(): String = "AgentCredentialSecret(<redacted>)"

    companion object {
        fun parse(raw: String): ValidationResult<AgentCredentialSecret> {
            when (
                val shape =
                    validateSecretShape(
                        raw = raw,
                        expectedLength = AGENT_CREDENTIAL_LENGTH,
                        expectedPrefix = AGENT_CREDENTIAL_PREFIX,
                        kind = SecretKind.AGENT_CREDENTIAL,
                    )
            ) {
                is Valid -> Unit
                is Invalid -> return shape
            }
            return when (val credentialId = CredentialId.parse(raw.split('.')[1])) {
                is Valid -> Valid(AgentCredentialSecret(raw, credentialId.value))
                is Invalid ->
                    invalidSecret(SecretKind.AGENT_CREDENTIAL, SecretViolation.INVALID_LOCATOR)
            }
        }
    }
}

private fun validateSecretShape(
    raw: String,
    expectedLength: Int,
    expectedPrefix: String,
    kind: SecretKind,
): ValidationResult<Unit> {
    if (raw.length != expectedLength) {
        return invalidSecret(kind, SecretViolation.INVALID_LENGTH)
    }
    val parts = raw.split('.')
    if (parts.size != 3) {
        return invalidSecret(kind, SecretViolation.INVALID_STRUCTURE)
    }
    if (parts[0] != expectedPrefix) {
        return invalidSecret(kind, SecretViolation.INVALID_PREFIX)
    }
    if (!base64UrlSegmentPattern.matches(parts[2])) {
        return invalidSecret(kind, SecretViolation.INVALID_SECRET_SEGMENT)
    }
    return Valid(Unit)
}

private fun invalidSecret(kind: SecretKind, violation: SecretViolation): Invalid =
    Invalid(InvalidSecretFormat(kind, violation))
