package com.wifitestorchestrator.agent.domain.error

sealed interface DomainValidationError {
    val code: String
    val description: String
}

enum class IdentifierKind {
    INSTALLATION_ID,
    AGENT_ID,
    DEVICE_ID,
    CREDENTIAL_ID,
    IDEMPOTENCY_KEY,
    CORRELATION_ID,
    ENROLLMENT_TOKEN_LOCATOR,
}

enum class IdentifierViolation {
    INVALID_FORMAT,
    NON_CANONICAL,
    INVALID_VARIANT,
    UNSUPPORTED_VERSION,
    NIL_UUID,
    UUID_V4_REQUIRED,
    INVALID_LENGTH,
    INVALID_CHARACTERS,
}

data class InvalidIdentifier(
    val kind: IdentifierKind,
    val violation: IdentifierViolation,
) : DomainValidationError {
    override val code: String = "invalid_identifier"
    override val description: String = "The identifier does not satisfy its required format."
}

enum class VersionKind {
    SEMANTIC,
    SCHEMA,
    PROTOCOL,
    AGENT,
}

enum class VersionViolation {
    INVALID_LENGTH,
    INVALID_FORMAT,
    LEADING_ZERO,
    PRERELEASE_TOO_LONG,
    PRERELEASE_EMPTY_IDENTIFIER,
    PRERELEASE_INVALID_CHARACTER,
    PRERELEASE_NUMERIC_LEADING_ZERO,
    BUILD_METADATA_NOT_ALLOWED,
    UNSUPPORTED,
}

data class InvalidVersion(
    val kind: VersionKind,
    val violation: VersionViolation,
) : DomainValidationError {
    override val code: String = "invalid_version"
    override val description: String = "The version does not satisfy the required syntax."
}

data object UnsupportedSchemaVersion : DomainValidationError {
    val kind: VersionKind = VersionKind.SCHEMA
    val violation: VersionViolation = VersionViolation.UNSUPPORTED
    override val code: String = "unsupported_schema_version"
    override val description: String = "The schema version is not supported."
}

data object UnsupportedProtocolVersion : DomainValidationError {
    val kind: VersionKind = VersionKind.PROTOCOL
    val violation: VersionViolation = VersionViolation.UNSUPPORTED
    override val code: String = "unsupported_protocol_version"
    override val description: String = "The protocol version is not supported."
}

enum class ConfigurationKind {
    SERVER_BASE_URL,
}

enum class ConfigurationViolation {
    SYNTAX,
    INSECURE,
}

enum class ConfigurationIssue {
    URI_SYNTAX,
    LEADING_OR_TRAILING_WHITESPACE,
    WHITESPACE,
    CONTROL_CHARACTER,
    BACKSLASH,
    PERCENT_ENCODING,
    RELATIVE_URI,
    OPAQUE_URI,
    MISSING_AUTHORITY,
    MISSING_HOST,
    USER_INFO,
    QUERY,
    FRAGMENT,
    INSECURE_SCHEME,
    UNSUPPORTED_SCHEME,
    INVALID_PORT,
    INVALID_HOST,
    TRAILING_DOT,
    INVALID_IPV4,
    AMBIGUOUS_IPV4,
    UNBRACKETED_IPV6,
    IPV6_SCOPE,
    INVALID_IPV6,
    DOUBLE_SLASH_PATH,
    DOT_SEGMENT,
    INVALID_PATH_SEGMENT,
}

data class InvalidConfiguration(
    val kind: ConfigurationKind,
    val violation: ConfigurationViolation,
    val issue: ConfigurationIssue,
) : DomainValidationError {
    override val code: String = "invalid_configuration"
    override val description: String =
        when (violation) {
            ConfigurationViolation.SYNTAX ->
                "The server configuration does not satisfy its required syntax."
            ConfigurationViolation.INSECURE ->
                "The server configuration violates the secure transport policy."
        }
}

enum class SecretKind {
    ENROLLMENT_TOKEN,
    AGENT_CREDENTIAL,
}

enum class SecretViolation {
    INVALID_LENGTH,
    INVALID_STRUCTURE,
    INVALID_PREFIX,
    INVALID_LOCATOR,
    INVALID_SECRET_SEGMENT,
}

data class InvalidSecretFormat(
    val kind: SecretKind,
    val violation: SecretViolation,
) : DomainValidationError {
    override val code: String = "invalid_secret_format"
    override val description: String = "The secret does not satisfy its required format."
}

enum class CredentialMetadataKind {
    VERSION,
    VALIDITY_WINDOW,
    DELIVERED_CREDENTIAL,
}

enum class CredentialMetadataViolation {
    NON_POSITIVE_VERSION,
    EXPIRY_NOT_AFTER_ISSUE,
    CREDENTIAL_ID_MISMATCH,
}

data class InvalidCredentialMetadata(
    val kind: CredentialMetadataKind,
    val violation: CredentialMetadataViolation,
) : DomainValidationError {
    override val code: String = "invalid_credential_metadata"
    override val description: String = "The credential metadata is inconsistent."
}
