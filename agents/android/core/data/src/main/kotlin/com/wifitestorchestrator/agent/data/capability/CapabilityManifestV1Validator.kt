package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.domain.identity.AgentId
import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Immutable validation profile for Android capability manifests whose schema and catalog are
 * both 1.0.0.
 *
 * This profile intentionally does not use the installed Android capability catalog or the
 * Android DTO enums. Persisted manifests describe the contract that was valid when they were
 * frozen, while new manifests are separately constrained by [CapabilityManifestCodec].
 */
internal object CapabilityManifestV1Validator {
    const val SCHEMA_VERSION: String = "1.0.0"
    const val CATALOG_VERSION: String = "1.0.0"

    fun validate(
        document: JsonObject,
        expectedAgentId: AgentId,
        expectedManifestId: String,
        expectedSequence: Long,
    ): Instant? {
        if (document.keys != ROOT_KEYS) return null
        if (document.stringValue("schema_version") != SCHEMA_VERSION) return null
        if (document.stringValue("capability_catalog_version") != CATALOG_VERSION) return null
        if (document.stringValue("protocol_version") != PROTOCOL_VERSION) return null
        if (document.stringValue("platform") != PLATFORM) return null

        val manifestId = document.stringValue("manifest_id") ?: return null
        if (manifestId != expectedManifestId || !UUID_PATTERN.matches(manifestId)) return null
        val agentId = document.stringValue("agent_id") ?: return null
        if (agentId != expectedAgentId.toString() || !UUID_PATTERN.matches(agentId)) return null
        val manifestSequence = document.integerValue("manifest_sequence") ?: return null
        if (manifestSequence < 0L || manifestSequence != expectedSequence) return null

        val agentVersion = document.stringValue("agent_version") ?: return null
        if (!agentVersion.hasCodePointLengthIn(5..32) || !SEMVER_PATTERN.matches(agentVersion)) {
            return null
        }
        val platformVersion = document.stringValue("platform_version") ?: return null
        if (!platformVersion.hasCodePointLengthIn(1..64)) return null
        val generatedAtRaw = document.stringValue("generated_at") ?: return null
        val generatedAt = parseGeneratedAt(generatedAtRaw) ?: return null

        val capabilities = document["capabilities"] as? JsonArray ?: return null
        if (capabilities.size != CAPABILITY_IDS.size) return null
        val observedIds = mutableSetOf<String>()
        for (element in capabilities) {
            val capability = element as? JsonObject ?: return null
            val id = validateCapability(capability) ?: return null
            if (!observedIds.add(id)) return null
        }
        if (observedIds != CAPABILITY_IDS) return null
        return generatedAt
    }

    private fun validateCapability(capability: JsonObject): String? {
        if (capability.keys != CAPABILITY_KEYS) return null
        val id = capability.stringValue("id") ?: return null
        if (id !in CAPABILITY_IDS) return null
        if (capability.stringValue("version") != CAPABILITY_VERSION) return null
        if (
            !validateStatusReasonDimension(
                capability["technical_support"],
                TECHNICAL_SUPPORT_STATUSES,
            ) ||
            !validateStatusReasonDimension(
                capability["implementation_status"],
                IMPLEMENTATION_STATUSES,
            ) ||
            !validatePermissionRequirement(capability["permission_requirement"]) ||
            !validateStatusReasonDimension(
                capability["user_interaction"],
                USER_INTERACTION_STATUSES,
            ) ||
            !validateStatusReasonDimension(
                capability["background_execution"],
                BACKGROUND_EXECUTION_STATUSES,
            ) ||
            !validateProvider(capability["provider"]) ||
            !validateLimitations(capability["limitations"])
        ) {
            return null
        }
        return id
    }

    private fun validateStatusReasonDimension(
        element: JsonElement?,
        statuses: Set<String>,
    ): Boolean {
        val dimension = element as? JsonObject ?: return false
        val status = dimension.stringValue("status") ?: return false
        return dimension.keys == STATUS_REASON_KEYS &&
            status in statuses &&
            validateNullableReason(dimension["reason"])
    }

    private fun validatePermissionRequirement(element: JsonElement?): Boolean {
        val dimension = element as? JsonObject ?: return false
        if (dimension.keys != PERMISSION_REQUIREMENT_KEYS) return false
        val status = dimension.stringValue("status") ?: return false
        if (status !in PERMISSION_REQUIREMENT_STATUSES) return false
        if (!validateNullableReason(dimension["reason"])) return false
        val permissions = dimension["permissions"] as? JsonArray ?: return false
        if (permissions.size > MAX_PERMISSIONS) return false
        val observed = mutableSetOf<String>()
        for (elementPermission in permissions) {
            val permission = elementPermission.stringValue() ?: return false
            if (
                !permission.hasCodePointLengthIn(1..64) ||
                !PERMISSION_PATTERN.matches(permission) ||
                !observed.add(permission)
            ) {
                return false
            }
        }
        return true
    }

    private fun validateProvider(element: JsonElement?): Boolean {
        val dimension = element as? JsonObject ?: return false
        if (dimension.keys != PROVIDER_KEYS) return false
        val status = dimension.stringValue("status") ?: return false
        if (status !in PROVIDER_STATUSES) return false
        if (!validateNullableReason(dimension["reason"])) return false
        val implementations = dimension["implementations"] as? JsonArray ?: return false
        if (implementations.size > MAX_PROVIDER_IMPLEMENTATIONS) return false
        val observed = mutableSetOf<ProviderIdentity>()
        for (implementationElement in implementations) {
            val implementation = implementationElement as? JsonObject ?: return false
            if (implementation.keys != PROVIDER_IMPLEMENTATION_KEYS) return false
            val providerId = implementation.stringValue("provider_id") ?: return false
            val providerVersion =
                implementation.stringValue("provider_version") ?: return false
            val method = implementation.stringValue("method") ?: return false
            if (
                !providerId.hasCodePointLengthIn(3..64) ||
                !PROVIDER_ID_PATTERN.matches(providerId) ||
                !providerVersion.hasCodePointLengthIn(5..32) ||
                !SEMVER_PATTERN.matches(providerVersion) ||
                !method.hasCodePointLengthIn(1..64) ||
                !PROVIDER_METHOD_PATTERN.matches(method) ||
                !observed.add(ProviderIdentity(providerId, providerVersion, method))
            ) {
                return false
            }
        }
        return true
    }

    private fun validateLimitations(element: JsonElement?): Boolean {
        val dimension = element as? JsonObject ?: return false
        if (
            !dimension.keys.containsAll(LIMITATIONS_REQUIRED_KEYS) ||
            dimension.keys.any { it !in LIMITATIONS_ALLOWED_KEYS }
        ) {
            return false
        }
        val status = dimension.stringValue("status") ?: return false
        if (status !in LIMITATIONS_STATUSES) return false
        if (!validateNullableReason(dimension["reason"])) return false
        return dimension.optionalIntegerInRange("max_duration_seconds", 1L..86_400L) &&
            dimension.optionalIntegerInRange(
                "max_throughput_bps",
                1L..1_000_000_000_000L,
            ) &&
            dimension.optionalIntegerInRange(
                "max_payload_bytes",
                1L..1_073_741_824L,
            ) &&
            dimension.optionalIntegerInRange("max_concurrency", 1L..1_024L) &&
            dimension.optionalIntegerInRange("max_streams", 1L..128L)
    }

    private fun validateNullableReason(element: JsonElement?): Boolean {
        if (element === JsonNull) return true
        val reason = element as? JsonObject ?: return false
        if (
            !reason.keys.containsAll(REASON_REQUIRED_KEYS) ||
            reason.keys.any { it !in REASON_ALLOWED_KEYS }
        ) {
            return false
        }
        val code = reason.stringValue("code") ?: return false
        if (code !in REASON_CODES) return false
        if ("detail" in reason) {
            val detail = reason["detail"].stringValue() ?: return false
            if (!detail.hasCodePointLengthIn(1..256)) return false
        }
        return true
    }

    private fun JsonObject.optionalIntegerInRange(
        key: String,
        range: LongRange,
    ): Boolean {
        if (key !in this) return true
        val value = integerValue(key) ?: return false
        return value in range
    }

    private fun JsonObject.integerValue(key: String): Long? {
        val primitive = this[key] as? JsonPrimitive ?: return null
        if (primitive.isString || !INTEGER_PATTERN.matches(primitive.content)) return null
        return primitive.content.toLongOrNull()
    }

    private fun JsonObject.stringValue(key: String): String? = this[key].stringValue()

    private fun JsonElement?.stringValue(): String? {
        val primitive = this as? JsonPrimitive ?: return null
        return primitive.content.takeIf { primitive.isString }
    }

    private fun String.hasCodePointLengthIn(range: IntRange): Boolean =
        codePointCount(0, length) in range

    private fun parseGeneratedAt(raw: String): Instant? {
        if (!raw.hasCodePointLengthIn(1..UTC_TIMESTAMP_MAX_CODE_POINTS)) return null
        val match = UTC_TIMESTAMP_PATTERN.matchEntire(raw) ?: return null
        val year = match.groupValues[1].toIntOrNull() ?: return null
        if (year !in 1..9999) return null

        val fraction = match.groupValues[7]
        if (
            fraction.length > NANOSECOND_FRACTION_DIGITS &&
            fraction.drop(NANOSECOND_FRACTION_DIGITS).any { it != '0' }
        ) {
            return null
        }
        val nanosecond =
            fraction
                .take(NANOSECOND_FRACTION_DIGITS)
                .padEnd(NANOSECOND_FRACTION_DIGITS, '0')
                .toIntOrNull()
                ?: 0
        return try {
            LocalDateTime
                .of(
                    year,
                    match.groupValues[2].toInt(),
                    match.groupValues[3].toInt(),
                    match.groupValues[4].toInt(),
                    match.groupValues[5].toInt(),
                    match.groupValues[6].toInt(),
                    nanosecond,
                ).toInstant(ZoneOffset.UTC)
        } catch (_: DateTimeException) {
            null
        }
    }

    private data class ProviderIdentity(
        val providerId: String,
        val providerVersion: String,
        val method: String,
    )

    private const val PLATFORM = "android"
    private const val PROTOCOL_VERSION = "1.0.0"
    private const val CAPABILITY_VERSION = "1.0.0"
    private const val MAX_PERMISSIONS = 16
    private const val MAX_PROVIDER_IMPLEMENTATIONS = 8
    private const val UTC_TIMESTAMP_MAX_CODE_POINTS = 32
    private const val MAX_SUPPORTED_FRACTION_DIGITS = 11
    private const val NANOSECOND_FRACTION_DIGITS = 9

    private val INTEGER_PATTERN = Regex("-?(?:0|[1-9][0-9]*)")
    private val UTC_TIMESTAMP_PATTERN =
        Regex(
            "^(\\d{4})-(\\d{2})-(\\d{2})[Tt](\\d{2}):(\\d{2}):(\\d{2})" +
                "(?:\\.(\\d{1,$MAX_SUPPORTED_FRACTION_DIGITS}))?Z$",
        )
    private val UUID_PATTERN =
        Regex(
            "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-" +
                "[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        )
    private val SEMVER_PATTERN =
        Regex(
            "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)" +
                "(?:-[0-9A-Za-z.-]{1,16})?",
        )
    private val PERMISSION_PATTERN = Regex("[a-z][a-z0-9._-]+")
    private val PROVIDER_ID_PATTERN = Regex("[a-z][a-z0-9.-]+")
    private val PROVIDER_METHOD_PATTERN = Regex("[A-Za-z0-9._-]+")

    private val ROOT_KEYS =
        setOf(
            "schema_version",
            "manifest_id",
            "manifest_sequence",
            "agent_id",
            "agent_version",
            "platform",
            "platform_version",
            "protocol_version",
            "capability_catalog_version",
            "generated_at",
            "capabilities",
        )
    private val CAPABILITY_KEYS =
        setOf(
            "id",
            "version",
            "technical_support",
            "implementation_status",
            "permission_requirement",
            "user_interaction",
            "background_execution",
            "provider",
            "limitations",
        )
    private val STATUS_REASON_KEYS = setOf("status", "reason")
    private val PERMISSION_REQUIREMENT_KEYS = setOf("status", "permissions", "reason")
    private val PROVIDER_KEYS = setOf("status", "implementations", "reason")
    private val PROVIDER_IMPLEMENTATION_KEYS =
        setOf("provider_id", "provider_version", "method")
    private val LIMITATIONS_REQUIRED_KEYS = setOf("status", "reason")
    private val LIMITATIONS_ALLOWED_KEYS =
        LIMITATIONS_REQUIRED_KEYS +
            setOf(
                "max_duration_seconds",
                "max_throughput_bps",
                "max_payload_bytes",
                "max_concurrency",
                "max_streams",
            )
    private val REASON_REQUIRED_KEYS = setOf("code")
    private val REASON_ALLOWED_KEYS = REASON_REQUIRED_KEYS + "detail"

    private val CAPABILITY_IDS =
        setOf(
            "wifi.connection.read",
            "wifi.scan",
            "wifi.rssi.read",
            "network.icmp.ping",
            "network.tcp.probe",
            "network.http.probe",
            "traffic.tcp.throughput",
            "traffic.udp.throughput",
            "traffic.http.download",
            "traffic.http.upload",
            "traffic.latency_under_load",
            "capture.ip",
            "capture.ieee80211.monitor",
            "traffic.pcap.replay",
            "execution.background.continuous",
        )
    private val TECHNICAL_SUPPORT_STATUSES =
        setOf("supported", "conditional", "unsupported", "unknown", "not_applicable")
    private val IMPLEMENTATION_STATUSES =
        setOf("implemented", "partial", "planned", "not_implemented", "excluded", "unknown")
    private val PERMISSION_REQUIREMENT_STATUSES =
        setOf(
            "none",
            "required",
            "conditional",
            "denied",
            "restricted",
            "unknown",
            "not_applicable",
        )
    private val USER_INTERACTION_STATUSES =
        setOf("none", "required", "conditional", "unknown", "not_applicable")
    private val BACKGROUND_EXECUTION_STATUSES =
        setOf(
            "continuous",
            "bounded",
            "foreground_only",
            "deferred",
            "not_supported",
            "unknown",
            "not_applicable",
        )
    private val PROVIDER_STATUSES =
        setOf("available", "unavailable", "unknown", "not_applicable")
    private val LIMITATIONS_STATUSES = setOf("known", "unknown", "not_applicable")
    private val REASON_CODES =
        setOf(
            "not_exposed_by_platform",
            "not_implemented",
            "permission_missing",
            "permission_denied",
            "user_interaction_required",
            "lifecycle_restricted",
            "provider_unavailable",
            "policy_denied",
            "not_applicable",
            "unknown",
            "incompatible_version",
            "agent_revoked",
            "expired",
            "blocked",
            "skipped",
        )
}
