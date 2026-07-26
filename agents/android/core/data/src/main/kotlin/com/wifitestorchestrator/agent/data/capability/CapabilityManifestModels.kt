package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilitySnapshot
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant

class Sha256Value private constructor(private val bytes: ByteArray) {
    fun copyBytes(): ByteArray = bytes.copyOf()

    fun contentEquals(other: Sha256Value): Boolean = bytes.contentEquals(other.bytes)

    fun lowercaseHex(): String = bytes.joinToString(separator = "") { "%02x".format(it) }

    override fun equals(other: Any?): Boolean =
        other is Sha256Value && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "Sha256Value(<redacted>)"

    companion object {
        const val SIZE_BYTES: Int = 32

        fun from(bytes: ByteArray): Sha256Value? =
            bytes.takeIf { it.size == SIZE_BYTES }?.let { Sha256Value(it.copyOf()) }
    }
}

data class CapabilityManifestSemanticInput(
    val agentId: AgentId,
    val agentVersion: AgentVersion,
    val protocolVersion: ProtocolVersion,
    val snapshot: AndroidCapabilitySnapshot,
)

class FrozenCapabilityManifest internal constructor(
    val manifestId: String,
    val manifestSequence: Long,
    val generatedAt: Instant,
    val semanticFingerprint: Sha256Value,
    val canonicalDigest: Sha256Value,
    canonicalPayload: ByteArray,
) {
    private val payload: ByteArray = canonicalPayload.copyOf()

    fun copyCanonicalPayload(): ByteArray = payload.copyOf()

    fun isByteIdenticalTo(other: FrozenCapabilityManifest): Boolean =
        manifestId == other.manifestId &&
            manifestSequence == other.manifestSequence &&
            generatedAt == other.generatedAt &&
            semanticFingerprint == other.semanticFingerprint &&
            canonicalDigest == other.canonicalDigest &&
            payload.contentEquals(other.payload)

    override fun toString(): String =
        "FrozenCapabilityManifest(" +
            "manifestId=$manifestId, " +
            "manifestSequence=$manifestSequence, " +
            "generatedAt=$generatedAt, " +
            "payload=<redacted>, digest=<redacted>, fingerprint=<redacted>)"
}

data class CapabilityManifestAcknowledgement(
    val manifestId: String,
    val manifestDigest: Sha256Value,
    val serverReceivedAt: Instant,
)

sealed interface CapabilityManifestFreezeResult {
    data class Frozen(val manifest: FrozenCapabilityManifest) :
        CapabilityManifestFreezeResult

    data object Invalid : CapabilityManifestFreezeResult
}
