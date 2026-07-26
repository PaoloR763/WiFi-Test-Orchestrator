package com.wifitestorchestrator.agent.data.capability

import java.security.SecureRandom
import java.time.Instant
import java.util.UUID

fun interface CapabilityManifestClock {
    fun now(): Instant
}

fun interface CapabilityManifestUuidSource {
    fun next(): String
}

fun interface CapabilityManifestRandomSource {
    fun nextBytes(size: Int): ByteArray
}

fun interface CapabilityManifestCorrelationSource {
    fun next(): String
}

internal object SystemCapabilityManifestClock : CapabilityManifestClock {
    override fun now(): Instant = Instant.now()
}

internal object SystemCapabilityManifestUuidSource : CapabilityManifestUuidSource {
    override fun next(): String = UUID.randomUUID().toString()
}

internal class SecureCapabilityManifestRandomSource(
    private val random: SecureRandom = SecureRandom(),
) : CapabilityManifestRandomSource {
    override fun nextBytes(size: Int): ByteArray =
        ByteArray(size).also(random::nextBytes)
}

internal object SystemCapabilityManifestCorrelationSource :
    CapabilityManifestCorrelationSource {
    override fun next(): String = UUID.randomUUID().toString()
}
