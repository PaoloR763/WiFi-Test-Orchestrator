package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityCatalog
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFacts
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilitySnapshot
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilitySnapshotResult
import com.wifitestorchestrator.agent.domain.capability.WifiHardwarePresence
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.AgentId
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import com.wifitestorchestrator.agent.domain.version.ProtocolVersion
import java.time.Instant

internal const val TEST_MANIFEST_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
internal const val SECOND_TEST_MANIFEST_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
internal const val TEST_AGENT_ID = "33333333-3333-4333-8333-333333333333"
internal val TEST_GENERATED_AT: Instant = Instant.parse("2026-07-25T12:00:00.123456789Z")

internal fun capabilitySemanticInput(
    platformVersion: String = "15",
    presence: WifiHardwarePresence = WifiHardwarePresence.PRESENT,
    agentVersion: String = "0.1.0",
): CapabilityManifestSemanticInput =
    CapabilityManifestSemanticInput(
        agentId = validCapabilityValue(AgentId.parse(TEST_AGENT_ID)),
        agentVersion = validCapabilityValue(AgentVersion.parse(agentVersion)),
        protocolVersion = ProtocolVersion.CURRENT,
        snapshot = capabilitySnapshot(platformVersion, presence),
    )

internal fun capabilitySnapshot(
    platformVersion: String = "15",
    presence: WifiHardwarePresence = WifiHardwarePresence.PRESENT,
): AndroidCapabilitySnapshot {
    val result =
        AndroidCapabilityCatalog.build(AndroidCapabilityFacts(platformVersion, presence))
    check(result is AndroidCapabilitySnapshotResult.Built)
    return result.snapshot
}

internal fun frozenManifest(
    sequence: Long = 0L,
    manifestId: String = TEST_MANIFEST_ID,
    generatedAt: Instant = TEST_GENERATED_AT,
    semanticInput: CapabilityManifestSemanticInput = capabilitySemanticInput(),
): FrozenCapabilityManifest {
    val result =
        CapabilityManifestCodec().freeze(
            input = semanticInput,
            manifestId = manifestId,
            manifestSequence = sequence,
            generatedAt = generatedAt,
        )
    check(result is CapabilityManifestFreezeResult.Frozen)
    return result.manifest
}

private fun <T : Any> validCapabilityValue(
    result: com.wifitestorchestrator.agent.domain.error.ValidationResult<T>,
): T {
    check(result is Valid)
    return result.value
}
