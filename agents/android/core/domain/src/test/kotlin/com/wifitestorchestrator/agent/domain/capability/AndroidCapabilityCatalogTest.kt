package com.wifitestorchestrator.agent.domain.capability

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidCapabilityCatalogTest {
    @Test
    fun `nominal matrix freezes all fifteen rows and seven dimensions`() {
        val snapshot = build(WifiHardwarePresence.PRESENT)

        assertEquals(AndroidCapabilityCatalog.IDS, snapshot.capabilities.map { it.id })
        assertEquals(15, snapshot.capabilities.size)
        val actual = snapshot.capabilities.map(AndroidCapability::signature)
        assertEquals(NOMINAL_SIGNATURES, actual)
        snapshot.capabilities.forEach { capability ->
            assertEquals("1.0.0", capability.version)
            assertNull(capability.limitations.maxDurationSeconds)
            assertNull(capability.limitations.maxThroughputBps)
            assertNull(capability.limitations.maxPayloadBytes)
            assertNull(capability.limitations.maxConcurrency)
            assertNull(capability.limitations.maxStreams)
        }
    }

    @Test
    fun `wifi hardware absence applies the exact fail closed transition only to wifi`() {
        val absent = build(WifiHardwarePresence.ABSENT)
        val nominal = build(WifiHardwarePresence.PRESENT)

        absent.capabilities.take(3).forEach { capability ->
            assertEquals(TechnicalSupportStatus.UNSUPPORTED, capability.technicalSupport.status)
            assertEquals(
                CapabilityReasonCode.NOT_EXPOSED_BY_PLATFORM,
                capability.technicalSupport.reason?.code,
            )
            assertEquals(ImplementationStatus.PLANNED, capability.implementationStatus.status)
            assertEquals(
                CapabilityReasonCode.NOT_IMPLEMENTED,
                capability.implementationStatus.reason?.code,
            )
            assertEquals(
                PermissionRequirementStatus.NOT_APPLICABLE,
                capability.permissionRequirement.status,
            )
            assertTrue(capability.permissionRequirement.permissions.isEmpty())
            assertEquals(
                CapabilityReasonCode.NOT_APPLICABLE,
                capability.permissionRequirement.reason?.code,
            )
            assertEquals(UserInteractionStatus.NOT_APPLICABLE, capability.userInteraction.status)
            assertEquals(
                BackgroundExecutionStatus.NOT_APPLICABLE,
                capability.backgroundExecution.status,
            )
            assertEquals(ProviderStatus.UNAVAILABLE, capability.provider.status)
            assertTrue(capability.provider.implementations.isEmpty())
            assertEquals(
                CapabilityReasonCode.PROVIDER_UNAVAILABLE,
                capability.provider.reason?.code,
            )
            assertEquals(LimitationsStatus.NOT_APPLICABLE, capability.limitations.status)
            assertEquals(
                CapabilityReasonCode.NOT_APPLICABLE,
                capability.limitations.reason?.code,
            )
        }
        assertEquals(
            nominal.capabilities.drop(3),
            absent.capabilities.drop(3),
        )
    }

    @Test
    fun `ambiguous wifi observation preserves nominal fallback except technical support`() {
        val unknown = build(WifiHardwarePresence.UNKNOWN)
        val nominal = build(WifiHardwarePresence.PRESENT)

        unknown.capabilities.take(3).forEachIndexed { index, capability ->
            assertEquals(TechnicalSupportStatus.UNKNOWN, capability.technicalSupport.status)
            assertEquals(CapabilityReasonCode.UNKNOWN, capability.technicalSupport.reason?.code)
            assertEquals(
                nominal.capabilities[index].copy(technicalSupport = capability.technicalSupport),
                capability,
            )
        }
        assertEquals(nominal.capabilities.drop(3), unknown.capabilities.drop(3))
    }

    @Test
    fun `platform version is opaque untrimmed and code point bounded`() {
        val opaque = "  Android β  "
        assertEquals(opaque, build(WifiHardwarePresence.PRESENT, opaque).platformVersion)
        assertIs<AndroidCapabilitySnapshotResult.InvalidPlatformVersion>(
            AndroidCapabilityCatalog.build(
                AndroidCapabilityFacts("", WifiHardwarePresence.PRESENT),
            ),
        )
        assertIs<AndroidCapabilitySnapshotResult.InvalidPlatformVersion>(
            AndroidCapabilityCatalog.build(
                AndroidCapabilityFacts("a".repeat(65), WifiHardwarePresence.PRESENT),
            ),
        )
        assertEquals(
            64,
            build(
                WifiHardwarePresence.PRESENT,
                "\uD83D\uDE00".repeat(64),
            ).platformVersion.codePointCount(0, 128),
        )
        assertIs<AndroidCapabilitySnapshotResult.InvalidPlatformVersion>(
            AndroidCapabilityCatalog.build(
                AndroidCapabilityFacts("\uD800", WifiHardwarePresence.PRESENT),
            ),
        )
    }

    private fun build(
        presence: WifiHardwarePresence,
        platformVersion: String = "15",
    ): AndroidCapabilitySnapshot =
        assertIs<AndroidCapabilitySnapshotResult.Built>(
            AndroidCapabilityCatalog.build(AndroidCapabilityFacts(platformVersion, presence)),
        ).snapshot
}

private fun AndroidCapability.signature(): String =
    listOf(
        id,
        technicalSupport.status.name,
        technicalSupport.reason.codeOrNull(),
        implementationStatus.status.name,
        implementationStatus.reason.codeOrNull(),
        permissionRequirement.status.name,
        permissionRequirement.permissions.joinToString(","),
        permissionRequirement.reason.codeOrNull(),
        userInteraction.status.name,
        userInteraction.reason.codeOrNull(),
        backgroundExecution.status.name,
        backgroundExecution.reason.codeOrNull(),
        provider.status.name,
        provider.implementations.joinToString(",") {
            "${it.providerId}:${it.providerVersion}:${it.method}"
        },
        provider.reason.codeOrNull(),
        limitations.status.name,
        limitations.maxDurationSeconds?.toString() ?: "null",
        limitations.maxThroughputBps?.toString() ?: "null",
        limitations.maxPayloadBytes?.toString() ?: "null",
        limitations.maxConcurrency?.toString() ?: "null",
        limitations.maxStreams?.toString() ?: "null",
        limitations.reason.codeOrNull(),
    ).joinToString("|")

private fun CapabilityReason?.codeOrNull(): String = this?.code?.name ?: "null"

private val NOMINAL_SIGNATURES =
    listOf(
        "wifi.connection.read|CONDITIONAL|null|PLANNED|NOT_IMPLEMENTED|REQUIRED|" +
            "nearby.wifi.devices|PERMISSION_MISSING|CONDITIONAL|USER_INTERACTION_REQUIRED|" +
            "BOUNDED|LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|" +
            "null|null|null|null|null|UNKNOWN",
        "wifi.scan|CONDITIONAL|null|PLANNED|NOT_IMPLEMENTED|REQUIRED|" +
            "nearby.wifi.devices|PERMISSION_MISSING|CONDITIONAL|USER_INTERACTION_REQUIRED|" +
            "BOUNDED|LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|" +
            "null|null|null|null|null|UNKNOWN",
        "wifi.rssi.read|CONDITIONAL|null|PLANNED|NOT_IMPLEMENTED|REQUIRED|" +
            "nearby.wifi.devices|PERMISSION_MISSING|CONDITIONAL|USER_INTERACTION_REQUIRED|" +
            "BOUNDED|LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|" +
            "null|null|null|null|null|UNKNOWN",
        "network.icmp.ping|UNKNOWN|UNKNOWN|PLANNED|NOT_IMPLEMENTED|UNKNOWN||UNKNOWN|" +
            "NONE|null|BOUNDED|LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|" +
            "UNKNOWN|null|null|null|null|null|UNKNOWN",
        "network.tcp.probe|SUPPORTED|null|PLANNED|NOT_IMPLEMENTED|NONE||null|NONE|null|" +
            "BOUNDED|LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|" +
            "null|null|null|null|null|UNKNOWN",
        "network.http.probe|SUPPORTED|null|PLANNED|NOT_IMPLEMENTED|NONE||null|NONE|null|" +
            "BOUNDED|LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|" +
            "null|null|null|null|null|UNKNOWN",
        "traffic.tcp.throughput|CONDITIONAL|null|PLANNED|NOT_IMPLEMENTED|NONE||null|" +
            "REQUIRED|USER_INTERACTION_REQUIRED|FOREGROUND_ONLY|LIFECYCLE_RESTRICTED|" +
            "UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|null|null|null|null|null|UNKNOWN",
        "traffic.udp.throughput|CONDITIONAL|null|PLANNED|NOT_IMPLEMENTED|NONE||null|" +
            "REQUIRED|USER_INTERACTION_REQUIRED|FOREGROUND_ONLY|LIFECYCLE_RESTRICTED|" +
            "UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|null|null|null|null|null|UNKNOWN",
        "traffic.http.download|SUPPORTED|null|PLANNED|NOT_IMPLEMENTED|NONE||null|" +
            "CONDITIONAL|USER_INTERACTION_REQUIRED|BOUNDED|LIFECYCLE_RESTRICTED|" +
            "UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|null|null|null|null|null|UNKNOWN",
        "traffic.http.upload|SUPPORTED|null|PLANNED|NOT_IMPLEMENTED|NONE||null|" +
            "CONDITIONAL|USER_INTERACTION_REQUIRED|BOUNDED|LIFECYCLE_RESTRICTED|" +
            "UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|null|null|null|null|null|UNKNOWN",
        "traffic.latency_under_load|CONDITIONAL|null|PLANNED|NOT_IMPLEMENTED|NONE||null|" +
            "REQUIRED|USER_INTERACTION_REQUIRED|FOREGROUND_ONLY|LIFECYCLE_RESTRICTED|" +
            "UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|null|null|null|null|null|UNKNOWN",
        "capture.ip|CONDITIONAL|null|NOT_IMPLEMENTED|NOT_IMPLEMENTED|REQUIRED|vpn.consent|" +
            "PERMISSION_MISSING|REQUIRED|USER_INTERACTION_REQUIRED|FOREGROUND_ONLY|" +
            "LIFECYCLE_RESTRICTED|UNAVAILABLE||PROVIDER_UNAVAILABLE|UNKNOWN|" +
            "null|null|null|null|null|UNKNOWN",
        "capture.ieee80211.monitor|UNSUPPORTED|NOT_EXPOSED_BY_PLATFORM|EXCLUDED|" +
            "NOT_APPLICABLE|NOT_APPLICABLE||NOT_APPLICABLE|NOT_APPLICABLE|" +
            "NOT_APPLICABLE|NOT_APPLICABLE|NOT_APPLICABLE|NOT_APPLICABLE||" +
            "NOT_APPLICABLE|NOT_APPLICABLE|null|null|null|null|null|NOT_APPLICABLE",
        "traffic.pcap.replay|UNSUPPORTED|NOT_APPLICABLE|EXCLUDED|NOT_APPLICABLE|" +
            "NOT_APPLICABLE||NOT_APPLICABLE|NOT_APPLICABLE|NOT_APPLICABLE|" +
            "NOT_APPLICABLE|NOT_APPLICABLE|NOT_APPLICABLE||NOT_APPLICABLE|" +
            "NOT_APPLICABLE|null|null|null|null|null|NOT_APPLICABLE",
        "execution.background.continuous|UNSUPPORTED|LIFECYCLE_RESTRICTED|EXCLUDED|" +
            "NOT_APPLICABLE|NOT_APPLICABLE||NOT_APPLICABLE|NOT_APPLICABLE|" +
            "NOT_APPLICABLE|NOT_SUPPORTED|LIFECYCLE_RESTRICTED|NOT_APPLICABLE||" +
            "NOT_APPLICABLE|NOT_APPLICABLE|null|null|null|null|null|NOT_APPLICABLE",
    )
