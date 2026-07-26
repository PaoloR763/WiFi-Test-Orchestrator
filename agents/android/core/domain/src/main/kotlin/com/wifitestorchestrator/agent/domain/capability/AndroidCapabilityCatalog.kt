package com.wifitestorchestrator.agent.domain.capability

object AndroidCapabilityCatalog {
    const val VERSION: String = "1.0.0"

    val IDS: List<String> =
        listOf(
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

    fun build(facts: AndroidCapabilityFacts): AndroidCapabilitySnapshotResult {
        val platformVersion =
            when (val validation = AndroidPlatformVersionPolicy.validate(facts.platformVersion)) {
                is PlatformVersionValidation.Valid -> validation.value
                PlatformVersionValidation.Invalid ->
                    return AndroidCapabilitySnapshotResult.InvalidPlatformVersion
            }
        val capabilities = nominalCapabilities().toMutableList()
        repeat(WIFI_CAPABILITY_COUNT) { index ->
            capabilities[index] =
                when (facts.wifiHardwarePresence) {
                    WifiHardwarePresence.PRESENT -> capabilities[index]
                    WifiHardwarePresence.ABSENT -> wifiHardwareAbsent(capabilities[index].id)
                    WifiHardwarePresence.UNKNOWN -> wifiHardwareUnknown(capabilities[index])
                }
        }
        return AndroidCapabilitySnapshotResult.Built(
            AndroidCapabilitySnapshot(
                platformVersion = platformVersion,
                capabilities = capabilities.toList(),
            ),
        )
    }

    private fun nominalCapabilities(): List<AndroidCapability> =
        listOf(
            wifi("wifi.connection.read"),
            wifi("wifi.scan"),
            wifi("wifi.rssi.read"),
            capability(
                id = "network.icmp.ping",
                technical = technical(TechnicalSupportStatus.UNKNOWN, UNKNOWN),
                permission =
                    permission(PermissionRequirementStatus.UNKNOWN, emptyList(), UNKNOWN),
                interaction = interaction(UserInteractionStatus.NONE, null),
                background = background(BackgroundExecutionStatus.BOUNDED, LIFECYCLE),
            ),
            networkProbe("network.tcp.probe"),
            networkProbe("network.http.probe"),
            foregroundTraffic("traffic.tcp.throughput"),
            foregroundTraffic("traffic.udp.throughput"),
            httpTraffic("traffic.http.download"),
            httpTraffic("traffic.http.upload"),
            foregroundTraffic("traffic.latency_under_load"),
            capability(
                id = "capture.ip",
                technical = technical(TechnicalSupportStatus.CONDITIONAL, null),
                implementation =
                    implementation(ImplementationStatus.NOT_IMPLEMENTED, NOT_IMPLEMENTED),
                permission =
                    permission(
                        PermissionRequirementStatus.REQUIRED,
                        listOf("vpn.consent"),
                        PERMISSION_MISSING,
                    ),
                interaction =
                    interaction(UserInteractionStatus.REQUIRED, USER_INTERACTION_REQUIRED),
                background =
                    background(BackgroundExecutionStatus.FOREGROUND_ONLY, LIFECYCLE),
            ),
            excluded(
                id = "capture.ieee80211.monitor",
                technicalReason = NOT_EXPOSED,
            ),
            excluded(
                id = "traffic.pcap.replay",
                technicalReason = NOT_APPLICABLE,
            ),
            capability(
                id = "execution.background.continuous",
                technical =
                    technical(TechnicalSupportStatus.UNSUPPORTED, LIFECYCLE),
                implementation =
                    implementation(ImplementationStatus.EXCLUDED, NOT_APPLICABLE),
                permission =
                    permission(
                        PermissionRequirementStatus.NOT_APPLICABLE,
                        emptyList(),
                        NOT_APPLICABLE,
                    ),
                interaction =
                    interaction(UserInteractionStatus.NOT_APPLICABLE, NOT_APPLICABLE),
                background =
                    background(BackgroundExecutionStatus.NOT_SUPPORTED, LIFECYCLE),
                provider = provider(ProviderStatus.NOT_APPLICABLE, NOT_APPLICABLE),
                limitations = limitations(LimitationsStatus.NOT_APPLICABLE, NOT_APPLICABLE),
            ),
        )

    private fun wifi(id: String): AndroidCapability =
        capability(
            id = id,
            technical = technical(TechnicalSupportStatus.CONDITIONAL, null),
            permission =
                permission(
                    PermissionRequirementStatus.REQUIRED,
                    listOf("nearby.wifi.devices"),
                    PERMISSION_MISSING,
                ),
            interaction =
                interaction(UserInteractionStatus.CONDITIONAL, USER_INTERACTION_REQUIRED),
            background = background(BackgroundExecutionStatus.BOUNDED, LIFECYCLE),
        )

    private fun wifiHardwareAbsent(id: String): AndroidCapability =
        capability(
            id = id,
            technical =
                technical(TechnicalSupportStatus.UNSUPPORTED, NOT_EXPOSED),
            permission =
                permission(
                    PermissionRequirementStatus.NOT_APPLICABLE,
                    emptyList(),
                    NOT_APPLICABLE,
                ),
            interaction =
                interaction(UserInteractionStatus.NOT_APPLICABLE, NOT_APPLICABLE),
            background =
                background(BackgroundExecutionStatus.NOT_APPLICABLE, NOT_APPLICABLE),
            limitations = limitations(LimitationsStatus.NOT_APPLICABLE, NOT_APPLICABLE),
        )

    private fun wifiHardwareUnknown(nominal: AndroidCapability): AndroidCapability =
        nominal.copy(
            technicalSupport = technical(TechnicalSupportStatus.UNKNOWN, UNKNOWN),
        )

    private fun networkProbe(id: String): AndroidCapability =
        capability(
            id = id,
            technical = technical(TechnicalSupportStatus.SUPPORTED, null),
            permission = permission(PermissionRequirementStatus.NONE, emptyList(), null),
            interaction = interaction(UserInteractionStatus.NONE, null),
            background = background(BackgroundExecutionStatus.BOUNDED, LIFECYCLE),
        )

    private fun foregroundTraffic(id: String): AndroidCapability =
        capability(
            id = id,
            technical = technical(TechnicalSupportStatus.CONDITIONAL, null),
            permission = permission(PermissionRequirementStatus.NONE, emptyList(), null),
            interaction =
                interaction(UserInteractionStatus.REQUIRED, USER_INTERACTION_REQUIRED),
            background =
                background(BackgroundExecutionStatus.FOREGROUND_ONLY, LIFECYCLE),
        )

    private fun httpTraffic(id: String): AndroidCapability =
        capability(
            id = id,
            technical = technical(TechnicalSupportStatus.SUPPORTED, null),
            permission = permission(PermissionRequirementStatus.NONE, emptyList(), null),
            interaction =
                interaction(UserInteractionStatus.CONDITIONAL, USER_INTERACTION_REQUIRED),
            background = background(BackgroundExecutionStatus.BOUNDED, LIFECYCLE),
        )

    private fun excluded(
        id: String,
        technicalReason: CapabilityReason,
    ): AndroidCapability =
        capability(
            id = id,
            technical =
                technical(TechnicalSupportStatus.UNSUPPORTED, technicalReason),
            implementation =
                implementation(ImplementationStatus.EXCLUDED, NOT_APPLICABLE),
            permission =
                permission(
                    PermissionRequirementStatus.NOT_APPLICABLE,
                    emptyList(),
                    NOT_APPLICABLE,
                ),
            interaction =
                interaction(UserInteractionStatus.NOT_APPLICABLE, NOT_APPLICABLE),
            background =
                background(BackgroundExecutionStatus.NOT_APPLICABLE, NOT_APPLICABLE),
            provider = provider(ProviderStatus.NOT_APPLICABLE, NOT_APPLICABLE),
            limitations = limitations(LimitationsStatus.NOT_APPLICABLE, NOT_APPLICABLE),
        )

    private fun capability(
        id: String,
        technical: TechnicalSupport,
        implementation: CapabilityImplementation =
            implementation(ImplementationStatus.PLANNED, NOT_IMPLEMENTED),
        permission: PermissionRequirement,
        interaction: UserInteraction,
        background: BackgroundExecution,
        provider: CapabilityProvider =
            provider(ProviderStatus.UNAVAILABLE, PROVIDER_UNAVAILABLE),
        limitations: CapabilityLimitations =
            limitations(LimitationsStatus.UNKNOWN, UNKNOWN),
    ): AndroidCapability =
        AndroidCapability(
            id = id,
            version = VERSION,
            technicalSupport = technical,
            implementationStatus = implementation,
            permissionRequirement = permission,
            userInteraction = interaction,
            backgroundExecution = background,
            provider = provider,
            limitations = limitations,
        )

    private fun technical(
        status: TechnicalSupportStatus,
        reason: CapabilityReason?,
    ): TechnicalSupport = TechnicalSupport(status, reason)

    private fun implementation(
        status: ImplementationStatus,
        reason: CapabilityReason?,
    ): CapabilityImplementation = CapabilityImplementation(status, reason)

    private fun permission(
        status: PermissionRequirementStatus,
        permissions: List<String>,
        reason: CapabilityReason?,
    ): PermissionRequirement = PermissionRequirement(status, permissions, reason)

    private fun interaction(
        status: UserInteractionStatus,
        reason: CapabilityReason?,
    ): UserInteraction = UserInteraction(status, reason)

    private fun background(
        status: BackgroundExecutionStatus,
        reason: CapabilityReason?,
    ): BackgroundExecution = BackgroundExecution(status, reason)

    private fun provider(
        status: ProviderStatus,
        reason: CapabilityReason?,
    ): CapabilityProvider = CapabilityProvider(status, emptyList(), reason)

    private fun limitations(
        status: LimitationsStatus,
        reason: CapabilityReason?,
    ): CapabilityLimitations =
        CapabilityLimitations(
            status = status,
            maxDurationSeconds = null,
            maxThroughputBps = null,
            maxPayloadBytes = null,
            maxConcurrency = null,
            maxStreams = null,
            reason = reason,
        )

    private const val WIFI_CAPABILITY_COUNT = 3
    private val NOT_IMPLEMENTED = CapabilityReason(CapabilityReasonCode.NOT_IMPLEMENTED)
    private val NOT_EXPOSED =
        CapabilityReason(CapabilityReasonCode.NOT_EXPOSED_BY_PLATFORM)
    private val PERMISSION_MISSING =
        CapabilityReason(CapabilityReasonCode.PERMISSION_MISSING)
    private val USER_INTERACTION_REQUIRED =
        CapabilityReason(CapabilityReasonCode.USER_INTERACTION_REQUIRED)
    private val LIFECYCLE =
        CapabilityReason(CapabilityReasonCode.LIFECYCLE_RESTRICTED)
    private val PROVIDER_UNAVAILABLE =
        CapabilityReason(CapabilityReasonCode.PROVIDER_UNAVAILABLE)
    private val NOT_APPLICABLE =
        CapabilityReason(CapabilityReasonCode.NOT_APPLICABLE)
    private val UNKNOWN = CapabilityReason(CapabilityReasonCode.UNKNOWN)
}
