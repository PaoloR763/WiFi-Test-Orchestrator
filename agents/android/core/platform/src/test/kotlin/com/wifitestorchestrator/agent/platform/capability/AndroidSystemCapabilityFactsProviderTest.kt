package com.wifitestorchestrator.agent.platform.capability

import com.wifitestorchestrator.agent.domain.capability.WifiHardwarePresence
import kotlin.test.Test
import kotlin.test.assertEquals

class AndroidSystemCapabilityFactsProviderTest {
    @Test
    fun `injected release remains opaque and wifi facts retain three states`() {
        listOf(
            WifiHardwarePresence.PRESENT,
            WifiHardwarePresence.ABSENT,
            WifiHardwarePresence.UNKNOWN,
        ).forEach { presence ->
            val provider =
                AndroidSystemCapabilityFactsProvider(
                    platformRelease = { "36.1 opaque " },
                    wifiFeaturePresence = { presence },
                )

            val facts = provider.observe()

            assertEquals("36.1 opaque ", facts.platformVersion)
            assertEquals(presence, facts.wifiHardwarePresence)
        }
    }

    @Test
    fun `API labels are not parsed normalized or substituted by the facts seam`() {
        listOf("10", "15", "16", "16.1").forEach { release ->
            val facts =
                AndroidSystemCapabilityFactsProvider(
                    platformRelease = { release },
                    wifiFeaturePresence = { WifiHardwarePresence.UNKNOWN },
                ).observe()

            assertEquals(release, facts.platformVersion)
        }
    }
}
