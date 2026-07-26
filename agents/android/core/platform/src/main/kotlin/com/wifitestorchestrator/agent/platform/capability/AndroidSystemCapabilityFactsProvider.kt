package com.wifitestorchestrator.agent.platform.capability

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFacts
import com.wifitestorchestrator.agent.domain.capability.AndroidCapabilityFactsProvider
import com.wifitestorchestrator.agent.domain.capability.WifiHardwarePresence

class AndroidSystemCapabilityFactsProvider internal constructor(
    private val platformRelease: () -> String,
    private val wifiFeaturePresence: () -> WifiHardwarePresence,
) : AndroidCapabilityFactsProvider {
    constructor(context: Context) : this(
        platformRelease = { Build.VERSION.RELEASE },
        wifiFeaturePresence =
            wifiFeatureObserver(
                requireNotNull(context.applicationContext) {
                    "An application context is required for capability facts."
                },
            ),
    )

    override fun observe(): AndroidCapabilityFacts =
        AndroidCapabilityFacts(
            platformVersion = platformRelease(),
            wifiHardwarePresence = wifiFeaturePresence(),
        )
}

private fun wifiFeatureObserver(context: Context): () -> WifiHardwarePresence = {
    try {
        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)) {
            WifiHardwarePresence.PRESENT
        } else {
            WifiHardwarePresence.ABSENT
        }
    } catch (_: RuntimeException) {
        WifiHardwarePresence.UNKNOWN
    }
}
