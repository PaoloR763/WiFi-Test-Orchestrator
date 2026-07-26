package com.wifitestorchestrator.agent.domain.capability

enum class WifiHardwarePresence {
    PRESENT,
    ABSENT,
    UNKNOWN,
}

data class AndroidCapabilityFacts(
    val platformVersion: String,
    val wifiHardwarePresence: WifiHardwarePresence,
)

fun interface AndroidCapabilityFactsProvider {
    fun observe(): AndroidCapabilityFacts
}

sealed interface PlatformVersionValidation {
    data class Valid(val value: String) : PlatformVersionValidation

    data object Invalid : PlatformVersionValidation
}

object AndroidPlatformVersionPolicy {
    private const val MIN_CODE_POINTS = 1
    private const val MAX_CODE_POINTS = 64

    fun validate(raw: String): PlatformVersionValidation {
        if (raw.hasUnpairedSurrogate()) return PlatformVersionValidation.Invalid
        val codePoints = raw.codePointCount(0, raw.length)
        return if (codePoints in MIN_CODE_POINTS..MAX_CODE_POINTS) {
            PlatformVersionValidation.Valid(raw)
        } else {
            PlatformVersionValidation.Invalid
        }
    }
}

private fun String.hasUnpairedSurrogate(): Boolean {
    var index = 0
    while (index < length) {
        val current = this[index]
        when {
            current.isHighSurrogate() -> {
                if (index + 1 >= length || !this[index + 1].isLowSurrogate()) return true
                index += 2
            }
            current.isLowSurrogate() -> return true
            else -> index += 1
        }
    }
    return false
}
