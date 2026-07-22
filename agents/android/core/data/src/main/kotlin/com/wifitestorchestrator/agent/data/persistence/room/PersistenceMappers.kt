package com.wifitestorchestrator.agent.data.persistence.room

import com.wifitestorchestrator.agent.data.persistence.StoredLocalInstallation
import com.wifitestorchestrator.agent.data.persistence.StoredServerConfiguration
import com.wifitestorchestrator.agent.domain.configuration.ServerBaseUrl
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.InstallationId
import com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity
import java.time.Instant

internal const val LOCAL_STATE_SINGLETON_ID = 1L

private const val MIN_NANOSECOND = 0L
private const val MAX_NANOSECOND = 999_999_999L

internal fun LocalInstallationEntity.toStoredInstallationOrNull(): StoredLocalInstallation? {
    if (singletonId != LOCAL_STATE_SINGLETON_ID) return null
    val parsedInstallationId = InstallationId.parse(installationId)
    if (parsedInstallationId !is Valid) return null
    val validatedNanoseconds = createdAtNanoseconds.toValidatedNanosecondsOrNull()
        ?: return null
    val createdAt =
        PersistedInstant(createdAtEpochSeconds, validatedNanoseconds).toInstantOrNull()
            ?: return null
    return StoredLocalInstallation(
        localIdentity = LocalInstallationIdentity(parsedInstallationId.value),
        createdAt = createdAt,
    )
}

internal fun ServerConfigurationEntity.toStoredConfigurationOrNull(): StoredServerConfiguration? {
    if (singletonId != LOCAL_STATE_SINGLETON_ID) return null
    val parsedBaseUrl = ServerBaseUrl.parse(baseUrl)
    if (parsedBaseUrl !is Valid || parsedBaseUrl.value.toString() != baseUrl) return null
    val validatedNanoseconds = updatedAtNanoseconds.toValidatedNanosecondsOrNull()
        ?: return null
    val updatedAt =
        PersistedInstant(updatedAtEpochSeconds, validatedNanoseconds).toInstantOrNull()
            ?: return null
    return StoredServerConfiguration(
        configuration = ServerConfiguration(parsedBaseUrl.value),
        updatedAt = updatedAt,
    )
}

internal fun LocalInstallationIdentity.toEntity(createdAt: Instant): LocalInstallationEntity {
    val timestamp = PersistedInstant.from(createdAt)
    return LocalInstallationEntity(
        singletonId = LOCAL_STATE_SINGLETON_ID,
        installationId = installationId.toString(),
        createdAtEpochSeconds = timestamp.epochSeconds,
        createdAtNanoseconds = timestamp.nanoseconds.toLong(),
    )
}

internal fun ServerConfiguration.toEntity(updatedAt: Instant): ServerConfigurationEntity {
    val timestamp = PersistedInstant.from(updatedAt)
    return ServerConfigurationEntity(
        singletonId = LOCAL_STATE_SINGLETON_ID,
        baseUrl = baseUrl.toString(),
        updatedAtEpochSeconds = timestamp.epochSeconds,
        updatedAtNanoseconds = timestamp.nanoseconds.toLong(),
    )
}

private fun Long.toValidatedNanosecondsOrNull(): Int? {
    if (this !in MIN_NANOSECOND..MAX_NANOSECOND) return null
    return toInt()
}

internal sealed interface MappedLocalState {
    data object Absent : MappedLocalState

    data class InstallationOnly(val installation: StoredLocalInstallation) : MappedLocalState

    data class Configured(
        val installation: StoredLocalInstallation,
        val serverConfiguration: StoredServerConfiguration,
    ) : MappedLocalState

    data object Incomplete : MappedLocalState
}

internal fun LocalStateRows.toMappedLocalState(): MappedLocalState {
    if (installations.size > 1 || serverConfigurations.size > 1) {
        return MappedLocalState.Incomplete
    }
    val installationEntity = installations.singleOrNull()
    val serverEntity = serverConfigurations.singleOrNull()
    if (installationEntity == null) {
        return if (serverEntity == null) MappedLocalState.Absent else MappedLocalState.Incomplete
    }
    val installation = installationEntity.toStoredInstallationOrNull()
        ?: return MappedLocalState.Incomplete
    if (serverEntity == null) return MappedLocalState.InstallationOnly(installation)
    val serverConfiguration = serverEntity.toStoredConfigurationOrNull()
        ?: return MappedLocalState.Incomplete
    return MappedLocalState.Configured(installation, serverConfiguration)
}
