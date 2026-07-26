package com.wifitestorchestrator.agent.data.capability

import com.wifitestorchestrator.agent.data.persistence.StoredProtectedEnrollment
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal object EnrollmentBindingFingerprint {
    private const val DOMAIN = "wto.android.enrollment-binding.v1"

    fun compute(enrollment: StoredProtectedEnrollment): Sha256Value? {
        val document =
            JsonObject(
                mapOf(
                    "domain" to JsonPrimitive(DOMAIN),
                    "installation_id" to
                        JsonPrimitive(enrollment.localIdentity.installationId.toString()),
                    "server_base_url" to
                        JsonPrimitive(enrollment.serverConfiguration.baseUrl.toString()),
                    "agent_id" to
                        JsonPrimitive(enrollment.backendIdentity.agentId.toString()),
                    "device_id" to
                        JsonPrimitive(enrollment.backendIdentity.deviceId.toString()),
                    "protocol_version" to
                        JsonPrimitive(enrollment.protocolVersion.toString()),
                ),
            )
        return CanonicalJson.encode(document)?.sha256()
    }
}
