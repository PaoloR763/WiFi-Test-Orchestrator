package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentEnrollmentContract
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

private val enrollmentEndpointSegments =
    AgentEnrollmentContract.PATH
        .split('/')
        .filter(String::isNotEmpty)

internal fun HttpUrl.hasEnrollmentEndpointSuffix(): Boolean {
    val effectivePathSegments =
        pathSegments.let { segments ->
            if (segments.lastOrNull() == "") segments.dropLast(1) else segments
        }
    return effectivePathSegments.size >= enrollmentEndpointSegments.size &&
        effectivePathSegments.takeLast(enrollmentEndpointSegments.size) == enrollmentEndpointSegments
}

internal object EnrollmentEndpoint {
    fun build(configuration: ServerConfiguration): String? {
        val base = configuration.baseUrl.toString().toHttpUrlOrNull() ?: return null
        if (!base.isHttps || base.query != null || base.fragment != null) return null

        if (base.hasEnrollmentEndpointSuffix()) return null

        val builder = base.newBuilder()
        enrollmentEndpointSegments.forEach(builder::addPathSegment)
        val endpoint = builder.build()
        return if (
            endpoint.isHttps &&
            endpoint.host == base.host &&
            endpoint.port == base.port &&
            endpoint.query == null &&
            endpoint.fragment == null
        ) {
            endpoint.toString()
        } else {
            null
        }
    }
}
