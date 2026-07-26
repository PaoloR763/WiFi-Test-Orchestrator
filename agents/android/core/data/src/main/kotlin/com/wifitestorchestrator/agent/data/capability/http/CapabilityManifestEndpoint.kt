package com.wifitestorchestrator.agent.data.capability.http

import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestContract
import com.wifitestorchestrator.agent.domain.configuration.ServerConfiguration
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

internal object CapabilityManifestEndpoint {
    private val pathSegments =
        CapabilityManifestContract.PATH.split('/').filter(String::isNotEmpty)

    fun build(configuration: ServerConfiguration): String? {
        val base = configuration.baseUrl.toString().toHttpUrlOrNull() ?: return null
        if (!base.isHttps || base.query != null || base.fragment != null) return null
        val builder = base.newBuilder()
        pathSegments.forEach(builder::addPathSegment)
        val endpoint = builder.build()
        return endpoint
            .takeIf {
                it.isHttps &&
                    it.host == base.host &&
                    it.port == base.port &&
                    it.query == null &&
                    it.fragment == null
            }?.toString()
    }
}
