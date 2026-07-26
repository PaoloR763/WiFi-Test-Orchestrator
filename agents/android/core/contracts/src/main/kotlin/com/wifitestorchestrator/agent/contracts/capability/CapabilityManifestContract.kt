package com.wifitestorchestrator.agent.contracts.capability

object CapabilityManifestContract {
    const val PATH: String = "/api/v1/agents/self/capability-manifest"
    const val SCHEMA_VERSION: String = "1.0.0"
    const val CAPABILITY_VERSION: String = "1.0.0"
    const val CATALOG_VERSION: String = "1.0.0"
    const val PLATFORM: String = "android"
    const val MAX_REQUEST_BYTES: Int = 262_144
    const val MAX_RESPONSE_BYTES: Int = 65_536

    const val AUTHORIZATION_HEADER: String = "Authorization"
    const val AGENT_TIMESTAMP_HEADER: String = "X-WTO-Agent-Timestamp"
    const val AGENT_NONCE_HEADER: String = "X-WTO-Agent-Nonce"
    const val AGENT_PROTOCOL_HEADER: String = "X-WTO-Agent-Protocol"
    const val CORRELATION_HEADER: String = "X-Correlation-ID"
}
