package com.wifitestorchestrator.agent.contracts.enrollment

object AgentEnrollmentContract {
    const val PATH: String = "/api/v1/agent-enrollments"
    const val IDEMPOTENCY_HEADER: String = "Idempotency-Key"
    const val CORRELATION_HEADER: String = "X-Correlation-ID"
}
