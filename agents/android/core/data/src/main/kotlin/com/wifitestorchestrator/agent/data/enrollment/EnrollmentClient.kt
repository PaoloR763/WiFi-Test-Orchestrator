package com.wifitestorchestrator.agent.data.enrollment

interface EnrollmentClient {
    fun newCall(command: EnrollmentCommand): EnrollmentCall
}

interface EnrollmentCall {
    val isCanceled: Boolean

    fun execute(): EnrollmentResult

    fun cancel()
}

object EnrollmentClients {
    private val sharedClient: EnrollmentClient by lazy {
        OkHttpEnrollmentClient(EnrollmentHttpClientPolicy.shared)
    }

    fun default(): EnrollmentClient = sharedClient
}
