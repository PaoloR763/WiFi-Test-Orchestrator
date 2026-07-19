package com.wifitestorchestrator.agent.contracts.error

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ErrorEnvelopeDto(
    @SerialName("schema_version")
    val schemaVersion: String,
    @SerialName("error")
    val error: ApiErrorDto,
)

@Serializable
data class ApiErrorDto(
    @SerialName("code")
    val code: String,
    @SerialName("message")
    val message: String,
    @SerialName("details")
    val details: List<ErrorDetailDto>?,
    @SerialName("correlation_id")
    val correlationId: String,
)

@Serializable
data class ErrorDetailDto(
    @SerialName("location")
    val location: List<String>,
    @SerialName("type")
    val type: String,
)
