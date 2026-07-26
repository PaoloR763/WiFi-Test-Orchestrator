package com.wifitestorchestrator.agent.data.capability.http

import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestAcceptedDto
import com.wifitestorchestrator.agent.contracts.capability.CapabilityManifestContract
import com.wifitestorchestrator.agent.data.capability.CapabilityJson
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestAcknowledgement
import com.wifitestorchestrator.agent.data.capability.CanonicalJson
import com.wifitestorchestrator.agent.data.capability.Sha256Value
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentWireTimestamp
import com.wifitestorchestrator.agent.data.enrollment.JsonDuplicateKeyDetector
import com.wifitestorchestrator.agent.data.enrollment.RawJsonValidation
import com.wifitestorchestrator.agent.domain.enrollment.AgentCredentialSecret
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.ProtocolException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.zip.ZipException
import javax.net.ssl.SSLException
import kotlinx.serialization.SerializationException
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSink

internal class OkHttpCapabilityManifestClient(
    private val httpClient: OkHttpClient,
) : CapabilityManifestHttpClient {
    override fun execute(
        command: CapabilityManifestHttpCommand,
        credential: AgentCredentialSecret,
        cancellation: CredentialScopedHttpCancellation,
    ): CapabilityManifestHttpResult {
        if (
            command.canonicalPayload.isEmpty() ||
            command.canonicalPayload.size > CapabilityManifestContract.MAX_REQUEST_BYTES
        ) {
            return CapabilityManifestHttpResult.InvalidLocalRequest
        }
        var call: okhttp3.Call? = null
        return try {
            val request =
                credential.useSecret { plaintext ->
                    Request
                        .Builder()
                        .url(command.endpointUrl)
                        .put(OneShotManifestBody(command.canonicalPayload))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .header(
                            CapabilityManifestContract.AUTHORIZATION_HEADER,
                            "Bearer $plaintext",
                        ).header(
                            CapabilityManifestContract.AGENT_TIMESTAMP_HEADER,
                            command.timestamp,
                        ).header(
                            CapabilityManifestContract.AGENT_NONCE_HEADER,
                            command.nonce,
                        ).header(
                            CapabilityManifestContract.AGENT_PROTOCOL_HEADER,
                            CapabilityManifestContract.SCHEMA_VERSION,
                        ).header(
                            CapabilityManifestContract.CORRELATION_HEADER,
                            command.correlationId,
                        ).build()
                }
            call = httpClient.newCall(request)
            val activeCall = requireNotNull(call)
            cancellation.register(activeCall::cancel)
            if (cancellation.isCancellationRequested()) {
                return CapabilityManifestHttpResult.Cancelled
            }
            var responseReceived = false
            try {
                val response = activeCall.execute()
                responseReceived = true
                response.use { processResponse(it, command) }
            } catch (failure: IOException) {
                if (cancellation.isCancellationRequested()) {
                    CapabilityManifestHttpResult.Cancelled
                } else {
                    CapabilityManifestHttpResult.Ambiguous(
                        classifyTransportFailure(responseReceived, failure),
                    )
                }
            }
        } catch (_: IllegalArgumentException) {
            CapabilityManifestHttpResult.InvalidLocalRequest
        } finally {
            cancellation.clear()
            call = null
        }
    }

    private fun processResponse(
        response: Response,
        command: CapabilityManifestHttpCommand,
    ): CapabilityManifestHttpResult {
        if (response.code in 300..399) {
            return CapabilityManifestHttpResult.Rejected(
                CapabilityManifestRejection.REDIRECT,
            )
        }
        if (response.code != 200) {
            return CapabilityManifestHttpResult.Rejected(
                rejectionFor(response.code),
            )
        }
        if (!hasExactCorrelation(response, command.correlationId)) {
            return CapabilityManifestHttpResult.InvalidAcknowledgement(
                InvalidAcknowledgementReason.CORRELATION,
            )
        }
        if (!hasAcceptedContentType(response)) {
            return CapabilityManifestHttpResult.InvalidAcknowledgement(
                InvalidAcknowledgementReason.CONTENT_TYPE,
            )
        }
        val body =
            when (val bounded = readBounded(response.body)) {
                is BoundedBody.Valid -> bounded.bytes
                BoundedBody.TooLarge ->
                    return CapabilityManifestHttpResult.InvalidAcknowledgement(
                        InvalidAcknowledgementReason.BODY_TOO_LARGE,
                    )
            }
        val raw =
            CanonicalJson.decodeUtf8Strict(body)
                ?: return CapabilityManifestHttpResult.InvalidAcknowledgement(
                    InvalidAcknowledgementReason.MALFORMED_JSON,
                )
        when (JsonDuplicateKeyDetector.validate(raw)) {
            RawJsonValidation.DUPLICATE_PROPERTY ->
                return CapabilityManifestHttpResult.InvalidAcknowledgement(
                    InvalidAcknowledgementReason.DUPLICATE_KEY,
                )
            RawJsonValidation.MALFORMED ->
                return CapabilityManifestHttpResult.InvalidAcknowledgement(
                    InvalidAcknowledgementReason.MALFORMED_JSON,
                )
            RawJsonValidation.VALID -> Unit
        }
        val dto =
            try {
                CapabilityJson.strict.decodeFromString(
                    CapabilityManifestAcceptedDto.serializer(),
                    raw,
                )
            } catch (_: SerializationException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            }
                ?: return CapabilityManifestHttpResult.InvalidAcknowledgement(
                    InvalidAcknowledgementReason.UNKNOWN_OR_MISSING_FIELD,
                )
        if (dto.schemaVersion != CapabilityManifestContract.SCHEMA_VERSION) {
            return CapabilityManifestHttpResult.InvalidAcknowledgement(
                InvalidAcknowledgementReason.SCHEMA_VERSION,
            )
        }
        if (dto.manifestId != command.expectedManifestId) {
            return CapabilityManifestHttpResult.InvalidAcknowledgement(
                InvalidAcknowledgementReason.MANIFEST_ID,
            )
        }
        if (!LOWERCASE_SHA256.matches(dto.manifestDigest)) {
            return CapabilityManifestHttpResult.InvalidAcknowledgement(
                InvalidAcknowledgementReason.MANIFEST_DIGEST,
            )
        }
        val digest =
            dto.manifestDigest.hexSha256OrNull()
                ?: return CapabilityManifestHttpResult.InvalidAcknowledgement(
                    InvalidAcknowledgementReason.MANIFEST_DIGEST,
                )
        val expectedDigest =
            command.canonicalPayload.sha256ForHttp()
                ?: return CapabilityManifestHttpResult.InvalidLocalRequest
        if (!digest.contentEquals(expectedDigest)) {
            return CapabilityManifestHttpResult.InvalidAcknowledgement(
                InvalidAcknowledgementReason.MANIFEST_DIGEST,
            )
        }
        val receivedAt =
            EnrollmentWireTimestamp.parse(dto.serverReceivedAt)
                ?: return CapabilityManifestHttpResult.InvalidAcknowledgement(
                    InvalidAcknowledgementReason.SERVER_TIMESTAMP,
                )
        return CapabilityManifestHttpResult.Accepted(
            CapabilityManifestAcknowledgement(
                manifestId = dto.manifestId,
                manifestDigest = digest,
                serverReceivedAt = receivedAt,
            ),
        )
    }
}

private class OneShotManifestBody(private val bytes: ByteArray) : RequestBody() {
    override fun contentType(): MediaType = APPLICATION_JSON

    override fun contentLength(): Long = bytes.size.toLong()

    override fun isOneShot(): Boolean = true

    override fun writeTo(sink: BufferedSink) {
        sink.write(bytes)
    }

    override fun toString(): String = "OneShotManifestBody(<redacted>)"
}

private fun hasExactCorrelation(response: Response, expected: String): Boolean {
    val values = response.headers.values(CapabilityManifestContract.CORRELATION_HEADER)
    return values.size == 1 && values.single() == expected
}

private fun hasAcceptedContentType(response: Response): Boolean {
    val values = response.headers.values("Content-Type")
    return values.size == 1 && ACCEPTED_CONTENT_TYPE.matches(values.single().trim())
}

private fun rejectionFor(status: Int): CapabilityManifestRejection =
    when (status) {
        401 -> CapabilityManifestRejection.AUTHENTICATION_BLOCKED
        409 -> CapabilityManifestRejection.CONFLICT
        413 -> CapabilityManifestRejection.REQUEST_TOO_LARGE
        422, 426 -> CapabilityManifestRejection.CONTRACT_INCOMPATIBLE
        429 -> CapabilityManifestRejection.RATE_LIMITED
        503 -> CapabilityManifestRejection.SERVICE_UNAVAILABLE
        else -> CapabilityManifestRejection.UNEXPECTED_STATUS
    }

private sealed interface BoundedBody {
    data class Valid(val bytes: ByteArray) : BoundedBody {
        override fun toString(): String = "BoundedBody.Valid(<redacted>)"
    }

    data object TooLarge : BoundedBody
}

private fun readBounded(body: ResponseBody): BoundedBody {
    val announced = body.contentLength()
    if (announced > CapabilityManifestContract.MAX_RESPONSE_BYTES) return BoundedBody.TooLarge
    val output =
        ByteArrayOutputStream(
            if (announced in 1..CapabilityManifestContract.MAX_RESPONSE_BYTES) {
                announced.toInt()
            } else {
                1_024
            },
        )
    val buffer = ByteArray(8_192)
    body.byteStream().use { stream ->
        var total = 0
        while (true) {
            val remaining = CapabilityManifestContract.MAX_RESPONSE_BYTES + 1 - total
            if (remaining <= 0) return BoundedBody.TooLarge
            val read = stream.read(buffer, 0, minOf(buffer.size, remaining))
            if (read == -1) break
            if (read == 0) continue
            output.write(buffer, 0, read)
            total += read
            if (total > CapabilityManifestContract.MAX_RESPONSE_BYTES) {
                return BoundedBody.TooLarge
            }
        }
    }
    return BoundedBody.Valid(output.toByteArray())
}

private fun classifyTransportFailure(
    responseReceived: Boolean,
    failure: IOException,
): CapabilityManifestTransportFailure =
    when {
        failure is UnknownHostException -> CapabilityManifestTransportFailure.DNS
        failure is SSLException -> CapabilityManifestTransportFailure.TLS
        failure is SocketTimeoutException || failure is InterruptedIOException ->
            CapabilityManifestTransportFailure.TIMEOUT
        failure is ConnectException || failure is NoRouteToHostException ->
            CapabilityManifestTransportFailure.CONNECTION
        responseReceived ||
            failure is EOFException ||
            failure is ProtocolException ||
            failure is ZipException ->
            CapabilityManifestTransportFailure.INCOMPLETE_RESPONSE
        else -> CapabilityManifestTransportFailure.IO
    }

private fun String.hexSha256OrNull(): Sha256Value? {
    if (length != 64) return null
    val bytes = ByteArray(32)
    for (index in bytes.indices) {
        val value = substring(index * 2, index * 2 + 2).toIntOrNull(16) ?: return null
        bytes[index] = value.toByte()
    }
    return Sha256Value.from(bytes)
}

private fun ByteArray.sha256ForHttp(): Sha256Value? =
    Sha256Value.from(java.security.MessageDigest.getInstance("SHA-256").digest(this))

private val APPLICATION_JSON = "application/json".toMediaType()
private val ACCEPTED_CONTENT_TYPE =
    Regex(
        "^application/json(?:\\s*;\\s*charset\\s*=\\s*utf-8)?$",
        RegexOption.IGNORE_CASE,
    )
private val LOWERCASE_SHA256 = Regex("[0-9a-f]{64}")
