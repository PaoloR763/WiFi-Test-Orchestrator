package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.contracts.enrollment.AgentEnrollmentContract
import com.wifitestorchestrator.agent.domain.error.Invalid
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.ProtocolException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.zip.ZipException
import javax.net.ssl.SSLException
import okhttp3.Call
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.BufferedSink

private const val MAX_RESPONSE_BYTES = 65_536
private const val RESPONSE_READ_LIMIT = MAX_RESPONSE_BYTES + 1
private val applicationJson: MediaType = "application/json".toMediaType()
private val acceptedContentType =
    Regex(
        pattern = "^application/json(?:\\s*;\\s*charset\\s*=\\s*utf-8)?$",
        option = RegexOption.IGNORE_CASE,
    )

internal class OkHttpEnrollmentClient(
    private val httpClient: OkHttpClient,
) : EnrollmentClient {
    override fun newCall(command: EnrollmentCommand): EnrollmentCall {
        val payload =
            try {
                EnrollmentJson.encodeValidatedRequest(command)
            } catch (_: RuntimeException) {
                null
            }
                ?: return ImmediateEnrollmentCall(EnrollmentFailureReason.INVALID_LOCAL_REQUEST)
        val request =
            try {
                Request
                    .Builder()
                    .url(command.endpointUrl)
                    .post(OneShotJsonRequestBody(payload))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header(
                        AgentEnrollmentContract.IDEMPOTENCY_HEADER,
                        command.idempotencyKey.toString(),
                    ).header(
                        AgentEnrollmentContract.CORRELATION_HEADER,
                        command.correlationId.toString(),
                    ).build()
            } catch (_: IllegalArgumentException) {
                return ImmediateEnrollmentCall(EnrollmentFailureReason.INVALID_LOCAL_REQUEST)
            }
        return RealEnrollmentCall(
            call = httpClient.newCall(request),
            localIdentity = command.localIdentity,
            requestedCorrelationId = command.correlationId,
        )
    }
}

private class OneShotJsonRequestBody(private val bytes: ByteArray) : RequestBody() {
    override fun contentType(): MediaType = applicationJson

    override fun contentLength(): Long = bytes.size.toLong()

    override fun isOneShot(): Boolean = true

    override fun writeTo(sink: BufferedSink) {
        sink.write(bytes)
    }

    override fun toString(): String = "OneShotJsonRequestBody(<redacted>)"
}

private class ImmediateEnrollmentCall(
    private val failure: EnrollmentFailureReason,
) : EnrollmentCall {
    private val canceled = AtomicBoolean(false)
    private val executed = AtomicBoolean(false)

    override val isCanceled: Boolean
        get() = canceled.get()

    override fun execute(): EnrollmentResult {
        if (!executed.compareAndSet(false, true)) {
            return EnrollmentResult.Failed(EnrollmentFailureReason.INVALID_LOCAL_REQUEST)
        }
        return if (canceled.get()) {
            EnrollmentResult.Failed(EnrollmentFailureReason.CANCELLED)
        } else {
            EnrollmentResult.Failed(failure)
        }
    }

    override fun cancel() {
        canceled.set(true)
    }
}

private class RealEnrollmentCall(
    private val call: Call,
    private val localIdentity: com.wifitestorchestrator.agent.domain.identity.LocalInstallationIdentity,
    private val requestedCorrelationId: CorrelationId,
) : EnrollmentCall {
    private val executed = AtomicBoolean(false)
    private val cancellationRequested = AtomicBoolean(false)

    override val isCanceled: Boolean
        get() = call.isCanceled()

    override fun execute(): EnrollmentResult {
        if (!executed.compareAndSet(false, true)) {
            return EnrollmentResult.Failed(EnrollmentFailureReason.INVALID_LOCAL_REQUEST)
        }
        var responseReceived = false
        return try {
            val response = call.execute()
            responseReceived = true
            response.use(::processResponse)
        } catch (error: IOException) {
            EnrollmentResult.Failed(
                classifyTransportFailure(
                    cancellationRequested = cancellationRequested.get(),
                    responseReceived = responseReceived,
                    error = error,
                ),
            )
        } catch (_: RuntimeException) {
            EnrollmentResult.Failed(
                if (cancellationRequested.get()) {
                    EnrollmentFailureReason.CANCELLED
                } else {
                    EnrollmentFailureReason.IO
                },
            )
        }
    }

    override fun cancel() {
        cancellationRequested.set(true)
        call.cancel()
    }

    private fun processResponse(response: Response): EnrollmentResult {
        if (response.code in 300..399) {
            return EnrollmentResult.Failed(EnrollmentFailureReason.REDIRECT)
        }
        val rejectionReason = rejectionFor(response.code)
        if (response.code != 201 && rejectionReason == null) {
            return EnrollmentResult.Failed(EnrollmentFailureReason.UNEXPECTED_STATUS)
        }
        val responseCorrelation =
            when (val validation = validateCorrelationHeader(response, requestedCorrelationId)) {
                is ResponseCorrelation.Valid -> validation.value
                is ResponseCorrelation.Invalid ->
                    return EnrollmentResult.Failed(validation.reason)
            }
        if (!hasAcceptedContentType(response)) {
            return EnrollmentResult.Failed(EnrollmentFailureReason.INVALID_CONTENT_TYPE)
        }
        val bytes =
            when (val body = readBounded(response.body)) {
                is BoundedBody.Valid -> body.bytes
                BoundedBody.TooLarge ->
                    return EnrollmentResult.Failed(EnrollmentFailureReason.RESPONSE_TOO_LARGE)
            }
        return if (response.code == 201) {
            processAccepted(bytes, responseCorrelation)
        } else {
            processRejected(bytes, response.code, rejectionReason!!, responseCorrelation)
        }
    }

    private fun processAccepted(
        bytes: ByteArray,
        responseCorrelation: CorrelationId,
    ): EnrollmentResult =
        when (val decoded = EnrollmentPayloadDecoder.decodeSuccess(bytes)) {
            is DecodedPayload.Failure -> EnrollmentResult.Failed(decoded.reason)
            is DecodedPayload.Success ->
                when (val mapped = EnrollmentResponseMapper.map(decoded.value, localIdentity)) {
                    EnrollmentDomainMappingResult.Invalid ->
                        EnrollmentResult.Failed(
                            EnrollmentFailureReason.INVALID_RESPONSE_SEMANTICS,
                        )
                    is EnrollmentDomainMappingResult.Valid ->
                        EnrollmentResult.Accepted(mapped.value, responseCorrelation)
                }
        }

    private fun processRejected(
        bytes: ByteArray,
        statusCode: Int,
        reason: EnrollmentRejectionReason,
        responseCorrelation: CorrelationId,
    ): EnrollmentResult {
        return when (val decoded = EnrollmentPayloadDecoder.decodeError(bytes)) {
            is DecodedPayload.Failure -> EnrollmentResult.Failed(decoded.reason)
            is DecodedPayload.Success -> {
                val bodyCorrelation =
                    when (val parsed = CorrelationId.parse(decoded.value.error.correlationId)) {
                        is Valid -> parsed.value
                        is Invalid ->
                            return EnrollmentResult.Failed(
                                EnrollmentFailureReason.MISSING_CORRELATION,
                            )
                    }
                if (
                    bodyCorrelation != requestedCorrelationId ||
                    bodyCorrelation != responseCorrelation
                ) {
                    EnrollmentResult.Failed(EnrollmentFailureReason.CORRELATION_MISMATCH)
                } else {
                    EnrollmentResult.Rejected(reason, statusCode, responseCorrelation)
                }
            }
        }
    }
}

private fun rejectionFor(statusCode: Int): EnrollmentRejectionReason? =
    when (statusCode) {
        401 -> EnrollmentRejectionReason.AUTHENTICATION_TOKEN_OR_CLOCK_REJECTED
        409 -> EnrollmentRejectionReason.CONFLICT
        413 -> EnrollmentRejectionReason.REQUEST_TOO_LARGE
        422 -> EnrollmentRejectionReason.CONTRACT_REJECTED
        429 -> EnrollmentRejectionReason.RATE_LIMITED
        503 -> EnrollmentRejectionReason.SERVICE_UNAVAILABLE
        else -> null
    }

private sealed interface ResponseCorrelation {
    data class Valid(val value: CorrelationId) : ResponseCorrelation

    data class Invalid(val reason: EnrollmentFailureReason) : ResponseCorrelation
}

private fun validateCorrelationHeader(
    response: Response,
    requested: CorrelationId,
): ResponseCorrelation {
    val values = response.headers.values(AgentEnrollmentContract.CORRELATION_HEADER)
    if (values.size != 1 || values.single().isEmpty()) {
        return ResponseCorrelation.Invalid(EnrollmentFailureReason.MISSING_CORRELATION)
    }
    val parsed =
        when (val result = CorrelationId.parse(values.single())) {
            is Valid -> result.value
            is Invalid ->
                return ResponseCorrelation.Invalid(EnrollmentFailureReason.MISSING_CORRELATION)
        }
    return if (parsed == requested) {
        ResponseCorrelation.Valid(parsed)
    } else {
        ResponseCorrelation.Invalid(EnrollmentFailureReason.CORRELATION_MISMATCH)
    }
}

private fun hasAcceptedContentType(response: Response): Boolean {
    val values = response.headers.values("Content-Type")
    if (values.size != 1) return false
    return acceptedContentType.matches(values.single().trim())
}

private sealed interface BoundedBody {
    data class Valid(val bytes: ByteArray) : BoundedBody {
        override fun toString(): String = "BoundedBody.Valid(<redacted>)"
    }

    data object TooLarge : BoundedBody
}

private fun readBounded(body: ResponseBody): BoundedBody {
    val announcedLength = body.contentLength()
    if (announcedLength > MAX_RESPONSE_BYTES) return BoundedBody.TooLarge

    val output = ByteArrayOutputStream(
        if (announcedLength in 1..MAX_RESPONSE_BYTES) announcedLength.toInt() else 1_024,
    )
    val buffer = ByteArray(8_192)
    body.byteStream().use { stream ->
        var total = 0
        while (true) {
            val remaining = RESPONSE_READ_LIMIT - total
            if (remaining <= 0) return BoundedBody.TooLarge
            val read = stream.read(buffer, 0, minOf(buffer.size, remaining))
            if (read == -1) break
            if (read == 0) continue
            output.write(buffer, 0, read)
            total += read
            if (total > MAX_RESPONSE_BYTES) return BoundedBody.TooLarge
        }
    }
    return BoundedBody.Valid(output.toByteArray())
}

private fun classifyTransportFailure(
    cancellationRequested: Boolean,
    responseReceived: Boolean,
    error: IOException,
): EnrollmentFailureReason =
    when {
        cancellationRequested -> EnrollmentFailureReason.CANCELLED
        error is UnknownHostException -> EnrollmentFailureReason.DNS
        error is SSLException -> EnrollmentFailureReason.TLS
        error is SocketTimeoutException -> EnrollmentFailureReason.TIMEOUT
        error is InterruptedIOException -> EnrollmentFailureReason.TIMEOUT
        error is ConnectException || error is NoRouteToHostException ->
            EnrollmentFailureReason.CONNECTION
        responseReceived ||
            error is EOFException ||
            error is ProtocolException ||
            error is ZipException ->
            EnrollmentFailureReason.INCOMPLETE_RESPONSE
        else -> EnrollmentFailureReason.IO
    }
