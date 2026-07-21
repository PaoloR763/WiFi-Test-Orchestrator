package com.wifitestorchestrator.agent.data.enrollment

import com.wifitestorchestrator.agent.domain.identity.CorrelationId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.OkHttpClient

class EnrollmentSecurityPolicyTest {
    @Test
    fun productionClientHasTheExactHardenedPolicy() {
        val client = EnrollmentHttpClientPolicy.build()
        val platformDefaults = OkHttpClient()

        assertEquals(10_000, client.connectTimeoutMillis)
        assertEquals(20_000, client.readTimeoutMillis)
        assertEquals(20_000, client.writeTimeoutMillis)
        assertEquals(30_000, client.callTimeoutMillis)
        assertFalse(client.retryOnConnectionFailure)
        assertFalse(client.fastFallback)
        assertFalse(client.followRedirects)
        assertFalse(client.followSslRedirects)
        assertNull(client.cache)
        assertSame(CookieJar.NO_COOKIES, client.cookieJar)
        assertSame(Authenticator.NONE, client.authenticator)
        assertSame(Authenticator.NONE, client.proxyAuthenticator)
        assertTrue(client.interceptors.isEmpty())
        assertTrue(client.networkInterceptors.isEmpty())
        assertSame(Dns.SYSTEM, client.dns)
        assertTrue(client.certificatePinner.pins.isEmpty())
        assertEquals(platformDefaults.hostnameVerifier, client.hostnameVerifier)
        assertEquals(platformDefaults.sslSocketFactory.javaClass, client.sslSocketFactory.javaClass)
        assertNotNull(client.x509TrustManager)
        assertEquals(
            platformDefaults.x509TrustManager?.javaClass,
            client.x509TrustManager?.javaClass,
        )
    }

    @Test
    fun publicResultsCannotCarryThrowableUrlOrBody() {
        val correlationId = validValue(CorrelationId.parse(TEST_CORRELATION_ID))
        val rejected =
            EnrollmentResult.Rejected(
                EnrollmentRejectionReason.RATE_LIMITED,
                429,
                correlationId,
            )
        val failed = EnrollmentResult.Failed(EnrollmentFailureReason.IO)

        assertEquals(
            setOf("reason", "statusCode", "correlationId"),
            EnrollmentResult.Rejected::class.java.declaredFields.map { it.name }.toSet(),
        )
        assertEquals(
            setOf("reason"),
            EnrollmentResult.Failed::class.java.declaredFields.map { it.name }.toSet(),
        )
        assertFalse(rejected.toString().contains("Throwable"))
        assertFalse(rejected.toString().contains("http"))
        assertFalse(rejected.toString().contains(TEST_CORRELATION_ID))
        assertFalse(failed.toString().contains("Throwable"))
    }

    @Test
    fun publicClientBoundaryDoesNotExposeOkHttpTypes() {
        val exposedTypes =
            listOf(
                EnrollmentClient::class.java,
                EnrollmentCall::class.java,
                EnrollmentClients::class.java,
                EnrollmentCommand::class.java,
                EnrollmentCommandCreationResult::class.java,
                EnrollmentResult::class.java,
                EnrollmentResult.Accepted::class.java,
                EnrollmentResult.Rejected::class.java,
                EnrollmentResult.Failed::class.java,
                EnrollmentHttpRuntime::class.java,
            ).flatMap { type ->
                type.declaredMethods.flatMap { method ->
                    method.parameterTypes.toList() + method.returnType
                } + type.declaredFields.map { field -> field.type }
            }
                .map(Class<*>::getName)

        assertFalse(exposedTypes.any { it.startsWith("okhttp3.") })
    }
}
