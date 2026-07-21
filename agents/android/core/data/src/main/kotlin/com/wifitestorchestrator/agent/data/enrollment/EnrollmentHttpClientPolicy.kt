package com.wifitestorchestrator.agent.data.enrollment

import java.util.concurrent.TimeUnit
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.OkHttpClient

internal object EnrollmentHttpClientPolicy {
    val shared: OkHttpClient by lazy(::build)

    fun build(): OkHttpClient =
        OkHttpClient
            .Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(20, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .fastFallback(false)
            .followRedirects(false)
            .followSslRedirects(false)
            .cache(null)
            .cookieJar(CookieJar.NO_COOKIES)
            .authenticator(Authenticator.NONE)
            .proxyAuthenticator(Authenticator.NONE)
            .build()
}
