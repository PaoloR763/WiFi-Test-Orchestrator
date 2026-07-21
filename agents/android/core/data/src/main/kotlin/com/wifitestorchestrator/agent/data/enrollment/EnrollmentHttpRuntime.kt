package com.wifitestorchestrator.agent.data.enrollment

import android.content.Context
import okhttp3.OkHttp

object EnrollmentHttpRuntime {
    fun initialize(applicationContext: Context) {
        OkHttp.initialize(applicationContext)
    }
}
