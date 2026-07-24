package com.wifitestorchestrator.agent

import android.app.Application
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentHttpRuntime

class WtoApplication : Application() {
    val compositionRoot: AndroidAgentCompositionRoot by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            AndroidAgentCompositionRoot(applicationContext)
        }

    override fun onCreate() {
        super.onCreate()
        EnrollmentHttpRuntime.initialize(applicationContext)
    }
}
