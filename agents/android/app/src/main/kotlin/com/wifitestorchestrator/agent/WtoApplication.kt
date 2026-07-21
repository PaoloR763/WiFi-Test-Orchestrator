package com.wifitestorchestrator.agent

import android.app.Application
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentHttpRuntime

class WtoApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        EnrollmentHttpRuntime.initialize(applicationContext)
    }
}
