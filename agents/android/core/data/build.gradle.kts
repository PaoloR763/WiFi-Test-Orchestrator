import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.wifitestorchestrator.agent.core.data"

    compileSdk {
        version = release(libs.versions.android.compile.api.get().toInt()) {
            minorApiLevel = libs.versions.android.compile.minor.get().toInt()
        }
    }

    defaultConfig {
        minSdk = libs.versions.android.min.sdk.get().toInt()
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(libs.versions.java.get().toInt())
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":core:contracts"))
    implementation(project(":core:domain"))
}
