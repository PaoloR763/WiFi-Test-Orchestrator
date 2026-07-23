import org.gradle.api.tasks.Sync
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.wifitestorchestrator.agent.core.platform"

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

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    jvmToolchain(libs.versions.java.get().toInt())
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

val robolectricSdk by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    isTransitive = false
}

val robolectricDependencyDirectory = layout.buildDirectory.dir("robolectric-dependencies")
val prepareRobolectricSdk by tasks.registering(Sync::class) {
    from(robolectricSdk)
    into(robolectricDependencyDirectory)
}

dependencies {
    implementation(project(":core:domain"))

    testImplementation(libs.robolectric)
    testImplementation(kotlin("test-junit"))

    add(robolectricSdk.name, libs.robolectric.android.all.instrumented)
}

tasks.withType<Test>().configureEach {
    dependsOn(prepareRobolectricSdk)
    doFirst {
        systemProperty("wto.android.platform.projectDir", layout.projectDirectory.asFile.absolutePath)
        systemProperty("robolectric.offline", "true")
        systemProperty(
            "robolectric.dependency.dir",
            robolectricDependencyDirectory.get().asFile.absolutePath,
        )
    }
}
