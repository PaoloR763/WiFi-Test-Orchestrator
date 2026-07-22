import org.gradle.api.tasks.Sync
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.androidx.room)
    alias(libs.plugins.ksp)
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

room {
    schemaDirectory("$projectDir/schemas")
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
    implementation(project(":core:contracts"))
    implementation(project(":core:domain"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.androidx.room.runtime)

    ksp(libs.androidx.room.compiler)

    testImplementation(libs.okhttp.mockwebserver3)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.androidx.room.testing)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.robolectric)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(kotlin("test-junit"))

    add(robolectricSdk.name, libs.robolectric.android.all.instrumented)
}

tasks.withType<Test>().configureEach {
    dependsOn(prepareRobolectricSdk)
    doFirst {
        systemProperty("wto.android.data.projectDir", layout.projectDirectory.asFile.absolutePath)
        systemProperty("robolectric.offline", "true")
        systemProperty(
            "robolectric.dependency.dir",
            robolectricDependencyDirectory.get().asFile.absolutePath,
        )
    }
}
