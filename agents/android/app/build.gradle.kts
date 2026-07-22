import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.wifitestorchestrator.agent"

    compileSdk {
        version = release(libs.versions.android.compile.api.get().toInt()) {
            minorApiLevel = libs.versions.android.compile.minor.get().toInt()
        }
    }

    defaultConfig {
        applicationId = "com.wifitestorchestrator.agent"
        minSdk = libs.versions.android.min.sdk.get().toInt()
        targetSdk = libs.versions.android.target.sdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"
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
    implementation(project(":core:data"))
    implementation(project(":core:platform"))

    testImplementation(kotlin("test-junit"))
}

val sourceManifest = layout.projectDirectory.file("src/main/AndroidManifest.xml")
val backupRules = layout.projectDirectory.file("src/main/res/xml/backup_rules.xml")
val dataExtractionRules =
    layout.projectDirectory.file("src/main/res/xml/data_extraction_rules.xml")
val mergedDebugManifest =
    layout.buildDirectory.file(
        "intermediates/merged_manifest/debug/processDebugMainManifest/AndroidManifest.xml",
    )
val mergedReleaseManifest =
    layout.buildDirectory.file(
        "intermediates/merged_manifest/release/processReleaseMainManifest/AndroidManifest.xml",
    )

tasks.withType<Test>().configureEach {
    if (name == "testDebugUnitTest") {
        dependsOn("processDebugMainManifest", "processReleaseMainManifest")
        inputs.files(
            sourceManifest,
            backupRules,
            dataExtractionRules,
            mergedDebugManifest,
            mergedReleaseManifest,
        )
        doFirst {
            systemProperty("wto.android.app.projectDir", layout.projectDirectory.asFile.absolutePath)
            systemProperty(
                "wto.android.app.mergedDebugManifest",
                mergedDebugManifest.get().asFile.absolutePath,
            )
            systemProperty(
                "wto.android.app.mergedReleaseManifest",
                mergedReleaseManifest.get().asFile.absolutePath,
            )
        }
    }
}
