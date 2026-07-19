import org.gradle.api.tasks.PathSensitivity
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(libs.versions.java.get().toInt()))
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.kotlinx.serialization.core)
    testImplementation(libs.kotlinx.serialization.json)
    testImplementation(kotlin("test"))
}

val canonicalContractExamples =
    rootProject.layout.projectDirectory.dir("../../shared/contracts/examples")

tasks.test {
    useJUnitPlatform()
    inputs
        .dir(canonicalContractExamples)
        .withPropertyName("canonicalContractExamples")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    systemProperty(
        "wto.contract.examples",
        canonicalContractExamples.asFile.absolutePath,
    )
}
