package com.wifitestorchestrator.agent.contracts

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json

private const val CONTRACT_EXAMPLES_PROPERTY = "wto.contract.examples"

@OptIn(ExperimentalSerializationApi::class)
internal val strictJson =
    Json {
        ignoreUnknownKeys = false
        isLenient = false
        coerceInputValues = false
        explicitNulls = true
        exceptionsWithDebugInfo = false
    }

internal object CanonicalContractFixtures {
    private val root: Path by lazy {
        val configured =
            System.getProperty(CONTRACT_EXAMPLES_PROPERTY)
                ?: error(
                    "Missing $CONTRACT_EXAMPLES_PROPERTY; run tests through the " +
                        ":core:contracts:test Gradle task",
                )
        Path.of(configured).toAbsolutePath().normalize().also { path ->
            check(Files.isDirectory(path)) {
                "Canonical contract fixture directory does not exist: $path"
            }
        }
    }

    fun read(relativePath: String): String {
        val fixture = root.resolve(relativePath).normalize()
        check(fixture.startsWith(root)) {
            "Canonical fixture path escapes the fixture directory: $relativePath"
        }
        check(Files.isRegularFile(fixture)) {
            "Required canonical contract fixture does not exist: $fixture"
        }
        return Files.readString(fixture)
    }
}
