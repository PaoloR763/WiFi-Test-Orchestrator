package com.wifitestorchestrator.agent.data.enrollment.coordination

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EnrollmentCoordinatorApiSurfaceTest {
    @Test
    fun `app facing factory exposes only the three existing ports`() {
        val factoryMethod =
            EnrollmentCoordinatorFactory::class.java.declaredMethods.single {
                it.name == "create"
            }

        assertEquals(
            listOf(
                "com.wifitestorchestrator.agent.data.enrollment.EnrollmentClient",
                "com.wifitestorchestrator.agent.data.persistence.ProtectedEnrollmentRepository",
                "com.wifitestorchestrator.agent.domain.credential.protection.CredentialProtector",
            ),
            factoryMethod.parameterTypes.map { it.name },
        )
        assertFalse(
            factoryMethod.parameterTypes.any {
                it.name.startsWith("kotlinx.coroutines")
            },
        )
        assertEquals(
            EnrollmentCoordinator::class.java,
            factoryMethod.returnType,
        )
    }

    @Test
    fun `public coordinator contract exposes no kotlinx coroutine type`() {
        val publicTypes =
            EnrollmentCoordinator::class.java.declaredMethods.flatMap { method ->
                method.parameterTypes.toList() + method.returnType
            }

        assertFalse(publicTypes.any { it.name.startsWith("kotlinx.coroutines") })
    }

    @Test
    fun `production source has one call site and no retry loop or fifteen minute promise`() {
        val source =
            Files.readString(
                dataProjectDir().resolve(
                    "src/main/kotlin/com/wifitestorchestrator/agent/data/" +
                        "enrollment/coordination/EnrollmentCoordinator.kt",
                ),
            )

        assertEquals(1, Regex("""\.newCall\(""").findAll(source).count())
        assertEquals(1, Regex("""awaitEnrollmentCall\(""").findAll(source).count())
        assertFalse(source.contains("repeat("))
        assertFalse(source.contains("while ("))
        assertFalse(source.contains("15 minute", ignoreCase = true))
        assertFalse(source.contains("900_000"))
    }

    @Test
    fun `composition root imports no coroutine implementation type`() {
        val appSource =
            dataProjectDir()
                .parent
                .parent
                .resolve(
                    "app/src/main/kotlin/com/wifitestorchestrator/agent/" +
                        "AndroidAgentCompositionRoot.kt",
                )
        val source = Files.readString(appSource)

        assertFalse(source.contains("kotlinx.coroutines"))
        assertTrue(source.contains("EnrollmentCoordinatorFactory.create"))
        assertTrue(source.contains("EnrollmentClients.default()"))
    }

    @Test
    fun `attempt source is neither data Parcelable nor serializable`() {
        val source =
            Files.readString(
                dataProjectDir().resolve(
                    "src/main/kotlin/com/wifitestorchestrator/agent/data/" +
                        "enrollment/coordination/EnrollmentAttempt.kt",
                ),
            )

        assertFalse(source.contains("data class EnrollmentAttempt"))
        assertFalse(source.contains("Parcelable"))
        assertFalse(source.contains("Serializable"))
        assertTrue(source.contains("EnrollmentAttempt(<redacted>)"))
    }

    private fun dataProjectDir(): Path =
        Path.of(
            requireNotNull(System.getProperty("wto.android.data.projectDir")) {
                "Data project directory test property is required."
            },
        )
}
