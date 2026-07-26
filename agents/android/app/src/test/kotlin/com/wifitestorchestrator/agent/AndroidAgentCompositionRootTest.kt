package com.wifitestorchestrator.agent

import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentAttempt
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinator
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinatorResult
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentInvocationIntent
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestPublicationResult
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestPublisher
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class AndroidAgentCompositionRootTest {
    @Test
    fun `coordinator composition is lazy and memoized without side effects`() {
        var compositions = 0
        val coordinator = NeverExecutedCoordinator()
        val root =
            AndroidAgentCompositionRoot {
                compositions += 1
                coordinator
            }

        assertEquals(0, compositions)
        assertSame(coordinator, root.enrollmentCoordinator)
        assertSame(coordinator, root.enrollmentCoordinator)
        assertEquals(1, compositions)
        assertEquals(0, coordinator.executions)
    }

    @Test
    fun `composition root imports no coroutines and application does not eagerly access it`() {
        val projectDir =
            Path.of(
                requireNotNull(System.getProperty("wto.android.app.projectDir")) {
                    "App project directory test property is required."
                },
            )
        val rootSource =
            Files.readString(
                projectDir.resolve(
                    "src/main/kotlin/com/wifitestorchestrator/agent/" +
                        "AndroidAgentCompositionRoot.kt",
                ),
            )
        val applicationSource =
            Files.readString(
                projectDir.resolve(
                    "src/main/kotlin/com/wifitestorchestrator/agent/WtoApplication.kt",
                ),
            )

        assertFalse(rootSource.contains("kotlinx.coroutines"))
        assertTrue(rootSource.contains("by\n        lazy"))
        assertTrue(applicationSource.contains("val compositionRoot"))
        val onCreate = applicationSource.substringAfter("override fun onCreate()")
        assertFalse(onCreate.contains("compositionRoot"))
        assertFalse(onCreate.contains("Room"))
        assertFalse(onCreate.contains("Keystore"))
        assertFalse(onCreate.contains("EnrollmentCoordinator"))
    }

    @Test
    fun `capability publisher composition is lazy memoized and receives BuildConfig version`() {
        var compositions = 0
        val publisher = NeverExecutedPublisher()
        val root =
            AndroidAgentCompositionRoot(
                coordinatorFactory = { NeverExecutedCoordinator() },
                capabilityManifestPublisherFactory = {
                    compositions += 1
                    publisher
                },
            )

        assertEquals(BuildConfig.VERSION_NAME, capabilityAgentVersionFromBuildConfig().toString())
        assertEquals(0, compositions)
        assertSame(publisher, root.capabilityManifestPublisher)
        assertSame(publisher, root.capabilityManifestPublisher)
        assertEquals(1, compositions)
        assertEquals(0, publisher.executions)
    }
}

private class NeverExecutedPublisher : CapabilityManifestPublisher {
    var executions: Int = 0
        private set

    override suspend fun publish(): CapabilityManifestPublicationResult {
        executions += 1
        error("The lazy composition test must not publish a manifest.")
    }
}

private class NeverExecutedCoordinator : EnrollmentCoordinator {
    var executions: Int = 0
        private set

    override suspend fun enroll(
        attempt: EnrollmentAttempt,
        intent: EnrollmentInvocationIntent,
    ): EnrollmentCoordinatorResult {
        executions += 1
        error("The lazy composition test must not execute enrollment.")
    }
}
