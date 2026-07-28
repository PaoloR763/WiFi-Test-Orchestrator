package com.wifitestorchestrator.agent

import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentAttempt
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinator
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinatorResult
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentInvocationIntent
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestPublicationResult
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestPublisher
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationListener
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserver
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverCommandResult
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverState
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

    @Test
    fun `connectivity observer composition is lazy memoized and never starts implicitly`() {
        var compositions = 0
        val observer = NeverStartedConnectivityObserver()
        val root =
            AndroidAgentCompositionRoot(
                coordinatorFactory = { NeverExecutedCoordinator() },
                capabilityManifestPublisherFactory = { NeverExecutedPublisher() },
                connectivityObserverFactory = {
                    compositions += 1
                    observer
                },
            )

        assertEquals(0, compositions)
        assertEquals(0, observer.starts)
        assertSame(observer, root.connectivityObserver)
        assertSame(observer, root.connectivityObserver)
        assertEquals(1, compositions)
        assertEquals(0, observer.starts)
    }
}

private class NeverStartedConnectivityObserver : ConnectivityObserver {
    var starts: Int = 0
        private set

    override fun start(
        profile: ConnectivityCollectionProfile,
    ): ConnectivityObserverCommandResult {
        starts += 1
        error("The lazy composition test must not start connectivity observation.")
    }

    override fun stop(): ConnectivityObserverCommandResult =
        ConnectivityObserverCommandResult.Accepted(ConnectivityObserverState.stopped())

    override fun currentState(): ConnectivityObserverState = ConnectivityObserverState.new()

    override fun setListener(
        listener: ConnectivityObservationListener?,
    ): ConnectivityObserverCommandResult =
        ConnectivityObserverCommandResult.Accepted(currentState())

    override fun close() = Unit
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
