package com.wifitestorchestrator.agent

import android.content.Context
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestPublisher
import com.wifitestorchestrator.agent.data.capability.CapabilityManifestPublisherFactory
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentClients
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinator
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinatorFactory
import com.wifitestorchestrator.agent.data.persistence.AndroidLocalPersistenceFactory
import com.wifitestorchestrator.agent.domain.error.Valid
import com.wifitestorchestrator.agent.domain.version.AgentVersion
import com.wifitestorchestrator.agent.platform.capability.AndroidSystemCapabilityFactsProvider
import com.wifitestorchestrator.agent.platform.security.AndroidCredentialProtectionFactory

/**
 * Lazy C07/C08 composition. Constructing this root performs no Room, Keystore, request, network,
 * capability observation, or coroutine work.
 */
class AndroidAgentCompositionRoot internal constructor(
    private val coordinatorFactory: () -> EnrollmentCoordinator,
    private val capabilityManifestPublisherFactory: () -> CapabilityManifestPublisher,
) {
    internal constructor(
        coordinatorFactory: () -> EnrollmentCoordinator,
    ) : this(
        coordinatorFactory = coordinatorFactory,
        capabilityManifestPublisherFactory = {
            error("Capability publisher was not configured for this composition root.")
        },
    )

    constructor(context: Context) : this(
        coordinatorFactory =
            coordinatorFactoryFor(
                requireNotNull(context.applicationContext) {
                    "An application context is required for Android composition."
                },
            ),
        capabilityManifestPublisherFactory =
            capabilityManifestPublisherFactoryFor(
                requireNotNull(context.applicationContext) {
                    "An application context is required for Android composition."
                },
            ),
    )

    val enrollmentCoordinator: EnrollmentCoordinator by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            coordinatorFactory()
        }

    val capabilityManifestPublisher: CapabilityManifestPublisher by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            capabilityManifestPublisherFactory()
        }
}

private fun capabilityManifestPublisherFactoryFor(
    applicationContext: Context,
): () -> CapabilityManifestPublisher = {
    val persistenceFactory = AndroidLocalPersistenceFactory(applicationContext)
    val agentVersion = capabilityAgentVersionFromBuildConfig()
    CapabilityManifestPublisherFactory.create(
        repository = persistenceFactory.createCapabilityManifestPublicationRepository(),
        credentialProtector = AndroidCredentialProtectionFactory.create(),
        factsProvider = AndroidSystemCapabilityFactsProvider(applicationContext),
        agentVersion = agentVersion,
    )
}

internal fun capabilityAgentVersionFromBuildConfig(): AgentVersion {
    val parsedVersion = AgentVersion.parse(BuildConfig.VERSION_NAME)
    check(parsedVersion is Valid) { "BuildConfig.VERSION_NAME must be a valid AgentVersion." }
    return parsedVersion.value
}

private fun coordinatorFactoryFor(
    applicationContext: Context,
): () -> EnrollmentCoordinator = {
    val persistenceFactory = AndroidLocalPersistenceFactory(applicationContext)
    EnrollmentCoordinatorFactory.create(
        enrollmentClient = EnrollmentClients.default(),
        protectedEnrollmentRepository =
            persistenceFactory.createProtectedEnrollmentRepository(),
        credentialProtector = AndroidCredentialProtectionFactory.create(),
    )
}
