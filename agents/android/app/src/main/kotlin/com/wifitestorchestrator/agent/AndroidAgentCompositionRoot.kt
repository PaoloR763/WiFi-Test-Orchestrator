package com.wifitestorchestrator.agent

import android.content.Context
import com.wifitestorchestrator.agent.data.enrollment.EnrollmentClients
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinator
import com.wifitestorchestrator.agent.data.enrollment.coordination.EnrollmentCoordinatorFactory
import com.wifitestorchestrator.agent.data.persistence.AndroidLocalPersistenceFactory
import com.wifitestorchestrator.agent.platform.security.AndroidCredentialProtectionFactory

/**
 * Lazy C07 composition. Constructing this root performs no Room, Keystore, request, network, or
 * coroutine work.
 */
class AndroidAgentCompositionRoot internal constructor(
    private val coordinatorFactory: () -> EnrollmentCoordinator,
) {
    constructor(context: Context) : this(
        coordinatorFactory =
            coordinatorFactoryFor(
                requireNotNull(context.applicationContext) {
                    "An application context is required for Android composition."
                },
            ),
    )

    val enrollmentCoordinator: EnrollmentCoordinator by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            coordinatorFactory()
        }
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
