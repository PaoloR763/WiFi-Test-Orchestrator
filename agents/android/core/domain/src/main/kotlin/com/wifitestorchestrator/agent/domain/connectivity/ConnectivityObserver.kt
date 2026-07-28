package com.wifitestorchestrator.agent.domain.connectivity

enum class ConnectivityObserverLifecycle {
    NEW,
    STARTING,
    ACTIVE,
    STOPPING,
    STOPPED,
    FAILED,
    CLOSED,
}

data class ConnectivityObserverState(
    val lifecycle: ConnectivityObserverLifecycle,
    val profile: ConnectivityCollectionProfile?,
    val snapshot: ConnectivitySnapshot?,
    val failure: ConnectivityObservationFailure?,
) {
    init {
        when (lifecycle) {
            ConnectivityObserverLifecycle.NEW,
            ConnectivityObserverLifecycle.STOPPED,
            -> require(profile == null && snapshot == null && failure == null)
            ConnectivityObserverLifecycle.CLOSED ->
                require(profile == null && snapshot == null)
            ConnectivityObserverLifecycle.STARTING,
            ConnectivityObserverLifecycle.ACTIVE,
            ConnectivityObserverLifecycle.STOPPING,
            -> require(profile != null && failure == null)
            ConnectivityObserverLifecycle.FAILED ->
                require(profile != null && failure != null)
        }
    }

    companion object {
        fun new(): ConnectivityObserverState =
            ConnectivityObserverState(
                lifecycle = ConnectivityObserverLifecycle.NEW,
                profile = null,
                snapshot = null,
                failure = null,
            )

        fun stopped(): ConnectivityObserverState =
            ConnectivityObserverState(
                lifecycle = ConnectivityObserverLifecycle.STOPPED,
                profile = null,
                snapshot = null,
                failure = null,
            )

        fun closed(): ConnectivityObserverState =
            ConnectivityObserverState(
                lifecycle = ConnectivityObserverLifecycle.CLOSED,
                profile = null,
                snapshot = null,
                failure = null,
            )
    }
}

fun interface ConnectivityObservationListener {
    fun onObservation(state: ConnectivityObserverState)
}

sealed interface ConnectivityObserverCommandResult {
    data class Accepted(val state: ConnectivityObserverState) :
        ConnectivityObserverCommandResult

    data class Rejected(val reason: ConnectivityObservationReason) :
        ConnectivityObserverCommandResult

    data class Failed(val state: ConnectivityObserverState) :
        ConnectivityObserverCommandResult
}

interface ConnectivityObserver : AutoCloseable {
    fun start(
        profile: ConnectivityCollectionProfile = ConnectivityCollectionProfile.BASIC,
    ): ConnectivityObserverCommandResult

    fun stop(): ConnectivityObserverCommandResult

    fun currentState(): ConnectivityObserverState

    /**
     * Replaces the single listener slot. A single slot prevents unbounded listener accumulation.
     */
    fun setListener(listener: ConnectivityObservationListener?): ConnectivityObserverCommandResult

    override fun close()
}
