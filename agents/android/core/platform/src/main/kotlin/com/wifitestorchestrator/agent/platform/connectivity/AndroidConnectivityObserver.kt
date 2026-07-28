package com.wifitestorchestrator.agent.platform.connectivity

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityCollectionProfile
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityFailureOperation
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationFailure
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationListener
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObservationReason
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserver
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverCommandResult
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverLifecycle
import com.wifitestorchestrator.agent.domain.connectivity.ConnectivityObserverState
import java.time.Instant
import java.util.ArrayDeque
import java.util.IdentityHashMap
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class AndroidConnectivityObserver internal constructor(
    private val connectivityFacade: AndroidConnectivityManagerFacade,
    private val dispatcherFactory: AndroidCallbackDispatcherFactory,
    private val timeSource: AndroidObservationTimeSource,
    private val mapper: AndroidConnectivitySnapshotMapper,
    private val cleanupWaiterObserver: AndroidLifecycleCleanupWaiterObserver =
        AndroidLifecycleCleanupWaiterObserver { _, _, _ -> },
) : ConnectivityObserver {
    constructor(context: Context) : this(
        connectivityFacade =
            FrameworkAndroidConnectivityManagerFacade(
                requireNotNull(context.applicationContext) {
                    "An application context is required for connectivity observation."
                },
            ),
        dispatcherFactory = HandlerThreadCallbackDispatcherFactory,
        timeSource = SystemAndroidObservationTimeSource,
        mapper = AndroidConnectivitySnapshotMapper(),
    )

    private val lock = Any()
    private val state = AtomicReference(ConnectivityObserverState.new())
    private val generationCounter = AtomicLong(0)
    private var listenerEpoch: Long = 0
    private var listenerSlot: ListenerSlot? = null
    private val listenerDeliveriesInProgress = IdentityHashMap<Thread, Int>()
    private var session: ActiveSession? = null
    private var closing: Boolean = false
    private var closeInProgress: CloseCompletion? = null

    override fun start(
        profile: ConnectivityCollectionProfile,
    ): ConnectivityObserverCommandResult {
        val active =
            synchronized(lock) {
                if (closing) {
                    return ConnectivityObserverCommandResult.Rejected(
                        ConnectivityObservationReason.OBSERVER_CLOSED,
                    )
                }
                val current = state.get()
                when (current.lifecycle) {
                    ConnectivityObserverLifecycle.CLOSED -> {
                        return ConnectivityObserverCommandResult.Rejected(
                            ConnectivityObservationReason.OBSERVER_CLOSED,
                        )
                    }
                    ConnectivityObserverLifecycle.STARTING,
                    ConnectivityObserverLifecycle.ACTIVE,
                    -> {
                        return if (current.profile == profile) {
                            ConnectivityObserverCommandResult.Accepted(current)
                        } else {
                            ConnectivityObserverCommandResult.Rejected(
                                ConnectivityObservationReason.MODE_CHANGE_REQUIRES_RESTART,
                            )
                        }
                    }
                    ConnectivityObserverLifecycle.STOPPING -> {
                        return ConnectivityObserverCommandResult.Rejected(
                            ConnectivityObservationReason.OBSERVER_STOPPED,
                        )
                    }
                    ConnectivityObserverLifecycle.FAILED -> {
                        return ConnectivityObserverCommandResult.Rejected(
                            ConnectivityObservationReason.OBSERVER_STOPPED,
                        )
                    }
                    ConnectivityObserverLifecycle.NEW,
                    ConnectivityObserverLifecycle.STOPPED,
                    -> Unit
                }

                val generation = generationCounter.incrementAndGet()
                val active =
                    ActiveSession(
                        generation = generation,
                        profile = profile,
                    )
                session = active
                val starting =
                    ConnectivityObserverState(
                        lifecycle = ConnectivityObserverLifecycle.STARTING,
                        profile = profile,
                        snapshot = null,
                        failure = null,
                    )
                state.set(starting)
                active
            }
        return executeStart(active)
    }

    private fun executeStart(active: ActiveSession): ConnectivityObserverCommandResult {
        val dispatcher =
            try {
                runLifecycleExternalOperation(active) {
                    dispatcherFactory.create()
                }
            } catch (failure: Throwable) {
                return completeStartFailure(
                    active = active,
                    operation = ConnectivityFailureOperation.CLEANUP_THREAD,
                    failure = failure,
                )
            }

        var cleanup =
            synchronized(lock) {
                if (session !== active) {
                    null
                } else {
                    active.dispatcher = dispatcher
                    if (active.stopRequested || closing) {
                        active.startInProgress = false
                        requestCleanupLocked(active)
                    } else {
                        null
                    }
                }
            }
        if (cleanup != null) return resolveCleanup(cleanup)

        val initial =
            try {
                mapper.initial(active.profile, active.nextStamp())
            } catch (failure: Throwable) {
                return completeStartFailure(
                    active = active,
                    operation = ConnectivityFailureOperation.MAP_PLATFORM_DATA,
                    failure = failure,
                )
            }

        cleanup =
            synchronized(lock) {
                if (session !== active) {
                    null
                } else {
                    val current = state.get()
                    state.set(
                        ConnectivityObserverState(
                            lifecycle =
                                if (active.stopRequested || closing) {
                                    ConnectivityObserverLifecycle.STOPPING
                                } else {
                                    ConnectivityObserverLifecycle.STARTING
                                },
                            profile = active.profile,
                            snapshot = initial,
                            failure = null,
                        ),
                    )
                    if (active.stopRequested || closing) {
                        active.startInProgress = false
                        requestCleanupLocked(active)
                    } else {
                        check(current.lifecycle == ConnectivityObserverLifecycle.STARTING)
                        null
                    }
                }
            }
        if (cleanup != null) return resolveCleanup(cleanup)

        val registration =
            try {
                runLifecycleExternalOperation(active) {
                    connectivityFacade.registerDefaultNetworkCallback(
                        profile = active.profile,
                        handler = dispatcher.handler,
                        events = SessionEvents(active.generation),
                    )
                }
            } catch (failure: Throwable) {
                return completeStartFailure(
                    active = active,
                    operation = ConnectivityFailureOperation.REGISTER_CALLBACK,
                    failure = failure,
                )
            }

        var result: ConnectivityObserverCommandResult? = null
        var drainer: ListenerSlot? = null
        cleanup =
            synchronized(lock) {
                check(session === active) {
                    "The reserved connectivity session changed during registration."
                }
                active.registration = registration
                active.startInProgress = false
                registration.controlFailureDuringRegistration?.throwable?.let { failure ->
                    recordPendingFailureLocked(
                        active = active,
                        failure = failure,
                        operation = null,
                        operational = false,
                        controlFlow = true,
                    )
                }
                when {
                    active.stopRequested || closing || active.pendingFailures.isNotEmpty() ->
                        requestCleanupLocked(active)
                    state.get().lifecycle == ConnectivityObserverLifecycle.FAILED -> {
                        val failed = state.get()
                        result = ConnectivityObserverCommandResult.Failed(failed)
                        drainer = enqueueListenerLocked(failed, active.generation)
                        null
                    }
                    else -> {
                        val activeState =
                            state.get().copy(lifecycle = ConnectivityObserverLifecycle.ACTIVE)
                        state.set(activeState)
                        result = ConnectivityObserverCommandResult.Accepted(activeState)
                        drainer = enqueueListenerLocked(activeState, active.generation)
                        null
                    }
                }
            }
        if (cleanup != null) {
            return resolveCleanup(action = cleanup)
        }
        try {
            drainer?.let(::drainListener)
        } catch (failure: Throwable) {
            val action =
                synchronized(lock) {
                    val current = session
                    if (current !== active) {
                        null
                    } else {
                        recordPendingFailureLocked(
                            active = active,
                            failure = failure,
                            operation = null,
                            operational = false,
                            controlFlow = true,
                        )
                        requestCleanupLocked(active)
                    }
                }
            if (action != null) {
                return resolveCleanup(action = action)
            }
            throw failure
        }
        return requireNotNull(result)
    }

    override fun stop(): ConnectivityObserverCommandResult {
        val cleanup =
            synchronized(lock) {
                val current = state.get()
                when (current.lifecycle) {
                    ConnectivityObserverLifecycle.CLOSED ->
                        return ConnectivityObserverCommandResult.Rejected(
                            ConnectivityObservationReason.OBSERVER_CLOSED,
                        )
                    ConnectivityObserverLifecycle.NEW,
                    ConnectivityObserverLifecycle.STOPPED,
                    -> {
                        val stopped = ConnectivityObserverState.stopped()
                        state.set(stopped)
                        return ConnectivityObserverCommandResult.Accepted(stopped)
                    }
                    ConnectivityObserverLifecycle.STOPPING -> {
                        val active = session
                        if (active == null) {
                            val failed =
                                failedState(
                                    profile = requireNotNull(current.profile),
                                    operation = ConnectivityFailureOperation.CLEANUP_THREAD,
                                    snapshot = current.snapshot,
                                )
                            state.set(failed)
                            return ConnectivityObserverCommandResult.Failed(failed)
                        }
                        return@synchronized requestCleanupLocked(active)
                    }
                    ConnectivityObserverLifecycle.STARTING,
                    ConnectivityObserverLifecycle.ACTIVE,
                    ConnectivityObserverLifecycle.FAILED,
                    -> Unit
                }
                val currentSession = session
                if (currentSession == null) {
                    if (current.lifecycle == ConnectivityObserverLifecycle.FAILED) {
                        return ConnectivityObserverCommandResult.Failed(current)
                    }
                    val stopped = ConnectivityObserverState.stopped()
                    state.set(stopped)
                    return ConnectivityObserverCommandResult.Accepted(stopped)
                }
                requestCleanupLocked(currentSession)
            }
        return resolveCleanup(
            action = cleanup,
            waiterKind = AndroidLifecycleCleanupWaiterKind.STOP,
        )
    }

    override fun currentState(): ConnectivityObserverState = state.get()

    internal fun diagnosticsForTesting(): AndroidConnectivityObserverDiagnostics =
        synchronized(lock) {
            AndroidConnectivityObserverDiagnostics(
                sessionPresent = session != null,
                closeInProgress = closeInProgress != null,
                listenerDeliveriesInProgress = listenerDeliveriesInProgress.values.sum(),
                pendingFailureCount = session?.pendingFailures?.size ?: 0,
            )
        }

    internal fun lifecycleLockHeldByCurrentThreadForTesting(): Boolean = Thread.holdsLock(lock)

    override fun setListener(
        listener: ConnectivityObservationListener?,
    ): ConnectivityObserverCommandResult {
        var drainer: ListenerSlot? = null
        val current: ConnectivityObserverState
        synchronized(lock) {
            if (closing) {
                return ConnectivityObserverCommandResult.Rejected(
                    ConnectivityObservationReason.OBSERVER_CLOSED,
                )
            }
            current = state.get()
            if (current.lifecycle == ConnectivityObserverLifecycle.CLOSED) {
                return ConnectivityObserverCommandResult.Rejected(
                    ConnectivityObservationReason.OBSERVER_CLOSED,
                )
            }
            listenerSlot?.invalidateLocked()
            val replacement =
                listener?.let {
                    ListenerSlot(
                        epoch = ++listenerEpoch,
                        listener = it,
                    )
                }
            listenerSlot = replacement
            drainer =
                replacement?.let { slot ->
                    enqueueListenerLocked(
                        state = current,
                        sessionGeneration = session?.generation,
                        slot = slot,
                    )
                }
        }
        drainer?.let(::drainActiveListener)
        return ConnectivityObserverCommandResult.Accepted(current)
    }

    override fun close() {
        var waitForClose: CloseCompletion? = null
        var cleanup: CleanupAction? = null
        var deferredToLifecycleOwner = false
        val ownedClose =
            synchronized(lock) {
                if (state.get().lifecycle == ConnectivityObserverLifecycle.CLOSED) {
                    return
                }
                val existing = closeInProgress
                if (existing != null) {
                    if (
                        isLifecycleDependentThreadLocked() ||
                        isListenerDeliveryThreadLocked()
                    ) {
                        return
                    }
                    waitForClose = existing
                    return@synchronized null
                }
                CloseCompletion(state.get().failure).also { completion ->
                    closeInProgress = completion
                    closing = true
                    session?.let { active ->
                        val action = requestCleanupLocked(active)
                        cleanup = action
                        if (!action.owner && !action.callerMayAwait) {
                            completion.deferredToLifecycleOwner = true
                            deferredToLifecycleOwner = true
                        }
                    }
                }
            }
        if (ownedClose == null) {
            requireNotNull(waitForClose).awaitAndPropagate()
            return
        }
        if (deferredToLifecycleOwner) return

        var terminalResult: ConnectivityObserverCommandResult? = null
        var propagated: Throwable? = null
        try {
            cleanup?.let { action ->
                terminalResult =
                    resolveCleanup(
                        action = action,
                        waiterKind = AndroidLifecycleCleanupWaiterKind.CLOSE,
                    )
            }
        } catch (failure: Throwable) {
            propagated = failure
        }
        val closeFailure = finalizeClose(ownedClose, terminalResult, propagated)
        closeFailure?.let(::throwPreservingIdentity)
    }

    private fun <T> runLifecycleExternalOperation(
        active: ActiveSession,
        operation: () -> T,
    ): T {
        val operationThread = Thread.currentThread()
        synchronized(lock) {
            check(session === active) {
                "Only the current connectivity session can run lifecycle operations."
            }
            check(active.lifecycleExternalOperationThread == null) {
                "Connectivity lifecycle operations must not overlap for one session."
            }
            active.lifecycleExternalOperationThread = operationThread
        }
        return try {
            operation()
        } finally {
            synchronized(lock) {
                check(active.lifecycleExternalOperationThread === operationThread) {
                    "The lifecycle operation owner changed before returning."
                }
                active.lifecycleExternalOperationThread = null
            }
        }
    }

    private fun isLifecycleDependentThreadLocked(): Boolean =
        session?.lifecycleExternalOperationThread === Thread.currentThread()

    private fun isListenerDeliveryThreadLocked(): Boolean =
        listenerDeliveriesInProgress.containsKey(Thread.currentThread())

    private fun finalizeDeferredClose(
        terminalResult: ConnectivityObserverCommandResult?,
        propagated: Throwable?,
    ): Throwable? {
        val deferred =
            synchronized(lock) {
                closeInProgress?.takeIf { it.deferredToLifecycleOwner }
            } ?: return propagated
        return finalizeClose(deferred, terminalResult, propagated)
    }

    private fun finalizeClose(
        completion: CloseCompletion,
        terminalResult: ConnectivityObserverCommandResult?,
        propagated: Throwable?,
    ): Throwable? {
        val closeFailure =
            synchronized(lock) {
                check(closeInProgress === completion) {
                    "Only the current close completion can finalize the observer."
                }
                val failure =
                    (terminalResult as? ConnectivityObserverCommandResult.Failed)
                        ?.state
                        ?.failure
                        ?: state.get().failure
                        ?: completion.priorFailure
                session = null
                generationCounter.incrementAndGet()
                listenerSlot?.invalidateLocked()
                listenerSlot = null
                state.set(
                    failure?.let {
                        ConnectivityObserverState(
                            lifecycle = ConnectivityObserverLifecycle.CLOSED,
                            profile = null,
                            snapshot = null,
                            failure = it,
                        )
                    } ?: ConnectivityObserverState.closed(),
                )
                closing = false
                closeInProgress = null
                propagated
            }
        completion.complete(closeFailure)
        return closeFailure
    }

    private fun completeStartFailure(
        active: ActiveSession,
        operation: ConnectivityFailureOperation,
        failure: Throwable,
    ): ConnectivityObserverCommandResult {
        var requiresExplicitPropagation = false
        val action =
            synchronized(lock) {
                check(session === active) {
                    "The reserved connectivity session changed during start failure cleanup."
                }
                requiresExplicitPropagation = active.consumeTimeCaptureFailure(failure)
                active.startInProgress = false
                requestCleanupLocked(active)
            }
        return resolveCleanup(
            action = action,
            seedFailure = failure,
            seedOperation = operation,
            seedIsOperational = failure.isOrdinaryRuntimeFailure(),
            seedIsControl = !failure.isOrdinaryRuntimeFailure(),
            seedRequiresExplicitPropagation = requiresExplicitPropagation,
        )
    }

    private fun recordPendingFailureLocked(
        active: ActiveSession,
        failure: Throwable,
        operation: ConnectivityFailureOperation?,
        operational: Boolean,
        controlFlow: Boolean,
        requiresExplicitPropagation: Boolean = false,
    ) {
        check(session === active) {
            "Only the current connectivity session can retain a pending failure."
        }
        active.pendingFailures +=
            PendingFailure(
                throwable = failure,
                operation = operation,
                operational = operational,
                controlFlow = controlFlow,
                requiresExplicitPropagation = requiresExplicitPropagation,
            )
    }

    private fun takePendingFailuresLocked(active: ActiveSession): List<PendingFailure> =
        active.pendingFailures.toList().also { active.pendingFailures.clear() }

    private fun requestCleanupLocked(active: ActiveSession): CleanupAction {
        check(session === active) { "Only the current connectivity session can be cleaned up." }
        active.stopRequested = true
        val current = state.get()
        if (current.lifecycle != ConnectivityObserverLifecycle.STOPPING) {
            state.set(
                ConnectivityObserverState(
                    lifecycle = ConnectivityObserverLifecycle.STOPPING,
                    profile = active.profile,
                    snapshot = current.snapshot,
                    failure = null,
                ),
            )
        }
        val completion =
            active.cleanupCompletion
                ?: LifecycleCompletion().also { active.cleanupCompletion = it }
        val owner = !active.startInProgress && !active.cleanupOwnerClaimed
        if (owner) active.cleanupOwnerClaimed = true
        return CleanupAction(
            active = active,
            completion = completion,
            owner = owner,
            callerMayAwait = active.lifecycleExternalOperationThread !== Thread.currentThread(),
        )
    }

    private fun resolveCleanup(
        action: CleanupAction,
        seedFailure: Throwable? = null,
        seedOperation: ConnectivityFailureOperation? = null,
        seedIsOperational: Boolean = false,
        seedIsControl: Boolean = seedFailure?.isControlFlowFailure() == true,
        seedRequiresExplicitPropagation: Boolean = false,
        waiterKind: AndroidLifecycleCleanupWaiterKind? = null,
    ): ConnectivityObserverCommandResult {
        if (!action.owner) {
            return if (action.callerMayAwait) {
                waiterKind?.let { kind ->
                    cleanupWaiterObserver.onWaiterEvent(
                        kind = kind,
                        phase = AndroidLifecycleCleanupWaiterPhase.REGISTERED,
                        thread = Thread.currentThread(),
                    )
                }
                action.completion.awaitAndPropagate {
                    waiterKind?.let { kind ->
                        cleanupWaiterObserver.onWaiterEvent(
                            kind = kind,
                            phase = AndroidLifecycleCleanupWaiterPhase.INTERRUPTED,
                            thread = Thread.currentThread(),
                        )
                    }
                }
            } else {
                ConnectivityObserverCommandResult.Rejected(
                    ConnectivityObservationReason.OBSERVER_STOPPED,
                )
            }
        }

        var result: ConnectivityObserverCommandResult? = null
        var propagated: Throwable? = null
        try {
            result =
                performCleanup(
                    action = action,
                    seedFailure = seedFailure,
                    seedOperation = seedOperation,
                    seedIsOperational = seedIsOperational,
                    seedIsControl = seedIsControl,
                    seedRequiresExplicitPropagation = seedRequiresExplicitPropagation,
                )
        } catch (failure: Throwable) {
            propagated = failure
        }
        val closeFailure = finalizeDeferredClose(result, propagated)
        closeFailure?.let(::throwPreservingIdentity)
        return requireNotNull(result)
    }

    private fun performCleanup(
        action: CleanupAction,
        seedFailure: Throwable?,
        seedOperation: ConnectivityFailureOperation?,
        seedIsOperational: Boolean,
        seedIsControl: Boolean,
        seedRequiresExplicitPropagation: Boolean,
    ): ConnectivityObserverCommandResult {
        val active = action.active
        val failures = FailureAccumulator()
        if (seedFailure != null) {
            failures.record(
                failure = seedFailure,
                operation = seedOperation,
                operational = seedIsOperational,
                controlFlow = seedIsControl,
                requiresExplicitPropagation = seedRequiresExplicitPropagation,
            )
        }
        takePendingFailures(active).forEach(failures::record)

        val registration =
            synchronized(lock) {
                active.registration?.takeIf { !active.unregisterAttempted }?.also {
                    active.unregisterAttempted = true
                }
        }
        if (registration != null) {
            try {
                runLifecycleExternalOperation(active) {
                    connectivityFacade.unregisterNetworkCallback(registration)
                }
            } catch (failure: Throwable) {
                failures.record(
                    failure = failure,
                    operation = ConnectivityFailureOperation.UNREGISTER_CALLBACK,
                    operational = true,
                )
            }
        }

        val dispatcher =
            synchronized(lock) {
                active.dispatcher?.takeIf { !active.dispatcherCloseAttempted }?.also {
                    active.dispatcherCloseAttempted = true
                }
        }
        if (dispatcher != null) {
            try {
                runLifecycleExternalOperation(active) {
                    dispatcher.close()
                }
            } catch (failure: Throwable) {
                failures.record(
                    failure = failure,
                    operation = ConnectivityFailureOperation.CLEANUP_THREAD,
                    operational = true,
                )
            }
        }

        var failureTime: AndroidObservationTime? = null
        var failureTimeResolved = false
        var failureTimeUnavailable = false
        var result: ConnectivityObserverCommandResult? = null
        var drainer: ListenerSlot? = null
        while (result == null) {
            takePendingFailures(active).forEach(failures::record)
            val snapshot =
                synchronized(lock) {
                    check(session === active) {
                        "The connectivity session changed before cleanup reconciliation."
                    }
                    state.get().snapshot
                }
            if (failures.operationalOperation != null && !failureTimeResolved) {
                failureTime =
                    try {
                        timeSource.capture()
                    } catch (failure: Throwable) {
                        failures.record(
                            failure = failure,
                            operation = ConnectivityFailureOperation.MAP_PLATFORM_DATA,
                            operational = true,
                        )
                        val fallback =
                            active.lastObservationTime
                            ?: snapshot?.let {
                                AndroidObservationTime(
                                    observedAtUtc = it.observedAtUtc,
                                    elapsedRealtimeNanos = it.elapsedRealtimeNanos,
                                )
                            }
                        failureTimeUnavailable = fallback == null
                        fallback
                    }
                failureTimeResolved = true
            }
            val terminal =
                failures.operationalOperation?.let { operation ->
                    failureTime?.let { captured ->
                        failedStateAt(
                            profile = active.profile,
                            operation = operation,
                            snapshot = snapshot,
                            captured = captured,
                        )
                    } ?: ConnectivityObserverState.stopped()
                } ?: ConnectivityObserverState.stopped()
            val lateFailures =
                synchronized(lock) {
                    check(session === active) {
                        "The connectivity session changed before terminal publication."
                    }
                    val pending = takePendingFailuresLocked(active)
                    if (pending.isEmpty()) {
                        session = null
                        generationCounter.incrementAndGet()
                        state.set(terminal)
                        drainer = enqueueListenerLocked(terminal, active.generation)
                        result = terminal.toCommandResult()
                    }
                    pending
            }
            lateFailures.forEach(failures::record)
        }

        val explicitPropagation =
            failureTimeUnavailable || failures.requiresExplicitPropagation
        var propagated =
            if (explicitPropagation) {
                requireNotNull(failures.primaryFailureForExplicitPropagation()) {
                    "A cleanup without a valid failure time requires an explicit primary failure."
                }
            } else {
                failures.controlFailure
            }
        try {
            drainer?.let(::drainListener)
        } catch (listenerFailure: Throwable) {
            if (explicitPropagation) {
                failures.recordSecondary(
                    primary = requireNotNull(propagated),
                    secondary = listenerFailure,
                )
            } else {
                failures.record(
                    failure = listenerFailure,
                    operation = null,
                    operational = false,
                    controlFlow = true,
                )
                propagated = failures.controlFailure
            }
        }
        if (failures.interrupted) Thread.currentThread().interrupt()
        action.completion.complete(
            CleanupOutcome(
                result = requireNotNull(result),
                controlFailure = propagated,
            ),
        )
        propagated?.let(::throwPreservingIdentity)
        return requireNotNull(result)
    }

    private fun takePendingFailures(active: ActiveSession): List<PendingFailure> =
        synchronized(lock) {
            check(session === active) {
                "Only the current connectivity session can expose pending failures."
            }
            takePendingFailuresLocked(active)
        }

    private fun onAvailable(
        generation: Long,
        network: AndroidNetworkIdentity,
    ) {
        publishFromCallback(generation) { active ->
            active.network = network
            active.capabilities = null
            active.blocked = null
            mapper.capabilitiesPending(
                profile = active.profile,
                stamp = active.nextStamp(),
                blocked = null,
            )
        }
    }

    private fun onCapabilitiesChanged(
        generation: Long,
        network: AndroidNetworkIdentity,
        capabilities: AndroidNetworkCapabilitiesSnapshot,
    ) {
        publishFromCallback(generation) { active ->
            if (network != active.network) return@publishFromCallback null
            active.capabilities = capabilities
            mapper.available(
                profile = active.profile,
                stamp = active.nextStamp(),
                capabilities = capabilities,
                blocked = active.blocked,
            )
        }
    }

    private fun onBlockedStatusChanged(
        generation: Long,
        network: AndroidNetworkIdentity,
        blocked: Boolean,
    ) {
        publishFromCallback(generation) { active ->
            if (network != active.network) return@publishFromCallback null
            active.blocked = blocked
            active.capabilities?.let {
                mapper.available(
                    profile = active.profile,
                    stamp = active.nextStamp(),
                    capabilities = it,
                    blocked = blocked,
                )
            } ?: mapper.capabilitiesPending(
                profile = active.profile,
                stamp = active.nextStamp(),
                blocked = blocked,
            )
        }
    }

    private fun onLost(
        generation: Long,
        network: AndroidNetworkIdentity,
    ) {
        publishFromCallback(generation) { active ->
            if (network != active.network) return@publishFromCallback null
            active.network = null
            active.capabilities = null
            active.blocked = null
            mapper.absent(active.profile, active.nextStamp())
        }
    }

    private fun onControlFailure(
        generation: Long,
        failure: AndroidCallbackControlFailure,
    ): Nothing {
        val primary = failure.throwable
        val cleanup =
            synchronized(lock) {
                val active = session
                val current = state.get()
                if (
                    active == null ||
                    active.generation != generation ||
                    current.lifecycle !in
                    setOf(
                        ConnectivityObserverLifecycle.STARTING,
                        ConnectivityObserverLifecycle.ACTIVE,
                    )
                ) {
                    null
                } else {
                    recordPendingFailureLocked(
                        active = active,
                        failure = primary,
                        operation = null,
                        operational = false,
                        controlFlow = true,
                    )
                    requestCleanupLocked(active)
                }
            }
        if (cleanup?.owner == true) {
            resolveCleanup(action = cleanup)
        }
        throwPreservingIdentity(primary)
    }

    private fun publishFromCallback(
        generation: Long,
        mapping: (ActiveSession) -> com.wifitestorchestrator.agent.domain.connectivity.ConnectivitySnapshot?,
    ) {
        var drainer: ListenerSlot? = null
        var cleanup: CleanupAction? = null
        var propagated: Throwable? = null
        synchronized(lock) {
            val active = session
            val current = state.get()
            if (
                active == null ||
                active.generation != generation ||
                current.lifecycle !in
                setOf(
                    ConnectivityObserverLifecycle.STARTING,
                    ConnectivityObserverLifecycle.ACTIVE,
                )
            ) {
                return
            }
            try {
                mapping(active)?.let { snapshot ->
                    val published = current.copy(snapshot = snapshot)
                    state.set(published)
                    if (current.lifecycle == ConnectivityObserverLifecycle.ACTIVE) {
                        drainer = enqueueListenerLocked(published, active.generation)
                    }
                }
            } catch (failure: Throwable) {
                val ordinary = failure.isOrdinaryRuntimeFailure()
                val requiresExplicitPropagation =
                    active.consumeTimeCaptureFailure(failure)
                recordPendingFailureLocked(
                    active = active,
                    failure = failure,
                    operation =
                        ConnectivityFailureOperation.MAP_PLATFORM_DATA.takeIf { ordinary },
                    operational = ordinary,
                    controlFlow = !ordinary,
                    requiresExplicitPropagation = requiresExplicitPropagation,
                )
                if (!ordinary) propagated = failure
                cleanup = requestCleanupLocked(active)
            }
        }
        cleanup?.let { action ->
            if (action.owner || action.callerMayAwait) {
                resolveCleanup(action = action)
            }
            propagated?.let(::throwPreservingIdentity)
        }
        drainer?.let(::drainActiveListener)
    }

    private fun ConnectivityObserverState.toCommandResult(): ConnectivityObserverCommandResult =
        if (lifecycle == ConnectivityObserverLifecycle.FAILED) {
            ConnectivityObserverCommandResult.Failed(this)
        } else {
            ConnectivityObserverCommandResult.Accepted(this)
        }

    private fun enqueueListenerLocked(
        state: ConnectivityObserverState,
        sessionGeneration: Long?,
        slot: ListenerSlot? = listenerSlot,
    ): ListenerSlot? {
        val target = slot ?: return null
        if (!target.active || listenerSlot !== target) return null
        val sequence = state.snapshot?.sequence
        if (sequence != null) {
            if (target.lastGeneration != sessionGeneration) {
                target.lastGeneration = sessionGeneration
                target.lastQueuedSequence = null
                target.lastQueuedState = null
            }
            val last = target.lastQueuedSequence
            if (last != null && sequence < last) return null
            if (last != null && sequence == last && target.lastQueuedState == state) return null
            if (last == null || sequence > last) target.lastQueuedSequence = sequence
        } else if (
            target.lastGeneration == sessionGeneration &&
            target.lastQueuedState == state
        ) {
            return null
        }
        target.lastGeneration = sessionGeneration
        target.lastQueuedState = state
        target.pending.addLast(PendingNotification(state, sessionGeneration))
        if (target.draining) return null
        target.draining = true
        return target
    }

    private fun drainListener(slot: ListenerSlot) {
        while (true) {
            val notification =
                synchronized(lock) {
                    if (!slot.active || listenerSlot !== slot) {
                        slot.pending.clear()
                        slot.draining = false
                        return
                    }
                    slot.pending.pollFirst()
                        ?: run {
                            slot.draining = false
                            return
                        }
                }
            try {
                deliverListener(slot.listener, notification.state)
            } catch (failure: CancellationException) {
                invalidateListenerAfterControlFailure(slot)
                throw failure
            } catch (_: RuntimeException) {
                // Ordinary consumer failures do not break lifecycle or delivery serialization.
            } catch (failure: Error) {
                invalidateListenerAfterControlFailure(slot)
                throw failure
            } catch (failure: Throwable) {
                invalidateListenerAfterControlFailure(slot)
                throw failure
            }
        }
    }

    private fun drainActiveListener(slot: ListenerSlot) {
        try {
            drainListener(slot)
        } catch (failure: Throwable) {
            val action =
                synchronized(lock) {
                    val active = session
                    val lifecycle = state.get().lifecycle
                    if (
                        active == null ||
                        lifecycle !in
                        setOf(
                            ConnectivityObserverLifecycle.STARTING,
                            ConnectivityObserverLifecycle.ACTIVE,
                            ConnectivityObserverLifecycle.STOPPING,
                        )
                    ) {
                        null
                    } else {
                        recordPendingFailureLocked(
                            active = active,
                            failure = failure,
                            operation = null,
                            operational = false,
                            controlFlow = true,
                        )
                        requestCleanupLocked(active)
                    }
                }
            if (action != null && (action.owner || action.callerMayAwait)) {
                resolveCleanup(action = action)
            }
            throwPreservingIdentity(failure)
        }
    }

    private fun deliverListener(
        listener: ConnectivityObservationListener,
        deliveredState: ConnectivityObserverState,
    ) {
        val deliveryThread = Thread.currentThread()
        synchronized(lock) {
            val depth = listenerDeliveriesInProgress[deliveryThread] ?: 0
            check(depth != Int.MAX_VALUE) { "Listener delivery reentrancy depth exhausted." }
            listenerDeliveriesInProgress[deliveryThread] = depth + 1
        }
        try {
            listener.onObservation(deliveredState)
        } finally {
            synchronized(lock) {
                val depth =
                    requireNotNull(listenerDeliveriesInProgress[deliveryThread]) {
                        "Listener delivery context was cleared before callback return."
                    }
                if (depth == 1) {
                    listenerDeliveriesInProgress.remove(deliveryThread)
                } else {
                    listenerDeliveriesInProgress[deliveryThread] = depth - 1
                }
            }
        }
    }

    private fun invalidateListenerAfterControlFailure(slot: ListenerSlot) {
        synchronized(lock) {
            slot.invalidateLocked()
            if (listenerSlot === slot) listenerSlot = null
        }
    }

    private fun failedState(
        profile: ConnectivityCollectionProfile,
        operation: ConnectivityFailureOperation,
        snapshot: com.wifitestorchestrator.agent.domain.connectivity.ConnectivitySnapshot? = null,
    ): ConnectivityObserverState =
        failedStateAt(
            profile = profile,
            operation = operation,
            snapshot = snapshot,
            captured = timeSource.capture(),
        )

    private fun failedStateAt(
        profile: ConnectivityCollectionProfile,
        operation: ConnectivityFailureOperation,
        snapshot: com.wifitestorchestrator.agent.domain.connectivity.ConnectivitySnapshot?,
        captured: AndroidObservationTime,
    ): ConnectivityObserverState {
        val reason =
            when (operation) {
                ConnectivityFailureOperation.REGISTER_CALLBACK ->
                    ConnectivityObservationReason.REGISTRATION_FAILED
                ConnectivityFailureOperation.UNREGISTER_CALLBACK ->
                    ConnectivityObservationReason.UNREGISTRATION_FAILED
                ConnectivityFailureOperation.CLEANUP_THREAD ->
                    ConnectivityObservationReason.THREAD_CLEANUP_FAILED
                ConnectivityFailureOperation.MAP_PLATFORM_DATA ->
                    ConnectivityObservationReason.PLATFORM_ERROR
            }
        return ConnectivityObserverState(
            lifecycle = ConnectivityObserverLifecycle.FAILED,
            profile = profile,
            snapshot = snapshot,
            failure =
                ConnectivityObservationFailure(
                    operation = operation,
                    reason = reason,
                    occurredAtUtc = captured.observedAtUtc,
                    elapsedRealtimeNanos = captured.elapsedRealtimeNanos,
                ),
        )
    }

    private data class CleanupAction(
        val active: ActiveSession,
        val completion: LifecycleCompletion,
        val owner: Boolean,
        val callerMayAwait: Boolean,
    )

    private data class CleanupOutcome(
        val result: ConnectivityObserverCommandResult,
        val controlFailure: Throwable?,
    )

    private class LifecycleCompletion {
        private val completed = CountDownLatch(1)

        @Volatile
        private var outcome: CleanupOutcome? = null

        fun complete(outcome: CleanupOutcome) {
            this.outcome = outcome
            completed.countDown()
        }

        fun awaitAndPropagate(
            onInterrupted: () -> Unit = {},
        ): ConnectivityObserverCommandResult {
            var interrupted: InterruptedException? = null
            while (true) {
                try {
                    completed.await()
                    break
                } catch (failure: InterruptedException) {
                    if (interrupted == null) {
                        interrupted = failure
                    } else {
                        addSuppressedByIdentity(interrupted, failure)
                    }
                    onInterrupted()
                }
            }
            val resolved = requireNotNull(outcome)
            interrupted?.let { failure ->
                resolved.controlFailure?.let { addSuppressedByIdentity(failure, it) }
                Thread.currentThread().interrupt()
                throw failure
            }
            resolved.controlFailure?.let(::throwPreservingIdentity)
            return resolved.result
        }
    }

    private data class CloseOutcome(
        val controlFailure: Throwable?,
    )

    private class CloseCompletion(
        val priorFailure: ConnectivityObservationFailure?,
    ) {
        private val completed = CountDownLatch(1)

        @Volatile
        private var outcome: CloseOutcome? = null
        var deferredToLifecycleOwner: Boolean = false

        fun complete(controlFailure: Throwable?) {
            outcome = CloseOutcome(controlFailure)
            completed.countDown()
        }

        fun awaitAndPropagate() {
            var interrupted: InterruptedException? = null
            while (true) {
                try {
                    completed.await()
                    break
                } catch (failure: InterruptedException) {
                    if (interrupted == null) {
                        interrupted = failure
                    } else {
                        addSuppressedByIdentity(interrupted, failure)
                    }
                }
            }
            val resolved = requireNotNull(outcome)
            interrupted?.let { failure ->
                resolved.controlFailure?.let { addSuppressedByIdentity(failure, it) }
                Thread.currentThread().interrupt()
                throw failure
            }
            resolved.controlFailure?.let(::throwPreservingIdentity)
        }
    }

    private data class PendingNotification(
        val state: ConnectivityObserverState,
        val sessionGeneration: Long?,
    )

    private class ListenerSlot(
        val epoch: Long,
        val listener: ConnectivityObservationListener,
    ) {
        val pending = ArrayDeque<PendingNotification>()
        var active: Boolean = true
        var draining: Boolean = false
        var lastGeneration: Long? = null
        var lastQueuedSequence: Long? = null
        var lastQueuedState: ConnectivityObserverState? = null

        fun invalidateLocked() {
            active = false
            pending.clear()
        }
    }

    private class FailureAccumulator {
        var operationalOperation: ConnectivityFailureOperation? = null
            private set
        var controlFailure: Throwable? = null
            private set
        var interrupted: Boolean = false
            private set
        var requiresExplicitPropagation: Boolean = false
            private set
        private var ordinaryPrimary: Throwable? = null

        fun record(
            failure: Throwable,
            operation: ConnectivityFailureOperation?,
            operational: Boolean,
            controlFlow: Boolean = failure.isControlFlowFailure(),
            requiresExplicitPropagation: Boolean = false,
        ) {
            if (operational && operationalOperation == null) {
                operationalOperation = requireNotNull(operation)
            }
            if (failure is InterruptedException) interrupted = true
            if (requiresExplicitPropagation) this.requiresExplicitPropagation = true
            if (controlFlow) {
                val current = controlFailure
                if (current == null) {
                    controlFailure = failure
                    ordinaryPrimary?.let { addSuppressedByIdentity(failure, it) }
                } else {
                    addSuppressedByIdentity(current, failure)
                }
            } else {
                val primary = ordinaryPrimary
                if (primary == null) {
                    ordinaryPrimary = failure
                    controlFailure?.let { addSuppressedByIdentity(it, failure) }
                } else {
                    addSuppressedByIdentity(primary, failure)
                }
            }
        }

        fun record(failure: PendingFailure) {
            record(
                failure = failure.throwable,
                operation = failure.operation,
                operational = failure.operational,
                controlFlow = failure.controlFlow,
                requiresExplicitPropagation = failure.requiresExplicitPropagation,
            )
        }

        fun primaryFailureForExplicitPropagation(): Throwable? =
            controlFailure ?: ordinaryPrimary

        fun recordSecondary(
            primary: Throwable,
            secondary: Throwable,
        ) {
            if (secondary is InterruptedException) interrupted = true
            addSuppressedByIdentity(primary, secondary)
        }
    }

    private inner class SessionEvents(
        private val generation: Long,
    ) : AndroidDefaultNetworkEvents {
        override fun onAvailable(network: AndroidNetworkIdentity) {
            this@AndroidConnectivityObserver.onAvailable(generation, network)
        }

        override fun onCapabilitiesChanged(
            network: AndroidNetworkIdentity,
            capabilities: AndroidNetworkCapabilitiesSnapshot,
        ) {
            this@AndroidConnectivityObserver.onCapabilitiesChanged(
                generation,
                network,
                capabilities,
            )
        }

        override fun onControlFailure(failure: AndroidCallbackControlFailure) {
            this@AndroidConnectivityObserver.onControlFailure(generation, failure)
        }

        override fun onBlockedStatusChanged(
            network: AndroidNetworkIdentity,
            blocked: Boolean,
        ) {
            this@AndroidConnectivityObserver.onBlockedStatusChanged(
                generation,
                network,
                blocked,
            )
        }

        override fun onLost(network: AndroidNetworkIdentity) {
            this@AndroidConnectivityObserver.onLost(generation, network)
        }
    }

    private inner class ActiveSession(
        val generation: Long,
        val profile: ConnectivityCollectionProfile,
    ) {
        var dispatcher: AndroidCallbackDispatcher? = null
        var registration: AndroidNetworkCallbackRegistration? = null
        var unregisterAttempted: Boolean = false
        var dispatcherCloseAttempted: Boolean = false
        var startInProgress: Boolean = true
        var stopRequested: Boolean = false
        var cleanupOwnerClaimed: Boolean = false
        var cleanupCompletion: LifecycleCompletion? = null
        var lifecycleExternalOperationThread: Thread? = null
        val pendingFailures = mutableListOf<PendingFailure>()
        var network: AndroidNetworkIdentity? = null
        var capabilities: AndroidNetworkCapabilitiesSnapshot? = null
        var blocked: Boolean? = null
        var lastObservationTime: AndroidObservationTime? = null
        private var timeCaptureFailure: Throwable? = null
        private var nextSequence: Long = 0

        fun nextStamp(): AndroidObservationStamp {
            check(nextSequence != Long.MAX_VALUE) {
                "Connectivity observation sequence exhausted."
            }
            val captured =
                try {
                    timeSource.capture()
                } catch (failure: Throwable) {
                    timeCaptureFailure = failure
                    throw failure
                }
            timeCaptureFailure = null
            lastObservationTime = captured
            return AndroidObservationStamp(
                observedAtUtc = captured.observedAtUtc,
                elapsedRealtimeNanos = captured.elapsedRealtimeNanos,
                sequence = nextSequence++,
            )
        }

        fun consumeTimeCaptureFailure(failure: Throwable): Boolean =
            (timeCaptureFailure === failure).also { matches ->
                if (matches) timeCaptureFailure = null
            }
    }
}

internal enum class AndroidLifecycleCleanupWaiterKind {
    STOP,
    CLOSE,
}

internal enum class AndroidLifecycleCleanupWaiterPhase {
    REGISTERED,
    INTERRUPTED,
}

internal fun interface AndroidLifecycleCleanupWaiterObserver {
    fun onWaiterEvent(
        kind: AndroidLifecycleCleanupWaiterKind,
        phase: AndroidLifecycleCleanupWaiterPhase,
        thread: Thread,
    )
}

internal data class AndroidConnectivityObserverDiagnostics(
    val sessionPresent: Boolean,
    val closeInProgress: Boolean,
    val listenerDeliveriesInProgress: Int,
    val pendingFailureCount: Int,
)

private data class PendingFailure(
    val throwable: Throwable,
    val operation: ConnectivityFailureOperation?,
    val operational: Boolean,
    val controlFlow: Boolean,
    val requiresExplicitPropagation: Boolean,
)

internal data class AndroidObservationTime(
    val observedAtUtc: Instant,
    val elapsedRealtimeNanos: Long,
) {
    init {
        require(elapsedRealtimeNanos >= 0)
    }
}

internal fun interface AndroidObservationTimeSource {
    fun capture(): AndroidObservationTime
}

private object SystemAndroidObservationTimeSource : AndroidObservationTimeSource {
    override fun capture(): AndroidObservationTime =
        AndroidObservationTime(
            observedAtUtc = Instant.now(),
            elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos(),
        )
}

internal interface AndroidCallbackDispatcher : AutoCloseable {
    val handler: Handler

    override fun close()
}

internal fun interface AndroidCallbackDispatcherFactory {
    fun create(): AndroidCallbackDispatcher
}

private object HandlerThreadCallbackDispatcherFactory : AndroidCallbackDispatcherFactory {
    override fun create(): AndroidCallbackDispatcher = HandlerThreadCallbackDispatcher()
}

private class HandlerThreadCallbackDispatcher : AndroidCallbackDispatcher {
    private val thread =
        HandlerThread("wto-connectivity-observer").apply {
            start()
        }

    override val handler: Handler = Handler(thread.looper)

    override fun close() {
        check(thread.quitSafely()) { "Connectivity callback thread did not accept shutdown." }
        if (Thread.currentThread() !== thread) {
            thread.join(THREAD_JOIN_TIMEOUT_MILLIS)
            check(!thread.isAlive) { "Connectivity callback thread did not stop." }
        }
    }

    private companion object {
        const val THREAD_JOIN_TIMEOUT_MILLIS = 5_000L
    }
}

private fun Throwable.isControlFlowFailure(): Boolean =
    this is CancellationException || this is Error

private fun Throwable.isOrdinaryRuntimeFailure(): Boolean =
    this is RuntimeException && this !is CancellationException

private fun addSuppressedByIdentity(
    primary: Throwable,
    secondary: Throwable,
) {
    if (
        primary !== secondary &&
        primary.suppressed.none { existing -> existing === secondary }
    ) {
        primary.addSuppressed(secondary)
    }
}

private fun throwPreservingIdentity(failure: Throwable): Nothing {
    if (failure is InterruptedException) Thread.currentThread().interrupt()
    throw failure
}
