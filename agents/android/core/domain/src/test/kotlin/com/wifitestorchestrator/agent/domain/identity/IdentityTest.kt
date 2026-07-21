package com.wifitestorchestrator.agent.domain.identity

import com.wifitestorchestrator.agent.domain.error.Valid
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals

class IdentityTest {
    private val installationId = valid(InstallationId.parse("10000000-0000-4000-8000-000000000001"))
    private val agentId = valid(AgentId.parse("10000000-0000-4000-8000-000000000002"))
    private val deviceId = valid(DeviceId.parse("10000000-0000-4000-8000-000000000003"))

    @Test
    fun absentRepresentsNoIdentityWithoutSentinels() {
        assertEquals(IdentityState.Absent, IdentityState.Absent)
    }

    @Test
    fun localOnlyContainsExactlyTheLocalInstallation() {
        val local = LocalInstallationIdentity(installationId)
        val state = IdentityState.LocalOnly(local)

        assertEquals(local, state.localIdentity)
    }

    @Test
    fun assignedRequiresCompleteLocalAndBackendIdentity() {
        val local = LocalInstallationIdentity(installationId)
        val backend = BackendAgentIdentity(agentId, deviceId)
        val state = IdentityState.Assigned(local, backend)

        assertEquals(local, state.localIdentity)
        assertEquals(backend, state.backendIdentity)
        assertEquals(
            setOf("agentId", "deviceId"),
            BackendAgentIdentity::class.java.declaredFields
                .filterNot { Modifier.isStatic(it.modifiers) }
                .map { it.name }
                .toSet(),
        )
    }

    @Test
    fun identitiesUseStructuralEquality() {
        val first = BackendAgentIdentity(agentId, deviceId)
        val second = BackendAgentIdentity(agentId, deviceId)

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
        assertNotEquals(LocalInstallationIdentity(installationId) as Any, first as Any)
    }

    @Test
    fun backendAssignedIdsDoNotExposeGenerationFactories() {
        assertFalse(AgentId.Companion::class.java.declaredMethods.any { it.name == "generate" })
        assertFalse(DeviceId.Companion::class.java.declaredMethods.any { it.name == "generate" })
        assertFalse(CredentialId.Companion::class.java.declaredMethods.any { it.name == "generate" })
    }

    private fun <T : Any> valid(result: com.wifitestorchestrator.agent.domain.error.ValidationResult<T>): T =
        assertIs<Valid<T>>(result).value
}
