package com.wifitestorchestrator.agent.contracts

import com.wifitestorchestrator.agent.contracts.enrollment.AgentCredentialDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationRequestDto
import com.wifitestorchestrator.agent.contracts.enrollment.AgentRegistrationResponseDto
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse
import kotlinx.serialization.decodeFromString

class SecretRedactionTest {
    @Test
    fun registrationRequestToStringRedactsEnrollmentToken() {
        val request =
            strictJson.decodeFromString<AgentRegistrationRequestDto>(
                CanonicalContractFixtures.read("valid/agent-registration-request.json"),
            )
        val rendered = request.toString()

        assertFalse(rendered.contains(request.enrollmentToken))
        assertFalse(rendered.contains("enrollment_token"))
        assertContains(rendered, "enrollmentToken=<redacted>")
    }

    @Test
    fun credentialToStringRedactsCredentialMaterial() {
        val credential =
            strictJson.decodeFromString<AgentCredentialDto>(
                CanonicalContractFixtures.read("valid/agent-credential.json"),
            )
        val rendered = credential.toString()

        assertFalse(rendered.contains(credential.credential))
        assertContains(rendered, "credential=<redacted>")
    }

    @Test
    fun registrationResponseToStringDoesNotDelegateToCredential() {
        val response =
            strictJson.decodeFromString<AgentRegistrationResponseDto>(
                CanonicalContractFixtures.read("valid/agent-registration-response.json"),
            )
        val rendered = response.toString()

        assertFalse(rendered.contains(response.credential.credential))
        assertFalse(rendered.contains(response.credential.credentialId))
        assertContains(rendered, "credential=<redacted>")
    }

    @Test
    fun sensitiveDtosDoNotExposeDataClassOrValueEqualityMethods() {
        listOf(
            AgentRegistrationRequestDto::class.java,
            AgentRegistrationResponseDto::class.java,
            AgentCredentialDto::class.java,
        ).forEach(::assertNoSensitiveDataClassApi)
    }

    private fun assertNoSensitiveDataClassApi(type: Class<*>) {
        val methods = type.declaredMethods.map { it.name }.toSet()

        assertFalse("copy" in methods)
        assertFalse(methods.any { it.startsWith("component") })
        assertFalse("equals" in methods)
        assertFalse("hashCode" in methods)
    }
}
