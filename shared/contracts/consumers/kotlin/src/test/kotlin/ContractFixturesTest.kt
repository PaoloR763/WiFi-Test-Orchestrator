import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.serialization.json.*

class ContractFixturesTest {
    private val json = Json { ignoreUnknownKeys = false }
    private val root = Path.of(System.getenv("WTO_CONTRACT_ROOT") ?: "../..")

    @Test
    fun validatesExactlyTheNormativeManifest() {
        val manifest = json.parseToJsonElement(Files.readString(root.resolve("examples/manifest.json"))).jsonObject
        val fixtures = manifest.getValue("fixtures").jsonArray
        fixtures.forEach { entryValue ->
            val entry = entryValue.jsonObject
            val payload = json.parseToJsonElement(
                Files.readString(root.resolve("examples").resolve(entry.getValue("path").jsonPrimitive.content))
            )
            val schema = entry.getValue("schema").jsonPrimitive.content
            val expected = entry.getValue("valid").jsonPrimitive.boolean
            assertEquals(expected, validate(schema, payload), entry.getValue("path").toString())
        }
        println("Kotlin semantic models validated ${fixtures.size} normative fixtures.")
    }

    private fun validate(schema: String, value: JsonElement): Boolean {
        val objectValue = value as? JsonObject ?: return false
        if (objectValue["schema_version"]?.jsonPrimitive?.content != "1.0.0") return false
        return when (schema) {
            "agent-registration-request.schema.json" ->
                strictKeys(objectValue, setOf("schema_version", "idempotency_key", "enrollment_token", "installation_id", "display_name", "platform", "platform_version", "agent_version", "protocol_min_version", "protocol_max_version", "agent_reported_at")) && uuid(objectValue["idempotency_key"])
            "agent-registration-response.schema.json" -> objectValue.keys == setOf("schema_version", "device_id", "agent_id", "protocol_version", "server_received_at", "credential")
            "agent-credential.schema.json" -> strictKeys(objectValue, setOf("schema_version", "credential_id", "credential_version", "credential", "issued_at", "expires_at", "state"))
            "capability-manifest.schema.json" -> validateManifest(objectValue)
            "desktop-heartbeat.schema.json" -> strictKeys(objectValue, setOf("schema_version", "agent_id", "boot_id", "sequence", "agent_version", "protocol_version", "agent_reported_at", "readiness", "reason", "manifest_id", "manifest_digest")) && objectValue["protocol_version"]?.jsonPrimitive?.content == "1.0.0"
            "mobile-presence.schema.json" -> strictKeys(objectValue, setOf("schema_version", "agent_id", "boot_id", "sequence", "agent_version", "protocol_version", "agent_reported_at", "lifecycle", "reason", "manifest_id", "manifest_digest"))
            "task-envelope.schema.json" -> objectValue["task_type"]?.jsonPrimitive?.content == "protocol.contract_check"
            "progress-event.schema.json" -> objectValue["progress_percent"]?.jsonPrimitive?.doubleOrNull?.let { it in 0.0..100.0 } == true
            "test-result.schema.json" -> objectValue["metrics"] is JsonArray
            "artifact-manifest.schema.json" ->
                strictKeys(objectValue, setOf("schema_version", "artifact_id", "execution_id", "artifact_type", "media_type", "size_bytes", "sha256", "created_at", "idempotency_key")) &&
                    objectValue["size_bytes"]?.jsonPrimitive?.longOrNull?.let { it in 0..1_073_741_824 } == true
            else -> false
        }
    }

    private fun validateManifest(value: JsonObject): Boolean {
        val items = value["capabilities"] as? JsonArray ?: return false
        if (items.size != 15) return false
        val allowed = setOf("supported", "conditional", "unsupported", "unknown", "not_applicable")
        val ids = items.mapNotNull { item ->
            val entry = item.jsonObject
            if (entry.keys != setOf("id", "version", "technical_support", "implementation_status", "permission_requirement", "user_interaction", "background_execution", "provider", "limitations")) return false
            if (entry["technical_support"]!!.jsonObject["status"]!!.jsonPrimitive.content !in allowed) return false
            entry["id"]!!.jsonPrimitive.content
        }
        return ids.toSet().size == 15 && ids.none { it.contains("iperf3") }
    }

    private fun strictKeys(value: JsonObject, keys: Set<String>) = value.keys == keys
    private fun uuid(value: JsonElement?) = value?.jsonPrimitive?.content?.matches(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) == true
}
