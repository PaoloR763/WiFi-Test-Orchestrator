import Foundation

public enum ContractValidator {
    public static func validate(schema: String, data: Data) -> Bool {
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: data),
              let object = value.objectValue,
              object["schema_version"]?.stringValue == "1.0.0"
        else { return false }
        switch schema {
        case "agent-registration-request.schema.json":
            return keys(object, equal: ["schema_version", "idempotency_key", "enrollment_token", "installation_id", "display_name", "platform", "platform_version", "agent_version", "protocol_min_version", "protocol_max_version", "agent_reported_at"]) && uuid(object["idempotency_key"]?.stringValue)
        case "agent-registration-response.schema.json":
            return keys(object, equal: ["schema_version", "device_id", "agent_id", "protocol_version", "server_received_at", "credential"])
        case "agent-credential.schema.json":
            return keys(object, equal: ["schema_version", "credential_id", "credential_version", "credential", "issued_at", "expires_at", "state"])
        case "capability-manifest.schema.json": return manifest(object)
        case "desktop-heartbeat.schema.json":
            return keys(object, equal: ["schema_version", "agent_id", "boot_id", "sequence", "agent_version", "protocol_version", "agent_reported_at", "readiness", "reason", "manifest_id", "manifest_digest"]) && object["protocol_version"]?.stringValue == "1.0.0"
        case "mobile-presence.schema.json":
            return keys(object, equal: ["schema_version", "agent_id", "boot_id", "sequence", "agent_version", "protocol_version", "agent_reported_at", "lifecycle", "reason", "manifest_id", "manifest_digest"])
        case "task-envelope.schema.json": return object["task_type"]?.stringValue == "protocol.contract_check"
        case "progress-event.schema.json":
            guard let number = object["progress_percent"]?.numberValue else { return false }
            return number >= 0 && number <= 100
        case "test-result.schema.json": return object["metrics"]?.arrayValue != nil
        case "artifact-manifest.schema.json":
            guard let size = object["size_bytes"]?.numberValue else { return false }
            return keys(object, equal: ["schema_version","artifact_id","execution_id","artifact_type","media_type","size_bytes","sha256","created_at","idempotency_key"])
                && size >= 0 && size <= 1_073_741_824
        default: return false
        }
    }

    private static func manifest(_ object: [String: JSONValue]) -> Bool {
        guard let capabilities = object["capabilities"]?.arrayValue, capabilities.count == 15 else { return false }
        let dimensions: Set<String> = ["id", "version", "technical_support", "implementation_status", "permission_requirement", "user_interaction", "background_execution", "provider", "limitations"]
        let statuses: Set<String> = ["supported","conditional","unsupported","unknown","not_applicable"]
        var ids = Set<String>()
        for capability in capabilities {
            guard let entry = capability.objectValue,
                  Set(entry.keys) == dimensions,
                  let id = entry["id"]?.stringValue, !id.contains("iperf3"),
                  let technical = entry["technical_support"]?.objectValue,
                  let status = technical["status"]?.stringValue, statuses.contains(status) else { return false }
            ids.insert(id)
        }
        return ids.count == 15
    }

    private static func keys(_ object: [String: JSONValue], equal expected: Set<String>) -> Bool { Set(object.keys) == expected }
    private static func uuid(_ text: String?) -> Bool {
        guard let text else { return false }
        let pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        return text.range(of: pattern, options: .regularExpression) != nil
    }
}

private enum JSONValue: Decodable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case number(Double)
    case boolean(Bool)
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .boolean(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else { self = .array(try container.decode([JSONValue].self)) }
    }

    var objectValue: [String: JSONValue]? {
        guard case let .object(value) = self else { return nil }
        return value
    }

    var arrayValue: [JSONValue]? {
        guard case let .array(value) = self else { return nil }
        return value
    }

    var stringValue: String? {
        guard case let .string(value) = self else { return nil }
        return value
    }

    var numberValue: Double? {
        guard case let .number(value) = self else { return nil }
        return value
    }
}
