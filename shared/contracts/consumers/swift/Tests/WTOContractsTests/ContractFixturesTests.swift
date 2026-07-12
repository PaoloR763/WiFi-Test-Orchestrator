import Foundation
import Testing
@testable import WTOContracts

private struct FixtureManifest: Decodable {
    let fixtures: [Fixture]
}

private struct Fixture: Decodable {
    let path: String
    let schema: String
    let valid: Bool
}

@Test func validatesExactlyTheNormativeManifest() throws {
    let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["WTO_CONTRACT_ROOT"] ?? "../..")
    let manifestURL = root.appending(path: "examples/manifest.json")
    let manifest = try JSONDecoder().decode(FixtureManifest.self, from: Data(contentsOf: manifestURL))
    var acceptedValid = 0
    var rejectedInvalid = 0

    #expect(manifest.fixtures.count == 25)
    for fixture in manifest.fixtures {
        let payload = try Data(contentsOf: root.appending(path: "examples/\(fixture.path)"))
        let actual = ContractValidator.validate(schema: fixture.schema, data: payload)
        #expect(actual == fixture.valid, Comment(rawValue: fixture.path))
        if actual && fixture.valid { acceptedValid += 1 }
        if !actual && !fixture.valid { rejectedInvalid += 1 }
    }

    #expect(acceptedValid == 12)
    #expect(rejectedInvalid == 13)
    print("Swift read \(manifestURL.path) and Codable/semantic validation processed 25 fixtures: accepted 12 valid and rejected 13 invalid.")
    print("Swift consumer is not a complete JSON Schema Draft 2020-12 validator.")
}
