// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "WTOContracts",
    products: [.library(name: "WTOContracts", targets: ["WTOContracts"])],
    targets: [
        .target(name: "WTOContracts"),
        .testTarget(name: "WTOContractsTests", dependencies: ["WTOContracts"])
    ]
)
