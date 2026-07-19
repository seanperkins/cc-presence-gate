// swift-tools-version:5.9
import PackageDescription
let package = Package(
  name: "cc-presence-gate",
  platforms: [.macOS(.v13)],
  targets: [
    .target(name: "CCGateCore"),
    .target(name: "CCFidoBackend", dependencies: ["CCGateCore"]),
    .target(name: "CCTouchIDBackend", dependencies: ["CCGateCore"]),
    .executableTarget(name: "cc-fido", dependencies: ["CCGateCore", "CCFidoBackend"]),
    .executableTarget(name: "cc-touch-id", dependencies: ["CCGateCore", "CCTouchIDBackend"]),
    .testTarget(name: "CCGateCoreTests", dependencies: ["CCGateCore"]),
    .testTarget(name: "CCFidoBackendTests", dependencies: ["CCFidoBackend", "CCGateCore"]),
    .testTarget(name: "CCTouchIDBackendTests", dependencies: ["CCTouchIDBackend", "CCGateCore"]),
  ]
)
