// swift-tools-version:5.9
import PackageDescription
let package = Package(
  name: "cc-fido-gate",
  platforms: [.macOS(.v13)],
  targets: [
    .target(name: "CCFidoCore"),
    .executableTarget(name: "cc-fido", dependencies: ["CCFidoCore"]),
    .testTarget(name: "CCFidoCoreTests", dependencies: ["CCFidoCore"]),
  ]
)
