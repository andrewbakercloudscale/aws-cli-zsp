// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "aws-cli-zsp",
    platforms: [.macOS(.v14)],
    targets: [
        // Everything that touches a secret: the Keychain, Touch ID, AWS signing, the AWS files,
        // the audit log. No UI.
        .target(
            name: "ZSPCore",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("LocalAuthentication")]
        ),
        // The only binary that reads secrets. The AWS CLI calls it as credential_process.
        .executableTarget(name: "zsp", dependencies: ["ZSPCore"]),
        // The menu bar app. It reads metadata and the audit log itself and asks zsp for
        // anything that needs a secret, so the Keychain only ever trusts one binary.
        .executableTarget(name: "ZSPMenu", dependencies: ["ZSPCore"]),
        .testTarget(name: "ZSPCoreTests", dependencies: ["ZSPCore"]),
    ]
)
