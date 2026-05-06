// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecureOpsDemo",
    dependencies: [
        // Intentionally vulnerable/outdated dependency to trigger Trivy (SCA)
        .package(url: "https://github.com/Alamofire/Alamofire.git", .exact("4.9.0"))
    ],
    targets: [
        .executableTarget(
            name: "SecureOpsDemo",
            dependencies: ["Alamofire"]
        ),
    ]
)
