// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SwiftIPMI",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "SwiftIPMI",
            targets: ["SwiftIPMI"]
        )
    ],
    targets: [
        .target(
            name: "SwiftIPMI",
            dependencies: []
        ),
        .testTarget(
            name: "SwiftIPMITests",
            dependencies: ["SwiftIPMI"]
        )
    ]
)
