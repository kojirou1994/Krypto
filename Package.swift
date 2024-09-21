// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "Krypto",
  platforms: [.macOS(.v10_15), .iOS(.v13), .tvOS(.v13), .watchOS(.v6), .macCatalyst(.v13)],
  products: [
    .library(name: "Krypto", targets: ["Krypto"]),
  ],
  dependencies: [
    .package(url: "https://github.com/kojirou1994/CUtility.git", from: "0.2.0"),
  ],
  targets: [
    .target(
      name: "Krypto",
      dependencies: [
        .product(name: "CUtility", package: "CUtility"),
      ]
    ),
    .testTarget(
      name: "KryptoTests",
      dependencies: [
        .target(name: "Krypto"),
      ]
    ),
  ]
)
