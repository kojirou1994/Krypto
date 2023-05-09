// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "Krypto",
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
