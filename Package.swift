// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "Krypto",
  products: [
    .library(name: "Krypto", targets: ["Krypto"]),
  ],
  dependencies: [
  ],
  targets: [
    .target(name: "Krypto"),
    .testTarget(
      name: "KryptoTests",
      dependencies: [
        .target(name: "Krypto"),
      ]),
  ]
)
