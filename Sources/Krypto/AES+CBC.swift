#if canImport(CommonCrypto)

import CommonCrypto

public enum AESCBC<Input: ContiguousBytes, Key: ContiguousBytes, IV: ContiguousBytes> {

  public static func decrypt(input: Input, key: Key, iv: IV) throws -> [UInt8] {
    try _cbc(input: input, key: key, iv: iv, operation: .decryption)
  }

  public static func encrypt(input: Input, key: Key, iv: IV) throws -> [UInt8] {
    try _cbc(input: input, key: key, iv: iv, operation: .encryption)
  }

  private static func _cbc(input: Input, key: Key, iv: IV, operation: CCKryptor.Operation) throws -> [UInt8] {
    let outputBufferLength = input.withUnsafeBytes(\.count) + CCKryptor.Algorithm.aes.blockSize
    return try [UInt8](unsafeUninitializedCapacity: outputBufferLength) { outputBuffer, initializedCount in
      try CommonKrypto.crypt(operation: operation, algorithm: .aes, options: .pkcs7Padding, key: key, initializationVector: iv, input: input, outputBuffer: outputBuffer, dataOutMoved: &initializedCount)
    }
  }
}

#if canImport(CryptoKit)
import CryptoKit
@available(iOS 13.0, macOS 10.15, watchOS 6.0, tvOS 13.0, *)
extension AES {
  typealias CBC = AESCBC
}
#endif // CryptoKit end
#endif // CommonCrypto end
