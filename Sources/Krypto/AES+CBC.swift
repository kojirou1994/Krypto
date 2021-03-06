#if canImport(CommonCrypto)

import CommonCrypto

public enum AESCBC<Input: ContiguousBytes, Key: ContiguousBytes, IV: ContiguousBytes> {

  public static func decrypt(input: Input, key: Key, iv: IV) throws -> [UInt8] {
    try _cbc(input: input, key: key, iv: iv, operation: kCCDecrypt)
  }

  public static func encrypt(input: Input, key: Key, iv: IV) throws -> [UInt8] {
    try _cbc(input: input, key: key, iv: iv, operation: kCCEncrypt)
  }

  private static func _cbc(input: Input, key: Key, iv: IV, operation: Int) throws -> [UInt8] {
    let outputBufferLength = input.withUnsafeBytes { inputBuffer in
      inputBuffer.count + kCCBlockSizeAES128
    }
    return try [UInt8](unsafeUninitializedCapacity: outputBufferLength) { outputBuffer, initializedCount in
      try CommonKrypto.crypt(operation: operation, algorithm: kCCAlgorithmAES, options: kCCOptionPKCS7Padding, key: key, initializationVector: iv, input: input, outputBuffer: outputBuffer, dataOutMoved: &initializedCount)
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
