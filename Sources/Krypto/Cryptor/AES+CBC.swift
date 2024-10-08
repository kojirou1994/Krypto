#if canImport(CommonCrypto)

import CommonCrypto

public enum AESCBC {

  public static func decrypt(input: some ContiguousBytes, key: some ContiguousBytes, iv: some ContiguousBytes) throws(CommonKryptoError) -> [UInt8] {
    try _cbc(input: input, key: key, iv: iv, operation: .decryption)
  }

  public static func encrypt(input: some ContiguousBytes, key: some ContiguousBytes, iv: some ContiguousBytes) throws(CommonKryptoError) -> [UInt8] {
    try _cbc(input: input, key: key, iv: iv, operation: .encryption)
  }

  private static func _cbc(input: some ContiguousBytes, key: some ContiguousBytes, iv: some ContiguousBytes, operation: Cryptor.Operation) throws(CommonKryptoError) -> [UInt8] {
    let outputBufferLength = input.withUnsafeBytes(\.count) + Cryptor.Algorithm.aes.blockSize
    do {
      // old std init func has no generic error throwing..
      return try [UInt8](unsafeUninitializedCapacity: outputBufferLength) { outputBuffer, initializedCount in
        try Cryptor.crypt(operation: operation, algorithm: .aes, options: .pkcs7Padding, key: key, initializationVector: iv, input: input, outputBuffer: outputBuffer, dataOutMoved: &initializedCount)
      }
    } catch let err as CommonKryptoError {
      throw err
    } catch { fatalError() }
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
