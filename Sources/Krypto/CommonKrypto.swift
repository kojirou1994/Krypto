#if canImport(CommonCrypto)
import CommonCrypto

public struct CommonKryptoError: RawRepresentable, Error {
  public init(rawValue: CCStatus) {
    self.rawValue = rawValue
  }

  @_alwaysEmitIntoClient
  init(_ rawValue: Int) {
    self.rawValue = numericCast(rawValue)
  }

  public let rawValue: CCStatus
}

public extension CommonKryptoError {

  /// Illegal parameter value.
  @_alwaysEmitIntoClient
  static var paramError: Self { .init(kCCParamError) }

  /// Insufficent buffer provided for specified operation.
  @_alwaysEmitIntoClient
  static var bufferTooSmall: Self { .init(kCCBufferTooSmall) }

  /// Memory allocation failure.
  @_alwaysEmitIntoClient
  static var memoryFailure: Self { .init(kCCMemoryFailure) }

  /// Input size was not aligned properly.
  @_alwaysEmitIntoClient
  static var alignmentError: Self { .init(kCCAlignmentError) }

  /// Input data did not decode or decrypt properly.
  @_alwaysEmitIntoClient
  static var decodeError: Self { .init(kCCDecodeError) }

  /// Function not implemented for the current algorithm.
  @_alwaysEmitIntoClient
  static var unimplemented: Self { .init(kCCUnimplemented) }

  @_alwaysEmitIntoClient
  static var overflow: Self { .init(kCCOverflow) }

  @_alwaysEmitIntoClient
  static var rngFailure: Self { .init(kCCRNGFailure) }

  @_alwaysEmitIntoClient
  static var unspecifiedError: Self { .init(kCCUnspecifiedError) }

  @_alwaysEmitIntoClient
  static var callSequenceError: Self { .init(kCCCallSequenceError) }

  @_alwaysEmitIntoClient
  static var keySizeError: Self { .init(kCCKeySizeError) }

  /// Key is not valid.
  @_alwaysEmitIntoClient
  static var invalidKey: Self { .init(kCCInvalidKey) }
}

@usableFromInline
func ccError(_ status: CCStatus) throws {
  if status != kCCSuccess {
    throw CommonKryptoError(rawValue: status)
  }
}

public enum CommonKrypto {

  public static func crypt<Input: ContiguousBytes, Key: ContiguousBytes, IV: ContiguousBytes>(operation: Int, algorithm: Int, options: Int, key: Key, initializationVector: IV, input: Input, outputBuffer: UnsafeMutableBufferPointer<UInt8>, dataOutMoved: inout Int) throws {
    try input.withUnsafeBytes { inputBuffer in
      try key.withUnsafeBytes { keyBuffer in
        try initializationVector.withUnsafeBytes { ivBuffer in
          try ccError(
            CCCrypt(
              .init(operation),
              .init(algorithm),
              .init(options),
              keyBuffer.baseAddress, keyBuffer.count,
              ivBuffer.baseAddress,
              inputBuffer.baseAddress, inputBuffer.count,
              outputBuffer.baseAddress, outputBuffer.count,
              &dataOutMoved
            )
          )
        }
      }
    }
  }
}
#endif
