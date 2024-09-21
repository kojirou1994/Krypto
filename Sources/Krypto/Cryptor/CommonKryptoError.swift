#if canImport(CommonCrypto)
import CommonCrypto

public struct CommonKryptoError: RawRepresentable, Error, Equatable, Sendable {
  public init(rawValue: CCStatus) {
    self.rawValue = rawValue
  }

  @_alwaysEmitIntoClient
  init(_ rawValue: Int) {
    self.rawValue = numericCast(rawValue)
  }

  public let rawValue: CCStatus
}

extension CommonKryptoError: CustomStringConvertible {
  public var description: String {
    switch self {
    case .alignmentError: return "Input data did not decode or decrypt properly."
    case .paramError: return "Illegal parameter value."
    case .bufferTooSmall: return "Insufficent buffer provided for specified operation."
    case .memoryFailure: return "Memory allocation failure."
    case .decodeError: return "Input data did not decode or decrypt properly."
    case .unimplemented: return "Function not implemented for the current algorithm."
    case .overflow: return "overflow"
    case .rngFailure: return "rngFailure"
    case .unspecifiedError: return "unspecifiedError"
    case .callSequenceError: return "callSequenceError"
    case .keySizeError: return "keySizeError"
    case .invalidKey: return "invalidKey"
    default:
      return "unknown: \(rawValue)"
    }
  }
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
func ccError(_ body: () -> CCStatus) throws(CommonKryptoError) {
  let status = body()
  if status != kCCSuccess {
    throw CommonKryptoError(rawValue: status)
  }
}

public enum CommonKrypto {

  @available(*, deprecated, renamed: "Cryptor.crypt")
  public static func crypt(operation: CCKryptor.Operation, algorithm: CCKryptor.Algorithm, options: CCKryptor.Options, key: some ContiguousBytes, initializationVector: some ContiguousBytes = CCKryptor.NoneInitializationVector(), input: some ContiguousBytes, outputBuffer: UnsafeMutableBufferPointer<UInt8>, dataOutMoved: inout Int) throws(CommonKryptoError) {
    try Cryptor.crypt(operation: operation, algorithm: algorithm, options: options, key: key, initializationVector: initializationVector, input: input, outputBuffer: outputBuffer, dataOutMoved: &dataOutMoved)
  }
}
#endif
