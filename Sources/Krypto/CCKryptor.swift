#if canImport(CommonCrypto)
import CommonCrypto

public final class CCKryptor {

  @usableFromInline
  internal let cryptorRef: OpaquePointer

  @inlinable
  public init<Key: ContiguousBytes, IV: ContiguousBytes>(operation: Operation, algorithm: Algorithm, options: Options, key: Key, initializationVector: IV) throws {
    var ptr: OpaquePointer?
    try key.withUnsafeBytes { keyBuffer in
      try initializationVector.withUnsafeBytes { ivBuffer in
        try ccError(
          CCCryptorCreate(
            numericCast(operation.rawValue),
            numericCast(algorithm.rawValue),
            numericCast(options.rawValue),
            keyBuffer.baseAddress, keyBuffer.count,
            ivBuffer.baseAddress, &ptr)
        )
      }
    }
    guard let v = ptr else {
      throw CommonKryptoError.memoryFailure
    }
    self.cryptorRef = v
  }

  @inlinable
  public func update<Input: ContiguousBytes>(input: Input, to output: UnsafeMutableRawBufferPointer, dataOutMoved: inout Int) throws {
    try input.withUnsafeBytes { inputBuffer in
      try ccError(
        CCCryptorUpdate(cryptorRef, inputBuffer.baseAddress, inputBuffer.count, output.baseAddress, output.count, &dataOutMoved)
      )
    }
  }

  @inlinable
  public func final(output: UnsafeMutableRawBufferPointer, dataOutMoved: inout Int) throws {
    try ccError(
      CCCryptorFinal(cryptorRef, output.baseAddress, output.count, &dataOutMoved)
    )
  }

  @inlinable
  public func reset<IV: ContiguousBytes>(newInitializationVector: IV) throws {
    try newInitializationVector.withUnsafeBytes { ivBuffer in
      try ccError(
        CCCryptorReset(cryptorRef, ivBuffer.baseAddress)
      )
    }
  }

  @inlinable
  public func reset() throws {
    try ccError(
      CCCryptorReset(cryptorRef, nil)
    )
  }

  @inlinable
  public func getOutputLength(inputLength: Int, isFinal: Bool) -> Int {
    CCCryptorGetOutputLength(cryptorRef, inputLength, isFinal)
  }

  @inlinable
  deinit {
    CCCryptorRelease(cryptorRef)
  }
}
#endif

extension CCKryptor {
  public struct Operation: RawRepresentable, Equatable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var encryption: Self { .init(rawValue: kCCEncrypt) }

    @_alwaysEmitIntoClient
    public static var decryption: Self { .init(rawValue: kCCDecrypt) }
  }

  public struct Algorithm: RawRepresentable, Equatable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    /// Block sizes, in bytes
    @inlinable
    public var blockSize: Int {
      switch self {
      case .aes: return kCCBlockSizeAES128
      case .des: return kCCBlockSizeDES
      case .tripleDES: return kCCBlockSize3DES
      case .cast: return kCCBlockSizeCAST
      case .rc2: return kCCBlockSizeRC2
      case .blowfish: return kCCBlockSizeBlowfish
      default:
        assertionFailure("Unsupported Block Size!")
        return 0
      }
    }

    @_alwaysEmitIntoClient
    public static var aes: Self { .init(rawValue: kCCAlgorithmAES) }

    @_alwaysEmitIntoClient
    public static var des: Self { .init(rawValue: kCCAlgorithmDES) }

    @_alwaysEmitIntoClient
    public static var tripleDES: Self { .init(rawValue: kCCAlgorithm3DES) }

    @_alwaysEmitIntoClient
    public static var cast: Self { .init(rawValue: kCCAlgorithmCAST) }

    @_alwaysEmitIntoClient
    public static var rc4: Self { .init(rawValue: kCCAlgorithmRC4) }

    @_alwaysEmitIntoClient
    public static var rc2: Self { .init(rawValue: kCCAlgorithmRC2) }

    @_alwaysEmitIntoClient
    public static var blowfish: Self { .init(rawValue: kCCAlgorithmBlowfish) }
  }

  public struct Options: OptionSet {
    public var rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var pkcs7Padding: Self { .init(rawValue: kCCOptionPKCS7Padding) }

    @_alwaysEmitIntoClient
    public static var ecbMode: Self { .init(rawValue: kCCOptionECBMode) }
  }
}
