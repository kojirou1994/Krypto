#if canImport(CommonCrypto)
import CommonCrypto
import CUtility

@available(*, deprecated, renamed: "Cryptor")
public typealias CCKryptor = Cryptor

public struct Cryptor: ~Copyable {

  @usableFromInline
  internal let cryptorRef: OpaquePointer

  @inlinable
  public init(operation: Operation, algorithm: Algorithm, options: Options, key: some ContiguousBytes, initializationVector: some ContiguousBytes = NoneInitializationVector()) throws(CommonKryptoError) {
    cryptorRef = try safeInitialize { ptr throws(CommonKryptoError) in
      try ccError {
        key.withUnsafeBytes { keyBuffer in
          initializationVector.withUnsafeBytes { ivBuffer in
            CCCryptorCreate(
              numericCast(operation.rawValue),
              numericCast(algorithm.rawValue),
              numericCast(options.rawValue),
              keyBuffer.baseAddress, keyBuffer.count,
              ivBuffer.baseAddress, &ptr)
          }
        }
      }
    }
  }

  @inlinable
  public init(operation: Operation, algorithm: Algorithm, options: Options, key: some ContiguousBytes, initializationVector: some ContiguousBytes = NoneInitializationVector(), data: UnsafeMutableRawBufferPointer, dataUsed: UnsafeMutablePointer<Int>?) throws(CommonKryptoError) {
    cryptorRef = try safeInitialize { ptr throws(CommonKryptoError) in
      try ccError {
        key.withUnsafeBytes { keyBuffer in
          initializationVector.withUnsafeBytes { ivBuffer in
            data.withUnsafeBytes { data in
              CCCryptorCreateFromData(
                numericCast(operation.rawValue),
                numericCast(algorithm.rawValue),
                numericCast(options.rawValue),
                keyBuffer.baseAddress, keyBuffer.count,
                ivBuffer.baseAddress,
                data.baseAddress, data.count,
                &ptr, dataUsed)
            }
          }
        }
      }
    }
  }

  @inlinable
  public init(operation: Operation, mode: Mode, algorithm: Algorithm, padding: Padding, options: ModeOptions, initializationVector: some ContiguousBytes = NoneInitializationVector(), key: some ContiguousBytes, tweak: some ContiguousBytes, rounds: Int32) throws(CommonKryptoError) {
    cryptorRef = try safeInitialize { ptr throws(CommonKryptoError) in
      try ccError {
        key.withUnsafeBytes { keyBuffer in
          tweak.withUnsafeBytes { tweak in
            initializationVector.withUnsafeBytes { ivBuffer in
              CCCryptorCreateWithMode(
                numericCast(operation.rawValue),
                numericCast(mode.rawValue),
                numericCast(algorithm.rawValue),
                numericCast(padding.rawValue),
                ivBuffer.baseAddress,
                keyBuffer.baseAddress, keyBuffer.count,
                tweak.baseAddress, tweak.count,
                rounds,
                numericCast(options.rawValue),
                &ptr)
            }
          }
        }
      }
    }
  }

  @inlinable
  public func update(input: some ContiguousBytes, to output: UnsafeMutableRawBufferPointer, dataOutMoved: inout Int) throws(CommonKryptoError) {
    try ccError {
      input.withUnsafeBytes { inputBuffer in
        CCCryptorUpdate(cryptorRef, inputBuffer.baseAddress, inputBuffer.count, output.baseAddress, output.count, &dataOutMoved)
      }
    }
  }

  @inlinable
  public func final(output: UnsafeMutableRawBufferPointer, dataOutMoved: inout Int) throws(CommonKryptoError) {
    try ccError {
      CCCryptorFinal(cryptorRef, output.baseAddress, output.count, &dataOutMoved)
    }
  }

  @inlinable
  public func reset(newInitializationVector: some ContiguousBytes = NoneInitializationVector()) throws(CommonKryptoError) {
    try ccError {
      newInitializationVector.withUnsafeBytes { ivBuffer in
        CCCryptorReset(cryptorRef, ivBuffer.baseAddress)
      }
    }
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

extension Cryptor {
  public struct Operation: RawRepresentable, Equatable, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var encryption: Self { .init(rawValue: kCCEncrypt) }

    @_alwaysEmitIntoClient
    public static var decryption: Self { .init(rawValue: kCCDecrypt) }
  }

  public struct Algorithm: RawRepresentable, Equatable, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    public struct KeySize: RawRepresentable, Equatable, Sendable {
      public let rawValue: Int
      public init(rawValue: Int) {
        self.rawValue = rawValue
      }

      @_alwaysEmitIntoClient
      public static var aes128: Self { .init(rawValue: kCCKeySizeAES128) }

      @_alwaysEmitIntoClient
      public static var aes192: Self { .init(rawValue: kCCKeySizeAES192) }

      @_alwaysEmitIntoClient
      public static var aes256: Self { .init(rawValue: kCCKeySizeAES256) }

      @_alwaysEmitIntoClient
      public static var des: Self { .init(rawValue: kCCKeySizeDES) }

      @_alwaysEmitIntoClient
      public static var tripleDES: Self { .init(rawValue: kCCKeySize3DES) }

      @_alwaysEmitIntoClient
      public static var minCAST: Self { .init(rawValue: kCCKeySizeMinCAST) }

      @_alwaysEmitIntoClient
      public static var maxCAST: Self { .init(rawValue: kCCKeySizeMaxCAST) }

      @_alwaysEmitIntoClient
      public static var minRC4: Self { .init(rawValue: kCCKeySizeMinRC4) }

      @_alwaysEmitIntoClient
      public static var maxRC4: Self { .init(rawValue: kCCKeySizeMaxRC4) }

      @_alwaysEmitIntoClient
      public static var minRC2: Self { .init(rawValue: kCCKeySizeMinRC2) }

      @_alwaysEmitIntoClient
      public static var maxRC2: Self { .init(rawValue: kCCKeySizeMaxRC2) }

      @_alwaysEmitIntoClient
      public static var minBlowfish: Self { .init(rawValue: kCCKeySizeMinBlowfish) }

      @_alwaysEmitIntoClient
      public static var maxBlowfish: Self { .init(rawValue: kCCKeySizeMaxBlowfish) }
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

    /// Minimum context sizes, for caller-allocated CCKryptor.
    @inlinable
    public var minimumContextSize: Int {
      switch self {
      case .aes: return kCCContextSizeAES128
      case .des: return kCCContextSizeDES
      case .tripleDES: return kCCContextSize3DES
      case .cast: return kCCContextSizeCAST
      case .rc4: return kCCContextSizeRC4
      default:
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

  public struct Options: OptionSet, Sendable {
    public var rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var pkcs7Padding: Self { .init(rawValue: kCCOptionPKCS7Padding) }

    @_alwaysEmitIntoClient
    public static var ecbMode: Self { .init(rawValue: kCCOptionECBMode) }
  }

  public struct Mode: RawRepresentable, Equatable, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var ecb: Self { .init(rawValue: kCCModeECB) }

    @_alwaysEmitIntoClient
    public static var cbc: Self { .init(rawValue: kCCModeCBC) }

    @_alwaysEmitIntoClient
    public static var cfb: Self { .init(rawValue: kCCModeCFB) }

    @_alwaysEmitIntoClient
    public static var ctr: Self { .init(rawValue: kCCModeCTR) }

    @_alwaysEmitIntoClient
    public static var ofb: Self { .init(rawValue: kCCModeOFB) }

    @_alwaysEmitIntoClient
    public static var rc4: Self { .init(rawValue: kCCModeRC4) }

    @_alwaysEmitIntoClient
    public static var cfb8: Self { .init(rawValue: kCCModeCFB8) }
  }

  public struct Padding: RawRepresentable, Equatable, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var noPadding: Self { .init(rawValue: ccNoPadding) }

    @_alwaysEmitIntoClient
    public static var pkcs7Padding: Self { .init(rawValue: ccPKCS7Padding) }
  }

  public struct ModeOptions: RawRepresentable, Equatable, Sendable {
    public let rawValue: Int
    public init(rawValue: Int) {
      self.rawValue = rawValue
    }

    @_alwaysEmitIntoClient
    public static var ctrBE: Self { .init(rawValue: kCCModeOptionCTR_BE) }
  }

  public struct NoneInitializationVector: ContiguousBytes, Sendable {
    public init() {}
    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
      try body(.init(start: nil, count: 0))
    }
  }
}


public extension Cryptor {
  static func crypt(operation: Operation, algorithm: Algorithm, options: Options, key: some ContiguousBytes, initializationVector: some ContiguousBytes = NoneInitializationVector(), input: some ContiguousBytes, outputBuffer: UnsafeMutableBufferPointer<UInt8>, dataOutMoved: inout Int) throws(CommonKryptoError) {
    try ccError {
      input.withUnsafeBytes { inputBuffer in
        key.withUnsafeBytes { keyBuffer in
          initializationVector.withUnsafeBytes { ivBuffer in
            CCCrypt(
              numericCast(operation.rawValue),
              numericCast(algorithm.rawValue),
              numericCast(options.rawValue),
              keyBuffer.baseAddress, keyBuffer.count,
              ivBuffer.baseAddress,
              inputBuffer.baseAddress, inputBuffer.count,
              outputBuffer.baseAddress, outputBuffer.count,
              &dataOutMoved
            )
          }
        }
      }
    }
  }
}

#endif
