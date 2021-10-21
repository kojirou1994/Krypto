#if canImport(CommonCrypto)
import CommonCrypto

public final class CCKryptor {

  @usableFromInline
  let cryptorRef: OpaquePointer

  @inlinable
  public init<Key: ContiguousBytes, IV: ContiguousBytes>(operation: Int, algorithm: Int, options: Int, key: Key, initializationVector: IV) throws {
    var ptr: OpaquePointer?
    try key.withUnsafeBytes { keyBuffer in
      try initializationVector.withUnsafeBytes { ivBuffer in
        try ccError(
          CCCryptorCreate(
            .init(operation), .init(algorithm), .init(options),
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
