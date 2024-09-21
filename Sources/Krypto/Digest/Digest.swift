#if canImport(CommonCrypto)
import CommonCrypto

/// the data is all on stack
public struct GenericStackDigest<Context> {
  @inlinable
  internal init(_ _init: (_ c: UnsafeMutablePointer<Context>) -> Int32, _ _update: @escaping (UnsafeMutablePointer<Context>, UnsafeRawPointer?, CC_LONG) -> Int32, _ _final: @escaping (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<Context>) -> Int32, _ digestLength: Int32) {
    // undefined value
    self.context = withUnsafeTemporaryAllocation(of: Context.self, capacity: 1) { $0[0] }
    self._update = _update
    self._final = _final
    self.digestLength = numericCast(digestLength)
    let r = _init(&self.context)
    assert(r == 1)
  }

  @usableFromInline
  internal var context: Context

  @usableFromInline
  internal let _update: (_ c: UnsafeMutablePointer<Context>, _ data: UnsafeRawPointer?, _ len: CC_LONG) -> Int32
  @usableFromInline
  internal let _final: (_ md: UnsafeMutablePointer<UInt8>, _ c: UnsafeMutablePointer<Context>) -> Int32

  public let digestLength: Int

  @inlinable
  public mutating func update(_ data: UnsafeRawBufferPointer) {
    _ = _update(&context, data.baseAddress, numericCast(data.count))
  }

  @inlinable
  public mutating func final(output: UnsafeMutablePointer<UInt8>) {
    _ = _final(output, &context)
  }
}

extension GenericStackDigest {

  @inlinable
  public __consuming func hash(bytes: some ContiguousBytes) -> [UInt8] {
    var copy = self
    copy.update(bytes: bytes)
    return copy.final()
  }

  @inlinable
  public mutating func final() -> [UInt8] {
    .init(unsafeUninitializedCapacity: digestLength) { buffer, initializedCount in
      final(output: buffer.baseAddress!)
      initializedCount = digestLength
    }
  }

  @inlinable
  public mutating func update(bytes: some ContiguousBytes) {
    bytes.withUnsafeBytes { update($0) }
  }
}

extension GenericStackDigest where Context == CC_SHA1_CTX {
  @inlinable
  public static func sha1() -> Self {
    .init(CC_SHA1_Init, CC_SHA1_Update, CC_SHA1_Final, CC_SHA1_DIGEST_LENGTH)
  }
}

extension GenericStackDigest where Context == CC_SHA256_CTX {
  @inlinable
  public static func sha224() -> Self {
    .init(CC_SHA224_Init, CC_SHA224_Update, CC_SHA224_Final, CC_SHA224_DIGEST_LENGTH)
  }

  @inlinable
  public static func sha256() -> Self {
    .init(CC_SHA256_Init, CC_SHA256_Update, CC_SHA256_Final, CC_SHA256_DIGEST_LENGTH)
  }
}

extension GenericStackDigest where Context == CC_SHA512_CTX {
  @inlinable
  public static func sha384() -> Self {
    .init(CC_SHA384_Init, CC_SHA384_Update, CC_SHA384_Final, CC_SHA384_DIGEST_LENGTH)
  }

  @inlinable
  public static func sha512() -> Self {
    .init(CC_SHA512_Init, CC_SHA512_Update, CC_SHA512_Final, CC_SHA512_DIGEST_LENGTH)
  }
}

// MARK: Insecure
@available(*, deprecated)
extension GenericStackDigest where Context == CC_MD2_CTX {
  @inlinable
  public static func md2() -> Self {
    .init(CC_MD2_Init, CC_MD2_Update, CC_MD2_Final, CC_MD2_DIGEST_LENGTH)
  }
}

@available(*, deprecated)
extension GenericStackDigest where Context == CC_MD4_CTX {
  @inlinable
  public static func md4() -> Self {
    .init(CC_MD4_Init, CC_MD4_Update, CC_MD4_Final, CC_MD4_DIGEST_LENGTH)
  }
}

@available(*, deprecated)
extension GenericStackDigest where Context == CC_MD5_CTX {
  @inlinable
  public static func md5() -> Self {
    .init(CC_MD5_Init, CC_MD5_Update, CC_MD5_Final, CC_MD5_DIGEST_LENGTH)
  }
}
#endif
