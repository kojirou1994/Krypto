import XCTest
import Krypto
import CryptoKit

final class KryptoTests: XCTestCase {
  func testWrappers() throws {

    let originData = [UInt8](repeating: 0, count: 1_000)
    let key = [UInt8](repeating: 0, count: 16)
    let iv = [UInt8](repeating: 0, count: 16)

    let oneShotEncryptedData = try AESCBC.encrypt(input: originData, key: key, iv: iv)

    let encryptor = try Cryptor(operation: .encryption, algorithm: .aes, options: .pkcs7Padding, key: key, initializationVector: iv)

    var streamEntryptedData = [UInt8]()
    streamEntryptedData.reserveCapacity(originData.count + Cryptor.Algorithm.aes.blockSize)

    let blockSize = 100
    let tempBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount: blockSize + Cryptor.Algorithm.aes.blockSize, alignment: MemoryLayout<UInt8>.alignment)
    defer {
      tempBuffer.deallocate()
    }
    var bufferCount = 0
    var restSize = originData.count
    while true {
      let input = originData.suffix(restSize).prefix(blockSize)
      try encryptor.update(input: input, to: tempBuffer, dataOutMoved: &bufferCount)
      streamEntryptedData.append(contentsOf: tempBuffer.prefix(bufferCount))
      if restSize > blockSize {
        restSize -= blockSize
      } else {
        break
      }
    }
    try encryptor.final(output: tempBuffer, dataOutMoved: &bufferCount)
    streamEntryptedData.append(contentsOf: tempBuffer.prefix(bufferCount))

    XCTAssertEqual(oneShotEncryptedData, streamEntryptedData)

  }

  func testDig() async {

    let d = Data(count: 200)

    XCTAssertTrue(Insecure.SHA1.hash(data: d).elementsEqual(GenericStackDigest.sha1().hash(bytes: d)))

    XCTAssertTrue(SHA256.hash(data: d).elementsEqual(GenericStackDigest.sha256().hash(bytes: d)))
    XCTAssertTrue(SHA384.hash(data: d).elementsEqual(GenericStackDigest.sha384().hash(bytes: d)))
    XCTAssertTrue(SHA512.hash(data: d).elementsEqual(GenericStackDigest.sha512().hash(bytes: d)))
  }
}
