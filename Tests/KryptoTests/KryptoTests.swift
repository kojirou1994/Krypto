import XCTest
import CommonCrypto
import Krypto

final class KryptoTests: XCTestCase {
  func testWrappers() throws {

    let originData = [UInt8](repeating: 0, count: 1_000)
    let key = [UInt8](repeating: 0, count: 16)
    let iv = [UInt8](repeating: 0, count: 16)

    let oneShotEncryptedData = try AESCBC.encrypt(input: originData, key: key, iv: iv)

    let encryptor = try CCKryptor(operation: .encryption, algorithm: .aes, options: .pkcs7Padding, key: key, initializationVector: iv)

    var streamEntryptedData = [UInt8]()
    streamEntryptedData.reserveCapacity(originData.count + kCCBlockSizeAES128)

    let blockSize = 100
    let tempBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount: blockSize + kCCBlockSizeAES128, alignment: MemoryLayout<UInt8>.alignment)
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
}
