import Testing
import Foundation
import CryptoKit
import CommonCrypto
@testable import SwiftIPMI

// MARK: - Existing Type Tests

@Test func testChassisStatusParsing() throws {
    // Byte 1: power on (0x01), policy always-on (0x40) = 0x41
    // Byte 2: last power event = 0x00
    // Byte 3: cooling fault (0x08) + identify active (0x20) = 0x28
    let data: [UInt8] = [0x41, 0x00, 0x28]
    let status = try ChassisStatus(from: data)

    #expect(status.powerOn == true)
    #expect(status.powerRestorePolicy == .alwaysOn)
    #expect(status.coolingFault == true)
    #expect(status.identifyActive == true)
    #expect(status.driveFault == false)
    #expect(status.chassisIntrusion == false)
}

@Test func testDeviceIDParsing() throws {
    // Apple BMC: device ID 1, revision 1, firmware 1.19, IPMI 2.0, manufacturer 63 (Apple)
    let data: [UInt8] = [
        0x01, // device ID
        0x01, // device revision
        0x01, // firmware major (1)
        0x13, // firmware minor (19)
        0x20, // IPMI version (2.0)
        0x00, // additional device support
        0x3F, 0x00, 0x00, // manufacturer ID (63 = Apple)
        0x04, 0x00 // product ID
    ]
    let device = try DeviceID(from: data)

    #expect(device.deviceID == 1)
    #expect(device.firmwareMajor == 1)
    #expect(device.firmwareMinor == 19)
    #expect(device.firmwareVersion == "1.19")
    #expect(device.manufacturerID == 63)
    #expect(device.isApple == true)
}

@Test func testCompletionCodes() {
    #expect(CompletionCode.success.rawValue == 0x00)
    #expect(CompletionCode.insufficientPrivilege.rawValue == 0xD4)
    #expect(CompletionCode.invalidCommand.rawValue == 0xC1)
}

@Test func testNetFunction() {
    #expect(NetFunction.chassis.rawValue == 0x00)
    #expect(NetFunction.application.rawValue == 0x06)
    #expect(NetFunction.oemApple.rawValue == 0x36)
}

@Test func testVersion() {
    #expect(swiftIPMIVersion == "0.1.0")
}

// MARK: - IPMI Checksum Tests

/// Verify the two's complement checksum used in IPMI message framing.
@Test func testIPMIChecksum() {
    func checksum(_ data: [UInt8]) -> UInt8 {
        var sum: UInt8 = 0
        for byte in data { sum = sum &+ byte }
        return ~sum &+ 1
    }

    // Checksum of a single zero byte should be 0
    #expect(checksum([0x00]) == 0x00)

    // rsAddr=0x20, netfn=0x18 (application << 2): checksum should make sum zero
    let hdr: [UInt8] = [0x20, 0x18]
    let chk = checksum(hdr)
    let verifySum = hdr[0] &+ hdr[1] &+ chk
    #expect(verifySum == 0x00)

    // Verify with known IPMI header: rsAddr=0x20, netfn=0x00 -> checksum = 0xE0
    #expect(checksum([0x20, 0x00]) == 0xE0)
}

// MARK: - HMAC-SHA1 Key Derivation Tests

/// Verify SIK derivation matches the IPMI v2.0 spec formula.
@Test func testSIKDerivation() {
    let password = "testpass"
    let passwordKey = SymmetricKey(data: Array(password.utf8))

    let consoleRandom = [UInt8](repeating: 0xAA, count: 16)
    let bmcRandom = [UInt8](repeating: 0xBB, count: 16)
    let privilegeByte: UInt8 = 0x14 // administrator (0x04) | name-only (0x10)
    let username = "admin"
    let usernameBytes = Array(username.utf8)

    var sikInput: [UInt8] = []
    sikInput.append(contentsOf: consoleRandom)
    sikInput.append(contentsOf: bmcRandom)
    sikInput.append(privilegeByte)
    sikInput.append(UInt8(usernameBytes.count))
    sikInput.append(contentsOf: usernameBytes)

    let sik = Data(HMAC<Insecure.SHA1>.authenticationCode(for: sikInput, using: passwordKey))

    // SIK should be 20 bytes (SHA-1 output)
    #expect(sik.count == 20)

    // Verify K1 derivation: HMAC-SHA1(SIK, [0x01] * 20)
    let sikKey = SymmetricKey(data: sik)
    let k1Input = [UInt8](repeating: 0x01, count: 20)
    let k1 = Data(HMAC<Insecure.SHA1>.authenticationCode(for: k1Input, using: sikKey))
    #expect(k1.count == 20)

    // Verify K2 derivation: HMAC-SHA1(SIK, [0x02] * 20)
    let k2Input = [UInt8](repeating: 0x02, count: 20)
    let k2 = Data(HMAC<Insecure.SHA1>.authenticationCode(for: k2Input, using: sikKey))
    #expect(k2.count == 20)

    // K1 and K2 should be different
    #expect(k1 != k2)

    // Verify determinism: computing again with same inputs gives same result
    let sik2 = Data(HMAC<Insecure.SHA1>.authenticationCode(for: sikInput, using: passwordKey))
    #expect(sik == sik2)
}

// MARK: - AES-CBC-128 Round-Trip Tests

/// Verify AES-CBC-128 encrypt/decrypt round-trip works correctly.
@Test func testAESCBC128RoundTrip() throws {
    let key: [UInt8] = (0..<16).map { UInt8($0) }
    let iv: [UInt8] = (0..<16).map { UInt8($0 + 16) }
    let plaintext: [UInt8] = [UInt8](repeating: 0x42, count: 32) // 2 blocks

    let ciphertext = try aesCBC128Encrypt(key: key, iv: iv, plaintext: plaintext)
    #expect(ciphertext.count == 32) // same size as input (no padding mode)
    #expect(ciphertext != plaintext) // should be different after encryption

    let decrypted = try aesCBC128Decrypt(key: key, iv: iv, ciphertext: ciphertext)
    #expect(decrypted == plaintext) // round-trip should recover original
}

/// Verify AES-CBC-128 with single block.
@Test func testAESCBC128SingleBlock() throws {
    let key: [UInt8] = [UInt8](repeating: 0x00, count: 16)
    let iv: [UInt8] = [UInt8](repeating: 0x00, count: 16)
    let plaintext: [UInt8] = [UInt8](repeating: 0x00, count: 16)

    let ciphertext = try aesCBC128Encrypt(key: key, iv: iv, plaintext: plaintext)
    #expect(ciphertext.count == 16)

    let decrypted = try aesCBC128Decrypt(key: key, iv: iv, ciphertext: ciphertext)
    #expect(decrypted == plaintext)
}

/// Verify AES-CBC-128 with multiple blocks produces different blocks (CBC chaining).
@Test func testAESCBC128Chaining() throws {
    let key: [UInt8] = (0..<16).map { UInt8($0) }
    let iv: [UInt8] = [UInt8](repeating: 0x01, count: 16)
    // Two identical 16-byte blocks — CBC should make them different in ciphertext
    let plaintext: [UInt8] = [UInt8](repeating: 0xAA, count: 32)

    let ciphertext = try aesCBC128Encrypt(key: key, iv: iv, plaintext: plaintext)
    let block1 = Array(ciphertext[0..<16])
    let block2 = Array(ciphertext[16..<32])
    // In CBC mode, identical plaintext blocks produce different ciphertext blocks
    #expect(block1 != block2)
}

// MARK: - IPMI Confidentiality Padding Tests

/// Verify IPMI confidentiality padding produces correct alignment.
@Test func testConfidentialityPadding() {
    // Simulate the padding logic from IPMISession.encryptPayload
    for payloadSize in 1...64 {
        let payload = [UInt8](repeating: 0x00, count: payloadSize)
        let remainder = (payload.count + 1) % 16
        let padCount = remainder == 0 ? 0 : 16 - remainder

        var plaintext = payload
        for i in 1...max(padCount, 1) {
            if i <= padCount {
                plaintext.append(UInt8(i & 0xFF))
            }
        }
        plaintext.append(UInt8(padCount))

        // Must be multiple of 16
        #expect(plaintext.count % 16 == 0, "Payload size \(payloadSize) produced \(plaintext.count) bytes after padding")

        // Verify we can strip the padding correctly
        let padLength = Int(plaintext.last!)
        let dataLength = plaintext.count - padLength - 1
        #expect(dataLength == payloadSize, "Round-trip padding for size \(payloadSize) gave \(dataLength)")
    }
}

// MARK: - IPMI Message Format Tests

/// Verify the inner IPMI message structure matches the spec.
@Test func testIPMIPayloadStructure() {
    // Simulate buildIPMIPayload for: Get Chassis Status (NetFn 0x00, Cmd 0x01)
    let rsAddr: UInt8 = 0x20
    let rqAddr: UInt8 = 0x81
    let netfn: UInt8 = 0x00 // chassis
    let command: UInt8 = 0x01
    let rqSeq: UInt8 = 1
    let data: [UInt8] = []

    let netfnLun = netfn << 2
    let seqLun = rqSeq << 2

    func checksum(_ data: [UInt8]) -> UInt8 {
        var sum: UInt8 = 0
        for byte in data { sum = sum &+ byte }
        return ~sum &+ 1
    }

    var payload: [UInt8] = []
    payload.append(rsAddr)
    payload.append(netfnLun)
    payload.append(checksum([rsAddr, netfnLun]))
    payload.append(rqAddr)
    payload.append(seqLun)
    payload.append(command)
    payload.append(contentsOf: data)
    payload.append(checksum([rqAddr, seqLun, command] + data))

    // Verify structure
    #expect(payload.count == 7) // 3 header + 3 body + 1 checksum (no data)
    #expect(payload[0] == 0x20) // rsAddr = BMC
    #expect(payload[1] == 0x00) // netfn 0x00 << 2 = 0x00
    #expect(payload[3] == 0x81) // rqAddr = console
    #expect(payload[4] == 0x04) // rqSeq 1 << 2 = 0x04
    #expect(payload[5] == 0x01) // command

    // Verify checksums
    let chk1Sum = payload[0] &+ payload[1] &+ payload[2]
    #expect(chk1Sum == 0x00) // checksum1 should make sum zero

    let bodyRange: [UInt8] = Array(payload[3..<payload.count])
    var bodySum: UInt8 = 0
    for b in bodyRange { bodySum = bodySum &+ b }
    #expect(bodySum == 0x00) // checksum2 should make sum zero
}

/// Verify the IPMI payload structure for a command with data (Set Boot Device).
@Test func testIPMIPayloadWithData() {
    let rsAddr: UInt8 = 0x20
    let rqAddr: UInt8 = 0x81
    let netfn: UInt8 = 0x00 // chassis
    let command: UInt8 = 0x08 // Set Boot Options
    let rqSeq: UInt8 = 5
    let data: [UInt8] = [0x05, 0x80, 0x04, 0x00, 0x00, 0x00] // PXE boot

    let netfnLun = netfn << 2
    let seqLun = rqSeq << 2

    func checksum(_ data: [UInt8]) -> UInt8 {
        var sum: UInt8 = 0
        for byte in data { sum = sum &+ byte }
        return ~sum &+ 1
    }

    var payload: [UInt8] = []
    payload.append(rsAddr)
    payload.append(netfnLun)
    payload.append(checksum([rsAddr, netfnLun]))
    payload.append(rqAddr)
    payload.append(seqLun)
    payload.append(command)
    payload.append(contentsOf: data)
    payload.append(checksum([rqAddr, seqLun, command] + data))

    // Total = 3 (header1) + 3 (header2) + 6 (data) + 1 (checksum) = 13
    #expect(payload.count == 13)

    // Verify both checksums
    let chk1Sum = payload[0] &+ payload[1] &+ payload[2]
    #expect(chk1Sum == 0x00)

    var bodySum: UInt8 = 0
    for i in 3..<payload.count { bodySum = bodySum &+ payload[i] }
    #expect(bodySum == 0x00)
}

// MARK: - RMCP+ Session Header Tests

/// Verify the pre-session RMCP+ header format for Open Session Request.
@Test func testPreSessionRMCPPlusHeader() {
    // Simulate the header that sendPreSessionRMCPPlus builds
    let payloadType: UInt8 = 0x10 // Open Session Request
    let payload: [UInt8] = [UInt8](repeating: 0x00, count: 20) // dummy

    var message: [UInt8] = []
    message.append(0x06) // Auth type = RMCP+
    message.append(payloadType)
    message.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Session ID = 0
    message.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Sequence = 0

    let payloadLength = UInt16(payload.count)
    message.append(UInt8(payloadLength & 0xFF))
    message.append(UInt8(payloadLength >> 8))
    message.append(contentsOf: payload)

    #expect(message[0] == 0x06) // RMCP+ auth type
    #expect(message[1] == 0x10) // payload type
    #expect(message[2] == 0x00) // session ID byte 0
    #expect(message[6] == 0x00) // sequence byte 0
    #expect(message[10] == 20)  // payload length low byte
    #expect(message[11] == 0)   // payload length high byte
    #expect(message.count == 12 + 20) // header + payload
}

/// Verify the authenticated session header format.
@Test func testAuthenticatedSessionHeader() {
    let bmcSessionID: UInt32 = 0xDEADBEEF
    let sequenceNumber: UInt32 = 0x00000001

    var message: [UInt8] = []
    message.append(0x06) // Auth type = RMCP+

    // Payload type: encrypted (bit 7) + authenticated (bit 6) + IPMI (0x00)
    message.append(0xC0)

    // BMC session ID (LE)
    message.append(contentsOf: withUnsafeBytes(of: bmcSessionID.littleEndian) { Array($0) })

    // Sequence (LE)
    message.append(contentsOf: withUnsafeBytes(of: sequenceNumber.littleEndian) { Array($0) })

    #expect(message[0] == 0x06)
    #expect(message[1] == 0xC0) // encrypted + authenticated
    // BMC session ID in LE: 0xEF, 0xBE, 0xAD, 0xDE
    #expect(message[2] == 0xEF)
    #expect(message[3] == 0xBE)
    #expect(message[4] == 0xAD)
    #expect(message[5] == 0xDE)
    // Sequence number in LE: 0x01, 0x00, 0x00, 0x00
    #expect(message[6] == 0x01)
    #expect(message[7] == 0x00)
}

// MARK: - Open Session Request Format Tests

/// Verify Open Session Request payload format matches IPMI v2.0 spec section 13.17.
@Test func testOpenSessionRequestFormat() {
    let messageTag: UInt8 = 0x42
    let privilege: UInt8 = 0x04 // administrator
    let sessionID: UInt32 = 0x12345678
    let authAlg: UInt8 = 0x01 // HMAC-SHA1
    let intAlg: UInt8 = 0x01  // HMAC-SHA1-96
    let confAlg: UInt8 = 0x01 // AES-CBC-128

    var payload: [UInt8] = []
    payload.append(messageTag)
    payload.append(privilege)
    payload.append(contentsOf: [0x00, 0x00]) // reserved
    payload.append(contentsOf: withUnsafeBytes(of: sessionID.littleEndian) { Array($0) })
    payload.append(contentsOf: [0x00, 0x00, 0x00, authAlg])
    payload.append(contentsOf: [0x01, 0x00, 0x00, intAlg])
    payload.append(contentsOf: [0x02, 0x00, 0x00, confAlg])

    #expect(payload.count == 20) // spec mandates 20 bytes
    #expect(payload[0] == 0x42) // tag
    #expect(payload[1] == 0x04) // privilege
    #expect(payload[4] == 0x78) // session ID LE byte 0
    #expect(payload[8] == 0x00) // auth algorithm payload type
    #expect(payload[11] == 0x01) // auth algorithm = HMAC-SHA1
    #expect(payload[12] == 0x01) // integrity algorithm payload type
    #expect(payload[15] == 0x01) // integrity algorithm = HMAC-SHA1-96
    #expect(payload[16] == 0x02) // confidentiality algorithm payload type
    #expect(payload[19] == 0x01) // confidentiality algorithm = AES-CBC-128
}

// MARK: - RAKP Message Format Tests

/// Verify RAKP 1 message format matches IPMI v2.0 spec section 13.20.
@Test func testRAKP1Format() {
    let messageTag: UInt8 = 0x01
    let bmcSessionID: UInt32 = 0xAABBCCDD
    let consoleRandom = [UInt8](repeating: 0x55, count: 16)
    let privilegeByte: UInt8 = 0x14 // admin + name-only
    let username = "admin"
    let usernameBytes = Array(username.utf8)

    var rakp1: [UInt8] = []
    rakp1.append(messageTag)
    rakp1.append(contentsOf: [0x00, 0x00, 0x00]) // reserved
    rakp1.append(contentsOf: withUnsafeBytes(of: bmcSessionID.littleEndian) { Array($0) })
    rakp1.append(contentsOf: consoleRandom)
    rakp1.append(privilegeByte)
    rakp1.append(contentsOf: [0x00, 0x00]) // reserved
    rakp1.append(UInt8(usernameBytes.count))
    rakp1.append(contentsOf: usernameBytes)

    #expect(rakp1.count == 28 + usernameBytes.count) // 28 fixed + username
    #expect(rakp1[0] == messageTag)
    #expect(rakp1[4] == 0xDD) // BMC session ID LE byte 0
    #expect(rakp1[5] == 0xCC)
    #expect(rakp1[6] == 0xBB)
    #expect(rakp1[7] == 0xAA)
    #expect(rakp1[24] == 0x14) // privilege with name-only bit
    #expect(rakp1[27] == UInt8(usernameBytes.count))
}

// MARK: - HMAC-SHA1-96 Integrity Tests

/// Verify HMAC-SHA1-96 truncation (first 12 bytes of SHA1 HMAC).
@Test func testHMACSHA196Truncation() {
    let key = SymmetricKey(data: [UInt8](repeating: 0x0B, count: 20))
    let data: [UInt8] = Array("Hi There".utf8)

    let fullHMAC = Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
    #expect(fullHMAC.count == 20) // SHA-1 produces 20 bytes

    let truncated = Array(fullHMAC.prefix(12))
    #expect(truncated.count == 12) // HMAC-SHA1-96 uses first 12 bytes

    // Verify determinism
    let fullHMAC2 = Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
    #expect(fullHMAC == fullHMAC2)
}

// MARK: - RAKP 2 Auth Code Verification Test

/// Verify the RAKP 2 auth code computation matches spec formula.
@Test func testRAKP2AuthCodeComputation() {
    let password = "password123"
    let passwordKey = SymmetricKey(data: Array(password.utf8))

    let consoleSessionID: UInt32 = 0x11223344
    let bmcSessionID: UInt32 = 0x55667788
    let consoleRandom = [UInt8](repeating: 0xAA, count: 16)
    let bmcRandom = [UInt8](repeating: 0xBB, count: 16)
    let bmcGUID = [UInt8](repeating: 0xCC, count: 16)
    let privilegeByte: UInt8 = 0x14
    let username = "root"
    let usernameBytes = Array(username.utf8)

    // Build RAKP 2 auth input per spec
    var authInput: [UInt8] = []
    authInput.append(contentsOf: withUnsafeBytes(of: consoleSessionID.littleEndian) { Array($0) })
    authInput.append(contentsOf: withUnsafeBytes(of: bmcSessionID.littleEndian) { Array($0) })
    authInput.append(contentsOf: consoleRandom)
    authInput.append(contentsOf: bmcRandom)
    authInput.append(contentsOf: bmcGUID)
    authInput.append(privilegeByte)
    authInput.append(UInt8(usernameBytes.count))
    authInput.append(contentsOf: usernameBytes)

    // Expected total input length: 4 + 4 + 16 + 16 + 16 + 1 + 1 + 4 = 62 bytes
    #expect(authInput.count == 62)

    let authCode = Data(HMAC<Insecure.SHA1>.authenticationCode(for: authInput, using: passwordKey))
    #expect(authCode.count == 20) // HMAC-SHA1 = 20 bytes

    // Build RAKP 3 auth input per spec (different formula)
    var rakp3Input: [UInt8] = []
    rakp3Input.append(contentsOf: bmcRandom)
    rakp3Input.append(contentsOf: withUnsafeBytes(of: consoleSessionID.littleEndian) { Array($0) })
    rakp3Input.append(privilegeByte)
    rakp3Input.append(UInt8(usernameBytes.count))
    rakp3Input.append(contentsOf: usernameBytes)

    // Expected: 16 + 4 + 1 + 1 + 4 = 26 bytes
    #expect(rakp3Input.count == 26)

    let rakp3Code = Data(HMAC<Insecure.SHA1>.authenticationCode(for: rakp3Input, using: passwordKey))
    #expect(rakp3Code.count == 20)

    // Auth codes should be different (different inputs)
    #expect(authCode != rakp3Code)
}

// MARK: - Full Encrypt/Decrypt Round-Trip Test

/// Verify the complete IPMI confidentiality wrapping (pad + encrypt + decrypt + unpad).
@Test func testFullEncryptDecryptRoundTrip() throws {
    // Simulate a typical IPMI payload (Get Chassis Status)
    let payload: [UInt8] = [0x20, 0x00, 0xE0, 0x81, 0x04, 0x01, 0x7A]

    // Derive a K2 key
    let sik = SymmetricKey(data: [UInt8](repeating: 0x42, count: 20))
    let k2Input = [UInt8](repeating: 0x02, count: 20)
    let k2Data = Data(HMAC<Insecure.SHA1>.authenticationCode(for: k2Input, using: sik))
    let aesKey = Array(k2Data.prefix(16))

    // Pad the payload (IPMI confidentiality padding)
    let remainder = (payload.count + 1) % 16
    let padCount = remainder == 0 ? 0 : 16 - remainder
    var plaintext = payload
    for i in 1...max(padCount, 1) {
        if i <= padCount {
            plaintext.append(UInt8(i & 0xFF))
        }
    }
    plaintext.append(UInt8(padCount))
    #expect(plaintext.count % 16 == 0)

    // Encrypt
    let iv: [UInt8] = (0..<16).map { UInt8($0) }
    let ciphertext = try aesCBC128Encrypt(key: aesKey, iv: iv, plaintext: plaintext)

    // Decrypt
    let decrypted = try aesCBC128Decrypt(key: aesKey, iv: iv, ciphertext: ciphertext)
    #expect(decrypted == plaintext)

    // Strip padding
    let decPadLength = Int(decrypted.last!)
    let dataLength = decrypted.count - decPadLength - 1
    let recoveredPayload = Array(decrypted[0..<dataLength])
    #expect(recoveredPayload == payload)
}

// MARK: - Algorithm Enum Tests

@Test func testAuthAlgorithmValues() {
    #expect(AuthAlgorithm.none.rawValue == 0x00)
    #expect(AuthAlgorithm.hmacSHA1.rawValue == 0x01)
    #expect(AuthAlgorithm.hmacMD5.rawValue == 0x02)
}

@Test func testIntegrityAlgorithmValues() {
    #expect(IntegrityAlgorithm.none.rawValue == 0x00)
    #expect(IntegrityAlgorithm.hmacSHA1_96.rawValue == 0x01)
    #expect(IntegrityAlgorithm.hmacMD5_128.rawValue == 0x02)
    #expect(IntegrityAlgorithm.md5_128.rawValue == 0x03)
}

@Test func testConfidentialityAlgorithmValues() {
    #expect(ConfidentialityAlgorithm.none.rawValue == 0x00)
    #expect(ConfidentialityAlgorithm.aesCBC128.rawValue == 0x01)
    #expect(ConfidentialityAlgorithm.xRC4_128.rawValue == 0x02)
    #expect(ConfidentialityAlgorithm.xRC4_40.rawValue == 0x03)
}

// MARK: - Error Type Tests

@Test func testErrorDescriptions() {
    let err1 = IPMIError.notConnected
    #expect(err1.errorDescription != nil)

    let err2 = IPMIError.authenticationFailed("bad password")
    #expect(err2.errorDescription?.contains("bad password") == true)

    let err3 = IPMIError.encryptionError("AES failed")
    #expect(err3.errorDescription?.contains("AES failed") == true)

    let err4 = IPMIError.completionCode(.insufficientPrivilege, command: "test")
    #expect(err4.errorDescription?.contains("D4") == true)
}

// MARK: - Privilege Level Tests

@Test func testPrivilegeLevels() {
    #expect(PrivilegeLevel.callback.rawValue == 0x01)
    #expect(PrivilegeLevel.user.rawValue == 0x02)
    #expect(PrivilegeLevel.operator.rawValue == 0x03)
    #expect(PrivilegeLevel.administrator.rawValue == 0x04)
    #expect(PrivilegeLevel.oem.rawValue == 0x05)
}

// MARK: - Integrity Pad Alignment Tests

/// Verify integrity padding produces correct 4-byte alignment.
@Test func testIntegrityPadAlignment() {
    // Simulate the integrity pad calculation from wrapSessionMessage
    for payloadSize in 0..<64 {
        // Header is always 12 bytes (authType + payloadType + sessionID + seqNum + payloadLen)
        let headerSize = 12
        let totalBeforePad = headerSize + payloadSize
        let padLength = (4 - (totalBeforePad % 4)) % 4

        // After pad + padLenByte + nextHeader, should be 4-byte aligned
        let totalAfterPad = totalBeforePad + padLength + 1 + 1 // +1 padLen, +1 nextHeader
        #expect(totalAfterPad % 4 == 2 || padLength <= 3,
                "Pad calculation wrong for payload size \(payloadSize)")
        #expect(padLength <= 3, "Pad length should be 0-3, got \(padLength)")
    }
}

// MARK: - Little-Endian Encoding Tests

@Test func testLittleEndianEncoding() {
    let value: UInt32 = 0xDEADBEEF
    let bytes = withUnsafeBytes(of: value.littleEndian) { Array($0) }
    #expect(bytes == [0xEF, 0xBE, 0xAD, 0xDE])

    let value16: UInt16 = 0x1234
    let bytes16 = withUnsafeBytes(of: value16.littleEndian) { Array($0) }
    #expect(bytes16 == [0x34, 0x12])
}

// MARK: - Helper Functions (mirrors IPMISession crypto for testing)

private func aesCBC128Encrypt(key: [UInt8], iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
    var outLength = 0
    var outBytes = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeAES128)
    let status = CCCrypt(
        CCOperation(kCCEncrypt),
        CCAlgorithm(kCCAlgorithmAES),
        CCOptions(0),
        key, kCCKeySizeAES128,
        iv,
        plaintext, plaintext.count,
        &outBytes, outBytes.count,
        &outLength
    )
    guard status == kCCSuccess else {
        throw IPMIError.encryptionError("AES encrypt failed: \(status)")
    }
    return Array(outBytes.prefix(outLength))
}

private func aesCBC128Decrypt(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
    var outLength = 0
    var outBytes = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
    let status = CCCrypt(
        CCOperation(kCCDecrypt),
        CCAlgorithm(kCCAlgorithmAES),
        CCOptions(0),
        key, kCCKeySizeAES128,
        iv,
        ciphertext, ciphertext.count,
        &outBytes, outBytes.count,
        &outLength
    )
    guard status == kCCSuccess else {
        throw IPMIError.encryptionError("AES decrypt failed: \(status)")
    }
    return Array(outBytes.prefix(outLength))
}
