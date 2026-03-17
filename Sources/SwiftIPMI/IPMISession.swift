import Foundation
import CryptoKit
import CommonCrypto

// MARK: - IPMI v2.0 Session

/// Manages an authenticated IPMI v2.0 RMCP+ session.
///
/// Session establishment follows the RMCP+ protocol:
/// 1. Get Channel Authentication Capabilities
/// 2. Open Session Request/Response
/// 3. RAKP Message 1/2 (key exchange)
/// 4. RAKP Message 3/4 (mutual authentication)
/// 5. Session is active — commands use negotiated keys
///
/// All messages after session activation are encrypted (AES-CBC-128)
/// and integrity-protected (HMAC-SHA1-96).
final class IPMISession {

    private let transport: RMCPTransport

    // Session state
    private(set) var isActive: Bool = false
    private var sessionID: UInt32 = 0
    private var bmcSessionID: UInt32 = 0
    private var sequenceNumber: UInt32 = 1

    // Negotiated algorithms
    private var authAlgorithm: AuthAlgorithm = .hmacSHA1
    private var integrityAlgorithm: IntegrityAlgorithm = .hmacSHA1_96
    private var confidentialityAlgorithm: ConfidentialityAlgorithm = .aesCBC128

    // Session keys (derived during RAKP)
    private var sik: SymmetricKey?       // Session Integrity Key
    private var k1: SymmetricKey?        // Integrity key (HMAC-SHA1-96)
    private var k2: SymmetricKey?        // Encryption key (AES-CBC-128)

    // Authentication data
    private var username: String = ""
    private var password: String = ""
    private var consoleRandom = [UInt8](repeating: 0, count: 16)
    private var bmcRandom = [UInt8](repeating: 0, count: 16)
    private var bmcGUID = [UInt8](repeating: 0, count: 16)

    // Message sequencing for inner IPMI messages
    private var rqSeq: UInt8 = 1

    // Message tag for session setup messages
    private var messageTag: UInt8 = 0

    init(transport: RMCPTransport) {
        self.transport = transport
    }

    // MARK: - Session Activation

    /// Perform the full RMCP+ session establishment handshake.
    func activate(username: String, password: String, privilege: PrivilegeLevel) async throws {
        self.username = username
        self.password = password

        // Generate console random number
        consoleRandom = (0..<16).map { _ in UInt8.random(in: 0...255) }

        // Generate a console session ID
        sessionID = UInt32.random(in: 1...UInt32.max)

        // Generate a message tag for correlating request/response
        messageTag = UInt8.random(in: 0...255)

        print("[SwiftIPMI] Step 1: Get Channel Auth Capabilities...")
        // Step 1: Get Channel Auth Capabilities (pre-session, unauthenticated)
        _ = try await sendPreSession(netfn: .application, command: 0x38,
                                      data: [0x8E, UInt8(privilege.rawValue)])
        print("[SwiftIPMI] Step 1 complete.")

        // Step 1b: Get Channel Cipher Suites (required by some BMCs before Open Session)
        // cmd 0x54, data: channel(0x0E), payloadType(0x00=IPMI), listIndex(0x80=start)
        print("[SwiftIPMI] Step 1b: Get Channel Cipher Suites...")
        _ = try? await sendPreSession(netfn: .application, command: 0x54,
                                       data: [0x0E, 0x00, 0x80])
        print("[SwiftIPMI] Step 1b complete.")

        print("[SwiftIPMI] Step 2: Open Session...")
        // Step 2: Open Session
        try await openSession(privilege: privilege)
        print("[SwiftIPMI] Step 2 complete. BMC session ID: 0x\(String(format: "%08X", bmcSessionID))")

        print("[SwiftIPMI] Step 3-4: RAKP handshake...")
        // Step 3-4: RAKP handshake
        try await rakpHandshake(privilege: privilege)

        isActive = true

        // Step 5: Set Session Privilege Level (required to activate the requested privilege)
        print("[SwiftIPMI] Step 5: Set Session Privilege Level to \(privilege.rawValue)...")
        let privResponse = try await sendCommand(netfn: .application, command: 0x3B,
                                                   data: [privilege.rawValue])
        print("[SwiftIPMI] Step 5 complete. Privilege set to: \(privResponse.first ?? 0)")
    }

    /// Close the session gracefully.
    func close() async throws {
        guard isActive else { return }
        // Close Session command (NetFn App, Cmd 0x3C)
        let sessionBytes = withUnsafeBytes(of: bmcSessionID.littleEndian) { Array($0) }
        _ = try? await sendCommand(netfn: .application, command: 0x3C, data: sessionBytes)
        isActive = false
    }

    // MARK: - Command Sending

    /// Send an authenticated IPMI command within the active session.
    func sendCommand(netfn: NetFunction, command: UInt8, data: [UInt8] = []) async throws -> [UInt8] {
        guard isActive else { throw IPMIError.notConnected }

        // Build IPMI message payload
        let payload = buildIPMIPayload(netfn: netfn, command: command, data: data)

        // Wrap in RMCP+ session header with encryption and integrity
        let message = try wrapSessionMessage(payload: payload)

        // Send and receive
        let response = try await transport.sendReceive(payload: message)

        // Unwrap response — returns the decrypted inner IPMI message
        let ipmiMessage = try unwrapSessionMessage(response)

        sequenceNumber += 1

        // Parse the inner IPMI response message.
        // Response format:
        //   Byte 0: rqAddr (0x81)
        //   Byte 1: netfn/lun (response netfn = request netfn | 0x01, shifted left 2)
        //   Byte 2: header checksum
        //   Byte 3: rsAddr (0x20)
        //   Byte 4: rqSeq/lun
        //   Byte 5: command
        //   Byte 6: completion code
        //   Bytes 7..N-1: response data
        //   Byte N: data checksum
        guard ipmiMessage.count >= 8 else {
            throw IPMIError.invalidResponse("Response IPMI message too short (\(ipmiMessage.count) bytes)")
        }

        // Completion code is at byte 6
        let completionCode = ipmiMessage[6]
        if completionCode != 0x00 {
            let code = CompletionCode(rawValue: completionCode) ?? .unspecified
            throw IPMIError.completionCode(code, command: String(format: "NetFn 0x%02X Cmd 0x%02X", netfn.rawValue, command))
        }

        // Return data after completion code, excluding trailing checksum
        if ipmiMessage.count > 8 {
            return Array(ipmiMessage[7..<(ipmiMessage.count - 1)])
        }
        return []
    }

    // MARK: - Pre-Session Commands

    /// Send an unauthenticated IPMI command (before session is established).
    private func sendPreSession(netfn: NetFunction, command: UInt8,
                                 data: [UInt8] = []) async throws -> [UInt8] {
        // IPMI v1.5 message wrapper (no auth, no session)
        var message: [UInt8] = []

        // Auth type: NONE
        message.append(0x00)
        // Session sequence: 0
        message.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        // Session ID: 0
        message.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        // Message length (inner IPMI message: rsAddr + netfn + chk + rqAddr + seq + cmd + data + chk = 7 + data.count)
        let payloadLen = UInt8(data.count + 7)
        message.append(payloadLen)

        // Inner IPMI message
        let rsAddr: UInt8 = 0x20 // BMC
        let rqAddr: UInt8 = 0x81 // Remote console
        let netfnLun = (netfn.rawValue << 2)

        message.append(rsAddr)
        message.append(netfnLun)
        message.append(checksum([rsAddr, netfnLun]))
        message.append(rqAddr)
        message.append(0x00) // rqSeq
        message.append(command)
        message.append(contentsOf: data)
        message.append(checksum([rqAddr, 0x00, command] + data))

        let response = try await transport.sendReceive(payload: message)

        return try parsePreSessionResponse(response)
    }

    // MARK: - Open Session (IPMI v2.0 Spec Section 13.17-13.18)

    /// Send Open Session Request and process Open Session Response.
    /// Negotiates authentication, integrity, and confidentiality algorithms with the BMC.
    private func openSession(privilege: PrivilegeLevel) async throws {
        var payload: [UInt8] = []

        // Byte 0: Message tag
        payload.append(messageTag)

        // Byte 1: Requested maximum privilege level
        payload.append(privilege.rawValue)

        // Bytes 2-3: Reserved
        payload.append(contentsOf: [0x00, 0x00])

        // Bytes 4-7: Remote console session ID (little-endian)
        payload.append(contentsOf: withUnsafeBytes(of: sessionID.littleEndian) { Array($0) })

        // Bytes 8-15: Authentication algorithm payload (8 bytes)
        // [payload_type(0x00), reserved(2), payload_length(0x08), algorithm_id, reserved(3)]
        payload.append(contentsOf: [0x00, 0x00, 0x00, 0x08, authAlgorithm.rawValue, 0x00, 0x00, 0x00])

        // Bytes 16-23: Integrity algorithm payload (8 bytes)
        // [payload_type(0x01), reserved(2), payload_length(0x08), algorithm_id, reserved(3)]
        payload.append(contentsOf: [0x01, 0x00, 0x00, 0x08, integrityAlgorithm.rawValue, 0x00, 0x00, 0x00])

        // Bytes 24-31: Confidentiality algorithm payload (8 bytes)
        // [payload_type(0x02), reserved(2), payload_length(0x08), algorithm_id, reserved(3)]
        payload.append(contentsOf: [0x02, 0x00, 0x00, 0x08, confidentialityAlgorithm.rawValue, 0x00, 0x00, 0x00])

        // Send wrapped in pre-session RMCP+ header (payload type 0x10)
        let response = try await sendPreSessionRMCPPlus(payloadType: 0x10, payload: payload)

        // Parse Open Session Response (36 bytes: 4 header + 8 IDs + 8*3 algorithms)
        guard response.count >= 36 else {
            throw IPMIError.invalidResponse("Open Session Response too short (\(response.count) bytes)")
        }

        // Byte 0: Message tag (must match)
        guard response[0] == messageTag else {
            throw IPMIError.invalidResponse("Open Session Response tag mismatch (expected \(messageTag), got \(response[0]))")
        }

        // Byte 1: Status code (0x00 = success)
        guard response[1] == 0x00 else {
            throw IPMIError.authenticationFailed("Open Session rejected with status 0x\(String(format: "%02X", response[1]))")
        }

        // Bytes 4-7: Remote console session ID (echo back, verify)
        let echoedSessionID = readUInt32LE(response, offset: 4)
        guard echoedSessionID == sessionID else {
            throw IPMIError.invalidResponse("Open Session Response session ID mismatch")
        }

        // Bytes 8-11: BMC session ID
        bmcSessionID = readUInt32LE(response, offset: 8)
    }

    // MARK: - RAKP Handshake (IPMI v2.0 Spec Sections 13.20-13.23)

    /// Perform the full RAKP 1-4 message exchange to establish mutual authentication
    /// and derive session keys (SIK, K1, K2).
    private func rakpHandshake(privilege: PrivilegeLevel) async throws {
        let usernameBytes = Array(username.utf8)
        let passwordBytes = Array(password.utf8)
        let passwordKey = SymmetricKey(data: passwordBytes)
        let privilegeByte = privilege.rawValue | 0x10 // bit 4 = name-only lookup

        // ---- RAKP Message 1 (payload type 0x12) ----

        var rakp1: [UInt8] = []
        rakp1.append(messageTag)                          // Byte 0: Message tag
        rakp1.append(contentsOf: [0x00, 0x00, 0x00])      // Bytes 1-3: Reserved
        appendUInt32LE(&rakp1, bmcSessionID)               // Bytes 4-7: BMC session ID
        rakp1.append(contentsOf: consoleRandom)            // Bytes 8-23: Console random (16 bytes)
        rakp1.append(privilegeByte)                        // Byte 24: Privilege + name-only lookup
        rakp1.append(contentsOf: [0x00, 0x00])             // Bytes 25-26: Reserved
        rakp1.append(UInt8(usernameBytes.count))           // Byte 27: Username length
        rakp1.append(contentsOf: usernameBytes)            // Bytes 28+: Username

        let rakp2 = try await sendPreSessionRMCPPlus(payloadType: 0x12, payload: rakp1)

        // ---- Parse RAKP Message 2 (payload type 0x13) ----

        guard rakp2.count >= 40 else {
            throw IPMIError.invalidResponse("RAKP 2 too short (\(rakp2.count) bytes)")
        }

        guard rakp2[0] == messageTag else {
            throw IPMIError.invalidResponse("RAKP 2 tag mismatch")
        }

        guard rakp2[1] == 0x00 else {
            throw IPMIError.authenticationFailed("RAKP 2 rejected with status 0x\(String(format: "%02X", rakp2[1]))")
        }

        // Verify echoed console session ID
        guard readUInt32LE(rakp2, offset: 4) == sessionID else {
            throw IPMIError.invalidResponse("RAKP 2 console session ID mismatch")
        }

        // Extract BMC random (16 bytes) and BMC GUID (16 bytes)
        bmcRandom = Array(rakp2[8..<24])
        bmcGUID = Array(rakp2[24..<40])

        // Verify RAKP 2 auth code (HMAC-SHA1 over the authentication parameters)
        if authAlgorithm == .hmacSHA1 {
            guard rakp2.count >= 60 else {
                throw IPMIError.invalidResponse("RAKP 2 missing auth code")
            }
            let bmcAuthCode = Array(rakp2[40..<60])

            // Auth input: consoleSessionID(4) + bmcSessionID(4) + consoleRandom(16) + bmcRandom(16)
            //           + bmcGUID(16) + privilegeLevel(1) + usernameLength(1) + username
            var authInput: [UInt8] = []
            appendUInt32LE(&authInput, sessionID)
            appendUInt32LE(&authInput, bmcSessionID)
            authInput.append(contentsOf: consoleRandom)
            authInput.append(contentsOf: bmcRandom)
            authInput.append(contentsOf: bmcGUID)
            authInput.append(privilegeByte)
            authInput.append(UInt8(usernameBytes.count))
            authInput.append(contentsOf: usernameBytes)

            let expectedAuthCode = Array(Data(HMAC<Insecure.SHA1>.authenticationCode(
                for: authInput, using: passwordKey)))
            guard bmcAuthCode == expectedAuthCode else {
                throw IPMIError.authenticationFailed("RAKP 2 auth code verification failed")
            }
        }

        // ---- Derive Session Integrity Key (SIK) ----
        // SIK = HMAC-SHA1(password, consoleRandom(16) + bmcRandom(16) + privilegeLevel(1) + usernameLength(1) + username)
        var sikInput: [UInt8] = []
        sikInput.append(contentsOf: consoleRandom)
        sikInput.append(contentsOf: bmcRandom)
        sikInput.append(privilegeByte)
        sikInput.append(UInt8(usernameBytes.count))
        sikInput.append(contentsOf: usernameBytes)

        let sikData = Data(HMAC<Insecure.SHA1>.authenticationCode(for: sikInput, using: passwordKey))
        let computedSIK = SymmetricKey(data: sikData)
        deriveKeys(sik: computedSIK)

        // ---- RAKP Message 3 (payload type 0x14) ----

        var rakp3: [UInt8] = []
        rakp3.append(messageTag)                          // Byte 0: Message tag
        rakp3.append(0x00)                                // Byte 1: Status code
        rakp3.append(contentsOf: [0x00, 0x00])            // Bytes 2-3: Reserved
        appendUInt32LE(&rakp3, bmcSessionID)               // Bytes 4-7: BMC session ID

        // Auth code: HMAC-SHA1(password, bmcRandom(16) + consoleSessionID(4) + privilegeLevel(1) + usernameLength(1) + username)
        if authAlgorithm == .hmacSHA1 {
            var rakp3AuthInput: [UInt8] = []
            rakp3AuthInput.append(contentsOf: bmcRandom)
            appendUInt32LE(&rakp3AuthInput, sessionID)
            rakp3AuthInput.append(privilegeByte)
            rakp3AuthInput.append(UInt8(usernameBytes.count))
            rakp3AuthInput.append(contentsOf: usernameBytes)

            let authCode = Data(HMAC<Insecure.SHA1>.authenticationCode(
                for: rakp3AuthInput, using: passwordKey))
            rakp3.append(contentsOf: authCode)
        }

        let rakp4 = try await sendPreSessionRMCPPlus(payloadType: 0x14, payload: rakp3)

        // ---- Parse RAKP Message 4 (payload type 0x15) ----

        guard rakp4.count >= 8 else {
            throw IPMIError.invalidResponse("RAKP 4 too short (\(rakp4.count) bytes)")
        }

        guard rakp4[0] == messageTag else {
            throw IPMIError.invalidResponse("RAKP 4 tag mismatch")
        }

        guard rakp4[1] == 0x00 else {
            throw IPMIError.authenticationFailed("RAKP 4 rejected with status 0x\(String(format: "%02X", rakp4[1]))")
        }

        guard readUInt32LE(rakp4, offset: 4) == sessionID else {
            throw IPMIError.invalidResponse("RAKP 4 console session ID mismatch")
        }

        // Verify integrity check value: HMAC-SHA1(SIK, consoleRandom(16) + bmcSessionID(4) + bmcGUID(16)) truncated to 12 bytes
        if authAlgorithm == .hmacSHA1 {
            guard rakp4.count >= 20 else {
                throw IPMIError.invalidResponse("RAKP 4 missing integrity check value")
            }
            let receivedICV = Array(rakp4[8..<20])

            var icvInput: [UInt8] = []
            icvInput.append(contentsOf: consoleRandom)
            appendUInt32LE(&icvInput, bmcSessionID)
            icvInput.append(contentsOf: bmcGUID)

            let fullICV = Data(HMAC<Insecure.SHA1>.authenticationCode(
                for: icvInput, using: computedSIK))
            let expectedICV = Array(fullICV.prefix(12))
            guard receivedICV == expectedICV else {
                throw IPMIError.authenticationFailed("RAKP 4 integrity check verification failed")
            }
        }
    }

    // MARK: - Inner IPMI Message Construction

    /// Build the inner IPMI message (the payload that gets encrypted).
    ///
    /// Format:
    /// ```
    /// rsAddr(1) + netFn/rsLUN(1) + checksum1(1) + rqAddr(1) + rqSeq/rqLUN(1) + command(1) + data... + checksum2(1)
    /// ```
    private func buildIPMIPayload(netfn: NetFunction, command: UInt8, data: [UInt8]) -> [UInt8] {
        let rsAddr: UInt8 = 0x20  // BMC slave address
        let rqAddr: UInt8 = 0x81  // Remote console (software ID)
        let netfnLun = netfn.rawValue << 2
        let seqLun = rqSeq << 2

        var payload: [UInt8] = []

        // Header part 1
        payload.append(rsAddr)
        payload.append(netfnLun)
        payload.append(checksum([rsAddr, netfnLun]))

        // Header part 2
        payload.append(rqAddr)
        payload.append(seqLun)
        payload.append(command)
        payload.append(contentsOf: data)
        payload.append(checksum([rqAddr, seqLun, command] + data))

        // Advance sequence number for next message (wraps at 63 since only 6 bits are used)
        rqSeq = (rqSeq + 1) & 0x3F

        return payload
    }

    // MARK: - Session Message Wrapping (Encrypt + Sign)

    /// Wrap an IPMI payload in an RMCP+ authenticated/encrypted session message.
    ///
    /// Structure:
    /// ```
    /// AuthType(1) + PayloadType(1) + SessionID(4) + SeqNum(4) + PayloadLen(2) +
    /// EncryptedPayload(N) + IntegrityPad(P) + PadLength(1) + NextHeader(1) + AuthCode(12)
    /// ```
    private func wrapSessionMessage(payload: [UInt8]) throws -> [UInt8] {
        guard let k1 = k1, let k2 = k2 else {
            throw IPMIError.encryptionError("Session keys not derived")
        }

        // Step 1: Encrypt the payload
        let encryptedPayload: [UInt8]
        if confidentialityAlgorithm == .aesCBC128 {
            encryptedPayload = try encryptPayload(payload: payload, key: k2)
        } else {
            encryptedPayload = payload
        }

        // Step 2: Build header + encrypted payload
        var message: [UInt8] = []

        // Auth type = 0x06 (RMCP+)
        message.append(0x06)

        // Payload type with encryption and authentication flags
        var payloadTypeByte: UInt8 = 0x00 // IPMI message type
        if integrityAlgorithm != .none {
            payloadTypeByte |= 0x40 // bit 6: authenticated
        }
        if confidentialityAlgorithm != .none {
            payloadTypeByte |= 0x80 // bit 7: encrypted
        }
        message.append(payloadTypeByte)

        // Session ID (BMC session ID, little-endian)
        appendUInt32LE(&message, bmcSessionID)

        // Session sequence number (little-endian)
        appendUInt32LE(&message, sequenceNumber)

        // Payload length (little-endian)
        appendUInt16LE(&message, UInt16(encryptedPayload.count))

        // Encrypted payload
        message.append(contentsOf: encryptedPayload)

        // Step 3: Add integrity trailer
        if integrityAlgorithm == .hmacSHA1_96 {
            // Integrity pad: align so that (header + payload + pad + padLen + nextHeader) % 4 == 0
            // before the auth code. The spec says the integrity pad is 0 to 3 bytes of 0xFF.
            let currentLen = message.count
            let padLength = (4 - (currentLen % 4)) % 4
            for _ in 0..<padLength {
                message.append(0xFF)
            }
            message.append(UInt8(padLength)) // Pad length byte
            message.append(0x07)              // Next header (always 0x07 for RMCP+)

            // HMAC-SHA1-96: computed over everything from AuthType through NextHeader
            let k1Bytes = k1.withUnsafeBytes { Array($0) }
            let hmacKey = SymmetricKey(data: k1Bytes)
            let hmac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: hmacKey))
            message.append(contentsOf: Array(hmac.prefix(12))) // Truncate to 96 bits
        }

        return message
    }

    // MARK: - Session Message Unwrapping (Verify + Decrypt)

    /// Unwrap an RMCP+ authenticated/encrypted session response.
    /// Verifies integrity, decrypts payload, and returns the inner IPMI message bytes.
    private func unwrapSessionMessage(_ data: [UInt8]) throws -> [UInt8] {
        guard let k1 = k1, let k2 = k2 else {
            throw IPMIError.encryptionError("Session keys not derived")
        }

        guard data.count >= 12 else {
            throw IPMIError.invalidResponse("Session response too short (\(data.count) bytes)")
        }

        // Byte 0: Auth type (must be 0x06 for RMCP+)
        guard data[0] == 0x06 else {
            throw IPMIError.invalidResponse("Unexpected auth type 0x\(String(format: "%02X", data[0]))")
        }

        // Byte 1: Payload type flags
        let payloadTypeByte = data[1]
        let isEncrypted = (payloadTypeByte & 0x80) != 0
        let isAuthenticated = (payloadTypeByte & 0x40) != 0

        // Bytes 10-11: Payload length (little-endian)
        let payloadLength = Int(UInt16(data[10]) | (UInt16(data[11]) << 8))
        let payloadStart = 12
        let payloadEnd = payloadStart + payloadLength

        guard data.count >= payloadEnd else {
            throw IPMIError.invalidResponse("Session response truncated (need \(payloadEnd) bytes, got \(data.count))")
        }

        // Verify integrity (HMAC-SHA1-96) if authenticated
        if isAuthenticated && integrityAlgorithm == .hmacSHA1_96 {
            // Auth code is the last 12 bytes of the message
            let authCodeLen = 12
            guard data.count >= payloadEnd + 2 + authCodeLen else {
                throw IPMIError.invalidResponse("Session response missing integrity data")
            }

            let authCodeStart = data.count - authCodeLen
            let receivedAuthCode = Array(data[authCodeStart...])

            // HMAC input: everything before the auth code
            let hmacInput = Array(data[0..<authCodeStart])
            let k1Bytes = k1.withUnsafeBytes { Array($0) }
            let hmacKey = SymmetricKey(data: k1Bytes)
            let hmac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: hmacInput, using: hmacKey))
            let expectedAuthCode = Array(hmac.prefix(12))

            guard receivedAuthCode == expectedAuthCode else {
                throw IPMIError.encryptionError("Session response integrity check failed")
            }
        }

        // Extract the encrypted payload
        let encryptedPayload = Array(data[payloadStart..<payloadEnd])

        // Decrypt if encrypted
        if isEncrypted && confidentialityAlgorithm == .aesCBC128 {
            return try decryptPayload(encrypted: encryptedPayload, key: k2)
        }

        return encryptedPayload
    }

    // MARK: - Pre-Session RMCP+ Transport

    /// Send a pre-session RMCP+ message (Open Session, RAKP) and return the response payload.
    ///
    /// Pre-session messages use a simplified RMCP+ header with session ID = 0 and sequence = 0,
    /// and are neither encrypted nor authenticated.
    private func sendPreSessionRMCPPlus(payloadType: UInt8, payload: [UInt8]) async throws -> [UInt8] {
        var message: [UInt8] = []
        message.append(0x06)                               // Auth type = RMCP+
        message.append(payloadType)                         // Payload type (0x10-0x15)
        message.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Session ID = 0
        message.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Sequence = 0
        appendUInt16LE(&message, UInt16(payload.count))      // Payload length
        message.append(contentsOf: payload)

        let response = try await transport.sendReceive(payload: message)

        // Response starts at auth_type (RMCP header already stripped by transport)
        guard response.count >= 12 else {
            throw IPMIError.invalidResponse("Pre-session RMCP+ response too short (\(response.count) bytes)")
        }

        guard response[0] == 0x06 else {
            throw IPMIError.invalidResponse("Pre-session response has wrong auth type 0x\(String(format: "%02X", response[0]))")
        }

        // Response payload type should be request type + 1
        let expectedType = payloadType + 1
        guard response[1] == expectedType else {
            throw IPMIError.invalidResponse("Expected payload type 0x\(String(format: "%02X", expectedType)), got 0x\(String(format: "%02X", response[1]))")
        }

        let respPayloadLen = Int(UInt16(response[10]) | (UInt16(response[11]) << 8))
        let respPayloadEnd = 12 + respPayloadLen

        guard response.count >= respPayloadEnd else {
            throw IPMIError.invalidResponse("Pre-session RMCP+ payload truncated")
        }

        return Array(response[12..<respPayloadEnd])
    }

    // MARK: - Pre-Session Response Parsing

    private func parsePreSessionResponse(_ data: [UInt8]) throws -> [UInt8] {
        // v1.5 response: auth_type(1) + seq(4) + session_id(4) + msg_len(1) = 10 bytes header
        guard data.count > 10 else {
            throw IPMIError.invalidResponse("Pre-session response too short")
        }
        let msgBytes = Array(data[10...])
        // Inner IPMI message: rsAddr(1) + netfn(1) + chk(1) + rqAddr(1) + seq(1) + cmd(1) + completion(1) + data... + chk(1)
        guard msgBytes.count >= 7 else {
            throw IPMIError.invalidResponse("Pre-session IPMI message too short")
        }
        let completionCode = msgBytes[6]
        if completionCode != 0x00 {
            let code = CompletionCode(rawValue: completionCode) ?? .unspecified
            throw IPMIError.completionCode(code, command: "pre-session")
        }
        if msgBytes.count > 8 {
            return Array(msgBytes[7..<(msgBytes.count - 1)])
        }
        return []
    }

    // MARK: - AES-CBC-128 Encryption

    /// Encrypt an IPMI payload using AES-CBC-128.
    ///
    /// Output format: IV(16) + ciphertext
    ///
    /// The plaintext is padded per IPMI spec Section 13.29:
    /// - Append 0 to N confidentiality pad bytes (values can be anything, we use 1,2,3...)
    /// - Append 1 pad length byte (number of confidentiality pad bytes, NOT counting itself)
    /// - Total (payload + pad + padLenByte) must be a multiple of 16 (AES block size)
    private func encryptPayload(payload: [UInt8], key: SymmetricKey) throws -> [UInt8] {
        let aesKey = key.withUnsafeBytes { Array($0.prefix(16)) }
        let iv: [UInt8] = (0..<16).map { _ in UInt8.random(in: 0...255) }

        // Calculate pad count: (payload + padCount + 1_for_padLenByte) must be multiple of 16
        let remainder = (payload.count + 1) % 16 // +1 for the pad length byte
        let padCount = remainder == 0 ? 0 : 16 - remainder

        var plaintext = payload
        for i in 1...max(padCount, 1) {
            if i <= padCount {
                plaintext.append(UInt8(i & 0xFF))
            }
        }
        plaintext.append(UInt8(padCount)) // pad length byte

        let ciphertext = try aesCBC128Encrypt(key: aesKey, iv: iv, plaintext: plaintext)

        var result = iv
        result.append(contentsOf: ciphertext)
        return result
    }

    /// Decrypt an AES-CBC-128 encrypted IPMI payload.
    ///
    /// Input format: IV(16) + ciphertext
    /// Strips confidentiality padding per IPMI spec.
    private func decryptPayload(encrypted: [UInt8], key: SymmetricKey) throws -> [UInt8] {
        guard encrypted.count >= 32 else {
            throw IPMIError.encryptionError("Encrypted payload too short (\(encrypted.count) bytes)")
        }

        let aesKey = key.withUnsafeBytes { Array($0.prefix(16)) }
        let iv = Array(encrypted[0..<16])
        let ciphertext = Array(encrypted[16...])

        guard ciphertext.count % 16 == 0 else {
            throw IPMIError.encryptionError("Ciphertext length \(ciphertext.count) is not a multiple of 16")
        }

        let plaintext = try aesCBC128Decrypt(key: aesKey, iv: iv, ciphertext: ciphertext)

        guard !plaintext.isEmpty else {
            throw IPMIError.encryptionError("Decrypted payload is empty")
        }

        // Last byte is pad length (number of pad bytes before this byte)
        let padLength = Int(plaintext.last!)
        let dataLength = plaintext.count - padLength - 1

        guard dataLength > 0 && dataLength <= plaintext.count else {
            throw IPMIError.encryptionError("Invalid confidentiality pad length \(padLength)")
        }

        return Array(plaintext[0..<dataLength])
    }

    // MARK: - Crypto Helpers

    /// Two's complement checksum used by IPMI message framing.
    private func checksum(_ data: [UInt8]) -> UInt8 {
        var sum: UInt8 = 0
        for byte in data {
            sum = sum &+ byte
        }
        return ~sum &+ 1
    }

    /// Derive session keys from SIK using HMAC-SHA1.
    private func deriveKeys(sik: SymmetricKey) {
        self.sik = sik
        k1 = deriveKey(sik: sik, constant: 0x01) // integrity key
        k2 = deriveKey(sik: sik, constant: 0x02) // encryption key
    }

    private func deriveKey(sik: SymmetricKey, constant: UInt8) -> SymmetricKey {
        let input = [UInt8](repeating: constant, count: 20)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: input, using: sik)
        return SymmetricKey(data: Data(hmac))
    }

    // MARK: - AES-CBC-128 via CommonCrypto

    private func aesCBC128Encrypt(key: [UInt8], iv: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        var outLength = 0
        var outBytes = [UInt8](repeating: 0, count: plaintext.count + kCCBlockSizeAES128)
        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(0), // no padding -- we pad ourselves
            key, kCCKeySizeAES128,
            iv,
            plaintext, plaintext.count,
            &outBytes, outBytes.count,
            &outLength
        )
        guard status == kCCSuccess else {
            throw IPMIError.encryptionError("AES-CBC-128 encrypt failed (status \(status))")
        }
        return Array(outBytes.prefix(outLength))
    }

    private func aesCBC128Decrypt(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        var outLength = 0
        var outBytes = [UInt8](repeating: 0, count: ciphertext.count + kCCBlockSizeAES128)
        let status = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(0), // no padding -- we pad ourselves
            key, kCCKeySizeAES128,
            iv,
            ciphertext, ciphertext.count,
            &outBytes, outBytes.count,
            &outLength
        )
        guard status == kCCSuccess else {
            throw IPMIError.encryptionError("AES-CBC-128 decrypt failed (status \(status))")
        }
        return Array(outBytes.prefix(outLength))
    }

    // MARK: - Little-Endian Helpers

    /// Read a UInt32 from a byte array at the given offset (little-endian).
    private func readUInt32LE(_ data: [UInt8], offset: Int) -> UInt32 {
        UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    /// Append a UInt32 to a byte array in little-endian order.
    private func appendUInt32LE(_ array: inout [UInt8], _ value: UInt32) {
        array.append(contentsOf: withUnsafeBytes(of: value.littleEndian) { Array($0) })
    }

    /// Append a UInt16 to a byte array in little-endian order.
    private func appendUInt16LE(_ array: inout [UInt8], _ value: UInt16) {
        array.append(contentsOf: withUnsafeBytes(of: value.littleEndian) { Array($0) })
    }
}
