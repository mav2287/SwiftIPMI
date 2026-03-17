import Foundation

// MARK: - Apple Xserve OEM IPMI Parameter Parsing
// Based on APPLE_OEM_IPMI_SPEC.md reverse-engineered from PlatformHardwareManagement framework.

/// Parsed payload from an Apple OEM IPMI parameter (NetFn 0x36).
public struct AppleOEMPayload: Sendable {
    /// Raw binary data portion (before the encoding marker).
    public let binaryData: [UInt8]
    /// Parsed strings from the packed string section.
    public let strings: [String]
}

/// Parser for Apple OEM IPMI parameter responses.
///
/// Wire format:
/// ```
/// Block 0 response: [completion_code, revision, total_len_lo, total_len_hi, payload...]
/// Block N response: [completion_code, block_number, payload...]
/// ```
///
/// Payload format:
/// ```
/// [binary_data (N bytes)] [0x01 encoding=UTF-8] [packed_strings...]
/// ```
///
/// String packing:
/// ```
/// [length_byte] [string_bytes] [0x00 null] [0x00 pad]
/// ```
/// Where `length_byte = strlen + 2` (includes null + pad).
/// Empty string: `[0x01] [0x00]`
public enum AppleOEMParser {

    /// Parse a raw OEM parameter payload into binary data + strings.
    ///
    /// - Parameters:
    ///   - payload: The reassembled payload bytes (after stripping block headers).
    ///   - binaryLength: Number of bytes at the start that are binary data.
    /// - Returns: Parsed payload with binary data and strings.
    public static func parse(payload: [UInt8], binaryLength: Int) -> AppleOEMPayload {
        guard !payload.isEmpty else {
            return AppleOEMPayload(binaryData: [], strings: [])
        }

        // Extract binary data
        let binaryEnd = min(binaryLength, payload.count)
        let binaryData = Array(payload[0..<binaryEnd])

        // Skip encoding marker byte (0x00=ASCII, 0x01=UTF-8, 0x02=UTF-16)
        var offset = binaryEnd
        if offset < payload.count {
            offset += 1  // skip encoding marker
        }

        // Parse packed strings
        var strings: [String] = []
        while offset < payload.count {
            let lenByte = Int(payload[offset])
            offset += 1

            if lenByte <= 1 {
                // Empty string marker: [0x01] [0x00] or just [0x00]
                strings.append("")
                if offset < payload.count && payload[offset] == 0x00 {
                    offset += 1
                }
                continue
            }

            // String data is (lenByte - 2) bytes, followed by null + pad
            let strLen = max(0, lenByte - 2)
            let strEnd = min(offset + strLen, payload.count)
            let strBytes = Array(payload[offset..<strEnd])
            let str = String(bytes: strBytes.filter { $0 >= 0x20 && $0 < 0x7F }, encoding: .ascii) ?? ""
            strings.append(str)

            // Skip past the full length (string + null + pad)
            offset += lenByte - 1  // -1 because we already read the length byte
            // Ensure we skip any trailing null/pad
            while offset < payload.count && payload[offset] == 0x00 {
                offset += 1
            }
        }

        return AppleOEMPayload(binaryData: binaryData, strings: strings)
    }

    /// Read a complete OEM parameter from the BMC, handling multi-block responses.
    ///
    /// - Parameters:
    ///   - client: Connected IPMIClient.
    ///   - param: Parameter ID (e.g., 0x01, 0xC0).
    ///   - setSelector: Set selector (e.g., DIMM/drive/NIC index).
    /// - Returns: Reassembled payload bytes (without block headers).
    public static func readParameter(client: IPMIClient, param: UInt8, setSelector: UInt8 = 0) async throws -> [UInt8] {
        // Read block 0
        let block0 = try await client.sendRaw(netfn: 0x36, command: 0x02,
                                               data: [0x00, param, setSelector, 0x00])

        // Block 0 response: [revision, total_len_lo, total_len_hi, payload...]
        guard block0.count >= 3 else { return [] }

        let totalLength = Int(block0[1]) | (Int(block0[2]) << 8)
        guard totalLength > 0 else { return [] }

        // Extract block 0 payload (bytes 3+)
        var allPayload = block0.count > 3 ? Array(block0[3...]) : [UInt8]()

        // Read additional blocks if needed (each holds up to 32 bytes)
        if totalLength > 30 {
            var blockNum: UInt8 = 1
            while allPayload.count < totalLength && blockNum < 20 {
                let blockN = try await client.sendRaw(netfn: 0x36, command: 0x02,
                                                       data: [0x00, param, setSelector, blockNum])
                // Block N response: [block_number, payload...]
                let payload = blockN.count > 1 ? Array(blockN[1...]) : []
                if payload.isEmpty { break }
                allPayload.append(contentsOf: payload)
                blockNum += 1
            }
        }

        // Trim to actual data length
        if allPayload.count > totalLength {
            allPayload = Array(allPayload.prefix(totalLength))
        }

        return allPayload
    }

    // MARK: - Typed Parameter Readers

    /// Read firmware/boot ROM version (param 0x01).
    public static func readFirmwareVersion(client: IPMIClient) async throws -> String {
        let payload = try await readParameter(client: client, param: 0x01)
        let parsed = parse(payload: payload, binaryLength: 0)
        return parsed.strings.first ?? ""
    }

    /// Read system name/hostname (param 0x02).
    public static func readSystemName(client: IPMIClient) async throws -> String {
        let payload = try await readParameter(client: client, param: 0x02)
        let parsed = parse(payload: payload, binaryLength: 0)
        return parsed.strings.first ?? ""
    }

    /// Read primary OS info (param 0x03). Returns (product, version, update).
    public static func readPrimaryOS(client: IPMIClient) async throws -> (product: String, version: String, update: String) {
        let payload = try await readParameter(client: client, param: 0x03)
        let parsed = parse(payload: payload, binaryLength: 0)
        return (
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : "",
            parsed.strings.count > 2 ? parsed.strings[2] : ""
        )
    }

    /// Read current OS info (param 0x04). Returns (product, version, build).
    public static func readCurrentOS(client: IPMIClient) async throws -> (product: String, version: String, build: String) {
        let payload = try await readParameter(client: client, param: 0x04)
        let parsed = parse(payload: payload, binaryLength: 0)
        return (
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : "",
            parsed.strings.count > 2 ? parsed.strings[2] : ""
        )
    }

    /// Read processor info (param 0xC0). Returns (packages, speedMHz, coresPerPackage, modelName).
    public static func readProcessorInfo(client: IPMIClient) async throws -> (packages: UInt32, speedMHz: UInt32, coresPerPackage: UInt32, modelName: String) {
        let payload = try await readParameter(client: client, param: 0xC0)
        let parsed = parse(payload: payload, binaryLength: 12)

        let bin = parsed.binaryData
        let packages = bin.count >= 4 ? readUInt32LE(bin, 0) : 0
        let speed = bin.count >= 8 ? readUInt32LE(bin, 4) : 0
        let cores = bin.count >= 12 ? readUInt32LE(bin, 8) : 0

        return (packages, speed, cores, parsed.strings.first ?? "")
    }

    /// Read miscellaneous info (param 0xC1). Returns (totalRAM_MB, model, serial).
    public static func readMiscInfo(client: IPMIClient) async throws -> (totalRAM_MB: UInt32, model: String, serial: String) {
        let payload = try await readParameter(client: client, param: 0xC1)
        let parsed = parse(payload: payload, binaryLength: 4)

        let ram = parsed.binaryData.count >= 4 ? readUInt32LE(parsed.binaryData, 0) : 0

        return (
            ram,
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : ""
        )
    }

    /// Read memory info for a DIMM slot (param 0xC2).
    public static func readMemoryInfo(client: IPMIClient, slot: UInt8) async throws -> (populated: Bool, eccEnabled: Bool, sizeMB: UInt32, slotName: String, speed: String, type: String)? {
        let payload: [UInt8]
        do {
            payload = try await readParameter(client: client, param: 0xC2, setSelector: slot)
        } catch {
            return nil  // No more DIMMs
        }
        guard !payload.isEmpty else { return nil }

        let parsed = parse(payload: payload, binaryLength: 6)
        let bin = parsed.binaryData
        guard bin.count >= 6 else { return nil }

        let configType = bin[0]
        let eccFlag = bin[1]
        let sizeMB = readUInt32LE(bin, 2)

        let populated = configType == 0x00 || configType != 0xFF
        let eccEnabled = eccFlag == 0x02

        return (
            populated, eccEnabled, sizeMB,
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : "",
            parsed.strings.count > 2 ? parsed.strings[2] : ""
        )
    }

    /// Read memory dynamic info for a DIMM slot (param 0xC9).
    public static func readMemoryDynamicInfo(client: IPMIClient, slot: UInt8) async throws -> (summary: UInt32, parityErrors: UInt32, baseline: UInt32)? {
        let payload: [UInt8]
        do {
            payload = try await readParameter(client: client, param: 0xC9, setSelector: slot)
        } catch {
            return nil
        }
        guard !payload.isEmpty else { return nil }

        let parsed = parse(payload: payload, binaryLength: 16)
        let bin = parsed.binaryData
        guard bin.count >= 12 else { return nil }

        return (
            readUInt32LE(bin, 0),
            readUInt32LE(bin, 4),
            readUInt32LE(bin, 8) & 0x7FFFFFFF
        )
    }

    /// Read drive static info (param 0xC3).
    public static func readDriveStaticInfo(client: IPMIClient, index: UInt8) async throws -> (capacityMB: Int32, kind: String, manufacturer: String, model: String, interconnect: String, location: String)? {
        let payload: [UInt8]
        do {
            payload = try await readParameter(client: client, param: 0xC3, setSelector: index)
        } catch {
            return nil
        }
        guard !payload.isEmpty else { return nil }

        let parsed = parse(payload: payload, binaryLength: 8)
        let bin = parsed.binaryData
        let capacity: Int32 = bin.count >= 4 ? Int32(bitPattern: readUInt32LE(bin, 0)) : 0

        return (
            capacity,
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : "",
            parsed.strings.count > 2 ? parsed.strings[2] : "",
            parsed.strings.count > 3 ? parsed.strings[3] : "",
            parsed.strings.count > 4 ? parsed.strings[4] : ""
        )
    }

    /// Read drive dynamic info (param 0xC5).
    public static func readDriveDynamicInfo(client: IPMIClient, index: UInt8) async throws -> (bytesRead: UInt64, bytesWritten: UInt64, readErrors: UInt32, writeErrors: UInt32, smartMessage: String, raidLevel: String)? {
        let payload: [UInt8]
        do {
            payload = try await readParameter(client: client, param: 0xC5, setSelector: index)
        } catch {
            return nil
        }
        guard !payload.isEmpty else { return nil }

        let parsed = parse(payload: payload, binaryLength: 36)
        let bin = parsed.binaryData

        let bytesRead: UInt64 = bin.count >= 8 ? readUInt64LE(bin, 0) : 0
        let bytesWritten: UInt64 = bin.count >= 16 ? readUInt64LE(bin, 8) : 0
        let readErrors: UInt32 = bin.count >= 24 ? readUInt32LE(bin, 20) : 0
        let writeErrors: UInt32 = bin.count >= 28 ? readUInt32LE(bin, 24) : 0

        return (
            bytesRead, bytesWritten, readErrors, writeErrors,
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : ""
        )
    }

    /// Read network static info (param 0xC4).
    public static func readNetworkStaticInfo(client: IPMIClient, index: UInt8) async throws -> (macAddress: String, userDefinedName: String, name: String)? {
        let payload: [UInt8]
        do {
            payload = try await readParameter(client: client, param: 0xC4, setSelector: index)
        } catch {
            return nil
        }
        guard !payload.isEmpty else { return nil }

        let parsed = parse(payload: payload, binaryLength: 0)
        return (
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : "",
            parsed.strings.count > 2 ? parsed.strings[2] : ""
        )
    }

    /// Read network dynamic info (param 0xC6).
    public static func readNetworkDynamicInfo(client: IPMIClient, index: UInt8) async throws -> (packetsIn: UInt32, packetsOut: UInt32, bytesIn: UInt32, bytesOut: UInt32, ipAddress: String, subnetMask: String, linkActive: Bool, speedMbps: String, duplex: String)? {
        let payload: [UInt8]
        do {
            payload = try await readParameter(client: client, param: 0xC6, setSelector: index)
        } catch {
            return nil
        }
        guard !payload.isEmpty else { return nil }

        let parsed = parse(payload: payload, binaryLength: 20)
        let bin = parsed.binaryData

        let packetsIn: UInt32 = bin.count >= 4 ? readUInt32LE(bin, 0) : 0
        let packetsOut: UInt32 = bin.count >= 8 ? readUInt32LE(bin, 4) : 0
        let bytesIn: UInt32 = bin.count >= 12 ? readUInt32LE(bin, 8) : 0
        let bytesOut: UInt32 = bin.count >= 16 ? readUInt32LE(bin, 12) : 0

        let link = parsed.strings.count > 2 ? parsed.strings[2] : ""

        return (
            packetsIn, packetsOut, bytesIn, bytesOut,
            parsed.strings.count > 0 ? parsed.strings[0] : "",
            parsed.strings.count > 1 ? parsed.strings[1] : "",
            link.lowercased() == "active",
            parsed.strings.count > 3 ? parsed.strings[3] : "",
            parsed.strings.count > 4 ? parsed.strings[4] : ""
        )
    }

    /// Read system uptime (param 0xC7).
    public static func readUptime(client: IPMIClient) async throws -> UInt32 {
        let payload = try await readParameter(client: client, param: 0xC7)
        let parsed = parse(payload: payload, binaryLength: 4)
        return parsed.binaryData.count >= 4 ? readUInt32LE(parsed.binaryData, 0) : 0
    }

    /// Read FQDN/computer name (param 0xCB).
    public static func readFQDN(client: IPMIClient) async throws -> String {
        let payload = try await readParameter(client: client, param: 0xCB)
        let parsed = parse(payload: payload, binaryLength: 0)
        return parsed.strings.first ?? ""
    }

    // MARK: - Helpers

    private static func readUInt32LE(_ data: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(data[offset]) | (UInt32(data[offset+1]) << 8) | (UInt32(data[offset+2]) << 16) | (UInt32(data[offset+3]) << 24)
    }

    private static func readUInt64LE(_ data: [UInt8], _ offset: Int) -> UInt64 {
        UInt64(readUInt32LE(data, offset)) | (UInt64(readUInt32LE(data, offset + 4)) << 32)
    }
}
