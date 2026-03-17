import Foundation

// MARK: - RMCP Transport Layer

/// Handles UDP communication with the BMC on port 623 using raw BSD sockets.
/// Uses POSIX socket APIs directly to avoid NWConnection's local network privacy restrictions.
///
/// RMCP Header (4 bytes):
/// - Byte 0: Version (0x06)
/// - Byte 1: Reserved (0x00)
/// - Byte 2: Sequence number
/// - Byte 3: Class (0x07 = IPMI, 0x06 = ASF)
final class RMCPTransport: @unchecked Sendable {

    let host: String
    let port: UInt16
    let timeout: TimeInterval

    private var sockfd: Int32 = -1
    private var addr = sockaddr_in()
    private let lock = NSLock()

    init(host: String, port: UInt16, timeout: TimeInterval) {
        self.host = host
        self.port = port
        self.timeout = timeout
    }

    /// Open the UDP socket and resolve the target address.
    func open() async throws {
        // Create UDP socket
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            throw IPMIError.connectionFailed("Failed to create UDP socket: errno \(errno)")
        }

        // Set receive timeout
        var tv = timeval()
        tv.tv_sec = Int(timeout)
        tv.tv_usec = Int32((timeout - Double(Int(timeout))) * 1_000_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Set send timeout
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Resolve host to sockaddr_in
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian

        // Try inet_pton first (IP address)
        if inet_pton(AF_INET, host, &address.sin_addr) != 1 {
            // Try DNS resolution
            guard let hostEntry = gethostbyname(host) else {
                Darwin.close(fd)
                throw IPMIError.connectionFailed("Cannot resolve host: \(host)")
            }
            memcpy(&address.sin_addr, hostEntry.pointee.h_addr_list[0]!, Int(hostEntry.pointee.h_length))
        }

        self.sockfd = fd
        self.addr = address
    }

    /// Close the UDP socket.
    func close() {
        lock.lock()
        defer { lock.unlock() }
        if sockfd >= 0 {
            Darwin.close(sockfd)
            sockfd = -1
        }
    }

    /// Send an RMCP-wrapped IPMI message and wait for the response.
    func sendReceive(payload: [UInt8], classOfMessage: UInt8 = 0x07) async throws -> [UInt8] {
        // Build RMCP header
        var message: [UInt8] = [
            0x06,               // RMCP version
            0x00,               // reserved
            0xFF,               // sequence number (0xFF = no ack)
            classOfMessage      // 0x07 = IPMI
        ]
        message.append(contentsOf: payload)

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global().async { [self] in
                lock.lock()
                let fd = sockfd
                var address = addr
                lock.unlock()

                guard fd >= 0 else {
                    continuation.resume(throwing: IPMIError.transportError("Socket not open"))
                    return
                }

                // Debug log with hex dump
                let hexDump = message.map { String(format: "%02x", $0) }.joined(separator: " ")
                let logLine = "[RMCPTransport] Sending \(message.count) bytes to \(self.host):\(self.port): \(hexDump)\n"
                if let logData = logLine.data(using: .utf8) {
                    let logPath = "/tmp/SwiftIPMI-debug.log"
                    if FileManager.default.fileExists(atPath: logPath) {
                        if let fh = FileHandle(forWritingAtPath: logPath) {
                            fh.seekToEndOfFile(); fh.write(logData); fh.closeFile()
                        }
                    } else {
                        FileManager.default.createFile(atPath: logPath, contents: logData)
                    }
                }

                // Send
                let sendResult = message.withUnsafeBufferPointer { buffer in
                    withUnsafePointer(to: &address) { addrPtr in
                        addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                            sendto(fd, buffer.baseAddress, buffer.count, 0,
                                   sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }

                // Log result
                let sendLog = "[RMCPTransport] sendto result: \(sendResult), errno: \(errno)\n"
                if let d = sendLog.data(using: .utf8) {
                    if let fh = FileHandle(forWritingAtPath: "/tmp/SwiftIPMI-debug.log") {
                        fh.seekToEndOfFile(); fh.write(d); fh.closeFile()
                    }
                }

                guard sendResult >= 0 else {
                    continuation.resume(throwing: IPMIError.transportError("sendto failed: errno \(errno)"))
                    return
                }

                // Receive
                var recvBuffer = [UInt8](repeating: 0, count: 65535)
                let recvResult = recvfrom(fd, &recvBuffer, recvBuffer.count, 0, nil, nil)

                // Log receive result
                let recvLog = "[RMCPTransport] recvfrom result: \(recvResult), errno: \(errno)\n"
                if let d = recvLog.data(using: .utf8) {
                    if let fh = FileHandle(forWritingAtPath: "/tmp/SwiftIPMI-debug.log") {
                        fh.seekToEndOfFile(); fh.write(d); fh.closeFile()
                    }
                }

                if recvResult < 0 {
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        continuation.resume(throwing: IPMIError.timeout("No response from \(self.host):\(self.port) within \(self.timeout)s"))
                    } else {
                        continuation.resume(throwing: IPMIError.transportError("recvfrom failed: errno \(errno)"))
                    }
                    return
                }

                let responseBytes = Array(recvBuffer.prefix(recvResult))

                // Strip RMCP header (4 bytes)
                if responseBytes.count > 4 {
                    continuation.resume(returning: Array(responseBytes[4...]))
                } else {
                    continuation.resume(returning: responseBytes)
                }
            }
        }
    }
}
