import Foundation
import Network

// MARK: - RMCP Transport Layer

/// Handles UDP communication with the BMC on port 623.
/// Implements the RMCP (Remote Management Control Protocol) message framing.
///
/// RMCP Header (4 bytes):
/// - Byte 0: Version (0x06)
/// - Byte 1: Reserved (0x00)
/// - Byte 2: Sequence number
/// - Byte 3: Class (0x07 = IPMI, 0x06 = ASF)
final class RMCPTransport: Sendable {

    let host: String
    let port: UInt16
    let timeout: TimeInterval

    private let connection: NWConnection

    init(host: String, port: UInt16, timeout: TimeInterval) {
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: .udp
        )
    }

    /// Open the UDP connection.
    func open() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    continuation.resume()
                case .failed(let error):
                    continuation.resume(throwing: IPMIError.connectionFailed(error.localizedDescription))
                default:
                    break
                }
            }
            connection.start(queue: DispatchQueue(label: "com.swiftipmi.transport"))
        }
    }

    /// Close the UDP connection.
    func close() {
        connection.cancel()
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

        // Send
        let data = Data(message)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: IPMIError.transportError(error.localizedDescription))
                } else {
                    continuation.resume()
                }
            })
        }

        // Receive with timeout
        return try await withThrowingTaskGroup(of: [UInt8].self) { group in
            group.addTask {
                try await self.receive()
            }
            group.addTask {
                try await Task.sleep(for: .seconds(self.timeout))
                throw IPMIError.timeout("No response from \(self.host):\(self.port) within \(self.timeout)s")
            }

            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    private func receive() async throws -> [UInt8] {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { content, _, _, error in
                if let error = error {
                    continuation.resume(throwing: IPMIError.transportError(error.localizedDescription))
                    return
                }
                guard let data = content else {
                    continuation.resume(throwing: IPMIError.invalidResponse("Empty response"))
                    return
                }
                // Strip RMCP header (4 bytes)
                let bytes = Array(data)
                if bytes.count > 4 {
                    continuation.resume(returning: Array(bytes[4...]))
                } else {
                    continuation.resume(returning: bytes)
                }
            }
        }
    }
}
