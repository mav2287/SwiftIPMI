import Foundation

/// Errors thrown by SwiftIPMI.
public enum IPMIError: LocalizedError, Sendable {
    case notConnected
    case connectionFailed(String)
    case authenticationFailed(String)
    case timeout(String)
    case completionCode(CompletionCode, command: String)
    case invalidResponse(String)
    case sessionClosed
    case transportError(String)
    case encryptionError(String)

    public var errorDescription: String? {
        switch self {
        case .notConnected:
            return "No active IPMI session"
        case .connectionFailed(let detail):
            return "Connection failed: \(detail)"
        case .authenticationFailed(let detail):
            return "Authentication failed: \(detail)"
        case .timeout(let detail):
            return "Timeout: \(detail)"
        case .completionCode(let code, let command):
            return "BMC returned error 0x\(String(format: "%02X", code.rawValue)) for \(command)"
        case .invalidResponse(let detail):
            return "Invalid response: \(detail)"
        case .sessionClosed:
            return "Session was closed by the BMC"
        case .transportError(let detail):
            return "Transport error: \(detail)"
        case .encryptionError(let detail):
            return "Encryption error: \(detail)"
        }
    }
}
