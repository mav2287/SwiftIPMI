import Foundation
import Network

// MARK: - Public API

/// A native Swift IPMI v2.0 client that communicates with BMCs over RMCP+ (UDP port 623).
///
/// Usage:
/// ```swift
/// let client = IPMIClient(host: "192.168.1.100", port: 623)
/// try await client.connect(username: "admin", password: "secret")
/// let status = try await client.chassisStatus()
/// let sensors = try await client.sensorList()
/// try await client.disconnect()
/// ```
public actor IPMIClient {

    // MARK: - Configuration

    /// BMC hostname or IP address.
    public let host: String

    /// IPMI RMCP+ port (default 623).
    public let port: UInt16

    /// Connection timeout in seconds.
    public var timeout: TimeInterval = 10

    /// Maximum retries per command.
    public var maxRetries: Int = 3

    // MARK: - Session State

    private var session: IPMISession?
    private var transport: RMCPTransport?

    // MARK: - Init

    public init(host: String, port: UInt16 = 623) {
        self.host = host
        self.port = port
    }

    // MARK: - Connection

    /// Establish an authenticated IPMI v2.0 session with the BMC.
    public func connect(username: String, password: String,
                        privilege: PrivilegeLevel = .administrator) async throws {
        let transport = RMCPTransport(host: host, port: port, timeout: timeout)
        try await transport.open()
        self.transport = transport

        let session = IPMISession(transport: transport)
        try await session.activate(username: username, password: password, privilege: privilege)
        self.session = session
    }

    /// Close the IPMI session and UDP connection.
    public func disconnect() async throws {
        if let session = session {
            try? await session.close()
            self.session = nil
        }
        transport?.close()
        transport = nil
    }

    /// Whether a session is currently active.
    public var isConnected: Bool {
        session?.isActive ?? false
    }

    // MARK: - Chassis Commands (NetFn 0x00)

    /// Get chassis power status and fault flags.
    public func chassisStatus() async throws -> ChassisStatus {
        let response = try await sendCommand(netfn: .chassis, command: 0x01)
        return try ChassisStatus(from: response)
    }

    /// Send a chassis power control command.
    public func chassisControl(_ action: ChassisControl) async throws {
        _ = try await sendCommand(netfn: .chassis, command: 0x02, data: [action.rawValue])
    }

    /// Activate/deactivate chassis identify LED.
    public func chassisIdentify(seconds: UInt8 = 15, forceOn: Bool = false) async throws {
        let data: [UInt8] = forceOn ? [seconds, 0x01] : [seconds]
        _ = try await sendCommand(netfn: .chassis, command: 0x04, data: data)
    }

    /// Set chassis power restore policy.
    public func setPowerRestorePolicy(_ policy: PowerRestorePolicy) async throws {
        _ = try await sendCommand(netfn: .chassis, command: 0x06, data: [policy.rawValue])
    }

    /// Set boot device for next boot.
    public func setBootDevice(_ device: BootDevice) async throws {
        // Set System Boot Options (cmd 0x08), parameter 5 (boot flags)
        _ = try await sendCommand(netfn: .chassis, command: 0x08,
                                  data: [0x05, 0x80, device.bootParam, 0x00, 0x00, 0x00])
    }

    // MARK: - Sensor/Event Commands (NetFn 0x04)

    /// Get a single sensor reading by sensor number.
    public func getSensorReading(number: UInt8) async throws -> SensorReading {
        let response = try await sendCommand(netfn: .sensorEvent, command: 0x2D, data: [number])
        return try SensorReading(sensorNumber: number, from: response)
    }

    // MARK: - App Commands (NetFn 0x06)

    /// Get BMC device ID and capabilities.
    public func getDeviceID() async throws -> DeviceID {
        let response = try await sendCommand(netfn: .application, command: 0x01)
        return try DeviceID(from: response)
    }

    /// Get IPMI user list.
    public func getUserAccess(channel: UInt8 = 1, userID: UInt8 = 1) async throws -> UserAccess {
        let response = try await sendCommand(netfn: .application, command: 0x44,
                                              data: [channel, userID])
        return try UserAccess(from: response)
    }

    /// Warm reset the BMC.
    public func bmcWarmReset() async throws {
        _ = try await sendCommand(netfn: .application, command: 0x03)
    }

    /// Cold reset the BMC.
    public func bmcColdReset() async throws {
        _ = try await sendCommand(netfn: .application, command: 0x02)
    }

    // MARK: - Storage Commands (NetFn 0x0A)

    /// Get SEL (System Event Log) info.
    public func getSELInfo() async throws -> SELInfo {
        let response = try await sendCommand(netfn: .storage, command: 0x40)
        return try SELInfo(from: response)
    }

    /// Get SDR (Sensor Data Record) repository info.
    public func getSDRRepositoryInfo() async throws -> SDRRepositoryInfo {
        let response = try await sendCommand(netfn: .storage, command: 0x20)
        return try SDRRepositoryInfo(from: response)
    }

    // MARK: - Raw Commands

    /// Send a raw IPMI command and return the response data.
    public func sendRaw(netfn: UInt8, command: UInt8, data: [UInt8] = []) async throws -> [UInt8] {
        return try await sendCommand(netfn: NetFunction(rawValue: netfn) ?? .application,
                                      command: command, data: data)
    }

    // MARK: - Internal

    private func sendCommand(netfn: NetFunction, command: UInt8,
                              data: [UInt8] = []) async throws -> [UInt8] {
        guard let session = session, session.isActive else {
            throw IPMIError.notConnected
        }
        return try await session.sendCommand(netfn: netfn, command: command, data: data)
    }
}
