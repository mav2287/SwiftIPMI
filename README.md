# SwiftIPMI

A native Swift implementation of the IPMI v2.0 (Intelligent Platform Management Interface) protocol for out-of-band server management.

**Zero external dependencies** — uses only Apple frameworks (CryptoKit, CommonCrypto, Foundation).

## Features

- Pure Swift async/await API
- IPMI v2.0 RMCP+ over UDP (port 623)
- HMAC-SHA1 authentication (RAKP handshake)
- AES-CBC-128 encryption
- HMAC-SHA1-96 integrity signing
- Session key derivation (SIK, K1, K2)
- Persistent sessions (connect once, send many commands)
- Typed responses for all standard IPMI commands
- Raw command support for OEM extensions (e.g., Apple NetFn 0x36)
- BSD socket transport (no Network.framework privacy restrictions)
- Tested against Apple Xserve BMC (firmware 1.19)

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/mav2287/SwiftIPMI.git", from: "0.1.0")
]
```

## Quick Start

```swift
import SwiftIPMI

let client = IPMIClient(host: "192.168.1.100")
try await client.connect(username: "admin", password: "secret")

// Chassis status
let status = try await client.chassisStatus()
print("Power: \(status.powerOn ? "On" : "Off")")
print("Identify LED: \(status.identifyActive)")
print("Fan fault: \(status.coolingFault)")

// BMC device info
let device = try await client.getDeviceID()
print("Firmware: \(device.firmwareVersion)")
print("Apple BMC: \(device.isApple)")
print("IPMI: \(device.ipmiVersion)")

// Power control
try await client.chassisControl(.powerOn)
try await client.chassisControl(.softOff)     // ACPI graceful shutdown
try await client.chassisControl(.hardReset)
try await client.chassisControl(.powerCycle)

// Chassis identify LED
try await client.chassisIdentify(seconds: 15)  // blink for 15 seconds
try await client.chassisIdentify(seconds: 0)   // turn off

// Power restore policy
try await client.setPowerRestorePolicy(.alwaysOn)

// Boot device override
try await client.setBootDevice(.pxe)
try await client.setBootDevice(.disk)

// Individual sensor reading
let reading = try await client.getSensorReading(number: 0x30)
print("Raw value: \(reading.rawValue)")

// System Event Log
let selInfo = try await client.getSELInfo()
print("SEL entries: \(selInfo.entries)")

// SDR Repository
let sdrInfo = try await client.getSDRRepositoryInfo()
print("SDR records: \(sdrInfo.recordCount)")

// User management
let access = try await client.getUserAccess(channel: 1, userID: 1)
print("Max users: \(access.maxUsers)")

// BMC reset
try await client.bmcWarmReset()  // restarts BMC only
try await client.bmcColdReset()  // full BMC hardware reset

// Raw commands (for OEM extensions)
let response = try await client.sendRaw(netfn: 0x36, command: 0x02, data: [0x00, 0xC7, 0x00, 0x00])
print("Response: \(response)")

try await client.disconnect()
```

## API Reference

### IPMIClient

The main entry point. `IPMIClient` is an `actor` providing thread-safe access.

```swift
public actor IPMIClient {
    /// Create a client targeting a specific BMC.
    public init(host: String, port: UInt16 = 623)

    /// Connection timeout in seconds (default: 10).
    public var timeout: TimeInterval

    /// Maximum retries per command (default: 3).
    public var maxRetries: Int

    // Connection
    public func connect(username: String, password: String,
                        privilege: PrivilegeLevel = .administrator) async throws
    public func disconnect() async throws
    public var isConnected: Bool

    // Chassis Commands (NetFn 0x00)
    public func chassisStatus() async throws -> ChassisStatus
    public func chassisControl(_ action: ChassisControl) async throws
    public func chassisIdentify(seconds: UInt8 = 15, forceOn: Bool = false) async throws
    public func setPowerRestorePolicy(_ policy: PowerRestorePolicy) async throws
    public func setBootDevice(_ device: BootDevice) async throws

    // Sensor Commands (NetFn 0x04)
    public func getSensorReading(number: UInt8) async throws -> SensorReading

    // Application Commands (NetFn 0x06)
    public func getDeviceID() async throws -> DeviceID
    public func getUserAccess(channel: UInt8, userID: UInt8) async throws -> UserAccess
    public func bmcWarmReset() async throws
    public func bmcColdReset() async throws

    // Storage Commands (NetFn 0x0A)
    public func getSELInfo() async throws -> SELInfo
    public func getSDRRepositoryInfo() async throws -> SDRRepositoryInfo

    // Raw Commands
    public func sendRaw(netfn: UInt8, command: UInt8, data: [UInt8] = []) async throws -> [UInt8]
}
```

### Types

#### ChassisStatus
```swift
public struct ChassisStatus {
    public let powerOn: Bool
    public let powerOverload: Bool
    public let powerInterlock: Bool
    public let powerFault: Bool
    public let powerControlFault: Bool
    public let powerRestorePolicy: PowerRestorePolicy
    public let chassisIntrusion: Bool
    public let frontPanelLockout: Bool
    public let driveFault: Bool
    public let coolingFault: Bool
    public let identifyActive: Bool
    public let lastPowerEvent: UInt8
}
```

#### DeviceID
```swift
public struct DeviceID {
    public let deviceID: UInt8
    public let deviceRevision: UInt8
    public let firmwareMajor: UInt8
    public let firmwareMinor: UInt8      // BCD encoded
    public let ipmiVersion: String
    public let manufacturerID: UInt32
    public let productID: UInt16
    public var isApple: Bool             // true if manufacturer ID == 63
    public var firmwareVersion: String   // "major.minor" with BCD decoding
}
```

#### Enums
```swift
public enum ChassisControl: UInt8 {
    case powerOff, powerOn, powerCycle, hardReset, pulse, softOff
}

public enum PowerRestorePolicy: UInt8 {
    case alwaysOff, previous, alwaysOn
}

public enum PrivilegeLevel: UInt8 {
    case callback, user, operator, administrator, oem
}

public enum NetFunction: UInt8 {
    case chassis, bridge, sensorEvent, application,
         firmware, storage, transport, oemApple
}
```

#### Errors
```swift
public enum IPMIError: LocalizedError {
    case notConnected
    case connectionFailed(String)
    case authenticationFailed(String)
    case timeout(String)
    case completionCode(CompletionCode, command: String)
    case invalidResponse(String)
    case sessionClosed
    case transportError(String)
    case encryptionError(String)
}
```

## Architecture

```
IPMIClient (public async actor API)
    └── IPMISession (RMCP+ session lifecycle)
        ├── Open Session Request/Response
        ├── RAKP 1-4 (mutual authentication, key exchange)
        ├── SIK/K1/K2 key derivation (HMAC-SHA1)
        ├── AES-CBC-128 message encryption (CommonCrypto)
        ├── HMAC-SHA1-96 message integrity (CryptoKit)
        └── Set Session Privilege Level
            └── RMCPTransport (raw BSD UDP socket)
```

### Session Establishment Flow

1. **Get Channel Auth Capabilities** — pre-session v1.5 message to query BMC support
2. **Get Channel Cipher Suites** — pre-session RMCP+ message to negotiate algorithms
3. **Open Session** — proposes cipher suite (HMAC-SHA1 + HMAC-SHA1-96 + AES-CBC-128)
4. **RAKP 1** — sends console random number + username
5. **RAKP 2** — receives BMC random number + GUID, verifies BMC's HMAC
6. **RAKP 3** — sends console's HMAC for mutual authentication
7. **RAKP 4** — receives integrity check value, derives session keys (SIK → K1, K2)
8. **Set Session Privilege Level** — activates requested privilege (e.g., ADMINISTRATOR)
9. **Session active** — all subsequent commands are encrypted and integrity-protected

### Transport

Uses POSIX BSD sockets (`socket()/sendto()/recvfrom()`) directly instead of Network.framework. This avoids macOS Local Network privacy restrictions that block `NWConnection` UDP in unsigned/ad-hoc signed app bundles.

## Platform Support

- macOS 13+ (Ventura)
- iOS 16+ (theoretical — IPMI is LAN-based, useful from management apps)
- Requires CryptoKit and CommonCrypto (built into all Apple platforms)

## Tested Hardware

- Apple Xserve (RackMac3,1) — BMC firmware 1.19, IPMI 2.0, Manufacturer ID 63
- Cipher Suite 3 (HMAC-SHA1 + HMAC-SHA1-96 + AES-CBC-128)

## Known Limitations

- **SDR Repository iteration** may fail on some BMCs (Apple Xserve returns non-standard completion codes for Get SDR). The consuming application should fall back to `ipmitool sensor list` for sensor enumeration on affected hardware.
- **Cipher suite negotiation** currently hardcodes cipher suite 3. Future versions will auto-negotiate based on the BMC's capabilities response.
- **SOL (Serial-Over-LAN)** is not yet implemented.
- **IPMI v1.5** session mode is not supported (only v2.0 RMCP+).

## License

MIT

## Acknowledgments

Protocol implementation informed by:
- [IPMI v2.0 Specification](https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-second-gen-interface-spec-v2-rev1-1.html) (Intel)
- [gebn/bmc](https://github.com/gebn/bmc) — Pure Go IPMI v2.0 client
- [rust-ipmi](https://crates.io/crates/rust-ipmi) — Rust IPMI v2.0 client
- [ipmitool](https://github.com/ipmitool/ipmitool) — C reference implementation
