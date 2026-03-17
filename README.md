# SwiftIPMI

A native Swift implementation of the IPMI v2.0 (Intelligent Platform Management Interface) protocol for out-of-band server management.

**Zero external dependencies** — uses only Apple frameworks (Network.framework, CryptoKit, Foundation).

## Status

🚧 **Work in Progress** — The public API and type definitions are stable. The RMCP+ session establishment (RAKP handshake, encryption) is under active development.

## Features

- Pure Swift async/await API
- IPMI v2.0 RMCP+ over UDP (port 623)
- HMAC-SHA1 authentication
- AES-CBC-128 encryption
- Persistent sessions (connect once, send many commands)
- Typed responses for all standard IPMI commands
- Apple OEM support (NetFn 0x36) for Xserve hardware

## Usage

```swift
import SwiftIPMI

let client = IPMIClient(host: "192.168.1.100")
try await client.connect(username: "admin", password: "secret")

let status = try await client.chassisStatus()
print("Power: \(status.powerOn ? "On" : "Off")")
print("Identify LED: \(status.identifyActive)")

let device = try await client.getDeviceID()
print("BMC: \(device.firmwareVersion)")
print("Apple: \(device.isApple)")

// Raw commands for OEM extensions
let response = try await client.sendRaw(netfn: 0x36, command: 0x02, data: [0x00, 0xC7, 0x00, 0x00])

try await client.disconnect()
```

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/YOUR_USERNAME/SwiftIPMI.git", from: "0.1.0")
]
```

## Architecture

```
IPMIClient (public API)
    └── IPMISession (RMCP+ session management, RAKP auth, encryption)
        └── RMCPTransport (UDP via Network.framework)
```

## Reference Implementations

- [gebn/bmc](https://github.com/gebn/bmc) — Pure Go IPMI v2.0 (~3000 lines)
- [rust-ipmi](https://crates.io/crates/rust-ipmi) — Rust IPMI v2.0
- [ipmitool](https://github.com/ipmitool/ipmitool) — C reference implementation

## License

MIT
