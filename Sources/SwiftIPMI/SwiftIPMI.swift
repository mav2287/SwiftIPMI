// SwiftIPMI - A native Swift IPMI v2.0 client library
//
// Pure Swift implementation of the Intelligent Platform Management Interface (IPMI)
// protocol for out-of-band server management via RMCP+ over UDP port 623.
//
// Zero external dependencies — uses only:
// - Network.framework (NWConnection for UDP)
// - CommonCrypto / CryptoKit (HMAC-SHA1, AES-CBC-128)
// - Foundation
//
// Reference implementations studied:
// - gebn/bmc (Go, ~3000 lines, MIT) — https://github.com/gebn/bmc
// - rust-ipmi (Rust, MIT) — https://crates.io/crates/rust-ipmi
// - ipmitool (C, BSD) — https://github.com/ipmitool/ipmitool
//
// IPMI v2.0 Specification: https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-second-gen-interface-spec-v2-rev1-1.html

/// SwiftIPMI library version
public let swiftIPMIVersion = "0.1.0"
