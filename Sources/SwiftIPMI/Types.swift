import Foundation

// MARK: - Network Functions

/// IPMI Network Function codes (NetFn).
public enum NetFunction: UInt8, Sendable {
    case chassis      = 0x00
    case bridge       = 0x02
    case sensorEvent  = 0x04
    case application  = 0x06
    case firmware     = 0x08
    case storage      = 0x0A
    case transport    = 0x0C
    case oemApple     = 0x36 // Apple OEM
}

// MARK: - Privilege Levels

/// IPMI session privilege levels.
public enum PrivilegeLevel: UInt8, Sendable {
    case callback      = 0x01
    case user          = 0x02
    case `operator`    = 0x03
    case administrator = 0x04
    case oem           = 0x05
}

// MARK: - Authentication Algorithms

/// RMCP+ authentication algorithms.
public enum AuthAlgorithm: UInt8, Sendable {
    case none     = 0x00
    case hmacSHA1 = 0x01
    case hmacMD5  = 0x02
}

// MARK: - Integrity Algorithms

/// RMCP+ integrity (message signing) algorithms.
public enum IntegrityAlgorithm: UInt8, Sendable {
    case none        = 0x00
    case hmacSHA1_96 = 0x01
    case hmacMD5_128 = 0x02
    case md5_128     = 0x03
}

// MARK: - Confidentiality Algorithms

/// RMCP+ confidentiality (encryption) algorithms.
public enum ConfidentialityAlgorithm: UInt8, Sendable {
    case none      = 0x00
    case aesCBC128 = 0x01
    case xRC4_128  = 0x02
    case xRC4_40   = 0x03
}

// MARK: - Chassis Types

/// Chassis power control actions.
public enum ChassisControl: UInt8, Sendable {
    case powerOff   = 0x00
    case powerOn    = 0x01
    case powerCycle = 0x02
    case hardReset  = 0x03
    case pulse      = 0x04 // diagnostic interrupt
    case softOff    = 0x05 // ACPI soft shutdown
}

/// Chassis power restore policies.
public enum PowerRestorePolicy: UInt8, Sendable {
    case alwaysOff = 0x00
    case previous  = 0x01
    case alwaysOn  = 0x02
}

/// Boot device options.
public enum BootDevice: Sendable {
    case none
    case pxe
    case disk
    case safe
    case cdrom
    case bios
    case floppy

    var bootParam: UInt8 {
        switch self {
        case .none:    return 0x00
        case .pxe:     return 0x04
        case .disk:    return 0x08
        case .safe:    return 0x0C
        case .cdrom:   return 0x14
        case .bios:    return 0x18
        case .floppy:  return 0x3C
        }
    }
}

// MARK: - Response Types

/// Chassis status response.
public struct ChassisStatus: Sendable {
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

    init(from data: [UInt8]) throws {
        guard data.count >= 3 else {
            throw IPMIError.invalidResponse("Chassis status response too short (\(data.count) bytes)")
        }
        let byte1 = data[0]
        powerOn = (byte1 & 0x01) != 0
        powerOverload = (byte1 & 0x02) != 0
        powerInterlock = (byte1 & 0x04) != 0
        powerFault = (byte1 & 0x08) != 0
        powerControlFault = (byte1 & 0x10) != 0
        let policyBits = (byte1 >> 5) & 0x03
        powerRestorePolicy = PowerRestorePolicy(rawValue: policyBits) ?? .alwaysOff

        lastPowerEvent = data[1]

        let byte3 = data[2]
        chassisIntrusion = (byte3 & 0x01) != 0
        frontPanelLockout = (byte3 & 0x02) != 0
        driveFault = (byte3 & 0x04) != 0
        coolingFault = (byte3 & 0x08) != 0
        identifyActive = (byte3 & 0x20) != 0
    }
}

/// BMC Device ID response.
public struct DeviceID: Sendable {
    public let deviceID: UInt8
    public let deviceRevision: UInt8
    public let firmwareMajor: UInt8
    public let firmwareMinor: UInt8
    public let ipmiVersion: String
    public let manufacturerID: UInt32
    public let productID: UInt16

    init(from data: [UInt8]) throws {
        guard data.count >= 11 else {
            throw IPMIError.invalidResponse("Device ID response too short (\(data.count) bytes)")
        }
        deviceID = data[0]
        deviceRevision = data[1] & 0x0F
        firmwareMajor = data[2] & 0x7F
        firmwareMinor = data[3]
        let ver = data[4]
        ipmiVersion = "\(ver & 0x0F).\(ver >> 4)"
        manufacturerID = UInt32(data[6]) | (UInt32(data[7]) << 8) | (UInt32(data[8]) << 16)
        productID = UInt16(data[9]) | (UInt16(data[10]) << 8)
    }

    /// Whether this is an Apple BMC (IANA Enterprise Number 63).
    public var isApple: Bool {
        manufacturerID == 63
    }

    /// Firmware version string.
    public var firmwareVersion: String {
        "\(firmwareMajor).\(firmwareMinor)"
    }
}

/// Single sensor reading.
public struct SensorReading: Sendable {
    public let sensorNumber: UInt8
    public let rawValue: UInt8
    public let eventStatus: UInt16
    public let isScanning: Bool
    public let isAvailable: Bool

    init(sensorNumber: UInt8, from data: [UInt8]) throws {
        guard data.count >= 3 else {
            throw IPMIError.invalidResponse("Sensor reading response too short")
        }
        self.sensorNumber = sensorNumber
        rawValue = data[0]
        isScanning = (data[1] & 0x40) != 0
        isAvailable = (data[1] & 0x20) == 0
        if data.count >= 4 {
            eventStatus = UInt16(data[2]) | (UInt16(data[3]) << 8)
        } else {
            eventStatus = UInt16(data[2])
        }
    }
}

/// User access info.
public struct UserAccess: Sendable {
    public let maxUsers: UInt8
    public let enabledUsers: UInt8
    public let fixedNames: UInt8
    public let privilege: PrivilegeLevel

    init(from data: [UInt8]) throws {
        guard data.count >= 4 else {
            throw IPMIError.invalidResponse("User access response too short")
        }
        maxUsers = data[0] & 0x3F
        enabledUsers = data[1] & 0x3F
        fixedNames = data[2] & 0x3F
        privilege = PrivilegeLevel(rawValue: data[3] & 0x0F) ?? .user
    }
}

/// SEL (System Event Log) info.
public struct SELInfo: Sendable {
    public let version: UInt8
    public let entries: UInt16
    public let freeSpace: UInt16

    init(from data: [UInt8]) throws {
        guard data.count >= 5 else {
            throw IPMIError.invalidResponse("SEL info response too short")
        }
        version = data[0]
        entries = UInt16(data[1]) | (UInt16(data[2]) << 8)
        freeSpace = UInt16(data[3]) | (UInt16(data[4]) << 8)
    }
}

/// SDR Repository info.
public struct SDRRepositoryInfo: Sendable {
    public let version: UInt8
    public let recordCount: UInt16
    public let freeSpace: UInt16

    init(from data: [UInt8]) throws {
        guard data.count >= 5 else {
            throw IPMIError.invalidResponse("SDR info response too short")
        }
        version = data[0]
        recordCount = UInt16(data[1]) | (UInt16(data[2]) << 8)
        freeSpace = UInt16(data[3]) | (UInt16(data[4]) << 8)
    }
}

// MARK: - Completion Codes

/// IPMI completion code from BMC response.
public enum CompletionCode: UInt8, Sendable {
    case success                = 0x00
    case nodeBusy               = 0xC0
    case invalidCommand         = 0xC1
    case invalidForLUN          = 0xC2
    case timeout                = 0xC3
    case outOfSpace             = 0xC4
    case reservationCancelled   = 0xC5
    case dataLengthInvalid      = 0xC7
    case dataFieldLengthExceeded = 0xC8
    case parameterOutOfRange    = 0xC9
    case sensorNotFound         = 0xCB
    case invalidDataField       = 0xCC
    case insufficientPrivilege  = 0xD4
    case commandNotAvailable    = 0xD5
    case unspecified             = 0xFF
}
