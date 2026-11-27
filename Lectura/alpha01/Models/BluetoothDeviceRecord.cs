using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BluetoothAuditor;

/// <summary>
/// Tipul de transport Bluetooth. Distincție critică pentru Dual-Mode devices
/// (același dispozitiv fizic poate avea adrese diferite pe Classic și BLE).
/// </summary>
public enum BluetoothTransport
{
    Unknown,
    BleAdvertising,     // Văzut doar pasiv prin advertising, neconectat
    BleConnected,       // BLE conectat/împerecheat cu gazda
    BrEdrClassic        // Bluetooth Classic (BR/EDR) conectat/împerecheat
}

public class AdvertisementObservation
{
    public ulong Address { get; set; }
    public string MacAddress => Address.ToString("X12");
    public string? LocalName { get; set; }
    public short Rssi { get; set; }
    public DateTime LastSeen { get; set; }
    public int PacketCount { get; set; }
    public bool IsConnectable { get; set; }
    public string AddressKind { get; set; } = "Unspecified";
    public bool IsStableAddress { get; set; }
    public HashSet<int> CompanyIds { get; } = new();
    public HashSet<string> ServiceUuids { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public class PassiveAdvertisementSnapshot
{
    public DateTime LastAdvertised { get; set; }
    public int? LastRssi { get; set; }
    public string? AddressKind { get; set; }
    public bool Connectable { get; set; }
    /// <summary>Nume rezolvate din Bluetooth SIG (pentru afișare / cuvinte cheie).</summary>
    public List<string> Companies { get; set; } = new();
    public List<int> CompanyIds { get; set; } = new();
    public List<string> ServiceUuids { get; set; } = new();
}

public class PassiveChipsetInfo
{
    public int? LmpManufacturerId { get; set; }
    public string LmpManufacturerName { get; set; } = "Necunoscut";
    public string LmpVersion { get; set; } = "Necunoscuta";
    public string? LmpSubversion { get; set; }
    public int? DeviceIdSource { get; set; }
    public int? DeviceIdVendorId { get; set; }
    public string? DeviceIdVendorName { get; set; }
    public int? DeviceIdProductId { get; set; }
}

public class PassiveHardwareInfo
{
    public List<string> HardwareIds { get; set; } = new();
    public string? FirmwareRevision { get; set; }
    public string? HardwareRevision { get; set; }
    public string? GattManufacturerName { get; set; }
}

public class PassiveSecurityInfo
{
    /// <summary>
    /// Transportul Bluetooth detectat. Înlocuiește șirul liber "BLE (doar advertising)"
    /// cu o etichetă tipizată pentru a preveni confuziile între Classic și BLE.
    /// </summary>
    public BluetoothTransport Transport { get; set; } = BluetoothTransport.Unknown;

    /// <summary>
    /// Numele human-readable al transportului (folosit la afișare / JSON export).
    /// </summary>
    public string ConnectionType
    {
        get => Transport switch
        {
            BluetoothTransport.BleAdvertising => "BLE (advertising pasiv)",
            BluetoothTransport.BleConnected => "BLE (conectat/împerecheat)",
            BluetoothTransport.BrEdrClassic => "BR/EDR (Classic)",
            _ => "Necunoscut"
        };
        set { /* setter gol pentru compatibilitate JSON la deserializare */ }
    }

    public bool IsPaired { get; set; }
    public string? ProtectionLevel { get; set; }
    public string? GattAccess { get; set; }
    public List<string> ExposedServices { get; set; } = new();
    public List<string> AuditNotes { get; set; } = new();
}

public class BluetoothDeviceRecord
{
    public string MacAddress { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public PassiveChipsetInfo Chipset { get; set; } = new();
    public PassiveHardwareInfo Hardware { get; set; } = new();
    public PassiveSecurityInfo Security { get; set; } = new();
    public PassiveAdvertisementSnapshot? Advertisement { get; set; }
    public string LastScanMode { get; set; } = "Passive";
    public DateTime FirstSeen { get; set; }
    public DateTime LastConnected { get; set; }
    public int ConnectionCount { get; set; }

    [JsonIgnore]
    public int? LastRssi => Advertisement?.LastRssi;

    [JsonIgnore]
    public bool? IsConnectable => Advertisement?.Connectable;
}
