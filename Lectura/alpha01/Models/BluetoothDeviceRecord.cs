using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BluetoothAuditor;

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

    /// <summary>Nume rezolvate din Bluetooth SIG (pentru afisare / cuvinte cheie).</summary>
    public List<string> Companies { get; set; } = new();

    /// <summary>ID-uri brute de companie (pentru potrivirea exacta in reguli).</summary>
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
    public string ConnectionType { get; set; } = "BLE (doar advertising)";
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
