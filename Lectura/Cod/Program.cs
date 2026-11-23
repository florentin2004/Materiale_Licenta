using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Enumeration;
using Windows.Storage.Streams;

public class ChipsetInfo
{
    public int? LmpManufacturerId { get; set; }
    public string LmpManufacturerName { get; set; }
    public string LmpVersion { get; set; }
    public string LmpSubversion { get; set; }
}

public class HardwareInfo
{
    public List<string> HardwareIds { get; set; } = new List<string>();
    public string FirmwareRevision { get; set; }
    public string HardwareRevision { get; set; }
    public string GattManufacturerName { get; set; }
}

public class SecurityPosture
{
    public string ConnectionType { get; set; }
    public bool IsPaired { get; set; }
    public string ProtectionLevel { get; set; }
    public List<string> ExposedServices { get; set; } = new List<string>();
    public List<string> AuditNotes { get; set; } = new List<string>();
}

public class BluetoothDeviceRecord
{
    public string MacAddress { get; set; }
    public string Name { get; set; }
    public string Vendor { get; set; }
    public ChipsetInfo Chipset { get; set; } = new ChipsetInfo();
    public HardwareInfo Hardware { get; set; } = new HardwareInfo();
    public SecurityPosture Security { get; set; } = new SecurityPosture();
    public DateTime FirstSeen { get; set; }
    public DateTime LastConnected { get; set; }
    public int ConnectionCount { get; set; }
}

public class BluetoothOuiAnalyzer
{
    private const string PropLmpVersion = "{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 2";
    private const string PropLmpSubversion = "{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 3";
    private const string PropLmpManufacturer = "{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 4";
    private const string PropAepDeviceAddress = "System.Devices.Aep.DeviceAddress";
    private const string PropHardwareIds = "System.Devices.HardwareIds";

    private static Dictionary<string, string> _ouiDatabase = new Dictionary<string, string>();
    private static Dictionary<int, string> _bluetoothSigCompanies = new Dictionary<int, string>();
    private static Dictionary<string, BluetoothDeviceRecord> _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
    private static readonly string _jsonDbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "devices_db.json");

    public static async Task Main(string[] args)
    {
        await RunAnalysis();
        Console.WriteLine("Apasa orice tasta pentru a iesi...");
        Console.ReadKey();
    }

    public static void LoadOuiDatabase(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Fisierul {filePath} nu a fost gasit.");
            return;
        }

        foreach (var line in File.ReadLines(filePath))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

            string[] parts = line.Contains('\t')
                ? line.Split(new[] { '\t' }, 2)
                : line.Split(new[] { ' ' }, 2);

            if (parts.Length < 2) continue;

            string rawPrefix = parts[0].Split('/')[0];
            string ouiKey = rawPrefix.Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
            string vendor = parts[1].Trim();

            if (ouiKey.Length == 6 && !_ouiDatabase.ContainsKey(ouiKey))
            {
                _ouiDatabase[ouiKey] = vendor;
            }
        }
        Console.WriteLine($"Baza de date OUI incarcata: {_ouiDatabase.Count} intrari.");
    }

    public static void LoadBluetoothSigCompanies(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Fisierul {filePath} nu a fost gasit.");
            return;
        }

        int? pendingYamlId = null;

        foreach (var rawLine in File.ReadLines(filePath))
        {
            string line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

            if (line.StartsWith("- value:") || line.StartsWith("value:"))
            {
                string valStr = line.Split(':')[1].Trim();
                if (TryParseCompanyId(valStr, out int id))
                {
                    pendingYamlId = id;
                }
                continue;
            }

            if (line.StartsWith("name:") && pendingYamlId.HasValue)
            {
                string name = line.Substring(5).Trim().Trim('\'', '"');
                if (!_bluetoothSigCompanies.ContainsKey(pendingYamlId.Value))
                {
                    _bluetoothSigCompanies[pendingYamlId.Value] = name;
                }
                pendingYamlId = null;
                continue;
            }
        }
        Console.WriteLine($"Baza Bluetooth SIG incarcata: {_bluetoothSigCompanies.Count} companii.");
    }

    private static bool TryParseCompanyId(string input, out int id)
    {
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(input.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out id);

        return int.TryParse(input, out id);
    }

    public static void LoadDeviceHistory()
    {
        if (!File.Exists(_jsonDbPath))
        {
            _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
            return;
        }

        try
        {
            string json = File.ReadAllText(_jsonDbPath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, BluetoothDeviceRecord>>(json);
            _deviceHistory = loaded ?? new Dictionary<string, BluetoothDeviceRecord>();
            Console.WriteLine($"Istoric incarcat: {_deviceHistory.Count} dispozitive salvate.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Eroare la citirea JSON: {ex.Message}");
            _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
        }
    }

    public static void SaveDeviceHistory()
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(_deviceHistory, options);
            File.WriteAllText(_jsonDbPath, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Eroare la salvarea JSON: {ex.Message}");
        }
    }

    public static string GetVendorFromMac(ulong bluetoothAddress)
    {
        string macString = bluetoothAddress.ToString("X12");
        string oui = macString.Substring(0, 6);

        if (_ouiDatabase.TryGetValue(oui, out string vendor))
        {
            return vendor;
        }
        return "Producator Necunoscut";
    }

    private static string MapLmpVersion(object lmpObj)
    {
        if (lmpObj == null || !int.TryParse(lmpObj.ToString(), out int lmp))
            return "Necunoscuta";

        return lmp switch
        {
            6 => "Bluetooth 4.0",
            7 => "Bluetooth 4.1",
            8 => "Bluetooth 4.2",
            9 => "Bluetooth 5.0",
            10 => "Bluetooth 5.1",
            11 => "Bluetooth 5.2",
            12 => "Bluetooth 5.3",
            13 => "Bluetooth 5.4",
            _ => $"LMP {lmp}"
        };
    }

    private static string MapCompanyId(int? companyId)
    {
        if (!companyId.HasValue) return "Necunoscut";
        return _bluetoothSigCompanies.TryGetValue(companyId.Value, out string name)
            ? name
            : $"Company ID {companyId.Value} (0x{companyId.Value:X4})";
    }

    private static async Task<Dictionary<string, DeviceInformation>> GetAepCacheAsync()
    {
        var cache = new Dictionary<string, DeviceInformation>(StringComparer.OrdinalIgnoreCase);
        string[] aepProps = new string[]
        {
            PropAepDeviceAddress,
            PropLmpVersion,
            PropLmpSubversion,
            PropLmpManufacturer,
            PropHardwareIds
        };

        var aeps = await DeviceInformation.FindAllAsync(null, aepProps, DeviceInformationKind.AssociationEndpoint);
        foreach (var aep in aeps)
        {
            if (aep.Properties.TryGetValue(PropAepDeviceAddress, out object addrObj) && addrObj != null)
            {
                string cleanMac = addrObj.ToString().Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
                if (cleanMac.Length == 12 && !cache.ContainsKey(cleanMac))
                {
                    cache[cleanMac] = aep;
                }
            }
        }
        return cache;
    }

    private static void ApplyLmpProperties(IReadOnlyDictionary<string, object> props, BluetoothDeviceRecord record)
    {
        if (props == null) return;

        if (props.TryGetValue(PropLmpManufacturer, out object lmpMan) && lmpMan != null && int.TryParse(lmpMan.ToString(), out int manId))
        {
            record.Chipset.LmpManufacturerId = manId;
            record.Chipset.LmpManufacturerName = MapCompanyId(manId);
        }

        if (props.TryGetValue(PropLmpVersion, out object lmpVer) && lmpVer != null)
        {
            string mappedVer = MapLmpVersion(lmpVer);
            if (mappedVer != "Necunoscuta")
                record.Chipset.LmpVersion = mappedVer;
        }

        if (props.TryGetValue(PropLmpSubversion, out object lmpSub) && lmpSub != null)
        {
            record.Chipset.LmpSubversion = $"0x{Convert.ToInt32(lmpSub):X4}";
        }

        if (props.TryGetValue(PropHardwareIds, out object hwIds) && hwIds is string[] idArray && idArray.Length > 0)
        {
            record.Hardware.HardwareIds = idArray.ToList();
        }
    }

    private static List<string> EvaluateSecurityNotes(BluetoothDeviceRecord record)
    {
        var notes = new List<string>();

        if (record.Security.ProtectionLevel == "None" || record.Security.ProtectionLevel == "Encryption")
        {
            notes.Add("Atentie: Nivel scazut de autentificare la asociere (risc potential MITM / asociere fara confirmare).");
        }

        if (!string.IsNullOrEmpty(record.Chipset.LmpVersion) &&
            (record.Chipset.LmpVersion.Contains("4.") || record.Chipset.LmpVersion.Contains("2.") || record.Chipset.LmpVersion.Contains("3.")))
        {
            notes.Add($"Versiune veche de protocol ({record.Chipset.LmpVersion}) - verifica suportul pentru Secure Connections.");
        }

        if (record.Chipset.LmpManufacturerName != null &&
            record.Chipset.LmpManufacturerName.Contains("Airoha", StringComparison.OrdinalIgnoreCase))
        {
            notes.Add("Chipset Airoha detectat - verifica versiunea de firmware pentru patch-urile recente.");
        }

        if (record.Security.ExposedServices.Any(s => s.StartsWith("0000111e", StringComparison.OrdinalIgnoreCase)))
        {
            notes.Add("Profil Hands-Free (HFP) activ - expune acces la microfon si comenzi apel.");
        }

        if (string.IsNullOrEmpty(record.Hardware.FirmwareRevision))
        {
            notes.Add("Versiunea de firmware nu este expusa prin GATT standard.");
        }

        return notes;
    }

    private static async Task<string> ReadGattCharacteristicStringAsync(GattDeviceService service, Guid characteristicUuid)
    {
        try
        {
            var charsResult = await service.GetCharacteristicsForUuidAsync(characteristicUuid, BluetoothCacheMode.Uncached);
            if (charsResult.Status != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
                return null;

            var readResult = await charsResult.Characteristics[0].ReadValueAsync(BluetoothCacheMode.Uncached);
            if (readResult.Status != GattCommunicationStatus.Success)
                return null;

            var reader = DataReader.FromBuffer(readResult.Value);
            byte[] input = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(input);
            return Encoding.UTF8.GetString(input).Trim('\0').Trim();
        }
        catch
        {
            return null;
        }
    }

    private static async Task EnrichBleDetailsAsync(BluetoothLEDevice bleDevice, BluetoothDeviceRecord record)
    {
        try
        {
            var servicesResult = await bleDevice.GetGattServicesAsync(BluetoothCacheMode.Uncached);
            if (servicesResult.Status != GattCommunicationStatus.Success) return;

            foreach (var service in servicesResult.Services)
            {
                string uuidStr = service.Uuid.ToString();
                if (!record.Security.ExposedServices.Contains(uuidStr))
                {
                    record.Security.ExposedServices.Add(uuidStr);
                }

                if (service.Uuid == GattServiceUuids.DeviceInformation)
                {
                    record.Hardware.FirmwareRevision = await ReadGattCharacteristicStringAsync(service, GattCharacteristicUuids.FirmwareRevisionString)
                                                       ?? record.Hardware.FirmwareRevision;
                    record.Hardware.HardwareRevision = await ReadGattCharacteristicStringAsync(service, GattCharacteristicUuids.HardwareRevisionString)
                                                       ?? record.Hardware.HardwareRevision;
                    record.Hardware.GattManufacturerName = await ReadGattCharacteristicStringAsync(service, GattCharacteristicUuids.ManufacturerNameString)
                                                           ?? record.Hardware.GattManufacturerName;
                }
            }
        }
        catch
        {
        }
    }

    public static async Task RunAnalysis()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        LoadOuiDatabase(Path.Combine(baseDir, "master_oui.txt"));
        LoadBluetoothSigCompanies(Path.Combine(baseDir, "company_identifiers.yaml"));
        LoadDeviceHistory();

        string[] requestedProperties = new string[]
        {
            PropLmpVersion,
            PropLmpSubversion,
            PropLmpManufacturer,
            PropHardwareIds
        };

        try
        {
            var aepCache = await GetAepCacheAsync();
            var updatedMacs = new HashSet<string>();

            var selectorClassic = BluetoothDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
            var classicDevices = await DeviceInformation.FindAllAsync(selectorClassic, requestedProperties);

            foreach (var item in classicDevices)
            {
                var btDevice = await BluetoothDevice.FromIdAsync(item.Id);
                if (btDevice == null) continue;

                string mac = btDevice.BluetoothAddress.ToString("X12");
                string vendor = GetVendorFromMac(btDevice.BluetoothAddress);

                if (!_deviceHistory.TryGetValue(mac, out var record))
                {
                    record = new BluetoothDeviceRecord
                    {
                        MacAddress = mac,
                        FirstSeen = DateTime.Now,
                        ConnectionCount = 0
                    };
                }

                record.Name = item.Name;
                record.Vendor = vendor;
                record.LastConnected = DateTime.Now;
                if (!updatedMacs.Contains(mac))
                {
                    record.ConnectionCount++;
                    updatedMacs.Add(mac);
                }

                ApplyLmpProperties(item.Properties, record);
                if (aepCache.TryGetValue(mac, out var aepItem))
                {
                    ApplyLmpProperties(aepItem.Properties, record);
                }

                if (string.IsNullOrEmpty(record.Chipset.LmpManufacturerName))
                    record.Chipset.LmpManufacturerName = "Necunoscut";
                if (string.IsNullOrEmpty(record.Chipset.LmpVersion))
                    record.Chipset.LmpVersion = "Necunoscuta";

                record.Security.ConnectionType = "Classic";
                record.Security.IsPaired = item.Pairing.IsPaired;
                record.Security.ProtectionLevel = item.Pairing.ProtectionLevel.ToString();

                var rfcommResult = await btDevice.GetRfcommServicesAsync(BluetoothCacheMode.Uncached);
                if (rfcommResult.Error == BluetoothError.Success)
                {
                    foreach (var svc in rfcommResult.Services)
                    {
                        string svcId = svc.ServiceId.Uuid.ToString();
                        if (!record.Security.ExposedServices.Contains(svcId))
                            record.Security.ExposedServices.Add(svcId);
                    }
                }

                record.Security.AuditNotes = EvaluateSecurityNotes(record);
                _deviceHistory[mac] = record;

                Console.WriteLine($"[CLASSIC] {record.Name} ({mac})");
                Console.WriteLine($"  MAC Vendor: {record.Vendor}");
                Console.WriteLine($"  Chipset: {record.Chipset.LmpManufacturerName} | {record.Chipset.LmpVersion} ({record.Chipset.LmpSubversion ?? "N/A"})");
                Console.WriteLine($"  Securitate: {record.Security.ProtectionLevel}");
                Console.WriteLine("---");
            }

            var selectorBle = BluetoothLEDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
            var bleDevices = await DeviceInformation.FindAllAsync(selectorBle, requestedProperties);

            foreach (var item in bleDevices)
            {
                var bleDevice = await BluetoothLEDevice.FromIdAsync(item.Id);
                if (bleDevice == null) continue;

                string mac = bleDevice.BluetoothAddress.ToString("X12");
                string vendor = GetVendorFromMac(bleDevice.BluetoothAddress);

                if (!_deviceHistory.TryGetValue(mac, out var record))
                {
                    record = new BluetoothDeviceRecord
                    {
                        MacAddress = mac,
                        FirstSeen = DateTime.Now,
                        ConnectionCount = 0
                    };
                }

                record.Name = item.Name;
                record.Vendor = vendor;
                record.LastConnected = DateTime.Now;
                if (!updatedMacs.Contains(mac))
                {
                    record.ConnectionCount++;
                    updatedMacs.Add(mac);
                }

                ApplyLmpProperties(item.Properties, record);
                if (aepCache.TryGetValue(mac, out var aepItem))
                {
                    ApplyLmpProperties(aepItem.Properties, record);
                }

                if (string.IsNullOrEmpty(record.Chipset.LmpManufacturerName))
                    record.Chipset.LmpManufacturerName = "Necunoscut";
                if (string.IsNullOrEmpty(record.Chipset.LmpVersion))
                    record.Chipset.LmpVersion = "Necunoscuta";

                record.Security.ConnectionType = record.Security.ConnectionType == "Classic" ? "Dual (Classic + BLE)" : "BLE";
                record.Security.IsPaired = item.Pairing.IsPaired;
                record.Security.ProtectionLevel = item.Pairing.ProtectionLevel.ToString();

                await EnrichBleDetailsAsync(bleDevice, record);
                record.Security.AuditNotes = EvaluateSecurityNotes(record);
                _deviceHistory[mac] = record;

                Console.WriteLine($"[BLE] {record.Name} ({mac})");
                Console.WriteLine($"  MAC Vendor: {record.Vendor}");
                Console.WriteLine($"  Chipset: {record.Chipset.LmpManufacturerName} | FW: {record.Hardware.FirmwareRevision ?? "N/A"}");
                Console.WriteLine("---");
            }

            if (updatedMacs.Count == 0)
            {
                Console.WriteLine("Nu exista niciun dispozitiv Bluetooth conectat in acest moment.");
                return;
            }

            SaveDeviceHistory();
            Console.WriteLine($"Baza de date a fost salvata in: {_jsonDbPath}");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Eroare: {e.Message}");
        }
    }
}