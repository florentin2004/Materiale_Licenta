using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Bluetooth.Rfcomm;
using Windows.Devices.Enumeration;
using Windows.Storage.Streams;

// =====================================================================
// MODEL DE DATE (campurile vechi raman compatibile cu devices_db.json existent)
// =====================================================================
public class ChipsetInfo
{
    public int? LmpManufacturerId { get; set; }
    public string LmpManufacturerName { get; set; }
    public string LmpVersion { get; set; }
    public string LmpSubversion { get; set; }

    // Device ID (Vendor/Product) expus de Windows prin proprietati documentate.
    // Sursa 1 = Bluetooth SIG company ID, sursa 2 = USB-IF Vendor ID.
    public int? DeviceIdSource { get; set; }
    public int? DeviceIdVendorId { get; set; }
    public string DeviceIdVendorName { get; set; }
    public int? DeviceIdProductId { get; set; }
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
    public string GattAccess { get; set; }          // Success / AccessDenied / Unreachable / Timeout / NotAttempted ...
    public List<string> ExposedServices { get; set; } = new List<string>();
    public List<string> AuditNotes { get; set; } = new List<string>();
}

// Date obtinute pasiv, din pachetele de advertising BLE.
public class AdvertisementInfo
{
    public DateTime LastAdvertised { get; set; }
    public int? LastRssi { get; set; }
    public string AddressKind { get; set; }          // Public / Random-Static / Random-Resolvable(RPA) / ...
    public bool Connectable { get; set; }
    public List<string> Companies { get; set; } = new List<string>();     // din manufacturer data (company ID -> nume SIG)
    public List<string> ServiceUuids { get; set; } = new List<string>();  // liste de UUID + service data pe 16 biti
}

public class BluetoothDeviceRecord
{
    public string MacAddress { get; set; }
    public string Name { get; set; }
    public string Vendor { get; set; }
    public ChipsetInfo Chipset { get; set; } = new ChipsetInfo();
    public HardwareInfo Hardware { get; set; } = new HardwareInfo();
    public SecurityPosture Security { get; set; } = new SecurityPosture();
    public AdvertisementInfo Advertisement { get; set; }
    public string LastScanMode { get; set; }         // "Live" sau "CachedFirst" - ca sa stii cat de proaspete sunt datele
    public DateTime FirstSeen { get; set; }
    public DateTime LastConnected { get; set; }
    public int ConnectionCount { get; set; }
}

public class BluetoothOuiAnalyzer
{
    private const string PropLmpVersion = "{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 2";
    private const string PropLmpSubversion = "{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 3";
    private const string PropLmpManufacturer = "{2BD67D8B-8BEB-48D5-87E0-6CDA3428040A} 4";
    private const string PropAepId = "System.Devices.Aep.AepId";
    private const string PropHardwareIds = "System.Devices.HardwareIds";

    // Proprietati documentate de Microsoft (System.DeviceInterface.Bluetooth.*);
    // cerem numele canonic, deci ID-ul numeric nu depinde de versiunea de Windows.
    private const string PropVendorId = "System.DeviceInterface.Bluetooth.VendorId";
    private const string PropVendorIdSource = "System.DeviceInterface.Bluetooth.VendorIdSource";
    private const string PropProductId = "System.DeviceInterface.Bluetooth.ProductId";

    private const int MaxParallelDevices = 8;
    private const int MaxProbeTargets = 10;

    private static Dictionary<string, string> _ouiDatabase = new Dictionary<string, string>();
    private static Dictionary<int, string> _bluetoothSigCompanies = new Dictionary<int, string>();
    private static Dictionary<string, BluetoothDeviceRecord> _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
    private static readonly string _jsonDbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "devices_db.json");

    // ---------------------------------------------------------------
    // Optiuni linie de comanda
    // ---------------------------------------------------------------
    private class Options
    {
        public int ScanSeconds = 8;                     // 0 = fara scan (--no-scan)
        public bool ActiveScan;                         // --active-scan (trimite SCAN_REQ; obtine nume din scan response)
        public bool Connect;                            // --connect  /  --connect=<nume sau MAC>
        public string ConnectFilter;
        public bool NoPrompt;                           // --no-prompt
        public bool Fast;                               // --fast  (Cached-first; mai rapid, dar date potential invechite)
        public bool Debug;                              // --debug (afiseaza toate proprietatile primite de la Windows)
        public TimeSpan DeviceTimeout = TimeSpan.FromSeconds(8);
        public TimeSpan EnumTimeout = TimeSpan.FromSeconds(15);

        public static Options Parse(string[] args)
        {
            var o = new Options();
            foreach (var raw in args ?? Array.Empty<string>())
            {
                string a = raw.Trim();
                string lower = a.ToLowerInvariant();

                if (lower == "--no-scan") o.ScanSeconds = 0;
                else if (lower.StartsWith("--scan=") && int.TryParse(a.Substring(7), out int s)) o.ScanSeconds = Math.Max(0, s);
                else if (lower == "--active-scan") o.ActiveScan = true;
                else if (lower == "--connect") o.Connect = true;
                else if (lower.StartsWith("--connect="))
                {
                    o.Connect = true;
                    o.ConnectFilter = a.Substring(10).Trim();
                }
                else if (lower == "--no-prompt") o.NoPrompt = true;
                else if (lower == "--fast") o.Fast = true;
                else if (lower == "--debug") o.Debug = true;
                else if (lower.StartsWith("--timeout=") && int.TryParse(a.Substring(10), out int t) && t > 0)
                    o.DeviceTimeout = TimeSpan.FromSeconds(t);
                else if (lower.StartsWith("--enum-timeout=") && int.TryParse(a.Substring(15), out int et) && et > 0)
                    o.EnumTimeout = TimeSpan.FromSeconds(et);
            }
            return o;
        }
    }

    private static Options _opts = new Options();

    // ---------------------------------------------------------------
    // Rezultate intermediare (faza paralela nu atinge starea partajata)
    // ---------------------------------------------------------------
    private class GattData
    {
        public List<string> Services { get; } = new List<string>();
        public string Firmware { get; set; }
        public string Hardware { get; set; }
        public string Manufacturer { get; set; }
        public string Status { get; set; } = "NotAttempted";
    }

    private class DeviceSnapshot
    {
        public bool IsBle { get; set; }
        public string Name { get; set; }
        public IReadOnlyDictionary<string, object> Props { get; set; }
        public IReadOnlyDictionary<string, object> ExtraAepProps { get; set; }
        public ulong Address { get; set; }
        public bool IsPaired { get; set; }
        public string ProtectionLevel { get; set; }
        public bool WasConnected { get; set; } = true;
        public List<string> RfcommServices { get; } = new List<string>();
        public GattData Gatt { get; set; }
    }

    private class AdvInfo
    {
        public ulong Address;
        public string Name;
        public short Rssi;
        public DateTime LastSeen;
        public int Packets;
        public bool Connectable;
        public string AddressKind;
        public HashSet<int> CompanyIds = new HashSet<int>();
        public HashSet<string> ServiceUuids = new HashSet<string>();
    }

    public static async Task Main(string[] args)
    {
        _opts = Options.Parse(args);

        var sw = Stopwatch.StartNew();
        await RunAnalysis();
        sw.Stop();
        Console.WriteLine($"Timp total: {sw.ElapsedMilliseconds} ms");

        if (!Console.IsInputRedirected)
        {
            Console.WriteLine("Apasa orice tasta pentru a iesi...");
            Console.ReadKey();
        }
    }

    // ---------------------------------------------------------------
    // Incarcare baze de date
    // ---------------------------------------------------------------
    private static Task TimedRun(string label, Action action) => Task.Run(() =>
    {
        var sw = Stopwatch.StartNew();
        action();
        Console.WriteLine($"[TIMING] {label}: {sw.ElapsedMilliseconds} ms");
    });

    public static void LoadOuiDatabase(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Fisierul {filePath} nu a fost gasit.");
            return;
        }

        string[] lines = File.ReadAllLines(filePath);

        var parsed = lines
            .AsParallel()
            .AsOrdered()
            .Select(ParseOuiLine)
            .Where(p => p.HasValue)
            .Select(p => p.Value)
            .ToList();

        var db = new Dictionary<string, string>(parsed.Count);
        foreach (var (key, vendor) in parsed)
            db.TryAdd(key, vendor);

        _ouiDatabase = db;
        Console.WriteLine($"Baza de date OUI incarcata: {_ouiDatabase.Count} intrari.");
    }

    private static (string Key, string Vendor)? ParseOuiLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) return null;

        int sepIdx = line.IndexOf('\t');
        if (sepIdx < 0) sepIdx = line.IndexOf(' ');
        if (sepIdx <= 0) return null;

        string rawPrefix = line.Substring(0, sepIdx);
        int slashIdx = rawPrefix.IndexOf('/');
        if (slashIdx >= 0) rawPrefix = rawPrefix.Substring(0, slashIdx);

        string ouiKey = rawPrefix.Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
        if (ouiKey.Length != 6) return null;

        string vendor = line.Substring(sepIdx + 1).Trim();
        return (ouiKey, vendor);
    }

    public static void LoadBluetoothSigCompanies(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Fisierul {filePath} nu a fost gasit.");
            return;
        }

        var db = new Dictionary<int, string>(4500);
        int? pendingYamlId = null;

        foreach (var rawLine in File.ReadLines(filePath))
        {
            string line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

            if (line.StartsWith("- value:") || line.StartsWith("value:"))
            {
                int colonIdx = line.IndexOf(':');
                if (colonIdx >= 0 && TryParseCompanyId(line.Substring(colonIdx + 1).Trim(), out int id))
                {
                    pendingYamlId = id;
                }
                continue;
            }

            if (line.StartsWith("name:") && pendingYamlId.HasValue)
            {
                string name = line.Substring(5).Trim().Trim('\'', '"');
                db.TryAdd(pendingYamlId.Value, name);
                pendingYamlId = null;
            }
        }

        _bluetoothSigCompanies = db;
        Console.WriteLine($"Baza Bluetooth SIG incarcata: {_bluetoothSigCompanies.Count} companii.");
    }

    private static bool TryParseCompanyId(string input, out int id)
    {
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(input.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out id);

        return int.TryParse(input, out id);
    }

    public static async Task LoadDeviceHistoryAsync()
    {
        var sw = Stopwatch.StartNew();
        if (!File.Exists(_jsonDbPath))
        {
            _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
            return;
        }

        try
        {
            string json = await File.ReadAllTextAsync(_jsonDbPath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, BluetoothDeviceRecord>>(json);
            _deviceHistory = loaded ?? new Dictionary<string, BluetoothDeviceRecord>();
            Console.WriteLine($"Istoric incarcat: {_deviceHistory.Count} dispozitive salvate. ({sw.ElapsedMilliseconds} ms)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Eroare la citirea JSON: {ex.Message}");
            _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
        }
    }

    public static async Task SaveDeviceHistoryAsync()
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(_deviceHistory, options);

            string tmp = _jsonDbPath + ".tmp";
            await File.WriteAllTextAsync(tmp, json);
            File.Move(tmp, _jsonDbPath, overwrite: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Eroare la salvarea JSON: {ex.Message}");
        }
    }

    // ---------------------------------------------------------------
    // Utilitare
    // ---------------------------------------------------------------
    public static string GetVendorFromMac(ulong bluetoothAddress)
    {
        string macString = bluetoothAddress.ToString("X12");
        string oui = macString.Substring(0, 6);

        return _ouiDatabase.TryGetValue(oui, out string vendor) ? vendor : "Producator Necunoscut";
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

    private static bool TryToInt(object o, out int value)
    {
        try { value = Convert.ToInt32(o, CultureInfo.InvariantCulture); return true; }
        catch { value = 0; return false; }
    }

    // Tipul adresei conteaza: OUI are sens DOAR pentru adrese Public (adresele random nu contin un OUI real),
    // iar adresele rotative (RPA / non-resolvable) se schimba si nu trebuie persistate.
    private static string ClassifyAddress(BluetoothAddressType type, ulong address)
    {
        if (type == BluetoothAddressType.Public) return "Public";
        if (type == BluetoothAddressType.Random)
        {
            int top = (int)((address >> 46) & 0x3);
            return top switch
            {
                3 => "Random-Static",
                1 => "Random-Resolvable(RPA)",
                0 => "Random-NonResolvable",
                _ => "Random-Rezervat"
            };
        }
        return "Unspecified";
    }

    private static bool IsStableAddress(string kind) =>
        kind == "Public" || kind == "Random-Static" || kind == "Unspecified";

    // Interogare tintita AEP DOAR pentru un dispozitiv deja conectat.
    private static async Task<IReadOnlyDictionary<string, object>> TryGetTargetedAepPropsAsync(IReadOnlyDictionary<string, object> itemProps, CancellationToken ct)
    {
        try
        {
            if (itemProps == null) return null;

            if (itemProps.TryGetValue(PropLmpManufacturer, out object lm) && lm != null)
                return null;

            string aepId = null;
            if (itemProps.TryGetValue(PropAepId, out object aepObj) && aepObj != null)
                aepId = aepObj.ToString();

            if (string.IsNullOrEmpty(aepId))
                return null;

            string[] aepProps = { PropLmpVersion, PropLmpSubversion, PropLmpManufacturer, PropHardwareIds,
                                  PropVendorId, PropVendorIdSource, PropProductId };
            var aepInfo = await DeviceInformation.CreateFromIdAsync(aepId, aepProps, DeviceInformationKind.AssociationEndpoint).AsTask(ct);
            return aepInfo?.Properties;
        }
        catch
        {
            return null;
        }
    }

    private static void ApplyDeviceProperties(IReadOnlyDictionary<string, object> props, BluetoothDeviceRecord record)
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

        if (props.TryGetValue(PropLmpSubversion, out object lmpSub) && lmpSub != null && TryToInt(lmpSub, out int subVal))
        {
            record.Chipset.LmpSubversion = $"0x{subVal:X4}";
        }

        if (props.TryGetValue(PropHardwareIds, out object hwIds) && hwIds is string[] idArray && idArray.Length > 0)
        {
            record.Hardware.HardwareIds = idArray.ToList();
        }

        // Device ID (documentat): sursa + vendor + produs.
        if (props.TryGetValue(PropVendorIdSource, out object vs) && vs != null && TryToInt(vs, out int srcVal))
            record.Chipset.DeviceIdSource = srcVal;

        if (props.TryGetValue(PropVendorId, out object vid) && vid != null && TryToInt(vid, out int vidVal))
        {
            record.Chipset.DeviceIdVendorId = vidVal;
            record.Chipset.DeviceIdVendorName = record.Chipset.DeviceIdSource switch
            {
                1 => MapCompanyId(vidVal),                       // Bluetooth SIG company ID
                2 => $"USB-IF VID 0x{vidVal:X4}",                // USB Implementers Forum
                _ => $"VendorId 0x{vidVal:X4} (sursa necunoscuta)"
            };
        }

        if (props.TryGetValue(PropProductId, out object pid) && pid != null && TryToInt(pid, out int pidVal))
            record.Chipset.DeviceIdProductId = pidVal;
    }

    private static List<string> EvaluateSecurityNotes(BluetoothDeviceRecord record)
    {
        var notes = new List<string>();

        // ProtectionLevel descrie asocierea EXISTENTA; fara asociere nu are sens sa "acuzam" nivelul.
        bool hasConnectionInfo = record.Security.ProtectionLevel != null;
        if (hasConnectionInfo)
        {
            if (!record.Security.IsPaired)
            {
                notes.Add("Dispozitiv conectat fara asociere (bonding) - nivelul de protectie nu poate fi evaluat; verifica daca link-ul este criptat.");
            }
            else if (record.Security.ProtectionLevel == "None" || record.Security.ProtectionLevel == "Encryption")
            {
                notes.Add("Atentie: Nivel scazut de autentificare la asociere (risc potential MITM / asociere fara confirmare).");
            }
        }

        if (!string.IsNullOrEmpty(record.Chipset.LmpVersion) &&
            (record.Chipset.LmpVersion.Contains("4.") || record.Chipset.LmpVersion.Contains("2.") || record.Chipset.LmpVersion.Contains("3.")))
        {
            notes.Add($"Versiune veche de protocol ({record.Chipset.LmpVersion}) - verifica suportul pentru Secure Connections.");
        }

        bool airoha =
            (record.Chipset.LmpManufacturerName?.Contains("Airoha", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (record.Chipset.DeviceIdVendorName?.Contains("Airoha", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (record.Advertisement?.Companies?.Any(c => c.Contains("Airoha", StringComparison.OrdinalIgnoreCase)) ?? false);
        if (airoha)
        {
            notes.Add("Chipset Airoha detectat - verifica versiunea de firmware pentru patch-urile recente.");
        }

        if (record.Security.ExposedServices.Any(s => s.StartsWith("0000111e", StringComparison.OrdinalIgnoreCase)))
        {
            notes.Add("Profil Hands-Free (HFP) activ - expune acces la microfon si comenzi apel.");
        }

        // df21fe2c-... = endpoint RFCOMM al "Message Stream" din Google Fast Pair; 0xFE2C = serviciul Fast Pair.
        bool fastPair =
            record.Security.ExposedServices.Any(s => s.StartsWith("df21fe2c", StringComparison.OrdinalIgnoreCase) ||
                                                     s.StartsWith("0000fe2c", StringComparison.OrdinalIgnoreCase)) ||
            (record.Advertisement?.ServiceUuids?.Any(s => s.StartsWith("0000fe2c", StringComparison.OrdinalIgnoreCase)) ?? false);
        if (fastPair)
        {
            notes.Add("Google Fast Pair detectat - candidat pentru verificarea WhisperPair; confirma patch-ul de firmware al producatorului.");
        }

        bool bleWithGatt = record.Security.ConnectionType != null && record.Security.ConnectionType.Contains("BLE") &&
                           record.Security.GattAccess == "Success";
        if (string.IsNullOrEmpty(record.Hardware.FirmwareRevision) && (hasConnectionInfo && (bleWithGatt || record.Security.ConnectionType == "Classic")))
        {
            notes.Add("Versiunea de firmware nu este expusa prin GATT standard.");
        }

        return notes;
    }

    // ---------------------------------------------------------------
    // Enumerare cu timeout (FindAllAsync nu avea niciun timeout)
    // ---------------------------------------------------------------
    private static async Task<IReadOnlyList<DeviceInformation>> FindAllSafeAsync(string selector, string[] props, string label)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(_opts.EnumTimeout);
            DeviceInformationCollection result;
            try
            {
                result = await DeviceInformation.FindAllAsync(selector, props).AsTask(cts.Token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.WriteLine($"[AVERTISMENT] enumerare {label} cu proprietati extra a esuat ({ex.Message}); reincerc fara ele.");
                result = await DeviceInformation.FindAllAsync(selector).AsTask(cts.Token);
            }

            Console.WriteLine($"[TIMING] enumerare {label}: {sw.ElapsedMilliseconds} ms ({result.Count} dispozitive)");
            return result;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine($"[TIMEOUT] enumerare {label} a depasit {_opts.EnumTimeout.TotalSeconds:0}s - ignorata.");
            return new List<DeviceInformation>();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[EROARE] enumerare {label}: {ex.Message}");
            return new List<DeviceInformation>();
        }
    }

    private static void DumpProps(string label, string name, IReadOnlyDictionary<string, object> props)
    {
        if (!_opts.Debug || props == null) return;
        var sb = new StringBuilder();
        sb.AppendLine($"[DEBUG] {label} {name}: {props.Count} proprietati");
        foreach (var kv in props)
            sb.AppendLine($"    {kv.Key} = {kv.Value ?? "null"} ({kv.Value?.GetType().Name ?? "-"})");
        Console.Write(sb.ToString());
    }

    // ---------------------------------------------------------------
    // Helpere Cached-first (doar cu --fast); implicit datele sunt citite LIVE
    // ---------------------------------------------------------------
    private static async Task<RfcommDeviceServicesResult> GetRfcommAsync(BluetoothDevice device, CancellationToken ct)
    {
        if (_opts.Fast)
        {
            var cached = await device.GetRfcommServicesAsync(BluetoothCacheMode.Cached).AsTask(ct);
            if (cached.Error == BluetoothError.Success && cached.Services.Count > 0) return cached;
        }
        return await device.GetRfcommServicesAsync(BluetoothCacheMode.Uncached).AsTask(ct);
    }

    private static async Task<GattDeviceServicesResult> GetGattServicesAsync(BluetoothLEDevice device, CancellationToken ct)
    {
        if (_opts.Fast)
        {
            var cached = await device.GetGattServicesAsync(BluetoothCacheMode.Cached).AsTask(ct);
            if (cached.Status == GattCommunicationStatus.Success && cached.Services.Count > 0) return cached;
        }
        return await device.GetGattServicesAsync(BluetoothCacheMode.Uncached).AsTask(ct);
    }

    private static async Task<GattCharacteristicsResult> GetCharacteristicsAsync(GattDeviceService service, Guid uuid, CancellationToken ct)
    {
        if (_opts.Fast)
        {
            var cached = await service.GetCharacteristicsForUuidAsync(uuid, BluetoothCacheMode.Cached).AsTask(ct);
            if (cached.Status == GattCommunicationStatus.Success && cached.Characteristics.Count > 0) return cached;
        }
        return await service.GetCharacteristicsForUuidAsync(uuid, BluetoothCacheMode.Uncached).AsTask(ct);
    }

    private static async Task<GattReadResult> ReadValueAsync(GattCharacteristic characteristic, CancellationToken ct)
    {
        if (_opts.Fast)
        {
            var cached = await characteristic.ReadValueAsync(BluetoothCacheMode.Cached).AsTask(ct);
            if (cached.Status == GattCommunicationStatus.Success) return cached;
        }
        return await characteristic.ReadValueAsync(BluetoothCacheMode.Uncached).AsTask(ct);
    }

    // ---------------------------------------------------------------
    // FAZA 1a - Colectare de la device-urile conectate
    // ---------------------------------------------------------------
    private static async Task<List<DeviceSnapshot>> GatherClassicAsync(string[] props, SemaphoreSlim gate)
    {
        var selector = BluetoothDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
        var devices = await FindAllSafeAsync(selector, props, "Classic");
        if (devices.Count == 0) return new List<DeviceSnapshot>();

        var snaps = await Task.WhenAll(devices.Select(d => GatherClassicDeviceAsync(d, gate)));
        return snaps.Where(s => s != null).ToList();
    }

    private static async Task<List<DeviceSnapshot>> GatherBleAsync(string[] props, SemaphoreSlim gate)
    {
        var selector = BluetoothLEDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
        var devices = await FindAllSafeAsync(selector, props, "BLE");
        if (devices.Count == 0) return new List<DeviceSnapshot>();

        var snaps = await Task.WhenAll(devices.Select(d => GatherBleDeviceAsync(d, gate)));
        return snaps.Where(s => s != null).ToList();
    }

    private static async Task<DeviceSnapshot> GatherClassicDeviceAsync(DeviceInformation item, SemaphoreSlim gate)
    {
        await gate.WaitAsync();
        BluetoothDevice btDevice = null;
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(_opts.DeviceTimeout);

            btDevice = await BluetoothDevice.FromIdAsync(item.Id).AsTask(cts.Token);
            if (btDevice == null) return null;

            DumpProps("CLASSIC", item.Name, item.Properties);
            var aepPropsTask = TryGetTargetedAepPropsAsync(item.Properties, cts.Token);

            var snap = new DeviceSnapshot
            {
                IsBle = false,
                Name = item.Name,
                Props = item.Properties,
                Address = btDevice.BluetoothAddress,
                IsPaired = item.Pairing.IsPaired,
                ProtectionLevel = item.Pairing.ProtectionLevel.ToString()
            };

            try
            {
                var rfcommResult = await GetRfcommAsync(btDevice, cts.Token);
                if (rfcommResult.Error == BluetoothError.Success)
                {
                    foreach (var svc in rfcommResult.Services)
                    {
                        snap.RfcommServices.Add(svc.ServiceId.Uuid.ToString());
                        svc.Dispose();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[CLASSIC] {item.Name}: RFCOMM indisponibil ({e.Message})");
            }

            snap.ExtraAepProps = await aepPropsTask;
            DumpProps("CLASSIC-AEP", item.Name, snap.ExtraAepProps);
            return snap;
        }
        catch (Exception e)
        {
            Console.WriteLine($"[CLASSIC] {item.Name}: eroare la colectare ({e.Message})");
            return null;
        }
        finally
        {
            btDevice?.Dispose();
            Console.WriteLine($"[TIMING] colectare CLASSIC {item.Name}: {sw.ElapsedMilliseconds} ms");
            gate.Release();
        }
    }

    private static async Task<DeviceSnapshot> GatherBleDeviceAsync(DeviceInformation item, SemaphoreSlim gate)
    {
        await gate.WaitAsync();
        BluetoothLEDevice bleDevice = null;
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(_opts.DeviceTimeout);

            bleDevice = await BluetoothLEDevice.FromIdAsync(item.Id).AsTask(cts.Token);
            if (bleDevice == null) return null;

            DumpProps("BLE", item.Name, item.Properties);
            var aepPropsTask = TryGetTargetedAepPropsAsync(item.Properties, cts.Token);

            var snap = new DeviceSnapshot
            {
                IsBle = true,
                Name = item.Name,
                Props = item.Properties,
                Address = bleDevice.BluetoothAddress,
                IsPaired = item.Pairing.IsPaired,
                ProtectionLevel = item.Pairing.ProtectionLevel.ToString()
            };

            snap.Gatt = await ReadBleGattAsync(bleDevice, cts.Token);
            snap.ExtraAepProps = await aepPropsTask;
            DumpProps("BLE-AEP", item.Name, snap.ExtraAepProps);
            return snap;
        }
        catch (Exception e)
        {
            Console.WriteLine($"[BLE] {item.Name}: eroare la colectare ({e.Message})");
            return null;
        }
        finally
        {
            bleDevice?.Dispose();
            Console.WriteLine($"[TIMING] colectare BLE {item.Name}: {sw.ElapsedMilliseconds} ms");
            gate.Release();
        }
    }

    private static async Task<GattData> ReadBleGattAsync(BluetoothLEDevice bleDevice, CancellationToken ct)
    {
        var data = new GattData();
        var services = new List<GattDeviceService>();

        try
        {
            var servicesResult = await GetGattServicesAsync(bleDevice, ct);
            data.Status = servicesResult.Status.ToString();
            if (servicesResult.Status != GattCommunicationStatus.Success) return data;

            services.AddRange(servicesResult.Services);

            foreach (var service in services)
            {
                string uuidStr = service.Uuid.ToString();
                if (!data.Services.Contains(uuidStr))
                    data.Services.Add(uuidStr);
            }

            var dis = services.FirstOrDefault(s => s.Uuid == GattServiceUuids.DeviceInformation);
            if (dis != null)
            {
                var fwTask = ReadGattCharacteristicStringAsync(dis, GattCharacteristicUuids.FirmwareRevisionString, ct);
                var hwTask = ReadGattCharacteristicStringAsync(dis, GattCharacteristicUuids.HardwareRevisionString, ct);
                var mnTask = ReadGattCharacteristicStringAsync(dis, GattCharacteristicUuids.ManufacturerNameString, ct);

                await Task.WhenAll(fwTask, hwTask, mnTask);

                data.Firmware = fwTask.Result;
                data.Hardware = hwTask.Result;
                data.Manufacturer = mnTask.Result;
            }
        }
        catch (OperationCanceledException)
        {
            data.Status = "Timeout";
        }
        catch (Exception ex)
        {
            data.Status = "Eroare: " + ex.GetType().Name;
        }
        finally
        {
            foreach (var s in services) s.Dispose();
        }

        return data;
    }

    private static async Task<string> ReadGattCharacteristicStringAsync(GattDeviceService service, Guid characteristicUuid, CancellationToken ct)
    {
        try
        {
            var charsResult = await GetCharacteristicsAsync(service, characteristicUuid, ct);
            if (charsResult.Status != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
                return null;

            var readResult = await ReadValueAsync(charsResult.Characteristics[0], ct);
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

    // ---------------------------------------------------------------
    // FAZA 1b - Scan BLE pasiv (ruleaza in paralel cu restul; nu adauga timp in plus)
    // ---------------------------------------------------------------
    private static async Task<List<AdvInfo>> ScanAdvertisementsAsync()
    {
        if (_opts.ScanSeconds <= 0) return new List<AdvInfo>();

        var found = new ConcurrentDictionary<ulong, AdvInfo>();
        var sw = Stopwatch.StartNew();

        try
        {
            var watcher = new BluetoothLEAdvertisementWatcher
            {
                ScanningMode = _opts.ActiveScan ? BluetoothLEScanningMode.Active : BluetoothLEScanningMode.Passive
            };

            watcher.Received += (w, e) =>
            {
                var info = found.GetOrAdd(e.BluetoothAddress, a => new AdvInfo
                {
                    Address = a,
                    AddressKind = ClassifyAddress(e.BluetoothAddressType, a)
                });

                lock (info)
                {
                    info.Packets++;
                    info.Rssi = e.RawSignalStrengthInDBm;
                    info.LastSeen = DateTime.Now;

                    if (e.AdvertisementType == BluetoothLEAdvertisementType.ConnectableUndirected ||
                        e.AdvertisementType == BluetoothLEAdvertisementType.ConnectableDirected)
                        info.Connectable = true;

                    string name = e.Advertisement.LocalName;
                    if (!string.IsNullOrWhiteSpace(name)) info.Name = name;

                    foreach (var m in e.Advertisement.ManufacturerData)
                        info.CompanyIds.Add(m.CompanyId);

                    foreach (var u in e.Advertisement.ServiceUuids)
                        info.ServiceUuids.Add(u.ToString());

                    // Service Data pe 16 biti (AD type 0x16): aici apare, de ex., Google Fast Pair (0xFE2C).
                    foreach (var section in e.Advertisement.DataSections)
                    {
                        if (section.DataType != 0x16) continue;
                        byte[] b = section.Data.ToArray();
                        if (b.Length >= 2)
                        {
                            int uuid16 = b[0] | (b[1] << 8);
                            info.ServiceUuids.Add($"0000{uuid16:x4}-0000-1000-8000-00805f9b34fb");
                        }
                    }
                }
            };

            watcher.Stopped += (w, e) =>
            {
                if (e.Error != BluetoothError.Success)
                    Console.WriteLine($"[SCAN] oprit cu eroare: {e.Error}");
            };

            try
            {
                watcher.Start();
                await Task.Delay(TimeSpan.FromSeconds(_opts.ScanSeconds));
            }
            finally
            {
                try { watcher.Stop(); } catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SCAN] indisponibil: {ex.Message}");
        }

        Console.WriteLine($"[TIMING] scan {(_opts.ActiveScan ? "activ" : "pasiv")}: {sw.ElapsedMilliseconds} ms ({found.Count} adrese unice)");
        return found.Values.ToList();
    }

    // ---------------------------------------------------------------
    // FAZA 1c - Selectie + interogare GATT (activa, doar la cerere) pentru device-uri gasite la scan
    // ---------------------------------------------------------------
    private static string DisplayName(AdvInfo a) => string.IsNullOrWhiteSpace(a.Name) ? "(fara nume)" : a.Name;

    private static List<AdvInfo> SelectProbeTargets(List<AdvInfo> scan, List<DeviceSnapshot> bleSnaps)
    {
        var already = new HashSet<ulong>(bleSnaps.Select(s => s.Address));
        var candidates = scan
            .Where(a => a.Connectable && !already.Contains(a.Address))
            .OrderByDescending(a => a.Rssi)
            .ToList();

        if (candidates.Count == 0) return new List<AdvInfo>();

        if (_opts.Connect)
        {
            if (!string.IsNullOrEmpty(_opts.ConnectFilter))
            {
                string f = _opts.ConnectFilter;
                string fMac = f.Replace(":", "").Replace("-", "").ToUpperInvariant();
                candidates = candidates
                    .Where(a => (a.Name?.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) ||
                                (fMac.Length > 0 && a.Address.ToString("X12").Contains(fMac)))
                    .ToList();
            }
            return candidates.Take(MaxProbeTargets).ToList();
        }

        if (_opts.NoPrompt || Console.IsInputRedirected)
        {
            Console.WriteLine($"[SCAN] {candidates.Count} device-uri conectabile gasite. Foloseste --connect[=nume/MAC] pentru interogare GATT.");
            return new List<AdvInfo>();
        }

        var shown = candidates.Take(15).ToList();
        Console.WriteLine();
        Console.WriteLine("Device-uri conectabile gasite (cele mai apropiate primele):");
        for (int i = 0; i < shown.Count; i++)
        {
            var a = shown[i];
            Console.WriteLine($"  {i + 1,2}. {DisplayName(a)} ({a.Address:X12}) {a.Rssi} dBm [{a.AddressKind}]");
        }
        Console.Write("Numere de interogat prin GATT (ex: 1,3) sau Enter pentru a sari peste: ");
        string line = Console.ReadLine();

        var chosen = new List<AdvInfo>();
        if (!string.IsNullOrWhiteSpace(line))
        {
            foreach (var part in line.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (int.TryParse(part, out int idx) && idx >= 1 && idx <= shown.Count && !chosen.Contains(shown[idx - 1]))
                    chosen.Add(shown[idx - 1]);
            }
        }
        return chosen;
    }

    private static async Task<DeviceSnapshot> ProbeAdvertisedDeviceAsync(AdvInfo adv, SemaphoreSlim gate)
    {
        await gate.WaitAsync();
        BluetoothLEDevice ble = null;
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(_opts.DeviceTimeout);

            ble = await BluetoothLEDevice.FromBluetoothAddressAsync(adv.Address).AsTask(cts.Token);
            if (ble == null)
            {
                Console.WriteLine($"[PROBE] {DisplayName(adv)}: device indisponibil pentru conectare.");
                return null;
            }

            var pairing = ble.DeviceInformation.Pairing;
            var snap = new DeviceSnapshot
            {
                IsBle = true,
                Name = !string.IsNullOrWhiteSpace(adv.Name) ? adv.Name : ble.Name,
                Props = ble.DeviceInformation.Properties,
                Address = adv.Address,
                IsPaired = pairing.IsPaired,
                ProtectionLevel = pairing.ProtectionLevel.ToString()
            };

            // GetGattServicesAsync(Uncached) declanseaza conectarea; nu se face pairing.
            snap.Gatt = await ReadBleGattAsync(ble, cts.Token);
            snap.WasConnected = ble.ConnectionStatus == BluetoothConnectionStatus.Connected;
            return snap;
        }
        catch (Exception e)
        {
            Console.WriteLine($"[PROBE] {DisplayName(adv)}: {e.Message}");
            return null;
        }
        finally
        {
            ble?.Dispose();
            Console.WriteLine($"[TIMING] probe GATT {DisplayName(adv)}: {sw.ElapsedMilliseconds} ms");
            gate.Release();
        }
    }

    // ---------------------------------------------------------------
    // FAZA 2 - Merge secvential in istoric
    // ---------------------------------------------------------------
    private static void MergeSnapshot(
        DeviceSnapshot snap,
        HashSet<string> updatedMacs,
        HashSet<string> classicMacsThisRun)
    {
        string mac = snap.Address.ToString("X12");
        string vendor = GetVendorFromMac(snap.Address);

        if (!_deviceHistory.TryGetValue(mac, out var record))
        {
            record = new BluetoothDeviceRecord
            {
                MacAddress = mac,
                FirstSeen = DateTime.Now,
                ConnectionCount = 0
            };
        }

        if (!string.IsNullOrWhiteSpace(snap.Name)) record.Name = snap.Name;
        record.Vendor = vendor;
        record.LastScanMode = _opts.Fast ? "CachedFirst" : "Live";

        if (snap.WasConnected)
        {
            record.LastConnected = DateTime.Now;
            if (updatedMacs.Add(mac))
                record.ConnectionCount++;
        }

        ApplyDeviceProperties(snap.Props, record);
        if (snap.ExtraAepProps != null)
            ApplyDeviceProperties(snap.ExtraAepProps, record);

        if (string.IsNullOrEmpty(record.Chipset.LmpManufacturerName))
            record.Chipset.LmpManufacturerName = "Necunoscut";
        if (string.IsNullOrEmpty(record.Chipset.LmpVersion))
            record.Chipset.LmpVersion = "Necunoscuta";

        if (!snap.IsBle)
        {
            classicMacsThisRun.Add(mac);
            record.Security.ConnectionType = "Classic";
        }
        else
        {
            record.Security.ConnectionType = classicMacsThisRun.Contains(mac) ? "Dual (Classic + BLE)" : "BLE";
        }

        record.Security.IsPaired = snap.IsPaired;
        record.Security.ProtectionLevel = snap.ProtectionLevel;

        if (!snap.IsBle)
        {
            foreach (var svcId in snap.RfcommServices)
            {
                if (!record.Security.ExposedServices.Contains(svcId))
                    record.Security.ExposedServices.Add(svcId);
            }
        }
        else if (snap.Gatt != null)
        {
            record.Security.GattAccess = snap.Gatt.Status;

            foreach (var uuid in snap.Gatt.Services)
            {
                if (!record.Security.ExposedServices.Contains(uuid))
                    record.Security.ExposedServices.Add(uuid);
            }

            record.Hardware.FirmwareRevision = snap.Gatt.Firmware ?? record.Hardware.FirmwareRevision;
            record.Hardware.HardwareRevision = snap.Gatt.Hardware ?? record.Hardware.HardwareRevision;
            record.Hardware.GattManufacturerName = snap.Gatt.Manufacturer ?? record.Hardware.GattManufacturerName;
        }

        record.Security.AuditNotes = EvaluateSecurityNotes(record);
        _deviceHistory[mac] = record;

        string tag = snap.IsBle ? "BLE" : "CLASSIC";
        Console.WriteLine($"[{tag}] {record.Name} ({mac})");
        Console.WriteLine($"  MAC Vendor: {record.Vendor}");
        if (!string.IsNullOrEmpty(record.Chipset.DeviceIdVendorName))
            Console.WriteLine($"  Device ID: {record.Chipset.DeviceIdVendorName} | produs 0x{record.Chipset.DeviceIdProductId:X4}");
        if (!snap.IsBle)
        {
            Console.WriteLine($"  Chipset: {record.Chipset.LmpManufacturerName} | {record.Chipset.LmpVersion} ({record.Chipset.LmpSubversion ?? "N/A"})");
            Console.WriteLine($"  Securitate: {record.Security.ProtectionLevel} (paired: {record.Security.IsPaired})");
        }
        else
        {
            Console.WriteLine($"  Chipset: {record.Chipset.LmpManufacturerName} | FW: {record.Hardware.FirmwareRevision ?? "N/A"} | GATT: {record.Security.GattAccess}");
        }
        foreach (var note in record.Security.AuditNotes)
            Console.WriteLine($"  ! {note}");
        Console.WriteLine("---");
    }

    // Atasam datele din advertising; device-urile cu adresa rotativa (RPA / non-resolvable) NU se persista.
    private static void MergeAdvertisements(List<AdvInfo> scan, out int persisted, out int transient)
    {
        persisted = 0;
        transient = 0;

        foreach (var adv in scan.OrderByDescending(a => a.Rssi))
        {
            string mac = adv.Address.ToString("X12");
            AdvertisementInfo advInfo;
            string name;
            bool isRandom;

            lock (adv)
            {
                name = adv.Name;
                isRandom = adv.AddressKind.StartsWith("Random");
                advInfo = new AdvertisementInfo
                {
                    LastAdvertised = adv.LastSeen,
                    LastRssi = adv.Rssi,
                    AddressKind = adv.AddressKind,
                    Connectable = adv.Connectable,
                    Companies = adv.CompanyIds.OrderBy(c => c).Select(c => MapCompanyId(c)).ToList(),
                    ServiceUuids = adv.ServiceUuids.OrderBy(s => s).ToList()
                };
            }

            bool known = _deviceHistory.TryGetValue(mac, out var record);
            bool stable = IsStableAddress(adv.AddressKind);

            string line = $"[SCAN] {(string.IsNullOrWhiteSpace(name) ? "(fara nume)" : name)} ({mac}) | {adv.Rssi} dBm | {adv.AddressKind}" +
                          $"{(adv.Connectable ? " | conectabil" : "")}" +
                          $"{(advInfo.Companies.Count > 0 ? " | SIG: " + string.Join(", ", advInfo.Companies) : "")}" +
                          $"{(advInfo.ServiceUuids.Count > 0 ? " | servicii: " + string.Join(", ", advInfo.ServiceUuids.Select(s => s.Substring(0, 8))) : "")}";

            if (!known && !stable)
            {
                transient++;
                Console.WriteLine(line + "  (nepersistat: adresa rotativa)");
                continue;
            }

            if (!known)
            {
                string vendor = isRandom
                    ? "N/A (adresa random - OUI nu se aplica)" + (advInfo.Companies.Count > 0 ? " | SIG: " + string.Join(", ", advInfo.Companies) : "")
                    : GetVendorFromMac(adv.Address);

                record = new BluetoothDeviceRecord
                {
                    MacAddress = mac,
                    Name = name,
                    Vendor = vendor,
                    FirstSeen = DateTime.Now,
                    ConnectionCount = 0,
                    LastScanMode = "Passive"
                };
                record.Chipset.LmpManufacturerName = "Necunoscut";
                record.Chipset.LmpVersion = "Necunoscuta";
                record.Security.ConnectionType = "BLE (doar advertising)";
                _deviceHistory[mac] = record;
            }

            if (string.IsNullOrWhiteSpace(record.Name) && !string.IsNullOrWhiteSpace(name))
                record.Name = name;

            record.Advertisement = advInfo;
            record.Security.AuditNotes = EvaluateSecurityNotes(record);
            persisted++;

            Console.WriteLine(line);
            foreach (var note in record.Security.AuditNotes.Where(n => n.Contains("Fast Pair") || n.Contains("Airoha")))
                Console.WriteLine($"  ! {note}");
        }
    }

    public static async Task RunAnalysis()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        string[] requestedProperties = new string[]
        {
            PropLmpVersion,
            PropLmpSubversion,
            PropLmpManufacturer,
            PropHardwareIds,
            PropAepId,
            PropVendorId,
            PropVendorIdSource,
            PropProductId
        };

        try
        {
            Console.WriteLine($"Scan: {(_opts.ScanSeconds > 0 ? (_opts.ActiveScan ? "activ " : "pasiv ") + _opts.ScanSeconds + "s" : "oprit")} | " +
                              $"mod citire: {(_opts.Fast ? "CachedFirst" : "Live")} | timeout device: {_opts.DeviceTimeout.TotalSeconds:0}s | debug: {_opts.Debug}");

            using var gate = new SemaphoreSlim(MaxParallelDevices);
            var phase1 = Stopwatch.StartNew();

            // Fisiere + enumerari + scan, toate simultan.
            var ouiTask = TimedRun("incarcare OUI", () => LoadOuiDatabase(Path.Combine(baseDir, "master_oui.txt")));
            var sigTask = TimedRun("incarcare SIG", () => LoadBluetoothSigCompanies(Path.Combine(baseDir, "company_identifiers.yaml")));
            var historyTask = LoadDeviceHistoryAsync();
            var classicTask = GatherClassicAsync(requestedProperties, gate);
            var bleTask = GatherBleAsync(requestedProperties, gate);
            var scanTask = ScanAdvertisementsAsync();

            await Task.WhenAll(ouiTask, sigTask, historyTask, classicTask, bleTask, scanTask);

            var classicSnaps = classicTask.Result;
            var bleSnaps = bleTask.Result;
            var scan = scanTask.Result;
            Console.WriteLine($"[TIMING] faza 1 (colectare + scan): {phase1.ElapsedMilliseconds} ms");

            // Interogare GATT optionala pentru device-uri gasite la scan (ex: un smart band nepereche).
            var probeTargets = SelectProbeTargets(scan, bleSnaps);
            if (probeTargets.Count > 0)
            {
                Console.WriteLine($"[PROBE] interoghez {probeTargets.Count} device-uri prin GATT (fara pairing). Foloseste doar pe dispozitive proprii / autorizate.");
                var probed = await Task.WhenAll(probeTargets.Select(a => ProbeAdvertisedDeviceAsync(a, gate)));
                bleSnaps.AddRange(probed.Where(p => p != null));
            }

            if (classicSnaps.Count == 0 && bleSnaps.Count == 0 && scan.Count == 0)
            {
                Console.WriteLine("Nu exista niciun dispozitiv conectat si scan-ul nu a detectat nimic.");
                return;
            }

            if (classicSnaps.Count == 0 && bleSnaps.Count == 0)
                Console.WriteLine("Niciun dispozitiv conectat in acest moment - raportez doar ce s-a vazut la scan.");

            var updatedMacs = new HashSet<string>();
            var classicMacsThisRun = new HashSet<string>();

            foreach (var snap in classicSnaps)
                MergeSnapshot(snap, updatedMacs, classicMacsThisRun);

            foreach (var snap in bleSnaps)
                MergeSnapshot(snap, updatedMacs, classicMacsThisRun);

            MergeAdvertisements(scan, out int persisted, out int transient);
            if (scan.Count > 0)
                Console.WriteLine($"[SCAN] {scan.Count} adrese: {persisted} persistate/actualizate, {transient} cu adresa rotativa (nepersistate).");

            await SaveDeviceHistoryAsync();
            Console.WriteLine($"Baza de date a fost salvata in: {_jsonDbPath}");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Eroare: {e.Message}");
        }
    }
}