using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
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

    // Dictionarele OUI / SIG sunt scrise o singura data la start si apoi doar citite.
    private static Dictionary<string, string> _ouiDatabase = new Dictionary<string, string>();
    private static Dictionary<int, string> _bluetoothSigCompanies = new Dictionary<int, string>();

    // _deviceHistory este modificat DOAR in faza de merge (secventiala) => nu are nevoie de lock.
    private static Dictionary<string, BluetoothDeviceRecord> _deviceHistory = new Dictionary<string, BluetoothDeviceRecord>();
    private static readonly string _jsonDbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "devices_db.json");

    // Cate device-uri (Classic + BLE la un loc) sunt interogate simultan.
    private const int MaxParallelDevices = 8;
    // Timeout total per device (FromIdAsync + RFCOMM / GATT).
    private static readonly TimeSpan DeviceTimeout = TimeSpan.FromSeconds(20);

    // ---------------------------------------------------------------
    // Rezultate intermediare produse de faza paralela (fara stare partajata)
    // ---------------------------------------------------------------
    private class GattData
    {
        public List<string> Services { get; } = new List<string>();
        public string Firmware { get; set; }
        public string Hardware { get; set; }
        public string Manufacturer { get; set; }
    }

    private class DeviceSnapshot
    {
        public bool IsBle { get; set; }
        public DeviceInformation Item { get; set; }
        public ulong Address { get; set; }
        public bool IsPaired { get; set; }
        public string ProtectionLevel { get; set; }
        public List<string> RfcommServices { get; } = new List<string>();
        public GattData Gatt { get; set; }
    }

    public static async Task Main(string[] args)
    {
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
    public static void LoadOuiDatabase(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Fisierul {filePath} nu a fost gasit.");
            return;
        }

        string[] lines = File.ReadAllLines(filePath);

        // AsOrdered pastreaza ordinea liniilor => "prima intrare castiga" ca in varianta secventiala.
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

        string[] parts = line.Contains('\t')
            ? line.Split(new[] { '\t' }, 2)
            : line.Split(new[] { ' ' }, 2);

        if (parts.Length < 2) return null;

        string rawPrefix = parts[0].Split('/')[0];
        string ouiKey = rawPrefix.Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
        string vendor = parts[1].Trim();

        return ouiKey.Length == 6 ? (ouiKey, vendor) : ((string, string)?)null;
    }

    public static void LoadBluetoothSigCompanies(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Fisierul {filePath} nu a fost gasit.");
            return;
        }

        var db = new Dictionary<int, string>();
        int? pendingYamlId = null;

        // Parsarea e stateful (value: apoi name:), deci ramane secventiala;
        // ruleaza insa in paralel cu celelalte incarcari.
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
            Console.WriteLine($"Istoric incarcat: {_deviceHistory.Count} dispozitive salvate.");
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

            // Scriere atomica: fisier temporar + inlocuire.
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
    // Utilitare (neschimbate)
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

    private static async Task<Dictionary<string, DeviceInformation>> GetAepCacheAsync()
    {
        var cache = new Dictionary<string, DeviceInformation>(StringComparer.OrdinalIgnoreCase);

        try
        {
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
        }
        catch (Exception e)
        {
            // Cache-ul AEP e doar un bonus; fara el continuam cu proprietatile din enumerarea normala.
            Console.WriteLine($"Avertisment: cache AEP indisponibil ({e.Message}).");
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

    // ---------------------------------------------------------------
    // FAZA 1 - colectare (I/O Bluetooth), complet paralela, fara stare partajata
    // ---------------------------------------------------------------
    private static async Task<List<DeviceSnapshot>> GatherClassicAsync(string[] props, SemaphoreSlim gate)
    {
        var selector = BluetoothDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
        var devices = await DeviceInformation.FindAllAsync(selector, props);

        var snaps = await Task.WhenAll(devices.Select(d => GatherClassicDeviceAsync(d, gate)));
        return snaps.Where(s => s != null).ToList();
    }

    private static async Task<List<DeviceSnapshot>> GatherBleAsync(string[] props, SemaphoreSlim gate)
    {
        var selector = BluetoothLEDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
        var devices = await DeviceInformation.FindAllAsync(selector, props);

        var snaps = await Task.WhenAll(devices.Select(d => GatherBleDeviceAsync(d, gate)));
        return snaps.Where(s => s != null).ToList();
    }

    private static async Task<DeviceSnapshot> GatherClassicDeviceAsync(DeviceInformation item, SemaphoreSlim gate)
    {
        await gate.WaitAsync();
        BluetoothDevice btDevice = null;
        try
        {
            using var cts = new CancellationTokenSource(DeviceTimeout);

            btDevice = await BluetoothDevice.FromIdAsync(item.Id).AsTask(cts.Token);
            if (btDevice == null) return null;

            var snap = new DeviceSnapshot
            {
                IsBle = false,
                Item = item,
                Address = btDevice.BluetoothAddress,
                IsPaired = item.Pairing.IsPaired,
                ProtectionLevel = item.Pairing.ProtectionLevel.ToString()
            };

            try
            {
                var rfcommResult = await btDevice.GetRfcommServicesAsync(BluetoothCacheMode.Uncached).AsTask(cts.Token);
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
            gate.Release();
        }
    }

    private static async Task<DeviceSnapshot> GatherBleDeviceAsync(DeviceInformation item, SemaphoreSlim gate)
    {
        await gate.WaitAsync();
        BluetoothLEDevice bleDevice = null;
        try
        {
            using var cts = new CancellationTokenSource(DeviceTimeout);

            bleDevice = await BluetoothLEDevice.FromIdAsync(item.Id).AsTask(cts.Token);
            if (bleDevice == null) return null;

            var snap = new DeviceSnapshot
            {
                IsBle = true,
                Item = item,
                Address = bleDevice.BluetoothAddress,
                IsPaired = item.Pairing.IsPaired,
                ProtectionLevel = item.Pairing.ProtectionLevel.ToString()
            };

            snap.Gatt = await ReadBleGattAsync(bleDevice, cts.Token);
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
            gate.Release();
        }
    }

    private static async Task<GattData> ReadBleGattAsync(BluetoothLEDevice bleDevice, CancellationToken ct)
    {
        var data = new GattData();
        var services = new List<GattDeviceService>();

        try
        {
            var servicesResult = await bleDevice.GetGattServicesAsync(BluetoothCacheMode.Uncached).AsTask(ct);
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
                // Cele 3 citiri din Device Information Service se lanseaza concurent.
                var fwTask = ReadGattCharacteristicStringAsync(dis, GattCharacteristicUuids.FirmwareRevisionString, ct);
                var hwTask = ReadGattCharacteristicStringAsync(dis, GattCharacteristicUuids.HardwareRevisionString, ct);
                var mnTask = ReadGattCharacteristicStringAsync(dis, GattCharacteristicUuids.ManufacturerNameString, ct);

                await Task.WhenAll(fwTask, hwTask, mnTask);

                data.Firmware = fwTask.Result;
                data.Hardware = hwTask.Result;
                data.Manufacturer = mnTask.Result;
            }
        }
        catch
        {
            // Ca in varianta originala: orice eroare GATT => pastram ce s-a colectat pana acum.
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
            var charsResult = await service.GetCharacteristicsForUuidAsync(characteristicUuid, BluetoothCacheMode.Uncached).AsTask(ct);
            if (charsResult.Status != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
                return null;

            var readResult = await charsResult.Characteristics[0].ReadValueAsync(BluetoothCacheMode.Uncached).AsTask(ct);
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
    // FAZA 2 - merge in istoric (secvential, CPU trivial) - pastreaza semantica originala
    // ---------------------------------------------------------------
    private static void MergeSnapshot(
        DeviceSnapshot snap,
        Dictionary<string, DeviceInformation> aepCache,
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

        record.Name = snap.Item.Name;
        record.Vendor = vendor;
        record.LastConnected = DateTime.Now;
        if (updatedMacs.Add(mac))
        {
            record.ConnectionCount++;
        }

        ApplyLmpProperties(snap.Item.Properties, record);
        if (aepCache.TryGetValue(mac, out var aepItem))
        {
            ApplyLmpProperties(aepItem.Properties, record);
        }

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
            // Dual doar daca device-ul a fost vazut si ca Classic in rularea curenta
            // (varianta originala se baza pe valoarea veche din istoric).
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

        if (!snap.IsBle)
        {
            Console.WriteLine($"[CLASSIC] {record.Name} ({mac})");
            Console.WriteLine($"  MAC Vendor: {record.Vendor}");
            Console.WriteLine($"  Chipset: {record.Chipset.LmpManufacturerName} | {record.Chipset.LmpVersion} ({record.Chipset.LmpSubversion ?? "N/A"})");
            Console.WriteLine($"  Securitate: {record.Security.ProtectionLevel}");
        }
        else
        {
            Console.WriteLine($"[BLE] {record.Name} ({mac})");
            Console.WriteLine($"  MAC Vendor: {record.Vendor}");
            Console.WriteLine($"  Chipset: {record.Chipset.LmpManufacturerName} | FW: {record.Hardware.FirmwareRevision ?? "N/A"}");
        }
        Console.WriteLine("---");
    }

    public static async Task RunAnalysis()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;

        string[] requestedProperties = new string[]
        {
            PropLmpVersion,
            PropLmpSubversion,
            PropLmpManufacturer,
            PropHardwareIds
        };

        try
        {
            using var gate = new SemaphoreSlim(MaxParallelDevices);

            // FAZA 1: incarcarea fisierelor si colectarea de la device-uri ruleaza SIMULTAN.
            // Colectarea nu depinde de OUI / SIG (acestea se folosesc abia in merge).
            var ouiTask = Task.Run(() => LoadOuiDatabase(Path.Combine(baseDir, "master_oui.txt")));
            var sigTask = Task.Run(() => LoadBluetoothSigCompanies(Path.Combine(baseDir, "company_identifiers.yaml")));
            var historyTask = LoadDeviceHistoryAsync();
            var aepTask = GetAepCacheAsync();
            var classicTask = GatherClassicAsync(requestedProperties, gate);
            var bleTask = GatherBleAsync(requestedProperties, gate);

            await Task.WhenAll(ouiTask, sigTask, historyTask, aepTask, classicTask, bleTask);

            var aepCache = aepTask.Result;
            var classicSnaps = classicTask.Result;
            var bleSnaps = bleTask.Result;

            if (classicSnaps.Count == 0 && bleSnaps.Count == 0)
            {
                Console.WriteLine("Nu exista niciun dispozitiv Bluetooth conectat in acest moment.");
                return;
            }

            // FAZA 2: merge secvential, Classic inainte de BLE (aceeasi ordine ca in codul original).
            var updatedMacs = new HashSet<string>();
            var classicMacsThisRun = new HashSet<string>();

            foreach (var snap in classicSnaps)
                MergeSnapshot(snap, aepCache, updatedMacs, classicMacsThisRun);

            foreach (var snap in bleSnaps)
                MergeSnapshot(snap, aepCache, updatedMacs, classicMacsThisRun);

            await SaveDeviceHistoryAsync();
            Console.WriteLine($"Baza de date a fost salvata in: {_jsonDbPath}");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Eroare: {e.Message}");
        }
    }
}