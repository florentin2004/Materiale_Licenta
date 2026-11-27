# Ghid de actualizare și implementare — `BluetoothAuditor`

Acest document conține specificațiile tehnice, structura fișierelor și codul sursă actualizat pentru a fi aplicat în proiectul C# (.NET WinRT) `BluetoothAuditor`.

## Obiectivele actualizării
1. **Diferențierea explicită a transportului Bluetooth (`BLE` vs. `BR/EDR Classic`)**: Introducerea enumerării `BluetoothTransport` și eliminarea prefixului artefact `LE-` adăugat de Windows, evitând duplicarea sau etichetarea greșită a dispozitivelor Dual-Mode în `devices_db.json`.
2. **Extragerea `FastPair_ModelID` din pachetele Advertising (`0x16` / `0xFE2C`)**: Parsarea celor 3 octeți (little-endian) ai Model ID-ului Google Fast Pair și creșterea nivelului de încredere în `ReconEngine` la `Probabil`.
3. **Sondare activă GATT cu mecanism de Retry & Timeout**: Actualizarea `ActiveGattProber` cu încercări multiple de conectare (retry + timeout) și verificare neinvazivă a permisiunilor de citire (`Read`) pe caracteristicile serviciului `0xFE2C` (audit postură `CVE-2025-36911` / WhisperPair).
4. **Actualizarea regulilor și a fluxului CLI**: Alinierea `vulnerabilities.json` și `Program.cs` cu noile semnale și mesaje de diagnosticare.

---

## Instrucțiuni pentru aplicarea modificărilor

* **Fișierul 1 (`Models/BluetoothDeviceRecord.cs`)**: Înlocuire completă. Adaugă `enum BluetoothTransport` și actualizează `PassiveSecurityInfo` (atenție la compatibilitatea `namespace` dacă proiectul folosește `namespace BluetoothAuditor;` fără sub-namespace-uri — verifică declarația `namespace` din restul fișierelor).
* **Fișierul 2 (`Data/ConnectedDeviceChecker.cs` sau `Models/ConnectedDeviceChecker.cs`)**: Înlocuire completă. Separă interogarea dispozitivelor asociate `BR/EDR` de cele `BLE` și elimină duplicatele Dual-Mode.
* **Fișierul 3 (`PassiveDetection/PassiveDetectionService.cs`)**: Înlocuire completă. Include extragerea `FastPair_ModelID:0xXXXXXX` din secțiunile `0x16` cu UUID `0xFE2C`.
* **Fișierul 4 (`ActiveDetection/ActiveGattProber.cs`)**: Înlocuire completă. Adaugă timeout, retry logic și verificarea citirii neautentificate pe serviciul `0xFE2C`.
* **Fișierul 5 (`Analysis/ReconEngine.cs`)**: Adăugarea blocului de potrivire pentru `FastPair_ModelID:` în metoda `MatchRule`.
* **Fișierul 6 (`Analysis/vulnerabilities.json`)**: Înlocuire completă a catalogului de reguli.
* **Fișierul 7 (`Program.cs`)**: Actualizarea secțiunii `if (opts.ActiveScan)` pentru a apela noua semnătură `ProbeAsync(device, timeoutSeconds: 15, maxRetries: 3)` și a afișa condițiile de testare în consolă.

> **Notă importantă de compilare (Namespaces & Tipuri):**
> În codul existent din proiect, toate clasele folosesc `namespace BluetoothAuditor;` la nivel rădăcină, iar în `DeviceHistoryStore.cs` la crearea unui record pasiv nou trebuie setat și `Security = new PassiveSecurityInfo { Transport = BluetoothTransport.BleAdvertising }`. Asigură-te că `namespace`-urile (`BluetoothAuditor` vs `BluetoothAuditor.Models` etc.) sunt aliniate în tot proiectul la compilare (`dotnet build`).

---

## FIȘIERUL 1: `Models/BluetoothDeviceRecord.cs` (COMPLET)

```csharp
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
```

---

## FIȘIERUL 2: `Models/ConnectedDeviceChecker.cs` (COMPLET RESCRIS)

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Enumeration;

namespace BluetoothAuditor;

public record ConnectedDeviceInfo(string Name, string Id, string Transport);

public static class ConnectedDeviceChecker
{
    // Regex pentru extragerea MAC-ului din DeviceInformation.Id
    private static readonly Regex MacRegex = new(
        @"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
        RegexOptions.Compiled);

    private static readonly string[] RequestedProps = new[]
    {
        "System.Devices.Aep.ProtocolId",
        "System.Devices.Aep.IsConnected"
    };

    public static async Task<List<ConnectedDeviceInfo>> CheckAndPrintConnectedAsync()
    {
        var connected = new List<ConnectedDeviceInfo>();

        try
        {
            // ============================================================
            // 1. BLUETOOTH CLASSIC (BR/EDR) - dispozitive împerecheate
            // ============================================================
            var classicSelector = BluetoothDevice.GetDeviceSelectorFromPairingState(true);
            var classicDevices = await DeviceInformation.FindAllAsync(classicSelector, RequestedProps);

            foreach (var dev in classicDevices)
            {
                if (!IsConnected(dev)) continue;
                connected.Add(new ConnectedDeviceInfo(
                    CleanDeviceName(dev.Name),
                    dev.Id,
                    "Classic"));
            }

            // ============================================================
            // 2. BLUETOOTH LOW ENERGY (BLE) - dispozitive împerecheate
            // ============================================================
            var bleSelector = BluetoothLEDevice.GetDeviceSelectorFromPairingState(true);
            var bleDevices = await DeviceInformation.FindAllAsync(bleSelector, RequestedProps);

            foreach (var dev in bleDevices)
            {
                if (!IsConnected(dev)) continue;

                // Evităm duplicatele: unele dispozitive Dual-Mode apar în ambele liste
                // cu același DeviceId. Verificăm dacă nu cumva deja există.
                if (connected.Any(c => c.Id == dev.Id)) continue;

                connected.Add(new ConnectedDeviceInfo(
                    CleanDeviceName(dev.Name),
                    dev.Id,
                    "BLE"));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CONECTAT] Nu am putut enumera dispozitivele conectate: {ex.Message}");
            return connected;
        }

        if (connected.Count == 0)
        {
            Console.WriteLine("[CONECTAT] Nu exista niciun dispozitiv Bluetooth conectat la laptop in acest moment.");
        }
        else
        {
            Console.WriteLine($"[CONECTAT] Da, exista {connected.Count} dispozitiv(e) conectat(e) la laptop:");
            foreach (var item in connected)
            {
                // Afișăm explicit transportul pentru claritate
                string transportTag = item.Transport == "Classic" ? "BR/EDR" : "BLE";
                Console.WriteLine($" - [{transportTag}] {item.Name} ({item.Id})");
            }
        }

        return connected;
    }

    /// <summary>
    /// Verifică dacă dispozitivul este în stare conectată folosind proprietatea AEP.
    /// </summary>
    private static bool IsConnected(DeviceInformation dev)
    {
        if (dev.Properties.TryGetValue("System.Devices.Aep.IsConnected", out var value))
        {
            if (value is bool b) return b;
            if (bool.TryParse(value.ToString(), out bool parsed)) return parsed;
        }
        return true;
    }

    /// <summary>
    /// Elimină prefixul "LE-" pe care Windows îl adaugă uneori la dispozitivele Dual-Mode.
    /// </summary>
    private static string CleanDeviceName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "(fara nume)";
        if (name.StartsWith("LE-", StringComparison.OrdinalIgnoreCase))
            return name[3..];
        return name;
    }
}
```

---

## FIȘIERUL 3: `PassiveDetection/PassiveDetectionService.cs` (COMPLET)

```csharp
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Radios;

namespace BluetoothAuditor;

public class PassiveDetectionService
{
    private readonly PassiveLookupStore _lookupStore;
    private readonly DeviceHistoryStore _historyStore;

    public PassiveDetectionService(PassiveLookupStore lookupStore, DeviceHistoryStore historyStore)
    {
        _lookupStore = lookupStore ?? throw new ArgumentNullException(nameof(lookupStore));
        _historyStore = historyStore ?? throw new ArgumentNullException(nameof(historyStore));
    }

    public async Task<List<BluetoothDeviceRecord>> ExecuteAsync(ScanOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));

        var sw = Stopwatch.StartNew();
        string baseDir = options.BaseDirectory;

        await Task.WhenAll(
            Task.Run(() => _lookupStore.LoadOuiDatabase(Path.Combine(baseDir, "master_oui.txt"))),
            Task.Run(() => _lookupStore.LoadBluetoothSigCompanies(Path.Combine(baseDir, "company_identifiers.yaml"))),
            _historyStore.LoadAsync()
        );

        var sessionStart = DateTime.UtcNow;
        var observations = await CaptureAdvertisementsAsync(options);
        var (persisted, transient) = _historyStore.ApplyPassiveObservations(observations, options.Debug);
        await _historyStore.SaveAsync();

        sw.Stop();
        Console.WriteLine($"[PASIV] Finalizat in {sw.ElapsedMilliseconds} ms | observate: {observations.Count}, persistate: {persisted}, rotative ignorate: {transient}.");

        bool sessionOnly = options.ScanSeconds > 0;
        return _historyStore.AllRecords
            .Where(r => r.Advertisement != null &&
                        (!sessionOnly || r.Advertisement.LastAdvertised.ToUniversalTime() >= sessionStart))
            .OrderByDescending(r => r.Advertisement?.LastRssi ?? short.MinValue)
            .ToList();
    }

    private static async Task<bool> IsBluetoothAvailableAsync()
    {
        try
        {
            var adapter = await BluetoothAdapter.GetDefaultAsync();
            if (adapter == null)
            {
                Console.WriteLine("[PASIV] Nu exista adaptor Bluetooth; scanarea este sarita.");
                return false;
            }
            if (!adapter.IsLowEnergySupported)
            {
                Console.WriteLine("[PASIV] Adaptorul nu suporta Bluetooth LE; scanarea este sarita.");
                return false;
            }
            var radio = await adapter.GetRadioAsync();
            if (radio != null && radio.State != RadioState.On)
            {
                Console.WriteLine($"[PASIV] Radioul Bluetooth nu este pornit (stare: {radio.State}); scanarea este sarita.");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PASIV] Nu am putut verifica starea adaptorului: {ex.Message}");
            return true;
        }
    }

    private static async Task<List<AdvertisementObservation>> CaptureAdvertisementsAsync(ScanOptions options)
    {
        if (options.ScanSeconds <= 0)
            return new List<AdvertisementObservation>();

        if (!await IsBluetoothAvailableAsync())
            return new List<AdvertisementObservation>();

        // Notă tehnică: WinRT nu suportă scanare pasivă BR/EDR (Inquiry/EIR).
        // Dispozitivele Classic sunt vizibile doar dacă sunt deja împerecheate cu gazda.
        Console.WriteLine("[INFO] Scanare pasivă BLE (WinRT). BR/EDR Inquiry nu este suportat nativ.");

        var seen = new ConcurrentDictionary<ulong, AdvertisementObservation>();
        var watcher = new BluetoothLEAdvertisementWatcher
        {
            ScanningMode = options.ActiveScan
                ? BluetoothLEScanningMode.Active
                : BluetoothLEScanningMode.Passive
        };

        watcher.Received += (_, args) =>
        {
            var entry = seen.GetOrAdd(args.BluetoothAddress, addr =>
            {
                var (kind, stable) = ClassifyAddress(args.BluetoothAddressType, addr);
                return new AdvertisementObservation
                {
                    Address = addr,
                    AddressKind = kind,
                    IsStableAddress = stable
                };
            });

            lock (entry)
            {
                entry.PacketCount++;
                entry.Rssi = args.RawSignalStrengthInDBm;
                entry.LastSeen = DateTime.UtcNow;

                if (args.AdvertisementType == BluetoothLEAdvertisementType.ConnectableUndirected ||
                    args.AdvertisementType == BluetoothLEAdvertisementType.ConnectableDirected)
                {
                    entry.IsConnectable = true;
                }

                if (!string.IsNullOrWhiteSpace(args.Advertisement.LocalName))
                    entry.LocalName = args.Advertisement.LocalName;

                foreach (var mfr in args.Advertisement.ManufacturerData)
                    entry.CompanyIds.Add(mfr.CompanyId);

                foreach (var uuid in args.Advertisement.ServiceUuids)
                    entry.ServiceUuids.Add(uuid.ToString());

                // ============================================================
                // PARSARE AVANSATĂ: AD Structure Type 0x16 (Service Data - 16 bit UUID)
                // ============================================================
                foreach (var section in args.Advertisement.DataSections)
                {
                    if (section.DataType != 0x16 || section.Data.Length < 2) continue;

                    byte[] raw = section.Data.ToArray();
                    int uuid16 = raw[0] | (raw[1] << 8);
                    entry.ServiceUuids.Add($"0000{uuid16:x4}-0000-1000-8000-00805f9b34fb");

                    // ========================================================
                    // EXTRAGERE MODEL ID GOOGLE FAST PAIR (WhisperPair)
                    // Structura: [UUID16 (2 bytes)] [Model ID (3 bytes)] [...]
                    // ========================================================
                    if (uuid16 == 0xFE2C && raw.Length >= 5)
                    {
                        int modelId = raw[2] | (raw[3] << 8) | (raw[4] << 16);
                        entry.ServiceUuids.Add($"FastPair_ModelID:0x{modelId:X6}");
                        if (options.Debug)
                        {
                            Console.WriteLine($"  [DEBUG] Fast Pair Model ID detectat: 0x{modelId:X6} pentru {args.BluetoothAddress:X12}");
                        }
                    }
                }
            }
        };

        watcher.Stopped += (_, args) =>
        {
            if (args.Error != BluetoothError.Success)
                Console.WriteLine($"[PASIV] Watcher oprit cu eroare: {args.Error}");
        };

        try
        {
            watcher.Start();
            await Task.Delay(TimeSpan.FromSeconds(options.ScanSeconds));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PASIV] Eroare la scanare: {ex.Message}");
        }
        finally
        {
            try { watcher.Stop(); } catch { }
        }

        return seen.Values.ToList();
    }

    private static (string Kind, bool IsStable) ClassifyAddress(BluetoothAddressType type, ulong address)
    {
        if (type == BluetoothAddressType.Public)
            return ("Public", true);

        if (type == BluetoothAddressType.Random)
        {
            int topBits = (int)((address >> 46) & 0x3);
            return topBits switch
            {
                3 => ("Random-Static", true),
                1 => ("Random-Resolvable(RPA)", false),
                0 => ("Random-NonResolvable", false),
                _ => ("Random-Rezervat", false)
            };
        }

        return ("Unspecified", true);
    }
}
```

---

## FIȘIERUL 4: `ActiveDetection/ActiveGattProber.cs` (COMPLET CU RETRY + WHISPERPAIR)

```csharp
using System;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;

namespace BluetoothAuditor;

public static class ActiveGattProber
{
    /// <summary>
    /// Sondează un dispozitiv BLE: enumeră serviciile GATT, citește Generic Access (0x1800)
    /// și Device Information Service (0x180A), și execută sonda neinvazivă pe serviciul Fast Pair (0xFE2C).
    /// Include retry logic pentru a gestiona dispozitivele care răspund greu la prima conexiune.
    /// </summary>
    public static async Task ProbeAsync(BluetoothDeviceRecord record, int timeoutSeconds = 15, int maxRetries = 3)
    {
        record.Security ??= new PassiveSecurityInfo();
        record.Hardware ??= new PassiveHardwareInfo();
        record.Security.ExposedServices ??= new();
        record.Security.AuditNotes ??= new();

        if (!ulong.TryParse(record.MacAddress, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong btAddress))
        {
            record.Security.GattAccess = "InvalidMac";
            Console.WriteLine("  -> Acces GATT esuat: InvalidMac");
            return;
        }

        // Necesar pentru adrese BLE Random-Static (ex. D1D32CE2AD64)
        var addressType = string.Equals(record.Advertisement?.AddressKind, "Public", StringComparison.OrdinalIgnoreCase)
            ? BluetoothAddressType.Public
            : BluetoothAddressType.Random;

        Console.WriteLine($"  -> Tentativa conectare la {record.MacAddress} ({record.Name})...");
        Console.WriteLine($"  -> Tip adresă: {record.Advertisement?.AddressKind ?? "necunoscut"}, Timeout: {timeoutSeconds}s, Retry: {maxRetries}");

        // ============================================================
        // RETRY LOGIC - unele dispozitive BLE răspund greu la prima conexiune
        // ============================================================
        BluetoothLEDevice? bleDevice = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                Console.WriteLine($"  -> Încercarea {attempt}/{maxRetries}...");

                var connectionTask = BluetoothLEDevice.FromBluetoothAddressAsync(btAddress, addressType).AsTask();
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds));

                var completedTask = await Task.WhenAny(connectionTask, timeoutTask);

                if (completedTask == timeoutTask)
                {
                    Console.WriteLine($"  -> Timeout la conectare ({timeoutSeconds}s). Se reîncearcă...");
                    continue;
                }

                bleDevice = await connectionTask;

                if (bleDevice != null)
                {
                    Console.WriteLine($"  -> Conectare reușită la încercarea {attempt}.");
                    break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  -> Eroare la încercarea {attempt}: {ex.Message}");
            }

            if (attempt < maxRetries)
            {
                Console.WriteLine($"  -> Așteptare 3 secunde înainte de următoarea încercare...");
                await Task.Delay(3000);
            }
        }

        if (bleDevice == null)
        {
            record.Security.GattAccess = "Unreachable";
            record.Security.AuditNotes.Add(
                "Dispozitiv indisponibil pentru sondare GATT după mai multe încercări. " +
                "Posibile cauze: conectat la alt dispozitiv, oprit, în afara razei, sau radio ocupat.");
            Console.WriteLine($"  -> Acces GATT esuat: Unreachable (după {maxRetries} încercări)");
            return;
        }

        using (bleDevice)
        {
            bleDevice.ConnectionStatusChanged += (s, args) =>
            {
                Console.WriteLine($"  -> Status conexiune: {bleDevice.ConnectionStatus}");
            };

            var servicesResult = await bleDevice.GetGattServicesAsync(BluetoothCacheMode.Uncached);
            record.Security.GattAccess = servicesResult.Status.ToString();

            if (servicesResult.Status != GattCommunicationStatus.Success)
            {
                Console.WriteLine($"  -> Acces GATT esuat: {servicesResult.Status}");
                record.Security.AuditNotes.Add($"Enumerare servicii eșuată: {servicesResult.Status}");
                return;
            }

            record.Security.ExposedServices.Clear();

            foreach (var service in servicesResult.Services)
            {
                using (service)
                {
                    string uuidStr = service.Uuid.ToString();
                    record.Security.ExposedServices.Add(uuidStr);
                    Console.WriteLine($"  -> Serviciu GATT: {uuidStr}");

                    // Generic Access (0x1800) -> Device Name (0x2A00)
                    if (service.Uuid == GattServiceUuids.GenericAccess)
                    {
                        await ReadGenericAccessNameAsync(service, record);
                    }
                    // Device Information Service (0x180A) -> Firmware, Hardware, Manufacturer
                    else if (service.Uuid == GattServiceUuids.DeviceInformation)
                    {
                        await ReadDeviceInformationAsync(service, record.Hardware);
                    }
                    // ========================================================
                    // SONDĂ ACTIVĂ WHISPERPAIR: Serviciul Google Fast Pair (0xFE2C)
                    // ========================================================
                    else if (uuidStr.Contains("fe2c", StringComparison.OrdinalIgnoreCase))
                    {
                        await ProbeFastPairUnauthenticatedReadAsync(service, record);
                    }
                }
            }
        }
    }

    private static async Task ReadGenericAccessNameAsync(GattDeviceService gapService, BluetoothDeviceRecord record)
    {
        var charsResult = await gapService.GetCharacteristicsForUuidAsync(
            GattCharacteristicUuids.GapDeviceName,
            BluetoothCacheMode.Uncached);

        if (charsResult.Status != GattCommunicationStatus.Success || charsResult.Characteristics.Count == 0)
            return;

        string? gattName = await ReadStringCharacteristicAsync(charsResult.Characteristics[0]);
        if (string.IsNullOrWhiteSpace(gattName))
            return;

        Console.WriteLine($"  -> Nume GATT (0x2A00): {gattName}");
        if (string.IsNullOrWhiteSpace(record.Name) ||
            string.Equals(record.Name, "(fara nume)", StringComparison.OrdinalIgnoreCase))
        {
            record.Name = gattName;
        }
    }

    private static async Task ReadDeviceInformationAsync(GattDeviceService disService, PassiveHardwareInfo hardware)
    {
        var charsResult = await disService.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
        if (charsResult.Status != GattCommunicationStatus.Success)
            return;

        foreach (var characteristic in charsResult.Characteristics)
        {
            string? value = await ReadStringCharacteristicAsync(characteristic);
            if (string.IsNullOrWhiteSpace(value))
                continue;

            if (characteristic.Uuid == GattCharacteristicUuids.FirmwareRevisionString)
                hardware.FirmwareRevision = value;
            else if (characteristic.Uuid == GattCharacteristicUuids.HardwareRevisionString)
                hardware.HardwareRevision = value;
            else if (characteristic.Uuid == GattCharacteristicUuids.ManufacturerNameString)
                hardware.GattManufacturerName = value;
        }
    }

    /// <summary>
    /// SONDĂ ACTIVĂ PENTRU WHISPERPAIR (CVE-2025-36911)
    /// Testează dacă serviciul Google Fast Pair (0xFE2C) poate fi citit fără pairing/bonding.
    /// </summary>
    private static async Task ProbeFastPairUnauthenticatedReadAsync(GattDeviceService fastPairService, BluetoothDeviceRecord record)
    {
        Console.WriteLine("  -> [!] Serviciu Google Fast Pair (0xFE2C) detectat. Se testează accesul neautentificat...");

        var charsResult = await fastPairService.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
        if (charsResult.Status != GattCommunicationStatus.Success)
        {
            Console.WriteLine($"  -> Nu s-au putut enumera caracteristicile: {charsResult.Status}");
            record.Security.AuditNotes.Add($"Fast Pair: enumerare caracteristici eșuată ({charsResult.Status})");
            return;
        }

        bool unauthenticatedReadSuccess = false;
        string? successfulCharUuid = null;

        foreach (var ch in charsResult.Characteristics)
        {
            if (ch.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Read))
            {
                try
                {
                    var readResult = await ch.ReadValueAsync(BluetoothCacheMode.Uncached);
                    if (readResult.Status == GattCommunicationStatus.Success)
                    {
                        unauthenticatedReadSuccess = true;
                        successfulCharUuid = ch.Uuid.ToString();
                        Console.WriteLine($"  -> [!] SUCCES: Citire neautentificată pe caracteristica {ch.Uuid}");
                        break;
                    }
                    else
                    {
                        Console.WriteLine($"  -> Citire eșuată pe {ch.Uuid}: {readResult.Status}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  -> Excepție la citirea {ch.Uuid}: {ex.Message}");
                }
            }
        }

        if (unauthenticatedReadSuccess && !record.Security.IsPaired)
        {
            record.Security.AuditNotes.Add(
                $"CRITIC: Serviciu Fast Pair accesibil fără pairing pe caracteristica {successfulCharUuid}. " +
                $"Dispozitivul este un candidat puternic pentru WhisperPair (CVE-2025-36911).");
        }
        else if (unauthenticatedReadSuccess && record.Security.IsPaired)
        {
            record.Security.AuditNotes.Add(
                $"INFO: Serviciu Fast Pair accesibil, dar dispozitivul este deja împerecheat (protejat prin bonding).");
        }
        else
        {
            record.Security.AuditNotes.Add(
                "INFO: Serviciu Fast Pair prezent, dar toate caracteristicile necesită autentificare.");
        }
    }

    private static async Task<string?> ReadStringCharacteristicAsync(GattCharacteristic characteristic)
    {
        if (!characteristic.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Read))
            return null;

        var readResult = await characteristic.ReadValueAsync(BluetoothCacheMode.Uncached);
        if (readResult.Status != GattCommunicationStatus.Success || readResult.Value == null)
            return null;

        byte[] data = readResult.Value.ToArray();
        return Encoding.UTF8.GetString(data).TrimEnd('\0').Trim();
    }
}
```

---

## FIȘIERUL 5: `Analysis/ReconEngine.cs` (SNIPPET DE INSERAT ÎN `MatchRule`)

În metoda `MatchRule`, imediat **după** blocul `if (sig.ServiceUuidPrefixes.Count > 0) { ... }`, adaugă:

```csharp
// ============================================================
// VERIFICARE SPECIFICĂ PENTRU MODEL ID FAST PAIR (Semnal Puternic)
// Acesta este un semnal mult mai specific decât simplul UUID 0xFE2C
// ============================================================
var fastPairModelId = allUuids.FirstOrDefault(u =>
    u.StartsWith("FastPair_ModelID:", StringComparison.OrdinalIgnoreCase));
if (fastPairModelId != null &&
    (string.Equals(rule.Id, "WHISPERPAIR-GFPS", StringComparison.OrdinalIgnoreCase) ||
     sig.ServiceUuidPrefixes.Any(p => p.StartsWith("FastPair_ModelID:", StringComparison.OrdinalIgnoreCase))))
{
    matched.Add($"Google Fast Pair Model ID detectat: {fastPairModelId}");
    strongSignal = true; // Crește încrederea din Candidat în Probabil
}
```

---

## FIȘIERUL 6: `Analysis/vulnerabilities.json` (COMPLET ACTUALIZAT)

```json
[
  {
    "id": "WHISPERPAIR-GFPS",
    "cve": "CVE-2025-36911",
    "name": "WhisperPair (Google Fast Pair Pairing-State Bypass)",
    "category": "Authentication Bypass / Hijack",
    "defaultConfidence": "Candidat",
    "elevatedConfidence": "Probabil",
    "signals": {
      "serviceUuidPrefixes": [ "0000fe2c", "df21fe2c", "FastPair_ModelID:" ],
      "companyIds": [ 224 ],
      "vendorKeywords": [ "Google", "Sony", "JBL", "Jabra", "Marshall", "Soundcore", "OnePlus", "Redmi", "Nothing", "Logitech", "Philips" ],
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Sondă activă GATT: Tentativă de citire a caracteristicilor din serviciul 0xFE2C fără ca dispozitivul să fie în mod de pairing. Succesul indică lipsa validării stării.",
    "remediation": "Actualizare firmware la versiunea care validează starea discoverable/pairing mode înainte de a permite interacțiunea cu serviciile Fast Pair."
  },
  {
    "id": "AIROHA-RACE-2025",
    "cve": "CVE-2025-20700 / CVE-2025-20701 / CVE-2025-20702",
    "name": "Airoha RACE Protocol Unauthenticated Access",
    "category": "Information Disclosure / RCE",
    "defaultConfidence": "Candidat",
    "elevatedConfidence": "Probabil",
    "signals": {
      "serviceUuidPrefixes": [ "5052494d-2dab-0341-6972-6f6861424c45" ],
      "companyIds": [ 148 ],
      "vendorKeywords": [ "Airoha" ],
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Interogare serviciu proprietar Airoha RACE (5052494D-...) si verificare comenzi FOTA/RAM read fara autentificare.",
    "remediation": "Actualizare SDK/firmware Airoha pentru dezactivarea sau autentificarea interfetei RACE peste BLE/RFCOMM."
  },
  {
    "id": "YAMAHA-SRB30A-UNAUTH",
    "cve": "CVE-2026-37100",
    "name": "Yamaha SR-B30A BLE Unauthenticated Control",
    "category": "Improper Authentication",
    "defaultConfidence": "Candidat",
    "elevatedConfidence": "Probabil",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 597 ],
      "vendorKeywords": [ "Yamaha" ],
      "namePatterns": [ "SR-B30A", "SR-B" ],
      "vulnerableFirmwareRegex": "^2\\.40$"
    },
    "evidenceRequiredForActive": "Conectare BLE fara bonding (GattAccess=Success) si verificare acces la serviciile proprietare Sound Bar Remote.",
    "remediation": "Actualizare firmware soundbar peste versiunea 2.40 si activarea autentificarii pe link-ul BLE."
  },
  {
    "id": "REALTEK-RTL8762-DOS",
    "cve": "CVE-2025-44526",
    "name": "Realtek RTL8762EKF-EVB BLE SDK LL_Length_Req DoS",
    "category": "Denial of Service",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 93 ],
      "vendorKeywords": [ "Realtek" ],
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Identificare exacta a chipului RTL8762 si trimitere pachet LL_LENGTH_REQ malformat pe Link Layer (necesita dongle HCI/nRF52840).",
    "remediation": "Actualizare Realtek BLE SDK la versiunea cu validare a lungimii PDU la negocierea Data Length Extension."
  },
  {
    "id": "CYPRESS-PSOC4-BLE",
    "cve": "CVE-2025-44557",
    "name": "Cypress PSoC4 BLE Stack 3.66 Vulnerability",
    "category": "Protocol / Pairing Flaw",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 305 ],
      "vendorKeywords": [ "Cypress", "Infineon" ],
      "namePatterns": [ "PSoC4", "PSoC" ]
    },
    "evidenceRequiredForActive": "Confirmare stiva BLE 3.66 si test activ de pairing SMP.",
    "remediation": "Upgrade la o versiune patch-uita a componentei Cypress/Infineon PSoC4 BLE."
  },
  {
    "id": "NORDIC-NRF-ACCESS-SE",
    "cve": "CVE-2025-9709 / CVE-2025-67841",
    "name": "Nordic nRF52810 Access Control / nRF54H20 IronSide SE",
    "category": "Access Control / Algorithmic Complexity",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 89 ],
      "vendorKeywords": [ "Nordic" ],
      "namePatterns": [ "nRF52", "nRF54", "Zephyr" ]
    },
    "evidenceRequiredForActive": "Verificare versiune Zephyr/nRF Connect SDK prin caracteristici GATT sau interogare activa pe servicii expuse.",
    "remediation": "Actualizare nRF Connect SDK / Zephyr RTOS la ultimele patch-uri de securitate Nordic."
  },
  {
    "id": "PERFEKTBLUE-BLUESDK-IVI",
    "cve": "CVE-2024-45434 / CVE-2024-45431 / CVE-2024-45432 / CVE-2024-45433",
    "name": "PerfektBlue (OpenSynergy BlueSDK Automotive IVI)",
    "category": "RCE / Classic Stack",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [ "0000111e", "0000110b", "0000112f" ],
      "companyIds": [],
      "vendorKeywords": [ "Harman", "Continental", "Aptiv", "Bosch", "Visteon", "Panasonic Automotive", "Alpine" ],
      "namePatterns": [ "IVI", "MBUX", "Sync", "Uconnect", "Car", "Auto", "Infotainment", "MyCar", "VW", "Audi", "BMW", "Skoda", "Renault" ]
    },
    "evidenceRequiredForActive": "Classic Inquiry + SDP dump (verificare profiluri HFP/AVRCP/PBAP si comportament L2CAP/RFCOMM).",
    "remediation": "Aplicare patch OEM pentru stiva OpenSynergy BlueSDK din unitatea infotainment."
  },
  {
    "id": "SWEYNTOOTH-LEGACY-BLE",
    "cve": "CVE-2019-16336 / SweynTooth",
    "name": "SweynTooth BLE Link Layer & SMP Crashes / Bypass",
    "category": "DoS / Security Bypass",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 13, 37, 48, 205, 210, 305, 529 ],
      "vendorKeywords": [ "Texas Instruments", "NXP", "Dialog", "Microchip", "STMicroelectronics", "Telink", "Cypress" ],
      "maxLmpVersion": 9,
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Test activ LL/SMP malformat cu nRF52840 dongle (SweynTooth test suite) pe dispozitive BLE 4.0 - 5.0.",
    "remediation": "Actualizare firmware BLE controller la revizia post-SweynTooth a producatorului SoC."
  },
  {
    "id": "WEAK-PAIRING-OR-OPEN-GATT",
    "cve": "CWE-287 / CWE-306",
    "name": "Unauthenticated GATT Exposure or Weak Pairing Protection",
    "category": "Configuration / Posture",
    "defaultConfidence": "Probabil",
    "elevatedConfidence": "Probabil",
    "signals": {
      "checkOpenGattWithoutPairing": true,
      "checkWeakProtectionLevel": true
    },
    "evidenceRequiredForActive": "Enumerare caracteristici GATT cu proprietati Read/Write fara criptare sau downgrade Just Works.",
    "remediation": "Impunere LE Secure Connections (MITM protection) si autentificare la nivel de caracteristica GATT."
  }
]
```

---

## FIȘIERUL 7: `Program.cs` (SNIPPET PENTRU SECȚIUNEA `--active-scan`)

Înlocuiește secțiunea `if (opts.ActiveScan) { ... }` cu:

```csharp
// 4. Scanare activa GATT (--active-scan)
if (opts.ActiveScan)
{
    Console.WriteLine("\n[ACTIVE] Pornire sondare GATT...");
    Console.WriteLine("[INFO] ================================================");
    Console.WriteLine("[INFO] PENTRU REZULTATE CORECTE, ASIGURĂ-TE CĂ:");
    Console.WriteLine("[INFO]   1. Ținta BLE NU este conectată la laptop");
    Console.WriteLine("[INFO]   2. Ținta BLE NU este conectată la alt dispozitiv (telefon)");
    Console.WriteLine("[INFO]   3. Ținta este în mod discoverable/pairing (dacă e necesar)");
    Console.WriteLine("[INFO]   4. Ținta este în raza de acoperire (RSSI > -70 dBm ideal)");
    Console.WriteLine("[INFO] ================================================\n");

    var activeCandidates = filteredDevices
        .Where(d => d.Advertisement?.Connectable == true)
        .ToList();

    if (activeCandidates.Count == 0)
    {
        Console.WriteLine("[ACTIVE] Nicio tinta conectabila gasita pentru sondare GATT.");
    }
    else
    {
        foreach (var device in activeCandidates)
        {
            Console.WriteLine($"\n[ACTIVE] Sondare {device.MacAddress} ({device.Name})...");
            Console.WriteLine($"  Transport: {device.Security?.ConnectionType ?? "N/A"}");
            Console.WriteLine($"  RSSI: {device.Advertisement?.LastRssi ?? 0} dBm | AddressKind: {device.Advertisement?.AddressKind}");

            await ActiveGattProber.ProbeAsync(device, timeoutSeconds: 15, maxRetries: 3);
            device.LastScanMode = "Active";
        }

        await historyStore.SaveAsync();
        Console.WriteLine("\n[ACTIVE] Sondare GATT finalizata. Istoricul devices_db.json a fost actualizat.");
    }
}
```