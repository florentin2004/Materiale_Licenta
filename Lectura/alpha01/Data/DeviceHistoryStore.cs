using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace BluetoothAuditor;

public class DeviceHistoryStore
{
    private readonly string _dbFilePath;
    private readonly PassiveLookupStore _lookupStore;
    private Dictionary<string, BluetoothDeviceRecord> _records = NewRecordMap();

    public DeviceHistoryStore(string dbFilePath, PassiveLookupStore lookupStore)
    {
        _dbFilePath = dbFilePath ?? throw new ArgumentNullException(nameof(dbFilePath));
        _lookupStore = lookupStore ?? throw new ArgumentNullException(nameof(lookupStore));
    }

    public IReadOnlyCollection<BluetoothDeviceRecord> AllRecords => _records.Values;

    private static Dictionary<string, BluetoothDeviceRecord> NewRecordMap() =>
        new(StringComparer.OrdinalIgnoreCase);

    public async Task LoadAsync()
    {
        _records = NewRecordMap();

        if (!File.Exists(_dbFilePath))
            return;

        try
        {
            string json = await File.ReadAllTextAsync(_dbFilePath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, BluetoothDeviceRecord>>(json);

            // Deserializarea creeaza un dictionar case-sensitive; reconstruim cu OrdinalIgnoreCase.
            if (loaded != null)
            {
                foreach (var kv in loaded)
                {
                    if (kv.Value != null)
                        _records[kv.Key] = kv.Value;
                }
            }

            Console.WriteLine($"[DB] Istoric incarcat: {_records.Count} dispozitive.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DB] Eroare la citirea {_dbFilePath}: {ex.Message}");
            _records = NewRecordMap();
        }
    }

    public (int Persisted, int Transient) ApplyPassiveObservations(IEnumerable<AdvertisementObservation> observations, bool debug)
    {
        int persisted = 0;
        int transient = 0;

        foreach (var obs in observations.OrderByDescending(o => o.Rssi))
        {
            string mac = obs.MacAddress;
            List<int> companyIds;
            List<string> companies;
            List<string> uuids;
            string? name;
            string addressKind;
            bool isStable;
            bool isConnectable;
            short rssi;
            DateTime lastSeen;

            lock (obs)
            {
                name = obs.LocalName;
                addressKind = obs.AddressKind;
                isStable = obs.IsStableAddress;
                isConnectable = obs.IsConnectable;
                rssi = obs.Rssi;
                lastSeen = obs.LastSeen;
                companyIds = obs.CompanyIds.OrderBy(id => id).ToList();
                companies = companyIds.Select(id => _lookupStore.ResolveCompanyName(id)).ToList();
                uuids = obs.ServiceUuids.OrderBy(u => u).ToList();
            }

            bool exists = _records.TryGetValue(mac, out var record);
            if (!exists && !isStable)
            {
                transient++;
                if (debug)
                {
                    Console.WriteLine($"[PASIV-SKIP] {(string.IsNullOrWhiteSpace(name) ? "(fara nume)" : name)} ({mac}) | {rssi} dBm | {addressKind}");
                }
                continue;
            }

            // Uniune cu snapshot-ul anterior: un dispozitiv care nu trimite scan response
            // in sesiunea curenta nu isi pierde UUID-urile/companiile vazute inainte.
            var previous = exists ? record!.Advertisement : null;
            var snapshot = new PassiveAdvertisementSnapshot
            {
                LastAdvertised = lastSeen,
                LastRssi = rssi,
                AddressKind = addressKind,
                Connectable = isConnectable || (previous?.Connectable ?? false),
                CompanyIds = MergeInts(previous?.CompanyIds, companyIds),
                Companies = MergeStrings(previous?.Companies, companies),
                ServiceUuids = MergeStrings(previous?.ServiceUuids, uuids)
            };

            bool isRandom = addressKind.StartsWith("Random", StringComparison.OrdinalIgnoreCase);
            if (!exists)
            {
                record = new BluetoothDeviceRecord
                {
                    MacAddress = mac,
                    Name = name ?? string.Empty,
                    Vendor = _lookupStore.ResolveMacVendor(obs.Address, isRandom, companies),
                    FirstSeen = DateTime.UtcNow,
                    LastScanMode = "Passive"
                };
                _records[mac] = record;
            }
            else if (string.IsNullOrWhiteSpace(record!.Name) && !string.IsNullOrWhiteSpace(name))
            {
                record.Name = name;
            }

            record!.Advertisement = snapshot;
            record.Security.AuditNotes = BuildPassiveNotes(record);
            persisted++;

            if (debug)
            {
                string display = string.IsNullOrWhiteSpace(record.Name) ? "(fara nume)" : record.Name;
                Console.WriteLine($"[PASIV] {display} ({mac}) | {rssi} dBm | {addressKind}");
            }
        }

        return (persisted, transient);
    }

    public async Task SaveAsync()
    {
        try
        {
            var json = JsonSerializer.Serialize(_records, new JsonSerializerOptions { WriteIndented = true });
            string tempPath = _dbFilePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json);
            File.Move(tempPath, _dbFilePath, overwrite: true);
            Console.WriteLine($"[DB] Salvat in {_dbFilePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DB] Eroare la salvare: {ex.Message}");
        }
    }

    private static List<string> MergeStrings(IEnumerable<string>? previous, IEnumerable<string> current) =>
        (previous ?? Enumerable.Empty<string>())
            .Concat(current)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static List<int> MergeInts(IEnumerable<int>? previous, IEnumerable<int> current) =>
        (previous ?? Enumerable.Empty<int>())
            .Concat(current)
            .Distinct()
            .OrderBy(i => i)
            .ToList();

    private static List<string> BuildPassiveNotes(BluetoothDeviceRecord record)
    {
        var notes = new List<string>();

        bool airoha =
            (record.Chipset?.LmpManufacturerName?.Contains("Airoha", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (record.Advertisement?.CompanyIds?.Contains(148) ?? false) ||
            (record.Advertisement?.Companies?.Any(c => c.Contains("Airoha", StringComparison.OrdinalIgnoreCase)) ?? false);
        if (airoha)
            notes.Add("Chipset Airoha observat pasiv - candidat pentru verificare RACE.");

        bool fastPair =
            (record.Advertisement?.ServiceUuids?.Any(u => u.StartsWith("0000fe2c", StringComparison.OrdinalIgnoreCase)) ?? false) ||
            (record.Security?.ExposedServices?.Any(u => u.StartsWith("0000fe2c", StringComparison.OrdinalIgnoreCase) ||
                                                       u.StartsWith("df21fe2c", StringComparison.OrdinalIgnoreCase)) ?? false);
        if (fastPair)
            notes.Add("Serviciu Google Fast Pair (0xFE2C) observat pasiv - candidat pentru verificare WhisperPair.");

        return notes;
    }
}
