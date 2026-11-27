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
