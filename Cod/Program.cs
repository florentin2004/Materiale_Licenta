using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Enumeration;

public class BluetoothDeviceRecord
{
    public string MacAddress { get; set; }
    public string Name { get; set; }
    public string Vendor { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastConnected { get; set; }
    public int ConnectionCount { get; set; }
}

public class BluetoothOuiAnalyzer
{
    private static Dictionary<string, string> _ouiDatabase = new Dictionary<string, string>();
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

            string[] parts;
            if (line.Contains('\t'))
                parts = line.Split(new[] { '\t' }, 2);
            else
                parts = line.Split(new[] { ' ' }, 2);

            if (parts.Length < 2) continue;

            string ouiKey = parts[0].Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
            string vendor = parts[1].Trim();

            if (ouiKey.Length == 6 && !_ouiDatabase.ContainsKey(ouiKey))
            {
                _ouiDatabase[ouiKey] = vendor;
            }
        }
        Console.WriteLine($"Baza de date OUI incarcata: {_ouiDatabase.Count} intrari.");
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

    public static void UpsertDevice(string mac, string name, string vendor)
    {
        if (_deviceHistory.TryGetValue(mac, out var existingRecord))
        {
            existingRecord.Name = name;
            existingRecord.Vendor = vendor;
            existingRecord.LastConnected = DateTime.Now;
            existingRecord.ConnectionCount++;
            Console.WriteLine($"[ACTUALIZAT] {name} ({mac}) - Conectari totale: {existingRecord.ConnectionCount}");
        }
        else
        {
            var newRecord = new BluetoothDeviceRecord
            {
                MacAddress = mac,
                Name = name,
                Vendor = vendor,
                FirstSeen = DateTime.Now,
                LastConnected = DateTime.Now,
                ConnectionCount = 1
            };
            _deviceHistory[mac] = newRecord;
            Console.WriteLine($"[NOU] {name} ({mac}) a fost adaugat in baza de date.");
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

    public static async Task RunAnalysis()
    {
        string dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "master_oui.txt");
        LoadOuiDatabase(dbPath);
        LoadDeviceHistory();

        try
        {
            BluetoothAdapter adapter = await BluetoothAdapter.GetDefaultAsync();
            if (adapter != null)
            {
                var radio = await adapter.GetRadioAsync();
                Console.WriteLine($"Stare Radio: {radio.State}");
            }

            var selector = BluetoothDevice.GetDeviceSelectorFromConnectionStatus(BluetoothConnectionStatus.Connected);
            var devices = await DeviceInformation.FindAllAsync(selector);

            if (devices.Count == 0)
            {
                Console.WriteLine("Nu exista niciun dispozitiv Bluetooth conectat in acest moment.");
                return;
            }

            foreach (var item in devices)
            {
                var bluetoothDevice = await BluetoothDevice.FromIdAsync(item.Id);
                if (bluetoothDevice == null) continue;

                string mac = bluetoothDevice.BluetoothAddress.ToString("X12");
                string vendor = GetVendorFromMac(bluetoothDevice.BluetoothAddress);

                Console.WriteLine($"Nume: {item.Name}");
                Console.WriteLine($"Adresa MAC: {mac}");
                Console.WriteLine($"Producator (OUI): {vendor}");
                Console.WriteLine($"Stare Conexiune: {bluetoothDevice.ConnectionStatus}");

                UpsertDevice(mac, item.Name, vendor);
                Console.WriteLine("---");
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