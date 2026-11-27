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
