using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Enumeration;

namespace BluetoothAuditor;

public record ConnectedDeviceInfo(string Name, string Id, string Transport);

public static class ConnectedDeviceChecker
{
    private static readonly string[] RequestedProps =
    {
        "System.Devices.Aep.IsConnected",
        "System.Devices.Aep.DeviceAddress"
    };

    public static async Task<List<ConnectedDeviceInfo>> CheckAndPrintConnectedAsync()
    {
        var connected = new List<ConnectedDeviceInfo>();

        try
        {
            var classicDevices = await DeviceInformation.FindAllAsync(
                BluetoothDevice.GetDeviceSelector(), RequestedProps);
            foreach (var dev in classicDevices)
            {
                if (IsConnected(dev))
                    connected.Add(new ConnectedDeviceInfo(DisplayName(dev), dev.Id, "Classic"));
            }

            var bleDevices = await DeviceInformation.FindAllAsync(
                BluetoothLEDevice.GetDeviceSelector(), RequestedProps);
            foreach (var dev in bleDevices)
            {
                if (IsConnected(dev))
                    connected.Add(new ConnectedDeviceInfo(DisplayName(dev), dev.Id, "BLE"));
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
                Console.WriteLine($"  - [{item.Transport}] {item.Name} ({item.Id})");
        }

        return connected;
    }

    private static string DisplayName(DeviceInformation dev) =>
        string.IsNullOrWhiteSpace(dev.Name) ? "(fara nume)" : dev.Name;

    private static bool IsConnected(DeviceInformation dev) =>
        dev.Properties.TryGetValue("System.Devices.Aep.IsConnected", out var val) && val is true;
}
