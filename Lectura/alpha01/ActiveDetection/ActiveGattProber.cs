using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;

namespace BluetoothAuditor;

public static class ActiveGattProber
{
    public static async Task ProbeAsync(BluetoothDeviceRecord record)
    {
        record.Security ??= new();
        record.Hardware ??= new();
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

        using var bleDevice = await BluetoothLEDevice.FromBluetoothAddressAsync(btAddress, addressType);
        if (bleDevice == null)
        {
            record.Security.GattAccess = "DeviceNotFound";
            Console.WriteLine("  -> Acces GATT esuat: DeviceNotFound");
            return;
        }

        var servicesResult = await bleDevice.GetGattServicesAsync(BluetoothCacheMode.Uncached);
        record.Security.GattAccess = servicesResult.Status.ToString();

        if (servicesResult.Status != GattCommunicationStatus.Success)
        {
            Console.WriteLine($"  -> Acces GATT esuat: {servicesResult.Status}");
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
                // Google Fast Pair Service (0xFE2C) -> sondă activă neinvazivă (citire neautentificată)
                else if (service.Uuid.ToString().Contains("fe2c", StringComparison.OrdinalIgnoreCase))
                {
                    await ProbeFastPairUnauthenticatedReadAsync(service, record);
                }
            }
        }
    }

    private static async Task ProbeFastPairUnauthenticatedReadAsync(GattDeviceService fastPairService, BluetoothDeviceRecord record)
    {
        Console.WriteLine("  -> [!] Serviciu Google Fast Pair (0xFE2C) detectat. Se testeaza accesul neautentificat...");

        var charsResult = await fastPairService.GetCharacteristicsAsync(BluetoothCacheMode.Uncached);
        if (charsResult.Status != GattCommunicationStatus.Success)
            return;

        bool unauthenticatedReadSuccess = false;

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
                        Console.WriteLine($"  -> [!] SUCCES: Citire neautentificata pe caracteristica {ch.Uuid}");
                        break;
                    }
                }
                catch
                {
                    // Ignoram erorile individuale de citire si continuam cu urmatoarea caracteristica.
                }
            }
        }

        record.Security.AuditNotes ??= new List<string>();
        if (unauthenticatedReadSuccess && !record.Security.IsPaired)
        {
            record.Security.AuditNotes.Add("CRITIC: Serviciu Fast Pair accesibil fara pairing/bonding. Dispozitivul este un candidat puternic pentru WhisperPair.");
        }
        else
        {
            record.Security.AuditNotes.Add("INFO: Serviciu Fast Pair prezent, dar accesul este restrictionat sau dispozitivul este deja imperecheat (protejat).");
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
