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
