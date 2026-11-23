using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace BluetoothAuditor;

public class PassiveLookupStore
{
    private readonly Dictionary<string, string> _ouiByPrefix = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, string> _sigCompanies = new();

    public void LoadOuiDatabase(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[LOOKUP] Fisierul OUI lipsa: {filePath}");
            return;
        }

        // Bucla secventiala: la duplicate castiga prima aparitie (deterministic).
        foreach (var line in File.ReadLines(filePath))
        {
            var item = ParseOuiLine(line);
            if (item.HasValue)
                _ouiByPrefix.TryAdd(item.Value.Oui, item.Value.Vendor);
        }

        Console.WriteLine($"[LOOKUP] OUI incarcat: {_ouiByPrefix.Count} prefixe.");
    }

    public void LoadBluetoothSigCompanies(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"[LOOKUP] Fisierul SIG lipsa: {filePath}");
            return;
        }

        int? pendingId = null;
        foreach (var rawLine in File.ReadLines(filePath))
        {
            string line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                continue;

            if (line.StartsWith("- value:") || line.StartsWith("value:"))
            {
                int colon = line.IndexOf(':');
                if (colon >= 0 && TryParseId(line[(colon + 1)..].Trim(), out int id))
                    pendingId = id;
                continue;
            }

            if (line.StartsWith("name:") && pendingId.HasValue)
            {
                string name = line[5..].Trim().Trim('\'', '"');
                _sigCompanies.TryAdd(pendingId.Value, name);
                pendingId = null;
            }
        }

        Console.WriteLine($"[LOOKUP] Bluetooth SIG incarcat: {_sigCompanies.Count} companii.");
    }

    public string ResolveMacVendor(ulong bluetoothAddress, bool isRandomAddress, IEnumerable<string>? companyNames = null)
    {
        if (isRandomAddress)
        {
            string baseText = "N/A (adresa random - OUI nu se aplica)";
            var companies = companyNames?.Where(c => !string.IsNullOrWhiteSpace(c)).ToList();
            return companies is { Count: > 0 }
                ? $"{baseText} | SIG: {string.Join(", ", companies)}"
                : baseText;
        }

        string oui = bluetoothAddress.ToString("X12")[..6];
        return _ouiByPrefix.TryGetValue(oui, out string? vendor) ? vendor : "Producator Necunoscut";
    }

    public string ResolveCompanyName(int companyId)
    {
        return _sigCompanies.TryGetValue(companyId, out string? name)
            ? name
            : $"Company ID {companyId} (0x{companyId:X4})";
    }

    /// <summary>
    /// Format Wireshark manuf: "OUI&lt;tab&gt;NumeScurt&lt;tab&gt;NumeLung". Pastram numele lung daca exista.
    /// </summary>
    private static (string Oui, string Vendor)? ParseOuiLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
            return null;

        string prefix;
        string vendor;

        var parts = line.Split('\t', 3, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
        {
            prefix = parts[0];
            vendor = parts.Length >= 3 ? parts[2] : parts[1];
        }
        else
        {
            int sep = line.IndexOf(' ');
            if (sep <= 0) return null;
            prefix = line[..sep];
            vendor = line[(sep + 1)..].Trim();
        }

        int slash = prefix.IndexOf('/');
        if (slash >= 0) prefix = prefix[..slash];

        string oui = prefix.Replace(":", "").Replace("-", "").Trim().ToUpperInvariant();
        if (oui.Length != 6 || string.IsNullOrWhiteSpace(vendor)) return null;

        return (oui, vendor);
    }

    private static bool TryParseId(string raw, out int id)
    {
        if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(raw[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out id);

        return int.TryParse(raw, out id);
    }
}
