using System;

namespace BluetoothAuditor;

public class ScanOptions
{
    public int ScanSeconds { get; private set; } = 8;
    public bool ActiveScan { get; private set; }
    public bool Connect { get; private set; }
    public string? ConnectFilter { get; private set; }
    public string? TargetFilter { get; private set; }
    public bool NoPrompt { get; private set; }
    public bool Fast { get; private set; }
    public bool Debug { get; private set; }
    public bool ShowHelp { get; private set; }
    public TimeSpan DeviceTimeout { get; private set; } = TimeSpan.FromSeconds(8);
    public TimeSpan EnumTimeout { get; private set; } = TimeSpan.FromSeconds(15);
    public string BaseDirectory { get; } = AppContext.BaseDirectory;

    /// <summary>Filtrul efectiv: --target are prioritate fata de --connect=filtru.</summary>
    public string? EffectiveFilter =>
        !string.IsNullOrWhiteSpace(TargetFilter) ? TargetFilter : ConnectFilter;

    public bool HasFilter => !string.IsNullOrWhiteSpace(EffectiveFilter);

    public static ScanOptions Parse(string[] args)
    {
        var o = new ScanOptions();
        foreach (var raw in args ?? Array.Empty<string>())
        {
            string a = raw.Trim();
            string lower = a.ToLowerInvariant();

            if (lower is "--help" or "-h" or "/?") o.ShowHelp = true;
            else if (lower == "--no-scan") o.ScanSeconds = 0;
            else if (lower.StartsWith("--scan=") && int.TryParse(a.AsSpan(7), out int s))
                o.ScanSeconds = Math.Max(0, s);
            else if (lower == "--active-scan") o.ActiveScan = true;
            else if (lower is "--connect")
            {
                o.Connect = true;
            }
            else if (lower.StartsWith("--connect="))
            {
                o.Connect = true;
                string value = a[(a.IndexOf('=') + 1)..].Trim();
                if (!string.IsNullOrEmpty(value))
                    o.ConnectFilter = value;
            }
            else if (lower.StartsWith("--target="))
            {
                o.TargetFilter = a[9..].Trim();
                // --target filtrează și declanșează triajul (conform mesajului de ajutor).
                o.Connect = true;
            }
            else if (lower == "--no-prompt") o.NoPrompt = true;
            else if (lower == "--fast") o.Fast = true;
            else if (lower == "--debug") o.Debug = true;
            else if (lower.StartsWith("--timeout=") && int.TryParse(a.AsSpan(10), out int t) && t > 0)
                o.DeviceTimeout = TimeSpan.FromSeconds(t);
            else if (lower.StartsWith("--enum-timeout=") && int.TryParse(a.AsSpan(15), out int et) && et > 0)
                o.EnumTimeout = TimeSpan.FromSeconds(et);
        }
        return o;
    }

    /// <summary>True daca nu exista filtru sau daca MAC-ul / numele se potrivesc cu filtrul.</summary>
    public bool MatchesFilter(string? macAddress, string? name)
    {
        string? filter = EffectiveFilter;
        if (string.IsNullOrWhiteSpace(filter))
            return true;

        string normalizedFilter = NormalizeMac(filter);
        string normalizedMac = NormalizeMac(macAddress ?? string.Empty);

        if (normalizedFilter.Length >= 4 &&
            normalizedMac.Length == 12 &&
            normalizedMac.Contains(normalizedFilter, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(name) &&
               name.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    public static string NormalizeMac(string value)
    {
        char[] hex = new char[value.Length];
        int idx = 0;
        foreach (char c in value)
        {
            if (Uri.IsHexDigit(c))
                hex[idx++] = char.ToUpperInvariant(c);
        }
        return idx >= 4 ? new string(hex, 0, idx) : string.Empty;
    }

    public static void PrintHelp()
    {
        Console.WriteLine("""
        Utilizare:
          dotnet run -- [optiuni]

        Optiuni disponibile:
          --help, -h               Afiseaza acest mesaj de ajutor si iese.
          --scan=<secunde>         Durata scanarii pasive BLE (implicit: 8 secunde).
          --no-scan                Sare peste scanarea BLE (analizeaza doar istoricul din devices_db.json).
          --target=<MAC|Nume>      Filtreaza si analizeaza doar o tinta anume (dupa MAC sau nume).
          --connect[=<filtru>]     Ruleaza triajul pasiv (ReconEngine) si salveaza candidații in recon_targets.json.
          --active-scan            Ruleaza sondarea activa GATT (enumera serviciile, citeste 0x180A si testeaza 0xFE2C) pe tintele conectabile.
          --debug                  Afiseaza detalii suplimentare in timpul scanarii si filtrarii.

        Optiuni rezervate (parsate, dar inca nefolosite):
          --fast, --no-prompt, --timeout=<sec>, --enum-timeout=<sec>

        Exemple:
          dotnet run -- --help
          dotnet run -- --scan=10 --debug
          dotnet run -- --no-scan --connect=2CE2AD64
          dotnet run -- --scan=6 --connect=2CE2AD64 --active-scan
          dotnet run -- --no-scan --connect=D1D32CE2AD64 --active-scan
          dotnet run -- --no-scan --target=D1D32CE2AD64 --active-scan
        """);
    }
}
