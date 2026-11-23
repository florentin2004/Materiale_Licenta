using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace BluetoothAuditor;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TriageConfidence
{
    NeevaluabilFaraTestActiv,
    Candidat,
    Probabil
}

public class VulnerabilityHypothesis
{
    public string RuleId { get; set; } = string.Empty;
    public string Cve { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public TriageConfidence Confidence { get; set; }
    public List<string> MatchedSignals { get; set; } = new();
    public string EvidenceRequiredForActive { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
}

public class BluetoothTarget
{
    public string MacAddress { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Transport { get; set; } = string.Empty;
    public string AddressKind { get; set; } = string.Empty;
    public int? Rssi { get; set; }
    public bool IsConnectable { get; set; }
    public bool IsPaired { get; set; }
    public string Vendor { get; set; } = string.Empty;
    public string? ChipsetVendor { get; set; }
    public string? LmpVersion { get; set; }
    public string? FirmwareRevision { get; set; }
    public List<string> ServiceUuids { get; set; } = new();
    public List<VulnerabilityHypothesis> Hypotheses { get; set; } = new();

    public int TriagePriority => Hypotheses.Count == 0
        ? 0
        : Hypotheses.Max(h => h.Confidence switch
        {
            TriageConfidence.Probabil => 3,
            TriageConfidence.Candidat => 2,
            TriageConfidence.NeevaluabilFaraTestActiv => 1,
            _ => 0
        });
}

public class VulnerabilityRule
{
    public string Id { get; set; } = string.Empty;
    public string Cve { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public TriageConfidence DefaultConfidence { get; set; } = TriageConfidence.Candidat;
    public TriageConfidence ElevatedConfidence { get; set; } = TriageConfidence.Probabil;
    public RuleSignals Signals { get; set; } = new();
    public string EvidenceRequiredForActive { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
}

public class RuleSignals
{
    public List<string> ServiceUuidPrefixes { get; set; } = new();
    public List<int> CompanyIds { get; set; } = new();
    public List<string> VendorKeywords { get; set; } = new();
    public List<string> NamePatterns { get; set; } = new();
    public string? VulnerableFirmwareRegex { get; set; }
    public int? MaxLmpVersion { get; set; }
    public bool CheckOpenGattWithoutPairing { get; set; }
    public bool CheckWeakProtectionLevel { get; set; }
}

public class ReconEngine
{
    // Modelele de nume de cel mult atatea caractere se potrivesc doar ca cuvinte intregi
    // ("Car" nu mai prinde "Carlos"); cele mai lungi se potrivesc ca prefix de cuvant ("nRF52" prinde "nRF52840").
    private const int ShortNamePatternLength = 4;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private readonly List<VulnerabilityRule> _rules;
    private readonly HashSet<string> _warnedRegex = new(StringComparer.Ordinal);

    public ReconEngine(List<VulnerabilityRule> rules)
    {
        _rules = rules ?? new List<VulnerabilityRule>();
    }

    public static ReconEngine LoadFromFile(string jsonPath)
    {
        if (!File.Exists(jsonPath))
        {
            Console.WriteLine($"[RECON] Fisierul de reguli {jsonPath} nu exista; triajul ruleaza fara reguli externe.");
            return new ReconEngine(new List<VulnerabilityRule>());
        }

        try
        {
            string json = File.ReadAllText(jsonPath);
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            };
            var rules = JsonSerializer.Deserialize<List<VulnerabilityRule>>(json, options) ?? new List<VulnerabilityRule>();
            Console.WriteLine($"[RECON] Reguli incarcate: {rules.Count} din {Path.GetFileName(jsonPath)}");
            return new ReconEngine(rules);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[RECON] Eroare la parsarea {jsonPath}: {ex.Message}");
            return new ReconEngine(new List<VulnerabilityRule>());
        }
    }

    public List<BluetoothTarget> BuildTargets(IEnumerable<BluetoothDeviceRecord> records)
    {
        var targets = new List<BluetoothTarget>();

        foreach (var rec in records)
        {
            targets.Add(EvaluateRecord(rec));
        }

        return targets
            .OrderByDescending(t => t.TriagePriority)
            .ThenByDescending(t => t.Rssi ?? -999)
            .ToList();
    }

    public BluetoothTarget EvaluateRecord(BluetoothDeviceRecord rec)
    {
        var allUuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (rec.Security?.ExposedServices != null)
            foreach (var u in rec.Security.ExposedServices) allUuids.Add(u);
        if (rec.Advertisement?.ServiceUuids != null)
            foreach (var u in rec.Advertisement.ServiceUuids) allUuids.Add(u);

        var target = new BluetoothTarget
        {
            MacAddress = rec.MacAddress,
            Name = string.IsNullOrWhiteSpace(rec.Name) ? "(fara nume)" : rec.Name,
            Transport = rec.Security?.ConnectionType ?? "Unknown",
            AddressKind = rec.Advertisement?.AddressKind ?? "Paired/Connected",
            Rssi = rec.Advertisement?.LastRssi,
            IsConnectable = rec.Advertisement?.Connectable ?? true,
            IsPaired = rec.Security?.IsPaired ?? false,
            Vendor = rec.Vendor,
            ChipsetVendor = rec.Chipset?.LmpManufacturerName,
            LmpVersion = rec.Chipset?.LmpVersion,
            FirmwareRevision = rec.Hardware?.FirmwareRevision,
            ServiceUuids = allUuids.OrderBy(u => u).ToList()
        };

        foreach (var rule in _rules)
        {
            var hypothesis = MatchRule(rec, allUuids, rule);
            if (hypothesis != null)
                target.Hypotheses.Add(hypothesis);
        }

        return target;
    }

    private VulnerabilityHypothesis? MatchRule(BluetoothDeviceRecord rec, HashSet<string> allUuids, VulnerabilityRule rule)
    {
        var sig = rule.Signals;
        if (sig == null) return null;

        var matched = new List<string>();
        bool strongSignal = false;
        bool weakSignal = false;

        if (sig.ServiceUuidPrefixes.Count > 0)
        {
            foreach (var prefix in sig.ServiceUuidPrefixes)
            {
                var hit = allUuids.FirstOrDefault(u => u.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
                if (hit != null)
                {
                    matched.Add($"Service UUID: {hit}");
                    strongSignal = true;
                }
            }
        }

        if (sig.CompanyIds.Count > 0)
        {
            foreach (int cid in sig.CompanyIds)
            {
                bool inLmp = rec.Chipset?.LmpManufacturerId == cid;
                bool inDevId = rec.Chipset?.DeviceIdSource == 1 && rec.Chipset?.DeviceIdVendorId == cid;

                // ID-uri brute (inregistrari noi) + fallback pe text pentru inregistrari vechi din devices_db.json.
                bool inAdv =
                    (rec.Advertisement?.CompanyIds?.Contains(cid) ?? false) ||
                    (rec.Advertisement?.Companies?.Any(c =>
                        c.Contains($"0x{cid:X4}", StringComparison.OrdinalIgnoreCase) ||
                        c.Contains($"ID {cid} ", StringComparison.OrdinalIgnoreCase)) ?? false);

                if (inLmp || inDevId || inAdv)
                {
                    matched.Add($"Company ID {cid} (0x{cid:X4})");
                    weakSignal = true;
                }
            }
        }

        if (sig.VendorKeywords.Count > 0)
        {
            var vendorSources = new[]
            {
                rec.Vendor,
                rec.Chipset?.LmpManufacturerName,
                rec.Chipset?.DeviceIdVendorName,
                rec.Hardware?.GattManufacturerName,
                rec.Advertisement?.Companies != null ? string.Join(" ", rec.Advertisement.Companies) : null
            };

            foreach (var kw in sig.VendorKeywords)
            {
                if (vendorSources.Any(src => !string.IsNullOrEmpty(src) &&
                                             src.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                {
                    matched.Add($"Vendor/Chipset keyword: {kw}");
                    weakSignal = true;
                }
            }
        }

        if (sig.NamePatterns.Count > 0 && !string.IsNullOrWhiteSpace(rec.Name))
        {
            foreach (var pat in sig.NamePatterns)
            {
                if (NameMatches(rec.Name, pat))
                {
                    matched.Add($"Device Name pattern: '{pat}'");
                    strongSignal = true;
                }
            }
        }

        bool firmwareConfirmed = false;
        string? firmware = rec.Hardware?.FirmwareRevision;
        if (!string.IsNullOrEmpty(sig.VulnerableFirmwareRegex) && !string.IsNullOrEmpty(firmware))
        {
            bool? fwMatch = SafeIsMatch(firmware, sig.VulnerableFirmwareRegex);
            if (fwMatch == true)
            {
                matched.Add($"Firmware vulnerabil confirmat: {firmware}");
                firmwareConfirmed = true;
            }
            else if (fwMatch == false && matched.Count > 0)
            {
                return null;
            }
            // fwMatch == null: regex invalid -> verificarea de firmware este ignorata.
        }

        if (sig.MaxLmpVersion.HasValue && matched.Count > 0)
        {
            int? parsedLmp = ExtractLmpNumber(rec.Chipset?.LmpVersion);
            if (parsedLmp.HasValue && parsedLmp.Value > sig.MaxLmpVersion.Value)
                return null;
            if (parsedLmp.HasValue && rec.Chipset?.LmpVersion != null)
                matched.Add($"LMP compatibil cu regula ({rec.Chipset.LmpVersion})");
        }

        if (sig.CheckOpenGattWithoutPairing &&
            rec.Security != null &&
            !rec.Security.IsPaired &&
            rec.Security.GattAccess == "Success")
        {
            matched.Add("GATT accesibil (Success) fara pairing/bonding");
            strongSignal = true;
        }

        if (sig.CheckWeakProtectionLevel &&
            rec.Security != null &&
            rec.Security.IsPaired &&
            (rec.Security.ProtectionLevel == "None" || rec.Security.ProtectionLevel == "Encryption"))
        {
            matched.Add($"Nivel slab de protectie la asociere: {rec.Security.ProtectionLevel}");
            strongSignal = true;
        }

        if (matched.Count == 0)
            return null;

        TriageConfidence confidence;
        if (firmwareConfirmed || (strongSignal && weakSignal))
            confidence = rule.ElevatedConfidence;
        else if (strongSignal)
            confidence = MaxConfidence(rule.DefaultConfidence, TriageConfidence.Candidat);
        else
            confidence = rule.DefaultConfidence;

        return new VulnerabilityHypothesis
        {
            RuleId = rule.Id,
            Cve = rule.Cve,
            Name = rule.Name,
            Category = rule.Category,
            Confidence = confidence,
            MatchedSignals = matched.Distinct().ToList(),
            EvidenceRequiredForActive = rule.EvidenceRequiredForActive,
            Remediation = rule.Remediation
        };
    }

    private static TriageConfidence MaxConfidence(TriageConfidence a, TriageConfidence b) =>
        (TriageConfidence)Math.Max((int)a, (int)b);

    private static bool NameMatches(string name, string pattern)
    {
        string p = pattern?.Trim() ?? string.Empty;
        if (p.Length == 0) return false;

        string body = Regex.Escape(p);
        string regex = p.Length <= ShortNamePatternLength
            ? $@"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])"
            : $@"(?<![A-Za-z0-9]){body}";

        try
        {
            return Regex.IsMatch(name, regex, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>true/false = rezultat; null = regex invalid sau timeout (avertizat o singura data).</summary>
    private bool? SafeIsMatch(string input, string pattern)
    {
        try
        {
            return Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase, RegexTimeout);
        }
        catch (Exception ex) when (ex is ArgumentException or RegexMatchTimeoutException)
        {
            if (_warnedRegex.Add(pattern))
                Console.WriteLine($"[RECON] Regex de firmware invalid/ignorat '{pattern}': {ex.Message}");
            return null;
        }
    }

    private static int? ExtractLmpNumber(string? lmpText)
    {
        if (string.IsNullOrWhiteSpace(lmpText)) return null;
        return lmpText switch
        {
            var s when s.Contains("4.0") => 6,
            var s when s.Contains("4.1") => 7,
            var s when s.Contains("4.2") => 8,
            var s when s.Contains("5.0") => 9,
            var s when s.Contains("5.1") => 10,
            var s when s.Contains("5.2") => 11,
            var s when s.Contains("5.3") => 12,
            var s when s.Contains("5.4") => 13,
            _ => int.TryParse(lmpText.Replace("LMP", "").Trim(), out int n) ? n : null
        };
    }

    public static void PrintTriageSummary(List<BluetoothTarget> targets)
    {
        var candidates = targets.Where(t => t.Hypotheses.Count > 0).ToList();

        Console.WriteLine();
        Console.WriteLine("=================================================================");
        Console.WriteLine($" REZULTAT TRIAJ PASIV (RECON): {candidates.Count} candidati din {targets.Count} dispozitive");
        Console.WriteLine("=================================================================");

        if (candidates.Count == 0)
        {
            Console.WriteLine("Niciun dispozitiv nu a declansat regulile din vulnerabilities.json.");
            return;
        }

        foreach (var t in candidates)
        {
            Console.WriteLine($"[TARGET] {t.Name} ({t.MacAddress}) | {t.Transport} | RSSI: {t.Rssi?.ToString() ?? "N/A"} dBm");
            foreach (var h in t.Hypotheses.OrderByDescending(x => x.Confidence))
            {
                Console.WriteLine($"   -> [{h.Confidence}] {h.Name} ({h.Cve})");
                Console.WriteLine($"      Semnale: {string.Join("; ", h.MatchedSignals)}");
                Console.WriteLine($"      Pas activ: {h.EvidenceRequiredForActive}");
            }
        }
        Console.WriteLine("=================================================================");
    }
}
