# Fluxul aplicației (BluetoothAuditor)

## 1. Etapele de execuție (Pipeline)

1. **Verificare dispozitive conectate la gazdă (`ConnectedDeviceChecker`)**
   - Interoghează Windows (`DeviceInformation`) după dispozitivele Bluetooth Classic și BLE aflate în starea `BluetoothConnectionStatus.Connected` și le afișează în consolă înainte de scanare.
   - *Exemplu observat (hardware personal de test):* `[Classic] Philips TAT3509` cu adresa publică `18:9C:2C:E2:AD:64`.

2. **Încărcare baze de date & istoric (în paralel)**
   - `master_oui.txt` — baza IEEE/Wireshark (~40.765 / ~59.320 prefixe) pentru identificarea producătorului din adresele MAC publice.
   - `company_identifiers.yaml` — registrul oficial Bluetooth SIG (4.071 companii) pentru decodarea *Company ID*-urilor din pachetele BLE.
   - `vulnerabilities.json` — catalogul extern de reguli (9 reguli, incluzând `WHISPERPAIR-GFPS` / `CVE-2025-36911` cu suport pentru `FastPair_ModelID:` și keyword-ul `Philips`) folosit de motorul de triaj pasiv `ReconEngine`.
   - `devices_db.json` — istoricul persistent al dispozitivelor observate anterior.

3. **Detecție pasivă & filtrare (`BleAdvertisementScanner` / `PassiveDetectionService`)**
   - Ascultă pachetele BLE Advertising folosind `BluetoothLEAdvertisementWatcher` (fără a iniția conexiuni către dispozitivele țintă).
   - Clasifică adresa MAC (`ClassifyAddress`): păstrează doar adresele stabile (`Public` și `Random-Static`) și ignoră adresele rotative efemere (`RPA` / `NRPA`) care își schimbă valoarea periodic, prevenind poluarea bazei de date.
   - Extrage MAC, nume, RSSI, `CompanyIds`, `ServiceUuids` și, pentru pachetele *Service Data — 16-bit UUID* (`DataType == 0x16`) cu UUID `0xFE2C` (Google Fast Pair) de cel puțin 5 octeți, extrage **Model ID-ul pe 3 octeți (little-endian)** sub forma `FastPair_ModelID:0xXXXXXX`. Actualizează `devices_db.json`.

4. **Triaj pasiv (`ReconEngine`) & export candidați (`recon_targets.json`)**
   - Evaluează dispozitivele selectate (toate din sesiune/istoric sau cele filtrate prin `--connect=<filtru>` / `--target=...`) față de regulile din `vulnerabilities.json`.
   - Recunoaște semnalul specific `FastPair_ModelID:` ca semnal puternic (`strongSignal = true`), crescând nivelul de încredere (`NeevaluabilFaraTestActiv`, `Candidat`, `Probabil`) și prioritatea de investigare (`TriagePriority`), afișează raportul în consolă și salvează candidații în `recon_targets.json`.

5. **Scanare activă / Sondare GATT (`--active-scan`) — integrată**
   - Modulul `ActiveGattProber.ProbeAsync` deschide conexiuni BLE (`BluetoothLEDevice`), enumeră serviciile GATT, citește *Device Information Service (`0x180A`)* și *Generic Access (`0x1800`)* și, la detectarea serviciului **Google Fast Pair (`0xFE2C`)**, testează **citirea neautentificată** (`ReadValueAsync`) pe caracteristicile cu proprietatea `Read` fără a forța pairing/bonding sau scrieri distructive.
   - Dacă citirea neautentificată reușește pe un dispozitiv neîmperecheat (`!record.Security.IsPaired`), adaugă o notă `CRITIC` în `record.Security.AuditNotes` (indicator de configurare slabă / posibilă susceptibilitate la **WhisperPair / CVE-2025-36911**); altfel adaugă o notă `INFO`.
   - Atenție: această etapă **nu mai este pasivă** — deschide conexiune BLE către țintă.

---

## 2. Arhitectura aplicației — Ce face fiecare clasă

### Orchestrare și nivel de intrare
* **`Program`** (`Program.cs`): Punctul de intrare al aplicației (`Main`). Parsează argumentele din linia de comandă (`--scan`, `--scan=N`, `--no-scan`, `--active-scan`, `--connect=<filtru>`, `--target=`), încarcă în paralel fișierele de referință și coordonează ordinea etapelor: verificare dispozitive conectate $\rightarrow$ scanare pasivă $\rightarrow$ filtrare $\rightarrow$ triaj `ReconEngine` $\rightarrow$ sondare activă opțională (`ActiveGattProber`, prin `--active-scan`) $\rightarrow$ salvare rezultate.
* **`ConnectedDeviceChecker`**: Verifică ce dispozitive Bluetooth (Classic și BLE) sunt deja conectate la laptop în momentul pornirii aplicației, interogând API-ul Windows `DeviceInformation` și eliminând duplicatele.

### Achiziție de date și persistență
* **`PassiveDetectionService`**: Motorul de scanare pasivă BLE. Pornește `BluetoothLEAdvertisementWatcher` pe durata configurată, interceptează pachetele *Advertising* și *Scan Response*, parsează secțiunile `0x16` (inclusiv `FastPair_ModelID:0xXXXXXX` pentru `0xFE2C`), filtrează adresele rotative temporare și actualizează înregistrările stabile în baza de date.
* **`DeviceHistoryStore`**: Gestionează citirea și scrierea fișierului `devices_db.json`. Încarcă istoricul la pornire (`LoadAsync`), aplică observațiile pasive (`ApplyPassiveObservations`), salvează modificările în format JSON (`SaveAsync`) și generează notele pasive (`BuildPassiveNotes`).

### Utilitare de identificare și rezolvare
* **`PassiveDetectionService.ClassifyAddress`**: Normalizează adresele MAC (12 caractere hexazecimale fără separatori) și determină tipul adresei BLE analizând biții primului octet:
  - `Public` — adresă fixă alocată de producător;
  - `Random-Static` — adresă random fixă pe durata ciclului de alimentare (primii 2 biți sunt `11`, ex. `0xD1`);
  - `Random-Resolvable(RPA)` / `Random-NonResolvable` — adrese temporare rotative, ignorate la salvare dacă nu există deja în istoric.
* **`PassiveLookupStore`**: Încarcă `master_oui.txt` și identifică producătorul hardware după prefixul OUI al adresei MAC; dacă adresa este de tip `Random-*`, returnează explicit `"N/A (adresa random - OUI nu se aplica)"` pentru a evita identificări false. De asemenea, încarcă `company_identifiers.yaml` și traduce *Company ID*-urile din pachetele BLE în numele oficial al companiei (ex. `0x00E0` $\rightarrow$ `Google`, `0x01DD` $\rightarrow$ `Koninklijke Philips N.V.`).

### Analiză de securitate (Triaj pasiv & Sondare activă)
* **`ReconEngine`**: Motorul de analiză pasivă. Încarcă regulile din `vulnerabilities.json`, verifică dacă un dispozitiv expune semnale asociate unor CVE-uri cunoscute (UUID-uri de servicii, `FastPair_ModelID:`, Company ID-uri, tipare de nume sau versiuni) și generează lista de ținte candidate în `recon_targets.json`.
  - **`VulnerabilityRule` / `RuleSignals`**: Modelele care descriu o regulă din `vulnerabilities.json` și condițiile ei de potrivire.
  - **`BluetoothTarget` / `VulnerabilityHypothesis`**: Modelele rezultatului de triaj pentru un dispozitiv și ipoteza de vulnerabilitate (ex. `CVE-2025-36911` / WhisperPair), incluzând încrederea și pașii activi necesari pentru confirmare.
* **`ActiveGattProber`**: Modulul de sondare activă GATT (pentru `--active-scan`), responsabil de conectarea la țintele BLE conectabile, enumerarea serviciilor GATT, extragerea metadatelor hardware/firmware din *Device Information Service (`0x180A`)* și testarea citirii neautentificate pe caracteristicile `Read` din serviciul Google Fast Pair (`0xFE2C`).

### Modele de date (`BluetoothDeviceRecord` și sub-componentele sale)
* **`BluetoothDeviceRecord`**: Entitatea centrală salvată în `devices_db.json`, care agregă identitatea de bază (`MacAddress`, `Name`, `Vendor`), metadatele de timp (`FirstSeen`, `LastConnected`, `ConnectionCount`, `LastScanMode`) și sub-obiectele de mai jos:
* **`PassiveChipsetInfo`**: Date despre controller-ul Bluetooth / Link Manager Protocol (`LmpManufacturerId`, `LmpManufacturerName`, `LmpVersion`, `LmpSubversion`) și identificatorii PnP / Device ID (`DeviceIdSource`, `DeviceIdVendorId`, `DeviceIdVendorName`, `DeviceIdProductId`).
* **`PassiveHardwareInfo`**: Identificatori hardware Windows (`HardwareIds`) și informații citite activ prin GATT DIS (`GattManufacturerName`, `HardwareRevision`, `FirmwareRevision`).
* **`PassiveSecurityInfo`**: Postura de securitate și conectivitate (`ConnectionType`, `IsPaired`, `ProtectionLevel`, `GattAccess`, `ExposedServices`, `AuditNotes`).
* **`PassiveAdvertisementSnapshot`**: Ultimul instantaneu recepționat în pachetele BLE Advertising (`LastAdvertised`, `LastRssi`, `AddressKind`, `Connectable`, `Companies`, `CompanyIds`, `ServiceUuids`).

---

## 3. Exemplu concret de date observate & Flux de testare (Philips TAT3509 — hardware personal)

Testarea se realizează pe căștile personale **Philips TAT3509**, unde același dispozitiv fizic folosește două adrese diferite în funcție de transport:
* **Bluetooth Classic (conectat la laptop):** `18:9C:2C:E2:AD:64` (adresă `Public`, prefix OUI `18:9C:2C`).
* **Bluetooth Low Energy (advertising pasiv):** `D1:D3:2C:E2:AD:64` (adresă `Random-Static`, unde primii 2 octeți sunt înlocuiți cu `D1:D3`, iar ultimii 4 octeți `2C:E2:AD:64` rămân identici cu cei ai adresei Classic).

### Pași de rulare și verificare
1. **Compilare:** Șterge folderele `bin` și `obj` din `alpha01` și rulează `dotnet build`.
2. **Scanare pasivă cu extragere Model ID:**
   ```bash
   dotnet run -- --scan=10 --debug
   ```
   Verifică în `ServiceUuids` prezența `0000fe2c-0000-1000-8000-00805f9b34fb` și `FastPair_ModelID:0xXXXXXX`.
3. **Triaj și sondă activă GATT pe ținta BLE:**
   ```bash
   dotnet run -- --no-scan --connect="D1D32CE2AD64" --active-scan
   ```
   Verifică în consolă testul de citire neautentificată pe `0xFE2C`, actualizarea `AuditNotes` (`CRITIC` / `INFO`) în `devices_db.json` și nivelul de încredere în `recon_targets.json`.

---

## COD

"\alpha01\ActiveDetection\ActiveGattProber.cs"
```csharp
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
```

"\alpha01\Analysis\ReconEngine.cs"
```csharp
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

        // Verificare specifica pentru Model ID Fast Pair extras din advertising
        var modelIdUuid = allUuids.FirstOrDefault(u => u.StartsWith("FastPair_ModelID:", StringComparison.OrdinalIgnoreCase));
        if (modelIdUuid != null &&
            (string.Equals(rule.Id, "WHISPERPAIR-GFPS", StringComparison.OrdinalIgnoreCase) ||
             sig.ServiceUuidPrefixes.Any(p => p.StartsWith("FastPair_ModelID:", StringComparison.OrdinalIgnoreCase))))
        {
            matched.Add($"Google Fast Pair Model ID detectat: {modelIdUuid}");
            strongSignal = true;
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
```

"\alpha01\Analysis\vulnerabilities.json"
```json
[
  {
    "id": "WHISPERPAIR-GFPS",
    "cve": "CVE-2025-36911",
    "name": "WhisperPair (Google Fast Pair Pairing-State Bypass)",
    "category": "Authentication Bypass / Hijack",
    "defaultConfidence": "Candidat",
    "elevatedConfidence": "Probabil",
    "signals": {
      "serviceUuidPrefixes": [ "0000fe2c", "df21fe2c", "FastPair_ModelID:" ],
      "companyIds": [ 224 ],
      "vendorKeywords": [ "Google", "Sony", "JBL", "Jabra", "Marshall", "Soundcore", "OnePlus", "Redmi", "Nothing", "Logitech", "Philips" ],
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Sondă activă GATT: Tentativă de citire a caracteristicilor din serviciul 0xFE2C fără ca dispozitivul să fie în mod de pairing. Succesul indică lipsa validării stării.",
    "remediation": "Actualizare firmware la versiunea care validează starea discoverable/pairing mode înainte de a permite interacțiunea cu serviciile Fast Pair."
  },
  {
    "id": "AIROHA-RACE-2025",
    "cve": "CVE-2025-20700 / CVE-2025-20701 / CVE-2025-20702",
    "name": "Airoha RACE Protocol Unauthenticated Access",
    "category": "Information Disclosure / RCE",
    "defaultConfidence": "Candidat",
    "elevatedConfidence": "Probabil",
    "signals": {
      "serviceUuidPrefixes": [ "5052494d-2dab-0341-6972-6f6861424c45" ],
      "companyIds": [ 148 ],
      "vendorKeywords": [ "Airoha" ],
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Interogare serviciu proprietar Airoha RACE (5052494D-...) si verificare comenzi FOTA/RAM read fara autentificare.",
    "remediation": "Actualizare SDK/firmware Airoha pentru dezactivarea sau autentificarea interfetei RACE peste BLE/RFCOMM."
  },
  {
    "id": "YAMAHA-SRB30A-UNAUTH",
    "cve": "CVE-2026-37100",
    "name": "Yamaha SR-B30A BLE Unauthenticated Control",
    "category": "Improper Authentication",
    "defaultConfidence": "Candidat",
    "elevatedConfidence": "Probabil",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 597 ],
      "vendorKeywords": [ "Yamaha" ],
      "namePatterns": [ "SR-B30A", "SR-B" ],
      "vulnerableFirmwareRegex": "^2\\.40$"
    },
    "evidenceRequiredForActive": "Conectare BLE fara bonding (GattAccess=Success) si verificare acces la serviciile proprietare Sound Bar Remote.",
    "remediation": "Actualizare firmware soundbar peste versiunea 2.40 si activarea autentificarii pe link-ul BLE."
  },
  {
    "id": "REALTEK-RTL8762-DOS",
    "cve": "CVE-2025-44526",
    "name": "Realtek RTL8762EKF-EVB BLE SDK LL_Length_Req DoS",
    "category": "Denial of Service",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 93 ],
      "vendorKeywords": [ "Realtek" ],
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Identificare exacta a chipului RTL8762 si trimitere pachet LL_LENGTH_REQ malformat pe Link Layer (necesita dongle HCI/nRF52840).",
    "remediation": "Actualizare Realtek BLE SDK la versiunea cu validare a lungimii PDU la negocierea Data Length Extension."
  },
  {
    "id": "CYPRESS-PSOC4-BLE",
    "cve": "CVE-2025-44557",
    "name": "Cypress PSoC4 BLE Stack 3.66 Vulnerability",
    "category": "Protocol / Pairing Flaw",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 305 ],
      "vendorKeywords": [ "Cypress", "Infineon" ],
      "namePatterns": [ "PSoC4", "PSoC" ]
    },
    "evidenceRequiredForActive": "Confirmare stiva BLE 3.66 si test activ de pairing SMP.",
    "remediation": "Upgrade la o versiune patch-uita a componentei Cypress/Infineon PSoC4 BLE."
  },
  {
    "id": "NORDIC-NRF-ACCESS-SE",
    "cve": "CVE-2025-9709 / CVE-2025-67841",
    "name": "Nordic nRF52810 Access Control / nRF54H20 IronSide SE",
    "category": "Access Control / Algorithmic Complexity",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 89 ],
      "vendorKeywords": [ "Nordic" ],
      "namePatterns": [ "nRF52", "nRF54", "Zephyr" ]
    },
    "evidenceRequiredForActive": "Verificare versiune Zephyr/nRF Connect SDK prin caracteristici GATT sau interogare activa pe servicii expuse.",
    "remediation": "Actualizare nRF Connect SDK / Zephyr RTOS la ultimele patch-uri de securitate Nordic."
  },
  {
    "id": "PERFEKTBLUE-BLUESDK-IVI",
    "cve": "CVE-2024-45434 / CVE-2024-45431 / CVE-2024-45432 / CVE-2024-45433",
    "name": "PerfektBlue (OpenSynergy BlueSDK Automotive IVI)",
    "category": "RCE / Classic Stack",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [ "0000111e", "0000110b", "0000112f" ],
      "companyIds": [],
      "vendorKeywords": [ "Harman", "Continental", "Aptiv", "Bosch", "Visteon", "Panasonic Automotive", "Alpine" ],
      "namePatterns": [ "IVI", "MBUX", "Sync", "Uconnect", "Car", "Auto", "Infotainment", "MyCar", "VW", "Audi", "BMW", "Skoda", "Renault" ]
    },
    "evidenceRequiredForActive": "Classic Inquiry + SDP dump (verificare profiluri HFP/AVRCP/PBAP si comportament L2CAP/RFCOMM).",
    "remediation": "Aplicare patch OEM pentru stiva OpenSynergy BlueSDK din unitatea infotainment."
  },
  {
    "id": "SWEYNTOOTH-LEGACY-BLE",
    "cve": "CVE-2019-16336 / SweynTooth",
    "name": "SweynTooth BLE Link Layer & SMP Crashes / Bypass",
    "category": "DoS / Security Bypass",
    "defaultConfidence": "NeevaluabilFaraTestActiv",
    "elevatedConfidence": "Candidat",
    "signals": {
      "serviceUuidPrefixes": [],
      "companyIds": [ 13, 37, 48, 205, 210, 305, 529 ],
      "vendorKeywords": [ "Texas Instruments", "NXP", "Dialog", "Microchip", "STMicroelectronics", "Telink", "Cypress" ],
      "maxLmpVersion": 9,
      "namePatterns": []
    },
    "evidenceRequiredForActive": "Test activ LL/SMP malformat cu nRF52840 dongle (SweynTooth test suite) pe dispozitive BLE 4.0 - 5.0.",
    "remediation": "Actualizare firmware BLE controller la revizia post-SweynTooth a producatorului SoC."
  },
  {
    "id": "WEAK-PAIRING-OR-OPEN-GATT",
    "cve": "CWE-287 / CWE-306",
    "name": "Unauthenticated GATT Exposure or Weak Pairing Protection",
    "category": "Configuration / Posture",
    "defaultConfidence": "Probabil",
    "elevatedConfidence": "Probabil",
    "signals": {
      "checkOpenGattWithoutPairing": true,
      "checkWeakProtectionLevel": true
    },
    "evidenceRequiredForActive": "Enumerare caracteristici GATT cu proprietati Read/Write fara criptare sau downgrade Just Works.",
    "remediation": "Impunere LE Secure Connections (MITM protection) si autentificare la nivel de caracteristica GATT."
  }
]
```

"\alpha01\Data\DeviceHistoryStore.cs"
```csharp
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
            (record.Advertisement?.ServiceUuids?.Any(u => u.StartsWith("0000fe2c", StringComparison.OrdinalIgnoreCase) ||
                                                         u.StartsWith("FastPair_ModelID:", StringComparison.OrdinalIgnoreCase)) ?? false) ||
            (record.Security?.ExposedServices?.Any(u => u.StartsWith("0000fe2c", StringComparison.OrdinalIgnoreCase) ||
                                                       u.StartsWith("df21fe2c", StringComparison.OrdinalIgnoreCase)) ?? false);
        if (fastPair)
            notes.Add("Serviciu Google Fast Pair (0xFE2C) observat pasiv - candidat pentru verificare WhisperPair.");

        return notes;
    }
}
```

"\alpha01\Data\PassiveLookupStore.cs"
```csharp
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
```

"\alpha01\Models\BluetoothDeviceRecord.cs"
```csharp
using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BluetoothAuditor;

public class AdvertisementObservation
{
    public ulong Address { get; set; }
    public string MacAddress => Address.ToString("X12");
    public string? LocalName { get; set; }
    public short Rssi { get; set; }
    public DateTime LastSeen { get; set; }
    public int PacketCount { get; set; }
    public bool IsConnectable { get; set; }
    public string AddressKind { get; set; } = "Unspecified";
    public bool IsStableAddress { get; set; }
    public HashSet<int> CompanyIds { get; } = new();
    public HashSet<string> ServiceUuids { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public class PassiveAdvertisementSnapshot
{
    public DateTime LastAdvertised { get; set; }
    public int? LastRssi { get; set; }
    public string? AddressKind { get; set; }
    public bool Connectable { get; set; }

    /// <summary>Nume rezolvate din Bluetooth SIG (pentru afisare / cuvinte cheie).</summary>
    public List<string> Companies { get; set; } = new();

    /// <summary>ID-uri brute de companie (pentru potrivirea exacta in reguli).</summary>
    public List<int> CompanyIds { get; set; } = new();

    public List<string> ServiceUuids { get; set; } = new();
}

public class PassiveChipsetInfo
{
    public int? LmpManufacturerId { get; set; }
    public string LmpManufacturerName { get; set; } = "Necunoscut";
    public string LmpVersion { get; set; } = "Necunoscuta";
    public string? LmpSubversion { get; set; }
    public int? DeviceIdSource { get; set; }
    public int? DeviceIdVendorId { get; set; }
    public string? DeviceIdVendorName { get; set; }
    public int? DeviceIdProductId { get; set; }
}

public class PassiveHardwareInfo
{
    public List<string> HardwareIds { get; set; } = new();
    public string? FirmwareRevision { get; set; }
    public string? HardwareRevision { get; set; }
    public string? GattManufacturerName { get; set; }
}

public class PassiveSecurityInfo
{
    public string ConnectionType { get; set; } = "BLE (doar advertising)";
    public bool IsPaired { get; set; }
    public string? ProtectionLevel { get; set; }
    public string? GattAccess { get; set; }
    public List<string> ExposedServices { get; set; } = new();
    public List<string> AuditNotes { get; set; } = new();
}

public class BluetoothDeviceRecord
{
    public string MacAddress { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public PassiveChipsetInfo Chipset { get; set; } = new();
    public PassiveHardwareInfo Hardware { get; set; } = new();
    public PassiveSecurityInfo Security { get; set; } = new();
    public PassiveAdvertisementSnapshot? Advertisement { get; set; }
    public string LastScanMode { get; set; } = "Passive";
    public DateTime FirstSeen { get; set; }
    public DateTime LastConnected { get; set; }
    public int ConnectionCount { get; set; }

    [JsonIgnore]
    public int? LastRssi => Advertisement?.LastRssi;

    [JsonIgnore]
    public bool? IsConnectable => Advertisement?.Connectable;
}
```

"\alpha01\Models\ConnectedDeviceChecker.cs"
```csharp
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
```

"\alpha01\Models\ScanOptions.cs"
```csharp
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
```

"\alpha01\PassiveDetection\PassiveDetectionService.cs"
```csharp
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

        // Cu scanare: doar dispozitivele vazute in aceasta sesiune.
        // Cu --no-scan: tot istoricul salvat (triaj offline).
        // ToUniversalTime() acopera si inregistrarile vechi salvate cu DateTime.Now (Kind=Local).
        bool sessionOnly = options.ScanSeconds > 0;

        return _historyStore.AllRecords
            .Where(r => r.Advertisement != null &&
                        (!sessionOnly || r.Advertisement.LastAdvertised.ToUniversalTime() >= sessionStart))
            .OrderByDescending(r => r.LastRssi ?? short.MinValue)
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
            // Verificarea in sine a esuat; lasam watcher-ul sa incerce.
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

                foreach (var section in args.Advertisement.DataSections)
                {
                    if (section.DataType != 0x16 || section.Data.Length < 2) continue;

                    byte[] raw = section.Data.ToArray();
                    int uuid16 = raw[0] | (raw[1] << 8);

                    // Adaugam UUID-ul standardizat
                    entry.ServiceUuids.Add($"0000{uuid16:x4}-0000-1000-8000-00805f9b34fb");

                    // Extragem Model ID-ul Google Fast Pair (daca este prezent)
                    if (uuid16 == 0xFE2C && raw.Length >= 5)
                    {
                        // Model ID-ul este stocat pe 3 octeti, little-endian
                        int modelId = raw[2] | (raw[3] << 8) | (raw[4] << 16);
                        entry.ServiceUuids.Add($"FastPair_ModelID:0x{modelId:X6}");
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
```

"\alpha01\Program.cs"
```csharp
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace BluetoothAuditor;

public class Program
{
    public static async Task Main(string[] args)
    {
        var opts = ScanOptions.Parse(args);
        if (opts.ShowHelp)
        {
            ScanOptions.PrintHelp();
            return;
        }

        string baseDir = opts.BaseDirectory;

        // 1. Verificare dispozitive conectate la laptop -> doar in consola, fara salvare in JSON
        await ConnectedDeviceChecker.CheckAndPrintConnectedAsync();

        // 2. Scanare pasiva (--scan=...); serviciul salveaza istoricul
        var lookupStore = new PassiveLookupStore();
        var historyStore = new DeviceHistoryStore(
            Path.Combine(baseDir, "devices_db.json"),
            lookupStore);

        var passiveDetection = new PassiveDetectionService(lookupStore, historyStore);
        var detectedDevices = await passiveDetection.ExecuteAsync(opts);

        // Filtrare optionala pe o tinta anume (--target=... sau --connect=... / --connection=...)
        var filteredDevices = detectedDevices
            .Where(d => opts.MatchesFilter(d.MacAddress, d.Name))
            .ToList();

        string scope = opts.ScanSeconds > 0 ? "in sesiune" : "din istoric (--no-scan)";
        Console.WriteLine($"[REZULTAT] Dispozitive {scope}: {detectedDevices.Count} (afisate/analizate: {filteredDevices.Count})");

        // 3. Triaj pasiv (ReconEngine) cand se cere --connect sau --target
        if (opts.Connect)
        {
            var reconEngine = ReconEngine.LoadFromFile(Path.Combine(baseDir, "vulnerabilities.json"));
            var targets = reconEngine.BuildTargets(filteredDevices);
            ReconEngine.PrintTriageSummary(targets);

            string targetsPath = Path.Combine(baseDir, "recon_targets.json");
            var candidates = targets.Where(t => t.Hypotheses.Count > 0).ToList();
            string targetsJson = JsonSerializer.Serialize(candidates, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(targetsPath, targetsJson);
            Console.WriteLine($"[RECON] Candidati salvati in: {targetsPath}");
        }

        // 4. Scanare activa GATT (--active-scan)
        if (opts.ActiveScan)
        {
            Console.WriteLine("\n[ACTIVE] Pornire sondare GATT...");

            var activeCandidates = filteredDevices
                .Where(d => d.Advertisement?.Connectable == true)
                .ToList();

            if (activeCandidates.Count == 0)
            {
                Console.WriteLine("[ACTIVE] Nicio tinta conectabila gasita pentru sondare GATT.");
            }
            else
            {
                foreach (var device in activeCandidates)
                {
                    Console.WriteLine($"[ACTIVE] Sondare {device.MacAddress} ({device.Name})...");
                    await ActiveGattProber.ProbeAsync(device);
                    device.LastScanMode = "Active";
                }

                await historyStore.SaveAsync();
                Console.WriteLine("[ACTIVE] Sondare GATT finalizata. Istoricul devices_db.json a fost actualizat.");
            }
        }
    }
}
```

## Testare aplicatie (OUTPUT)

```text
D:\GoCrazy\Licenta\Lectura\alpha01>dotnet build
Restore complete (0.6s)
  alpha0.1 net10.0-windows10.0.19041.0 succeeded (3.0s) → bin\Debug\net10.0-windows10.0.19041.0\alpha0.1.dll

Build succeeded in 3.9s

D:\GoCrazy\Licenta\Lectura\alpha01>dotnet run -- --help
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

D:\GoCrazy\Licenta\Lectura\alpha01>dotnet run -- --scan --debug
[CONECTAT] Da, exista 1 dispozitiv(e) conectat(e) la laptop:
  - [Classic] Philips TAT3509 (Bluetooth#Bluetooth38:d5:7a:be:fc:58-18:9c:2c:e2:ad:64)
[LOOKUP] Bluetooth SIG incarcat: 4071 companii.
[LOOKUP] OUI incarcat: 40765 prefixe.
[DB] Istoric incarcat: 22 dispozitive.
[PASIV] (fara nume) (E38A2CE2AD64) | -45 dBm | Random-Static
[PASIV] LE-Philips TAT3509 (189C2C39063D) | -56 dBm | Public
[PASIV-SKIP] (fara nume) (3B8490FB68FC) | -60 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (0DCEF9A2E9B5) | -62 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (13B6A90098E5) | -62 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (38355D4D330C) | -63 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (7FC7B8057C4A) | -64 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (6A21FDFC6F1D) | -64 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (7AA2FF38BC95) | -64 dBm | Random-Resolvable(RPA)
[PASIV] (fara nume) (D7041166F80E) | -65 dBm | Random-Static
[PASIV-SKIP] (fara nume) (2B0E5D377F78) | -65 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (38526FEF8B3C) | -68 dBm | Random-NonResolvable
[PASIV] (fara nume) (DD8CFD5D63F5) | -68 dBm | Random-Static
[PASIV-SKIP] (fara nume) (6736C21968AC) | -69 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (69916F294C20) | -70 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (77BE98A79C7F) | -70 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (6C7EE5F1053E) | -71 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (3AB7F6D1BA6F) | -71 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (2CF2C1AE65DC) | -72 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (700B66CB9F84) | -72 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (38247605B57D) | -73 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (433B257EA471) | -73 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (7C005AE89480) | -73 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (2F1012A54D0E) | -74 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (0F0AFF500A62) | -74 dBm | Random-NonResolvable
[PASIV] (fara nume) (FC98A12D9C59) | -75 dBm | Random-Static
[PASIV-SKIP] (fara nume) (5A17DE4F1F3F) | -75 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (2D9A7C8E0A5F) | -76 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (7F5C2B493039) | -76 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (7CF7B8D3C26F) | -76 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (63547807FE1D) | -77 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (77F846C5BE6D) | -77 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (45A0E5FBD662) | -78 dBm | Random-Resolvable(RPA)
[PASIV] (fara nume) (D509E73A6C5C) | -78 dBm | Random-Static
[PASIV] (fara nume) (EA5678951669) | -78 dBm | Random-Static
[PASIV] (fara nume) (CDA34104E95D) | -79 dBm | Random-Static
[PASIV-SKIP] (fara nume) (49FA7BB5C012) | -81 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (075A3C3DE70C) | -81 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (0FEC4F3D4312) | -82 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (044E1C49860B) | -82 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (0690F505E097) | -83 dBm | Random-NonResolvable
[PASIV-SKIP] Meta Quest 2 (6A83FF7C1111) | -85 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (778DF3F41C03) | -85 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (0FC89D124F75) | -85 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (33AF5907F921) | -86 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (286EF460E9C1) | -86 dBm | Random-NonResolvable
[PASIV] (fara nume) (FFFF202654E0) | -86 dBm | Public
[PASIV-SKIP] (fara nume) (5B620A193295) | -88 dBm | Random-Resolvable(RPA)
[PASIV] (fara nume) (D0D00326C10D) | -89 dBm | Public
[PASIV-SKIP] (fara nume) (4024802F8939) | -89 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (5FD56CC3AE66) | -89 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (100C4764B045) | -90 dBm | Random-NonResolvable
[PASIV] (fara nume) (C039370F72F7) | -91 dBm | Public
[PASIV-SKIP] (fara nume) (70DC4F8EE6C4) | -91 dBm | Random-Resolvable(RPA)
[PASIV] (fara nume) (D0D0032694A3) | -91 dBm | Public
[PASIV-SKIP] (fara nume) (3D322954326D) | -92 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (0A292F34A9DC) | -92 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (50491A137084) | -93 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (0E0DE567E8A3) | -93 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (4773861C65B2) | -93 dBm | Random-Resolvable(RPA)
[PASIV] (fara nume) (0CE4A032E41C) | -93 dBm | Public
[PASIV-SKIP] (fara nume) (6A38A08C8DA7) | -95 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (4C238687C0E7) | -95 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (572000DEEA4D) | -95 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (78351C056EEA) | -96 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (040E10454EA5) | -96 dBm | Random-NonResolvable
[PASIV-SKIP] (fara nume) (41E2D45DCDD3) | -96 dBm | Random-Resolvable(RPA)
[PASIV-SKIP] (fara nume) (0A3FF3B12206) | -96 dBm | Random-NonResolvable
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[PASIV] Finalizat in 8160 ms | observate: 68, persistate: 13, rotative ignorate: 55.
[REZULTAT] Dispozitive in sesiune: 13 (afisate/analizate: 13)

D:\GoCrazy\Licenta\Lectura\alpha01>dotnet run -- --no-scan --connect="189C2C39063D" --active-scan
[CONECTAT] Da, exista 1 dispozitiv(e) conectat(e) la laptop:
  - [Classic] Philips TAT3509 (Bluetooth#Bluetooth38:d5:7a:be:fc:58-18:9c:2c:e2:ad:64)
[LOOKUP] Bluetooth SIG incarcat: 4071 companii.
[LOOKUP] OUI incarcat: 40765 prefixe.
[DB] Istoric incarcat: 33 dispozitive.
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[PASIV] Finalizat in 85 ms | observate: 0, persistate: 0, rotative ignorate: 0.
[REZULTAT] Dispozitive din istoric (--no-scan): 33 (afisate/analizate: 1)
[RECON] Reguli incarcate: 9 din vulnerabilities.json

=================================================================
 REZULTAT TRIAJ PASIV (RECON): 0 candidati din 1 dispozitive
=================================================================
Niciun dispozitiv nu a declansat regulile din vulnerabilities.json.
[RECON] Candidati salvati in: D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\recon_targets.json

[ACTIVE] Pornire sondare GATT...
[ACTIVE] Sondare 189C2C39063D (LE-Philips TAT3509)...
  -> Serviciu GATT: 00001800-0000-1000-8000-00805f9b34fb
  -> Nume GATT (0x2A00): LE-Philips TAT3509
  -> Serviciu GATT: 0000ae00-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 80727376-7380-8372-6965-688072797869
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[ACTIVE] Sondare GATT finalizata. Istoricul devices_db.json a fost actualizat.

D:\GoCrazy\Licenta\Lectura\alpha01>dotnet run -- --no-scan --target="2C39063D" --active-scan
[CONECTAT] Da, exista 1 dispozitiv(e) conectat(e) la laptop:
  - [Classic] Philips TAT3509 (Bluetooth#Bluetooth38:d5:7a:be:fc:58-18:9c:2c:e2:ad:64)
[LOOKUP] Bluetooth SIG incarcat: 4071 companii.
[LOOKUP] OUI incarcat: 40765 prefixe.
[DB] Istoric incarcat: 33 dispozitive.
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[PASIV] Finalizat in 82 ms | observate: 0, persistate: 0, rotative ignorate: 0.
[REZULTAT] Dispozitive din istoric (--no-scan): 33 (afisate/analizate: 1)
[RECON] Reguli incarcate: 9 din vulnerabilities.json

=================================================================
 REZULTAT TRIAJ PASIV (RECON): 1 candidati din 1 dispozitive
=================================================================
[TARGET] LE-Philips TAT3509 (189C2C39063D) | BLE (doar advertising) | RSSI: -56 dBm
   -> [Probabil] Unauthenticated GATT Exposure or Weak Pairing Protection (CWE-287 / CWE-306)
      Semnale: GATT accesibil (Success) fara pairing/bonding
      Pas activ: Enumerare caracteristici GATT cu proprietati Read/Write fara criptare sau downgrade Just Works.
=================================================================
[RECON] Candidati salvati in: D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\recon_targets.json

[ACTIVE] Pornire sondare GATT...
[ACTIVE] Sondare 189C2C39063D (LE-Philips TAT3509)...
  -> Serviciu GATT: 00001800-0000-1000-8000-00805f9b34fb
  -> Nume GATT (0x2A00): LE-Philips TAT3509
  -> Serviciu GATT: 0000ae00-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 80727376-7380-8372-6965-688072797869
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[ACTIVE] Sondare GATT finalizata. Istoricul devices_db.json a fost actualizat.

D:\GoCrazy\Licenta\Lectura\alpha01>dotnet run -- --no-scan --target=2CE2AD64 --active-scan
[CONECTAT] Da, exista 1 dispozitiv(e) conectat(e) la laptop:
  - [Classic] Philips TAT3509 (Bluetooth#Bluetooth38:d5:7a:be:fc:58-18:9c:2c:e2:ad:64)
[LOOKUP] Bluetooth SIG incarcat: 4071 companii.
[LOOKUP] OUI incarcat: 40765 prefixe.
[DB] Istoric incarcat: 33 dispozitive.
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[PASIV] Finalizat in 83 ms | observate: 0, persistate: 0, rotative ignorate: 0.
[REZULTAT] Dispozitive din istoric (--no-scan): 33 (afisate/analizate: 2)
[RECON] Reguli incarcate: 9 din vulnerabilities.json

=================================================================
 REZULTAT TRIAJ PASIV (RECON): 2 candidati din 2 dispozitive
=================================================================
[TARGET] Philips TAT3509(BLE) (CD9D2CE2AD64) | BLE (doar advertising) | RSSI: -54 dBm
   -> [Probabil] Unauthenticated GATT Exposure or Weak Pairing Protection (CWE-287 / CWE-306)
      Semnale: GATT accesibil (Success) fara pairing/bonding
      Pas activ: Enumerare caracteristici GATT cu proprietati Read/Write fara criptare sau downgrade Just Works.
   -> [Candidat] WhisperPair (Google Fast Pair Pairing-State Bypass) (CVE-2025-36911)
      Semnale: Service UUID: 0000fe2c-0000-1000-8000-00805f9b34fb
      Pas activ: Sondă activă GATT: Tentativă de citire a caracteristicilor din serviciul 0xFE2C fără ca dispozitivul să fie în mod de pairing. Succesul indică lipsa validării stării.
[TARGET] (fara nume) (E38A2CE2AD64) | BLE (doar advertising) | RSSI: -45 dBm
   -> [Candidat] WhisperPair (Google Fast Pair Pairing-State Bypass) (CVE-2025-36911)
      Semnale: Service UUID: 0000fe2c-0000-1000-8000-00805f9b34fb; Service UUID: FastPair_ModelID:0x1D4000; Google Fast Pair Model ID detectat: FastPair_ModelID:0x1D4000
      Pas activ: Sondă activă GATT: Tentativă de citire a caracteristicilor din serviciul 0xFE2C fără ca dispozitivul să fie în mod de pairing. Succesul indică lipsa validării stării.
=================================================================
[RECON] Candidati salvati in: D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\recon_targets.json

[ACTIVE] Pornire sondare GATT...
[ACTIVE] Sondare E38A2CE2AD64 ()...
  -> Acces GATT esuat: Unreachable
[ACTIVE] Sondare CD9D2CE2AD64 (Philips TAT3509(BLE))...
  -> Acces GATT esuat: Unreachable
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[ACTIVE] Sondare GATT finalizata. Istoricul devices_db.json a fost actualizat.

D:\GoCrazy\Licenta\Lectura\alpha01>dotnet run -- --scan --active-scan
[CONECTAT] Da, exista 1 dispozitiv(e) conectat(e) la laptop:
  - [Classic] Philips TAT3509 (Bluetooth#Bluetooth38:d5:7a:be:fc:58-18:9c:2c:e2:ad:64)
[LOOKUP] Bluetooth SIG incarcat: 4071 companii.
[LOOKUP] OUI incarcat: 40765 prefixe.
[DB] Istoric incarcat: 33 dispozitive.
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[PASIV] Finalizat in 8127 ms | observate: 56, persistate: 14, rotative ignorate: 42.
[REZULTAT] Dispozitive in sesiune: 14 (afisate/analizate: 14)

[ACTIVE] Pornire sondare GATT...
[ACTIVE] Sondare CF9C2CE2AD64 (LE-Philips TAT3509)...
  -> Serviciu GATT: 00001800-0000-1000-8000-00805f9b34fb
  -> Nume GATT (0x2A00): Philips TAT3509(BLE)
  -> Serviciu GATT: 0000fe2c-0000-1000-8000-00805f9b34fb
  -> [!] Serviciu Google Fast Pair (0xFE2C) detectat. Se testeaza accesul neautentificat...
  -> [!] SUCCES: Citire neautentificata pe caracteristica fe2c1233-8366-4814-8eb0-01de32100bea
[ACTIVE] Sondare 54D9C67C47F7 ()...
  -> Serviciu GATT: 00001800-0000-1000-8000-00805f9b34fb
  -> Nume GATT (0x2A00): HUAWEI FreeBuds SE 2
  -> Serviciu GATT: 00001801-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 00007033-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 01000100-0000-1000-8000-009e78563412
[ACTIVE] Sondare CB975F0B2627 ()...
  -> Acces GATT esuat: Unreachable
[ACTIVE] Sondare D0D00326C10D ([TV] Blue1)...
  -> Acces GATT esuat: Unreachable
[ACTIVE] Sondare C039370F72F7 (GR-AC_10001_09_72f7_SC)...
  -> Acces GATT esuat: Unreachable
[ACTIVE] Sondare 0CE4A032E41C (HUAWEI WATCH GT 2e-41C)...
  -> Serviciu GATT: 00001800-0000-1000-8000-00805f9b34fb
  -> Nume GATT (0x2A00): HUAWEI WATCH GT 2e-41C
  -> Serviciu GATT: 00001801-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 00003802-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 0000180f-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 0000fe86-0000-1000-8000-00805f9b34fb
  -> Serviciu GATT: 00001812-0000-1000-8000-00805f9b34fb
[DB] Salvat in D:\GoCrazy\Licenta\Lectura\alpha01\bin\Debug\net10.0-windows10.0.19041.0\devices_db.json
[ACTIVE] Sondare GATT finalizata. Istoricul devices_db.json a fost actualizat.
```

### Observații din output

- Buildul reușește (`alpha0.1 net10.0-windows10.0.19041.0`), iar helpul reflectă exact opțiunile noi, inclusiv `--target` și testarea serviciului `0xFE2C`.
- Scanarea pasivă cu `--scan --debug`: 68 de advertising-uri văzute, 13 adrese stabile persistate, 55 de adrese rotative (RPA/NRPA) ignorate.
- `--connect="189C2C39063D"` a rulat triajul, dar a raportat **0 candidați**, deoarece `GattAccess` nu era încă populat în acel moment; după sondarea activă, valoarea `Success` a fost salvată în `devices_db.json`.
- `--target="2C39063D"` confirmă fixul: filtrează, pornește `ReconEngine` și găsește candidatul `WEAK-PAIRING-OR-OPEN-GATT`, afișat ca „Unauthenticated GATT Exposure or Weak Pairing Protection (CWE-287 / CWE-306)”.
- `--target=2CE2AD64` găsește două dispozitive cu UUID Fast Pair; pe `E38A2CE2AD64` apare și `FastPair_ModelID:0x1D4000`, deci regula `WHISPERPAIR-GFPS` prinde atât UUID-ul, cât și Model ID-ul.
- În runul final, `dotnet run -- --scan --active-scan` detectează serviciul `0000fe2c-...` pe Philips TAT3509 și **citește cu succes o caracteristică fără pairing** (`fe2c1233-8366-4814-8eb0-01de32100bea`) — confirmare activă pentru WhisperPair.
- Țintele `Unreachable` apar din istoricul `--no-scan` (dispozitive salvate anterior, dar nu mai sunt în rază).

> Posibilă îmbunătățire de analizat: ordinea curentă e `ReconEngine` → sondare activă, deci triajul nu poate folosi `GattAccess` proaspăt în același run. Mutarea sau duplicarea triajului după `--active-scan` ar elimina dependența de datele salvage din rularea anterioară.
