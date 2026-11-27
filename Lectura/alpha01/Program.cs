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