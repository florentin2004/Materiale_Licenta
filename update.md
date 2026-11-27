# Status proiect — BluetoothAuditor (27.11.2026)

> Document de status, nu specificație de cod. Specificațiile aplicate anterior se regăsesc în git: `git show 68a7e99:update.md`.

## Pe scurt

| Componentă | Stadiu | Comentariu |
|---|---|---|
| Build / CLI | **Funcțional** | `dotnet build` OK pe `net10.0-windows10.0.19041.0`; `--help`, `--scan=N`, `--no-scan`, `--connect[=filtru]`, `--active-scan`, `--debug` merg. |
| Detecție pasivă BLE | **Finalizată (funcțional)** | WinRT, OUI + Bluetooth SIG, filtrare RPA/NRPA, istoric `devices_db.json`, transport tipizat. |
| BR/EDR pasiv | **Limitat de platformă** | WinRT nu oferă Inquiry; se văd doar dispozitivele deja asociate, etichetate `[BR/EDR]`. |
| Triaj pasiv (`ReconEngine`) | **Funcțional, cu o limitare** | 9 reguli, `--connect`, `recon_targets.json`; rulează înainte de sondarea activă. |
| Sondare activă GATT | **Prototip validat, nu complet finalizat** | Conectare, enumerare, `0x180A`, test neautentificat pe `0xFE2C`; retry doar la conectare. |
| Opțiuni rezervate | **Parsate, fără efect** | `--fast`, `--no-prompt`, `--timeout`, `--enum-timeout` — de decis (vezi mai jos). |

## Ce funcționează bine

* **Scanarea pasivă** e stabilă: sesiuni de 8 s / 20 s, 30–65 advertising-uri văzute, 3–12 adrese stabile persistate, restul ignorate ca rotative (`Random-Resolvable`/`Random-NonResolvable`). Nu se persistă RPA/NRPA.
* **Lookup-urile** încarcă 4071 companii Bluetooth SIG și 40765 prefixe OUI; numele și vendorii apar în raport.
* **Transportul** e corect: `[BR/EDR]` în lista `[CONECTAT]`, `BLE (advertising pasiv)` pentru fiecare țintă; înregistrările vechi fără `Transport` sunt migrate la `BleAdvertising` la încărcare, deci nu apare `Necunoscut`.
* **Dedup-ul Dual-Mode** funcționează: același dispozitiv fizic nu e duplicat între adresa Classic și cea BLE.
* **Triajul** produce candidați coercenți: `WEAK-PAIRING-OR-OPEN-GATT` (pe `GattAccess = Success`), `WHISPERPAIR-GFPS`, `Cypress PSoC4`, `SweynTooth` (doar `NeevaluabilFaraTestActiv`, fără test activ LL/SMP).
* **Confirmarea activă WhisperPair** s-a repetat pe mai multe adrese Random-Static (`DD15…`, `DAAD…`, `C402…`, toate cu sufixul `2CE2AD64`): serviciul `0000fe2c-…` prezent și citire neautentificată reușită pe `fe2c1233-8366-4814-8eb0-01de32100bea`, inclusiv în runul cu `--no-scan`.
* **`--no-scan`** funcționează corect (88 ms, 0 observate, istoric din `devices_db.json`), iar `--connect=<filtru>` selectează o singură țintă din istoric.
* **Retry-ul de conectare** afișează clar tipul adresei, timeoutul și încercarea curentă; toate conectările din teste au reușit la încercarea 1.

## Ce rămâne de făcut (în ordinea priorății)

1. **Extragerea `FastPair_ModelID` nu e robustă.** S-au văzut `0x004000`, `0x0E4000`, `0x804000`, `0x054000`, `0x1D4000`, `0x024000`, inclusiv pe o adresă RPA a unui Sony WH-1000XM5 care nici nu e persistată. Trebuie verificat offsetul celor 3 octeți din `0x16`, multiplele secțiuni `0x16` și validarea UUID-ului. Până atunci valoarea nu trebuie folosită ca semnal de încredere.
2. **Validarea argumentelor.** Argumentele necunoscute sunt ignorate silent (`no-scan` fără `--` a pornit o scanare de 8 s). `--scan` simplu e și el ignorat, dar „pare” să meargă din cauza defaultului. De afișat eroare + help și de ieșit.
3. **Ordinea triajului.** `ReconEngine` rulează înainte de `--active-scan`, deci `recon_targets.json` nu vede `GattAccess`/`AuditNotes` proaspete. De adăugat un al doilea triaj după sondare.
4. **Retry incomplet.** `Conectare reușită` → `Unreachable` apare când eșuează `GetGattServicesAsync` (ex. `Hue Play` la `-91 dBm`); retry-ul acoperă doar `FromBluetoothAddressAsync`.
5. **Încredere WhisperPair.** Rămâne `Candidat` deși are Model ID, pentru că `ElevatedConfidence` cere `strongSignal && weakSignal`; comentariul din `ReconEngine` promite `Probabil`. De aliniat codul sau textul.
6. **Nume cu prefix `LE-`.** `CleanDeviceName` curăță doar lista `[CONECTAT]`; `LE-Philips TAT3509` rămâne în istoric și în raport.
7. **Opțiuni rezervate** — de decis ce fac (mai jos).
8. **Merge final în `cercetare`**, la sfârșitul licenței, cu `git merge --allow-unrelated-histories implementare` (istoriile sunt orfane).

## Ce sunt opțiunile rezervate

Toate sunt **parsate** în `ScanOptions.Parse`, dar valorile nu sunt citite nicăieri în `Program.cs` / `ActiveGattProber.cs`. Deci nu au niciun efect acum — nu greșesc, dar nu fac nimic.

| Opțiune | Ce setează în cod | Intenție presupusă | Stare |
|---|---|---|---|
| `--fast` | `o.Fast = true` | Scanare scurtă / fără așteptări între probe | **Neutilizată.** Aplicația nu are mod rapid. |
| `--no-prompt` | `o.NoPrompt = true` | Suprimă întrebări interactive | **Neutilizată.** Aplicația nu pune întrebări deloc. |
| `--timeout=<sec>` | `o.DeviceTimeout` (implicit 8 s) | Timeout per dispozitiv la conectare | **Neutilizată.** `Program.cs` apelează `ProbeAsync(..., timeoutSeconds: 15, maxRetries: 3)` hardcoded. |
| `--enum-timeout=<sec>` | `o.EnumTimeout` (implicit 15 s) | Timeout la enumerarea serviciilor GATT | **Neutilizată.** Valoarea nu ajunge în prober. |

Propunere: **leagă `--timeout` și `--enum-timeout`** de `ActiveGattProber` (înlocuiește constanta `15` din `Program.cs`), iar **`--fast` / `--no-prompt` scoate-le din help** cât timp nu au comportament. Altfel utilizatorul crede că le-a folosit, dar nu se întâmplă nimic.

## Dovada din ultimele teste

* `dotnet run -- --scan=20` → `20141 ms`, 51 observate / 12 persistate / 39 ignorate.
* `--scan --connect --active-scan` → 6 dispozitive, 3 candidați, `C4022CE2AD64` confirmat activ.
* `--no-scan --connect=C4022CE2AD64 --active-scan` → 96 în istoric, 1 candidat, citire `0xFE2C` reușită.
* `Hue Play` (`-91 dBm`): enumerare completă într-un run, `Unreachable` în altul.
* Nicio eroare de build și niciun conflict după merge-ul în `implementare`.

## Repo

* `implementare` = `68a7e99`, împins pe `origin/implementare`; `test_cod` a fost merge-uit fast-forward și șters local.
* `cercetare` = `86ceb2d`, neatinsă.
* Artefactele `bin/`, `obj/`, `devices_db.json` și `recon_targets.json` rămân ignorate de git.
