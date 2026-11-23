# Rezumat complet al folderului `Licenta`

> Document generat pe 23.11.2026 prin citirea integrală a fișierelor din acest folder (text, `.docx`, `.json`, `.html`, cod C#, istoric Git). Este **versiunea mea de înțelegere**, scrisă ca să o poți verifica și corecta. Nu am modificat niciun alt fișier.

---

## 1. Ce este proiectul, pe scurt

Lucrarea de licență se intitulează (în `Obiective_IVAN.docx`): **„Software pentru detecție vulnerabilități în Bluetooth BR/EDR și BLE"**.

Ideea centrală, așa cum reiese din toate documentele: vrei un **framework de tip „nmap pentru Bluetooth"** care să:

1. observe dispozitivele din proximitate (pasiv) și să le facă fingerprinting;
2. coreleze amprentele cu vulnerabilități cunoscute (CVE-uri) stocate într-o bază de cunoștințe;
3. confirme susceptibilitatea prin teste active controlate (non-distructive);
4. execute cel puțin un exploit demonstrativ într-un mediu controlat (Renode / hardware propriu);
5. livreze un patch demonstrativ și să verifice eficiența lui.

Direcția s-a mai schimbat pe parcurs (documentat în `CVE/Identity_Shift.docx`): ai început de la reproducerea CVE-2025-20700 (Airoha RACE), dar nu ai găsit o simulare fiabilă, ai trecut la chipseturi (Nordic) și la simulare în Renode, iar în final **te-ai axat pe partea de detecție**, pentru că majoritatea vulnerabilităților găsite sunt deja patch-uite și/script-urile PoC nu sunt întotdeauna disponibile.

---

## 2. Inventarul complet al folderului

### 2.1 Rădăcina (documente de proiect)

| Fișier | Ce conține |
|---|---|
| `Obiective_IVAN.docx` | Enunțul scurt în 5 module al lucrării (colectare vulnerabilități, detecție pasivă, detecție activă, exploatare, remediere). |
| `obiective_gemini.md` | Versiunea extinsă a obiectivelor, cu cerințe măsurabile **C1.1 – C5.2** (baze de date CVE/CVSS, PoC-uri, clasificare BR/EDR vs BLE vs dual-mode, sniffing OTA, probing KNOB/SMP/WhisperPair, mediu hibrid Renode + BlueZ, patch în `net/bluetooth/smp.c` sau logică de stare, post-patch testing). |
| `Sprint0.md` | Specificația formală: cerințe utilizator **SDD-01…04**, cerințe funcționale **SRS-01…04**, non-funcționale **NFR-01…03**, criterii de acceptare, arhitectura pipeline și setup-ul mediului. Sprint 0 e marcat ca realizat. |
| `arhitectura.txt` | Arborele țintă al aplicației `BluetoothAuditor/` (Program.cs, vulnerabilities.json, `Models/`, `Data/`, `Scanners/`, `Analysis/ReconEngine.cs`, `Reporting/AuditReporter.cs`). Este un plan: implementarea reală din `alpha01` seamănă, dar nu e identică. |

### 2.2 `BLE/` – material de studiu despre protocoale și atacuri (7 fișiere)

- `Bluetooth și Bluetooth Low energy.docx` – notele tale despre SSP / LE Secure Connections, ECDH pe P-256, cei 5 pași ai pairing-ului, reconectarea (paging, autentificare mutuală, derivarea `K_C` prin LMP – locul unde se aplică KNOB), plus rezumat AI și referințe (Stealtooth, KNOB, Invalid Curve, CBSE).
- `Low Entropy Key Negotiation Attacks.pdf` – lucrarea KNOB (Antonioli, Tippenhauer, Rasmussen): entropia cheii scade de la 16 → 1 octet pe BR/EDR și 16 → 7 octeți pe BLE; testat pe 17 cipuri și 15 dispozitive BLE.
- `Neumann-BreakingBluetoothPairing.pdf` – **Fixed Coordinate Invalid Curve Attack** (Biham & Neumann, Technion), atac la ECDH-ul de la pairing.
- `Stealtooth.pdf` – *Breaking Bluetooth Security Abusing Silent Automatic Pairing* (Kobe University): suprascrierea tăcută a Link Key-ului prin auto-pairing; extensia MitM Stealtooth.
- `Classic Bluetooth Security and Exploitation.pdf` – Rivera & Celik (ASIA '24), introducere în securitatea Bluetooth Classic.
- `Exploiting Low Entropy.pdf`, `BLE_phone_calls.pdf` – PDF-uri suplimentare despre entropie și despre apeluri telefonice peste BLE (textul nu a putut fi extras complet cu uneltele disponibile, dar titlurile și contextul sunt clare).

### 2.3 `CVE/` – documentația de vulnerabilități (cu subfoldere)

**Documente Word scrise de tine:**

| Fișier | Conținut |
|---|---|
| `Vulnerabilities.docx` | Catalogul principal: linkuri CVE + fișe tehnice pentru Yamaha SR-B30A, Nordic (x2), Realtek, Cypress, MediaTek, WhisperPair, PerfektBlue, BlueToolkit, Bluesnarfing. |
| `CVE-2025-2070X.docx` | Lanțul Airoha 20700+20701+20702, cuvinte cheie (RACE, privilege escalation, HID), versiuni afectate, ideea de atac în lanț și explicațiile AI despre KNOB/BIAS/BLURtooth/BrakTooth/SweynTooth/BLESA/CVE-2023-45866. |
| `Identity_Shift.docx` | Jurnalul de decizii: de ce ai abandonat reproducerea directă, de ce Nordic/Renode, problema vulnerabilităților doar-DoS, ideea „malware minimalist", observația despre pairing ca graniță de încredere. |
| `Materials.docx` | Comparație **scanare pasivă vs activă** pentru Airoha: detectarea serviciului RACE prin UUID-ul `5052494D-2DAB-0341-6972-6F6861424C45` cu LightBlue (telefon) vs `race-toolkit` (Python/Linux); nivel de confirmare „Probabil vulnerabil" vs „Certificat vulnerabil"; avertismentul că scanarea activă poate deconecta căștile. |
| `Nordic.docx` | Analiza CVE-2025-67841 (IronSide SE, nRF54H20, DoS/complexitate) și CVE-2025-9709 (nRF52810, control defectuos al accesului), planul de simulare în Renode cu Zephyr RTOS. |
| `Bluetooth/BLE/BLE.docx` | Note tehnice BLE: 2.4 GHz, 40 canale (0–36 date, 37–39 descoperire), 2 MHz, Access Address de 4 octeți, CSA, Hop Increment 5–16, pachet `CONNECT_IND`, connection events. |
| `Bluetooth/BR_EDR/BR_EDR.docx` | Note BR/EDR: 79 canale (2402–2480 MHz, 1 MHz), AFH 1600 hop/s, piconet master + 7 slave, SCO vs ACL, A2DP, Legacy Pairing (PIN → E21/E22), SSP (ECDH → DHKey → f2 → Link Key → E0/AES-CCM), funcțiile f1–f6. |

**Alte resurse din `CVE/`:**

- `Airoha_Race_Vulnerabilities.html` – articolul complet ERNW/Insinuator (dec. 2025) despre CVE-2025-20700/20701/20702: structura pachetului RACE (header de 6 octeți: Head `0x05`/`0x15`, Type `0x5A`/`0x5B`, Length, CMD), comenzile `0x1E08` (Get Build Version), `0x0403` (Read Flash), `0x1680`/`0x1681` (Read/Write RAM), `0x0CD5` (Get BD_ADDR), transporturile (USB HID report IDs `0x06`/`0x07`, RFCOMM canal 21 cu UUID-uri vendor, GATT `5052494D-...`), impactul (exfiltrare Link Key → impersonare telefon → HfP `AT+CNUM`, `AT+BVRA`, interceptare apeluri), lista a ~29 de dispozitive confirmate vulnerabile, mitigări și timeline-ul de divulgare.
- `woot25-zubkov.pdf` – *Bluetooth Security Testing with BlueToolkit* (USENIX WOOT '25): 44 de exploit-uri, configurare YAML, 22 de mașini / 14 producători / 891 de teste / 128 de vulnerabilități; atacurile D1–D6 (Method Confusion, NiNo, Invalid Curve, KNOB, LegacyPairing, PBAP Extraction).
- `Armis-Exploiting-BlueBorne-in-Linux-Based-IoT-Devices-WP.pdf` – whitepaper BlueBorne (Armis).
- `NIST.SP.800-121r2-upd1.pdf` – ghidul NIST pentru securitate Bluetooth (update 2022).
- `TR22_ProjectTEMPA.pdf` – raport BSI despre proiectul TEMPA.
- `simulare_nordic.resc` – script Renode: `mach create "nrf52840-vulnerable"`, încarcă `platforms/cpus/nrf52840.repl` și `samples/nrf52840/zephyr-shell_module.elf`, `showAnalyzer uart0`, `logLevel -1 sysbus.radio`.

### 2.4 `Lectura/` – **repository-ul Git** (ce ai pus pe GitHub până acum)

Remote: `https://github.com/florentin2004/Materiale_Licenta.git`; branch curent **`cod_test`**; ultimul commit local `e9c3584 – „versiunea alpha01"`.

Istoricul commits (vechi → nou):
`394aa44` (Bluetoolkit, Stealtooth, Sweyntooth, Whisperpair, CBSE) → `10de68a` (Adaugare ordine de executie, = `main`) → `4d83ee9` (Cod pentru analiza pasiva) → `b61fe53` (Fisiere de input si de output) → `df7145b` (Testare cod pentru Dectectia Pasiva) → `3f414ec`/`7ed8e79` (update readme) → `e9c3584` (versiunea alpha01).

| Subfolder | Conținut |
|---|---|
| `Bluetoolkit/` | `woot25-zubkov.pdf` + `BlueToolkit.txt` – notițele tale: black-box recon, requirements (black-box, high coverage, extensibil, usable), necesitatea adresei țintei, ESP32 vs Nexus 5 vs dongle nRF52, IVI = In-Vehicle Infotainment, JW Central Downgrade, ideea de simulare pe microcontroller Nordic în loc de mașină, sugestia Renode din partea lui Gemini. |
| `CBSE/` | Copie a PDF-ului Classic Bluetooth Security and Exploitation. |
| `Stealtooth/` | PDF + `stealtooth.txt`: securitatea se bazează pe pairing, dar auto-pairing-ul îl ocolește; BIAS și Blacktooth; întrebări despre impersonare, deconectare, injectare audio/backdoor și HID keystroke injection (Rubber Ducky). |
| `Sweyntooth/` | PDF + `sweyntooth.txt` (doar link-ul disclosure: asset-group.github.io/disclosures/sweyntooth/). |
| `Whisperpair/` | PDF (*One Tap to Hijack Them All: A Security Analysis of the Google Fast Pair Protocol*, KU Leuven) + `whisperpair.txt` cu linkurile: whisperpair.eu, `aalex954/whisperpair-poc-tool`, `Bazskillz/WhisperPair-PoC`. |
| `Cod/` | Primele 3 variante **monolitice** ale scannerului C# (`Program.cs`, `paralel.cs`, `program2.cs`) + `vulnerabilities.json`, `devices_db.json`, `readme.md`. |
| `alpha01/` | Varianta **modulară** „BluetoothAuditor" (detaliată în §4). |
| `cuprins.txt`, `obiective.md` | Cuprinsul lecturilor; respectiv product backlog-ul cu 3 pași, 4 sprinturi (0: 2 săpt., 1: recunoaștere 2–3 săpt., 2: motor audit 3 săpt., 3: raportare 2 săpt.), NFR și factori de risc. Se termină cu întrebarea lui Gemini despre mediul de execuție preferat (Linux/VM/simulare). |

### 2.5 `carwhisperer-0.2/` – tool vechi de referință (8 fișiere)

`carwhisperer.c`, `cw_pin.pl` (PIN helper care returnează `0000`/`1234` în funcție de OUI), `cw_scanner`, `hcid.conf`, `Makefile`, `README`, `LICENSE` și 4 fișiere `.raw` (sample-uri audio).

Scopul istoric: conștientizarea riscului kiturilor auto cu PIN standard – scannerul caută dispozitive din clasa Headset/Hands-Free, se conectează pe RFCOMM channel 1, deschide SCO și permite **injectare audio în mașină** și **ascultarea conversațiilor**. Este util ca exemplu de atac BR/EDR clasic, nu face parte din codul aplicației tale.

---

## 3. Cerințele și arhitectura, așa cum le-am înțeles

### 3.1 Cei 5 module ai lucrării (din `Obiective_IVAN.docx`, detaliați în `obiective_gemini.md`)

1. **Colectarea și managementul vulnerabilităților (Knowledge Base + catalog PoC)** – C1.1: entități cu ID CVE, nume atac (KNOB, BIAS, BrakTooth, WhisperPair), scor CVSS, vector, impact (MitM, DoS, RCE, Auth Bypass, Information Leakage) și mapare pe nivel (Controller/LMP, Host/L2CAP/SMP/GATT, Application Profiles/PBAP/HFP/OBEX/GFPS). C1.2: încărcare modulară a PoC-urilor (plugin/YAML per exploit, ca BlueToolkit) cu dependențe hardware (HCI, ESP32, SDR, Ubertooth). C1.3: clasificare BR/EDR vs BLE vs dual-mode și pe versiuni Bluetooth.
2. **Detecție pasivă** – C2.1 sniffing OTA (BLE Advertising, EIR pe BR/EDR), C2.2 fingerprinting (BD_ADDR, OUI, nume, CoD, UUID-uri, service data RACE / Fast Pair Model ID), C2.3 corelare cu baza CVE **fără nicio emisie RF către țintă**.
3. **Detecție activă** – C3.1 enumerare SDP/GATT, capabilități I/O, Just Works / Numeric Comparison / Passkey Entry, SC vs LSC/E0; C3.2 probing controlat (test de entropie 1 octet BR/EDR / 7 octeți BLE = KNOB, scriere pe Key-based Pairing fără pairing mode = WhisperPair, profiluri PBAP/OBEX); C3.3 clasificare *Vulnerabil / Imun / Indeterminat* din evenimente HCI/LMP.
4. **Exploatare** – C4.1 mediu hibrid (Renode/QEMU + bench fizic BlueZ/HCI/Scapy/PyBluez); C4.2 un exploit demonstrativ (KNOB / Just Works Downgrade / Silent Pairing / WhisperPair / PBAP exfiltration); C4.3 monitorizare L2CAP ping, clasificare crash permanent/temporar/sesiune compromisă.
5. **Remediere** – C5.1 patch software (ex. `SMP_MIN_ENC_KEY_SIZE = 16` în `net/bluetooth/smp.c`, sau validarea stării de pairing în firmware) și C5.2 re-rularea testelor după patch.

### 3.2 Cerințele din `Sprint0.md`

- **SDD**: scanare autonomă fără configurare complicată; selecție țintă după MAC; sumar de securitate; export JSON.
- **SRS**: reconnaissance pasiv+activ cu metadate radio (adresă, Manufacturer Data, UUID, versiune, SC/SSP); evaluare pe bază de reguli/knowledge base; evaluare activă de protocol; serializare raport cu stări Pass/Fail/Info.
- **NFR**: modularitate/cuplare slabă (CLI acum, GUI ulterior), rulare asincronă și rezilientă la timeout-uri, execuție non-distructivă.
- **Criterii de acceptare**: găsirea a cel puțin un dispozitiv real, flux complet „adresă → obiect țintă → verificare → raport", JSON valid.
- **Arhitectura**: `Reconnaissance Engine → Vulnerability Assessment Engine → Reporting Engine`, cu interfața `IVulnerabilityCheck` și modelul `BluetoothTarget`.
- **Mediu**: C# (.NET 8/9) sau Python; adaptor Bluetooth local / dongle nRF52840; spike de conectivitate deja făcut.

### 3.3 Backlogul și sprinturile (`Lectura/obiective.md`)

Pasul 1 – modul de recunoaștere; Pasul 2 – evaluare (fingerprint/CVE + detecție activă); Pasul 3 – raportare JSON/PDF. Sprinturi: 0 (cerințe + arhitectură + mediu), 1 (recon, diagrame, testare pe telefoane/căști/dongle-uri), 2 (motor de reguli inspirat din YAML-urile BlueToolkit), 3 (raportare + test de sistem cap-coadă). Riscul principal: dependența de firmware/driverul plăcii Bluetooth.

---

## 4. Starea codului: de la script monolitic la `alpha01`

### 4.1 Evoluția din `Lectura/Cod/`

1. **`Program.cs` (522 linii)** – prima variantă, C# + WinRT (`Windows.Devices.Bluetooth`). Încarcă `master_oui.txt` (IEEE, ~40.765 prefixe), `company_identifiers.yaml` (Bluetooth SIG, ~4.071 companii) și `devices_db.json`. Enumerază dispozitivele **conectate** Classic și BLE, citește proprietățile LMP din cache-ul AEP (`LmpManufacturerId`, `LmpVersion`, `LmpSubversion`), RFCOMM services și GATT Device Information Service. Regurile de securitate (`EvaluateSecurityNotes`) sunt scrise direct în cod: autentificare slabă (`None`/`Encryption`), versiune LMP veche, chipset Airoha, profil HFP activ, firmware neexpus.
2. **`paralel.cs` (710 linii)** – aceeași funcționalitate, refactorizată pentru **paralelism**: seamăn `SemaphoreSlim(8)`, timeout 20 s/device, obiecte intermediare `DeviceSnapshot`/`GattData` fără stare partajată în faza 1, merge secvențial în faza 2, parsare OUI cu `AsParallel().AsOrdered()`, scriere atomică JSON (fișier `.tmp` + `File.Move`).
3. **`program2.cs` (1270 linii)** – adaugă **scanarea pasivă BLE** cu `BluetoothLEAdvertisementWatcher` (8 s implicit), clasificarea adreselor (`Public`, `Random-Static`, `Random-Resolvable(RPA)`, `Random-NonResolvable`), parsarea *Service Data* pe 16 biți (AD type `0x16`, de unde apare `0xFE2C` = Google Fast Pair), opțiuni CLI (`--scan`, `--active-scan`, `--connect[=filtru]`, `--fast`, `--debug`, `--timeout`, `--enum-timeout`), sondare GATT **fără pairing** pentru dispozitivele găsite la scan, și persistență doar pentru adrese stabile. Regulile includ acum și detectarea Fast Pair (`df21fe2c` în RFCOMM / `0000fe2c` în advertising).

`Cod/readme.md` documentează limitele importante: **BLE din jur da, Classic din jur nu** (doar ce e conectat la PC); paired-dar-tăcut nu apare; datele sunt suficiente pentru triaj/fingerprinting, **nu** pentru a declara vulnerabilitatea; lipsesc parsarea Model ID Fast Pair, check-ul local al driverului MediaTek, Classic inquiry, urmărirea RPA și corectarea potrivirii OUI pe măști de 28/36 biți.

### 4.2 Varianta modulară `Lectura/alpha01/` (commitul „versiunea alpha01")

Arhitectura (confirmată de `flux.md`):

```
Program.cs  →  ConnectedDeviceChecker (doar consolă)
            →  PassiveDetectionService  →  DeviceHistoryStore (devices_db.json)
            →  filtru --target / --connect
            →  ReconEngine (vulnerabilities.json)  →  recon_targets.json
            →  ActiveGattProber (--active-scan)
```

| Fișier | Rol |
|---|---|
| `Program.cs` | Orchestrare; opțiuni `--help`, `--scan=N`, `--no-scan`, `--target=`, `--connect[=filtru]`, `--active-scan`, `--debug`. |
| `Models/ScanOptions.cs` | Parsare CLI, `EffectiveFilter` (`--target` are prioritate peste `--connect=`), `MatchesFilter` pe MAC/nume, `PrintHelp`. |
| `Models/BluetoothDeviceRecord.cs` | Modelul central + `AdvertisementObservation`, `PassiveAdvertisementSnapshot`, `PassiveChipsetInfo`, `PassiveHardwareInfo`, `PassiveSecurityInfo`. |
| `Models/ConnectedDeviceChecker.cs` | Afișează dispozitivele deja conectate la gazdă. |
| `Data/PassiveLookupStore.cs` | Încarcă OUI + SIG. |
| `Data/DeviceHistoryStore.cs` | Citire/scriere istoric, `GetOrCreate`, `ApplyPassiveObservations`. |
| `PassiveDetection/PassiveDetectionService.cs` | Verifică adaptorul (`BluetoothAdapter`, `RadioState.On`), pornește watcher-ul pasiv/activ, colectează MAC, nume, RSSI, tip adresă, CompanyIds, ServiceUuids; `Task.WhenAll` pentru încărcări; filtrează adresele rotative. |
| `Analysis/ReconEngine.cs` | Motorul de triaj (detaliat în §5.3). |
| `ActiveDetection/ActiveGattProber.cs` | Conectare BLE (`Public` vs `Random`), enumerare GATT, citire `Generic Access` (`0x2A00`) și `Device Information Service` (`0x180A`): firmware, hardware, producător; setează `GattAccess`. |
| `Analysis/vulnerabilities.json` | Baza de reguli (9 reguli). |
| `alpha0.1.csproj` / `.slnx` | Proiect .NET 10 cu target `net10.0-windows10.0.19041.0`. |

**Confirmat de tine pe 23.11.2026:** `--active-scan` **este legat** în `alpha01/Program.cs` (secțiunea 4, liniile 56–81 apelează `ActiveGattProber.ProbeAsync`). Nota veche din `flux.md` a fost corectată în același sens; deci nu mai există discrepanță între documentație și cod.

### 4.3 Datele observate (`devices_db.json` din `Cod/`)

8 dispozitive înregistrate pe 12.11.2026: **Philips TAT3509** (`189C2CE2AD64`, Dongguan Huayin, 2 conexiuni), **HUAWEI FreeBuds 6i** (`64B0E8DDAA74`), **Dime 3 / Skullcandy** (`88089456AD96`), **ANDREEA / Intel** (`6C2F80208B76`), **HUAWEI WATCH GT 2e-41C** (`0CE4A032E41C`), **Air Mini Lite** (`3530D5BB2B90`), **Tepes / Lenovo-Motorola** (`D45B51AEAA98`), **Fit Watch 5000** (`F4FAF3B25546`).

Exemplul din `alpha01/flux.md`: același dispozitiv fizic (Philips TAT3509) are adresa Classic publică `18:9C:2C:E2:AD:64` și adresa BLE `D1:D3:2C:E2:AD:64` (**Random-Static**, ultimii 4 octeți identici). În advertising expune `0000fe2c-...` (Fast Pair), RSSI −40, conectabil; `ReconEngine` îi dă ipoteza `WHISPERPAIR-GFPS` cu încredere **Candidat**. Fișierul `recon_targets.json` din `bin/Debug/...` este în prezent gol (`[]`).

---

## 5. Vulnerabilitățile documentate de tine (catalogul complet)

### 5.1 Lanțul Airoha – CVE-2025-20700 / 20701 / 20702

- **CVE-2025-20700** – *Missing Authentication for GATT (BLE)*: conectare fără pairing la serviciile GATT; oferă acces la RACE.
- **CVE-2025-20701** – *Missing Authentication for Bluetooth BR/EDR*: conexiune Classic neautentificată, **fără interacțiunea utilizatorului**; permite și profilul HfP (microfon/audio).
- **CVE-2025-20702** – *Critical Capabilities in Custom Protocol*: protocolul proprietar **RACE** permite citire/scriere arbitrară în flash și RAM (inclusiv MMIO).
- **Versiuni afectate** (din `CVE-2025-2070X.docx`): Airoha IoT SDK for BT audio ≤ 5.5.0; AB1561x/AB1562x/AB1563x SDK ≤ 3.3.1.
- **Ce se poate face după compromitere**: injecție firmware persistentă (FOTA), exfiltrare date/înregistrări microfon, **HID keystroke injection**.
- **Lanțul către telefon** (din articolul HTML): conectare tăcută → dump flash → extragerea tabelului de conexiuni cu **Link Key** → impersonarea căștilor (spoof de adresă + cheie) → comenzi HfP: `AT+CNUM` (număr de telefon), `AT+BVRA` (asistent vocal), acceptare/inițiere apeluri, sunet către numărul atacatorului → preluare conturi WhatsApp/Amazon (demo 39c3).
- **Fingerprinting pasiv**: GATT `5052494D-2DAB-0341-6972-6F6861424C45` (default) sau `dc405470-a351-4a59-97d8-2e2e3b207fbb` (Sony); RFCOMM canal 21 cu `00000000-0000-0000-0099-AABBCCDDEEFF` / `8901DFA8-...` (Sony) / `2D064AA9-...` (Bose); comanda `0x1E08` dă modelul SoC, versiunea SDK și build timestamp-ul.
- **Dispozitive confirmate vulnerabile** (lista din articol): Beyerdynamic Amiron 300, Bose QuietComfort Earbuds, EarisMax Sender, Jabra Elite 8 Active, JBL Endurance Race 2 / Live Buds 3, Jlab Epic Air Sport ANC, Marshall ACTON III / MAJOR V / MINOR IV / MOTIF II / STANMORE III / WOBURN III, MoerLabs EchoBeatz, Sony Link Buds S / ULT Wear / WF-1000XM3/4/5 / WF-C500 / WF-C510-GFP / WH-1000XM4/5/6 / WH-CH520 / WH-CH720N / WH-XB910N / WI-C100, Teufel Tatws2. (Jabra Elite 8 Active e marcat ca *nu* e vulnerabil pe Classic în notele articolului – fișa e puțin ambiguă în lista Reproduced.)
- **Remediere**: SDK-ul Airoha patch-uit (iunie 2025), update firmware; GATT-ul să ceară autentificare per-characteristic, conexiunile Classic doar în pairing mode, RACE să nu expună operații critice.

### 5.2 Nordic

- **CVE-2025-67841** – *Algorithmic Complexity* în **IronSide SE** de pe **nRF54H20**: date care forțează Secure Element-ul într-un calcul foarte costisitor → DoS / epuizarea bateriei. Concluzia ta: „maxim un DoS, fără escaladări".
- **CVE-2025-9709** – *Improper Access Control* pe **nRF52810**. ⚠️ **Discrepanță în notele tale**: în `Nordic.docx` e descrisă ca „comenzi/date sensibile expuse fără autentificare/pairing, de la distanță"; în `Vulnerabilities.docx` e descrisă ca *EM Fault Injection* cu **acces fizic temporar**, care ocolește APPROTECT și deschide interfața de debug. De decis care varianta e cea corectă în lucrare.
- **Simulare**: chipurile Nordic sunt publice, deci pot fi emulate în **Renode** cu **Zephyr RTOS** (`simulare_nordic.resc`); plan: detecție pasivă a manufacturer-ului, apoi interogare activă a versiunii de stivă.

### 5.3 Celelalte CVE-uri și atacuri din `Vulnerabilities.docx`

| Vulnerabilitate | Tip / țintă | Ce am reținut |
|---|---|---|
| **CVE-2026-37100** – Yamaha SR-B30A | Improper Authentication, soundbar firmware **2.40** | Conectare BLE directă fără nicio autentificare; control prin protocolul proprietar Sound Bar Remote. |
| **CVE-2025-44526** – Realtek RTL8762EKF-EVB | DoS, SDK BLE | Verificări insuficiente în câmpurile pachetelor BLE; `LL_Length_Req` malformat → crash/reboot. Detectabil slab (OUI-ul e al produsului, nu al chipului). |
| **CVE-2025-44557** – Cypress PSoC4 (stiva BLE 3.66) | Authentication Bypass / state machine flaw | Injectare `pairing_failed` → stiva acceptă conexiune necriptată/neautentificată. Testul real e activ, pe SMP. |
| **CVE-2025-20680** – MediaTek | EoP local, driver Bluetooth | OOB write/heap overflow; necesită acces user deja existent. **Nu e detectabil remote** – doar check local al vendorului/versiunii driverului (neimplementat). |
| **CVE-2025-0093** – Android Bluetooth Adapter Service | Unapproved data access | Doar nivelul de patch Android, aflat local; nimic remote. |
| **WhisperPair** – Google Fast Pair (GFPS) | Hijack, location tracking, eavesdropping | Cereri Fast Pair nesolicitate → asociere în fundație + cheie falsă de proprietar; pe iOS sau fără cont Android, dispozitivul poate fi înregistrat în *Find My Device* → urmărire globală și activarea microfonului. Afectează sute de modele Sony, Pixel Buds, JBL, Anker, Jabra, Xiaomi. Articol: whisperpair.eu; PoC-uri: `aalex954/whisperpair-poc-tool`, `Bazskillz/WhisperPair-PoC`. |
| **PerfektBlue** – OpenSynergy BlueSDK | RCE în infotainment auto | Lanț de 4 vulnerabilități (inclusiv Use-After-Free în AVRCP); testat pe VW, Mercedes, Skoda; >350M vehicule; GPS, contacte, microfon. |
| **BlueToolkit / Bluesnarfing** | instrumente / atacuri active | Sunt etapa de *confirmare*, nu de detecție pasivă. |

### 5.4 Atacurile „de bază" din notele de curs

- **KNOB** – forțarea entropiei minime la negocierea cheii de sesiune: 1 octet pe BR/EDR, 7 octeți pe BLE → brute-force, decriptare și injectare în timp real.
- **BIAS** – bypass de autentificare la reconectare („ne știm deja").
- **BLURtooth** – abuzează CTKD: cheia BLE suprascrie cheia Classic.
- **BrakTooth** – peste 20 de bug-uri în stack-uri LMP (Intel, Qualcomm, TI), de la DoS la RCE.
- **SweynTooth** – 12 vulnerabilități în batchul 1 (TI, NXP, Cypress, Dialog, Microchip, ST, Telink) + 5 în batchul 2 (TI, Espressif, Microchip, ON Semi, Zephyr): deadlock-uri, crash-uri, buffer overflow-uri, bypass de securitate.
- **BLESA** – injectare de date false la reconectare, înainte de finalizarea verificării de securitate.
- **Invalid Curve / Fixed Coordinate** – dacă nu se verifică faptul că punctul public primit aparține curbei P-256, atacatorul deduce cheia privată.
- **Stealtooth / Blacktooth / BIAS** – auto-pairing tăcut, suprascrierea Link Key-ului; posibilitatea de a deschide canal HID și a injecta tastări (Rubber Ducky).
- **CVE-2023-45866** – forțarea unei conexiuni HID fără confirmare (Android/Linux/macOS/iOS în anumite condiții).
- **Carwhisperer** – PIN-uri standard `0000`/`1234` pe kituri auto → injectare/ascultare audio peste RFCOMM + SCO.

### 5.5 Baza de reguli `vulnerabilities.json` (9 reguli)

Există **două versiuni**: `Cod/vulnerabilities.json` (mai veche, cu `CVE-2025-GFPS`, `CVE-2025-PERFEKTBLUE`, ID-uri SweynTooth vechi) și `alpha01/Analysis/vulnerabilities.json` (mai nouă, cu `CVE-2025-36911`, CVE-urile reale PerfektBlue `CVE-2024-45434/45431/45432/45433`, ID-uri actualizate). Le redau pe cele din `alpha01`:

| ID regulă | CVE | Semnale de potrivire | Încredere implicită → ridicată |
|---|---|---|---|
| `WHISPERPAIR-GFPS` | CVE-2025-36911 | UUID `0000fe2c` / `df21fe2c`; Company ID 224; Google, Sony, JBL, Jabra, Marshall, Soundcore, OnePlus, Redmi, Nothing, Logitech | NeevaluabilFaraTestActiv → Probabil |
| `AIROHA-RACE-2025` | 2025-20700/20701/20702 | UUID `5052494d-...`; Company ID 148; „Airoha" | Candidat → Probabil |
| `YAMAHA-SRB30A-UNAUTH` | CVE-2026-37100 | Company ID 597; nume `SR-B30A`/`SR-B`; firmware `^2\.40$` | Candidat → Probabil |
| `REALTEK-RTL8762-DOS` | CVE-2025-44526 | Company ID 93; „Realtek" | Neevaluabil → Candidat |
| `CYPRESS-PSOC4-BLE` | CVE-2025-44557 | Company ID 305; Cypress/Infineon; `PSoC4`, `PSoC` | Neevaluabil → Candidat |
| `NORDIC-NRF-ACCESS-SE` | CVE-2025-9709 / 67841 | Company ID 89; Nordic; `nRF52`, `nRF54`, `Zephyr` | Neevaluabil → Candidat |
| `PERFEKTBLUE-BLUESDK-IVI` | CVE-2024-45434/45431/45432/45433 | profiluri `0000111e`/`0000110b`/`0000112f`; Harman, Continental, Aptiv, Bosch, Visteon, Panasonic Automotive, Alpine; `IVI`, `MBUX`, `Sync`, `Uconnect`, `Car`, `Auto`, `Infotainment`, `VW`, `Audi`, `BMW`, `Skoda`, `Renault`… | Neevaluabil → Candidat |
| `SWEYNTOOTH-LEGACY-BLE` | CVE-2019-16336 / SweynTooth | Company IDs 13, 37, 48, 205, 210, 305, 529; TI, NXP, Dialog, Microchip, ST, Telink, Cypress; `maxLmpVersion: 9` | Neevaluabil → Candidat |
| `WEAK-PAIRING-OR-OPEN-GATT` | CWE-287 / CWE-306 | `checkOpenGattWithoutPairing`, `checkWeakProtectionLevel` | Probabil → Probabil |

**Logica lui `ReconEngine`** (cum am înțeles): fiecare regulă produce o `VulnerabilityHypothesis` doar dacă cel puțin un semnal se potrivește. UUID-urile, tiparele de nume, firmware-ul confirmat, GATTul deschis și nivelul slab de protecție sunt **semnale tari**; Company ID-urile și cuvintele-cheie vendor sunt **semnale slabe**. Dacă firma se potrivește → încredere ridicată; dacă firma nu se potrivește, regula e eliminată; dacă apare doar semnal tare → cel puțin `Candidat`. `maxLmpVersion` elimină versiunile prea noi. Numele scurte (≤4 caractere) se potrivesc doar ca întreg cuvânt (`Car` nu prinde `Carlos`). `TriagePriority` = 3/2/1 după încredere, iar în `recon_targets.json` se salvează doar țintele cu ipoteze. Atenție: **nivelul de încredere nu înseamnă „vulnerabil"**, ci „candidat la verificare activă".

---

## 6. Ce am înțeles din limitele curente (ca să le rezolvăm în proiect)

1. **„Pasiv" are limite**: scan BLE pasiv = da; Classic inquiry = nu (doar dispozitive conectate la PC); dispozitive paired dar tăcute nu apar. `--active-scan` / `--connect` / probele GATT **nu mai sunt pasive**.
2. **Advertising-ul nu transportă versiunea de firmware sau stiva software** – deci detecția pasivă poate da doar *Candidat/Probabil/Neevaluabil*, niciodată confirmare. Confirmarea cere test activ (GATT/RFCOMM/LMP) sau hardware dedicat (nRF52840, Ubertooth, HCI pe Linux).
3. **Windows/WinRT nu expune pachetul `LL_VERSION_IND`** de la conectare, deci vendorul real al cipului și subversion-ul nu pot fi citite prin API-urile WinRT; singurele căi: sniffer extern sau HCI pe Linux.
4. **Adresele rotative (RPA/NRPA) nu trebuie persistate** – se schimbă și poluează baza de date; adresele Random-Static sunt stabile și pot fi păstrate, dar OUI-ul nu se aplică lor (vendor-ul se ia din Manufacturer Data/SIG).
5. **Philips TAT3509 e exemplul perfect** de dual-mode cu două adrese diferite și de candidat WhisperPair prin UUID-ul Fast Pair.
6. **Regulile trebuie să rămână externe** (JSON/YAML), cu niveluri de încredere, nu hard-coded în `EvaluateSecurityNotes`.
7. **De adăugat**: parsarea completă Fast Pair (Model ID pe 3 octeți + flaguri + pairing mode), check local pentru MediaTek/Android, Classic inquiry opțional, urmărirea RPA în timp, corectarea OUI pe 28/36 biți.
8. **Reproductibilitate**: două fișe par să aibă numere de CVE placeholder sau neverificate (`CVE-2026-37100`, `CVE-2025-GFPS`, `CVE-2025-PERFEKTBLUE`) – de verificat înainte de a le pune în lucrare.

---

## 7. Starea Git (doar constatată, **nu am modificat nimic**)

- Repository-ul există doar în `Lectura/` (nu în rădăcina folderului).
- Branch local `cod_test` are un commit în plus față de `origin/cod_test` (`e9c3584`); `main` = `origin/main` = `10de68a`.
- Working tree-ul are **multe fișiere modificate, nemișcate în commit**: aproape toate fișierele din `Cod/`, notițele `.txt`, `obiective.md`, `cuprins.txt`, `alpha01/flux.md`, `alpha01/Program.cs`, fișierele de proiect și mai ales **artefacte generate `bin/` și `obj/` care sunt track-uite** (DLL-uri, `.pdb`, `.cache`, `.json` de build).
- Când facem curățenia cerută, punctele de atenție vor fi: commitul `e9c3584` neîmpins, modificările locale nesalvate, artefactele `bin/obj` din Git, fișierele mari PDF duplicate în mai multe locuri (`woot25-zubkov.pdf`, `Classic Bluetooth Security and Exploitation.pdf`, `Stealtooth.pdf`, `Exploiting Low Entropy.pdf`) și `recon_targets.json` gol.

---

## 8. Ce am înțeles eu, pe scurt (spune-mi dacă e greșit)

> Lucrarea e un **auditor Bluetooth modular**: scanare pasivă BLE → fingerprinting (OUI/SIG/advertising) → triaj pe reguli externe cu niveluri de încredere → sondare activă GATT/RFCOMM doar pe țintele alese → raport JSON. Nu promitem „detectare de vulnerabilitate" din advertising, ci „candidat care merită verificat". Exploatarea e demonstrativă și controlată (Renode pentru Nordic, eventual RACE Toolkit pentru Airoha pe hardware propriu), iar patch-ul e ultimul modul. Codul a evoluat de la trei scripturi C# monolitice în `Cod/` la proiectul `alpha01`, care conține deja majoritatea modulelor, iar notele din `flux.md` au fost aliniate la cod (`--active-scan` e legat de `ActiveGattProber`).
>
> Vulnerabilitățile pe care le-ai documentat personal și care trebuie să apară în lucrare sunt: **Airoha RACE (20700/20701/20702)**, **Nordic (9709/67841)**, **Yamaha SR-B30A (2026-37100)**, **Realtek (44526)**, **Cypress PSoC4 (44557)**, **MediaTek (20680)**, **Android (0093)**, **WhisperPair**, **PerfektBlue**, plus atacurile de fundament KNOB, BIAS, BLURtooth, BrakTooth, SweynTooth, BLESA, Invalid Curve, Stealtooth și carwhisperer.

Dacă vreo afirmație de aici e greșită (mai ales numerele CVE sau interpretarea CVE-2025-9709), spune-mi și corectez imediat înainte de curățenia de pe Git.
