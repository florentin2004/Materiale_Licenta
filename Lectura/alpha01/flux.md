# Fluxul aplicației (BluetoothAuditor)

## 1. Etapele de execuție (Pipeline)

1. **Verificare dispozitive conectate la gazdă (`ConnectedDeviceChecker`)**
   - Interoghează Windows (`DeviceInformation`) după dispozitivele Bluetooth Classic și BLE aflate în starea `BluetoothConnectionStatus.Connected` și le afișează în consolă înainte de scanare.
   - *Exemplu observat:* `[Classic] Philips TAT3509` cu adresa publică `18:9C:2C:E2:AD:64`.

2. **Încărcare baze de date & istoric (în paralel)**
   - `master_oui.txt` — baza IEEE/Wireshark (~40.765 prefixe) pentru identificarea producătorului din adresele MAC publice.
   - `company_identifiers.yaml` — registrul oficial Bluetooth SIG (4.071 companii) pentru decodarea *Company ID*-urilor din pachetele BLE.
   - `vulnerabilities.json` — catalogul extern de reguli (9 reguli) folosit de motorul de triaj pasiv `ReconEngine`.
   - `devices_db.json` — istoricul persistent al dispozitivelor observate anterior.

3. **Detecție pasivă & filtrare (`BleAdvertisementScanner` / `PassiveScan`)**
   - Ascultă pachetele BLE Advertising folosind `BluetoothLEAdvertisementWatcher` (fără a iniția conexiuni către dispozitivele țintă).
   - Clasifică adresa MAC (`MacAddressHelper`): păstrează doar adresele stabile (`Public` și `Random-Static`) și ignoră adresele rotative efemere (`RPA` / `NRPA`) care își schimbă valoarea periodic, prevenind poluarea bazei de date.
   - Extrage MAC, nume, RSSI, `CompanyIds` și `ServiceUuids` și actualizează `devices_db.json`.

4. **Triaj pasiv (`ReconEngine`) & export candidați (`recon_targets.json`)**
   - Evaluează dispozitivele selectate (toate din sesiune/istoric sau cele filtrate prin `--connect=<filtru>`) față de regulile din `vulnerabilities.json`.
   - Calculează nivelul de încredere (`NeevaluabilFaraTestActiv`, `Candidat`, `Probabil`) și prioritatea de investigare (`TriagePriority`), afișează raportul în consolă și salvează candidații în `recon_targets.json`.

5. **Scanare activă / Sondare GATT (`--active-scan`) — integrată**
   - Modulul de sondare activă este implementat pentru a deschide conexiuni BLE (`BluetoothLEDevice`), a enumera serviciile GATT și a citi *Device Information Service (`0x180A`)* (firmware, hardware, producător GATT, PnP ID).
   - **Stare curentă (corectat):** flag-ul `--active-scan` este parsat în `Program.cs` **și apelat la finalul metodei `Main`** prin `ActiveGattProber.ProbeAsync` pentru țintele selectate. Câmpurile active din `devices_db.json` (`FirmwareRevision`, `GattAccess`, `ExposedServices`, producător GATT etc.) se populează când sondarea reușește; rămân `null`/`[]` doar dacă nu se cere scanarea activă sau dacă conexiunea/GATT-ul eșuează/expiră.
   - Atenție: această etapă **nu mai este pasivă** — deschide conexiune BLE către țintă.

---

## 2. Arhitectura aplicației — Ce face fiecare clasă

### Orchestrare și nivel de intrare
* **`Program`** (`Program.cs`): Punctul de intrare al aplicației (`Main`). Parsează argumentele din linia de comandă (`--scan`, `--scan=N`, `--no-scan`, `--active-scan`, `--connect=<filtru>`, `--target=`), încarcă în paralel fișierele de referință și coordonează ordinea etapelor: verificare dispozitive conectate $\rightarrow$ scanare pasivă $\rightarrow$ filtrare $\rightarrow$ triaj `ReconEngine` $\rightarrow$ sondare activă opțională (`ActiveGattProber`, prin `--active-scan`) $\rightarrow$ salvare rezultate.
* **`ConnectedDeviceChecker`**: Verifică ce dispozitive Bluetooth (Classic și BLE) sunt deja conectate la laptop în momentul pornirii aplicației, interogând API-ul Windows `DeviceInformation` și eliminând duplicatele.

### Achiziție de date și persistență
* **`BleAdvertisementScanner`**: Motorul de scanare pasivă BLE. Pornește `BluetoothLEAdvertisementWatcher` pe durata configurată, interceptează pachetele *Advertising* și *Scan Response*, filtrează adresele rotative temporare și actualizează înregistrările stabile în baza de date.
* **`DeviceDatabase`**: Gestionează citirea și scrierea fișierului `devices_db.json`. Încarcă istoricul la pornire (`LoadAsync`), salvează modificările în format JSON (`SaveAsync`) și oferă metoda `GetOrCreate` pentru a crea sau actualiza profilul unui dispozitiv după adresa MAC normalizată.

### Utilitare de identificare și rezolvare
* **`MacAddressHelper`**: Normalizează adresele MAC (12 caractere hexazecimale fără separatori) și determină tipul adresei BLE (`ClassifyBleAddress`) analizând biții primului octet:
  - `Public` — adresă fixă alocată de producător;
  - `Random-Static` — adresă random fixă pe durata ciclului de alimentare (primii 2 biți sunt `11`, ex. `0xD1`);
  - `Random-Resolvable (RPA)` / `Random-NonResolvable (NRPA)` — adrese temporare rotative, ignorate la salvare (`IsStableAddress`).
* **`OuiLookup`**: Încarcă `master_oui.txt` și identifică producătorul hardware după primii 24, 28 sau 36 de biți ai adresei MAC. Dacă adresa este de tip `Random-*`, returnează explicit `"N/A (adresa random - OUI nu se aplica)"` pentru a evita identificări false.
* **`BluetoothSigLookup`**: Încarcă `company_identifiers.yaml` și traduce codurile numerice pe 16 biți (*Company IDs*) din secțiunea *Manufacturer Specific Data* a pachetelor BLE în numele oficial al companiei (ex. `0x00E0` $\rightarrow$ `Google`, `0x01DD` $\rightarrow$ `Koninklijke Philips N.V.`).

### Analiză de securitate (Triaj pasiv & Sondare activă)
* **`ReconEngine`**: Motorul de analiză pasivă. Încarcă regulile din `vulnerabilities.json`, verifică dacă un dispozitiv expune semnale asociate unor CVE-uri cunoscute (UUID-uri de servicii, Company ID-uri, tipare de nume sau versiuni) și generează lista de ținte candidate în `recon_targets.json`.
  - **`VulnerabilityRule` / `RuleMatchCriteria`**: Modelele care descriu o regulă din `vulnerabilities.json` și condițiile ei de potrivire.
  - **`ReconTarget` / `VulnerabilityHypothesis`**: Modelele rezultatului de triaj pentru un dispozitiv și ipoteza de vulnerabilitate (ex. `CVE-2025-36911` / WhisperPair), incluzând încrederea și pașii activi necesari pentru confirmare.
* **`ActiveScanner` / `ActiveGattProber`**: Modulul de sondare activă GATT (pentru `--active-scan`), responsabil de conectarea la țintele BLE conectabile, enumerarea serviciilor GATT și extragerea metadatelor hardware/firmware din *Device Information Service (`0x180A`)*.

### Modele de date (`DeviceRecord` și sub-componentele sale)
* **`DeviceRecord`**: Entitatea centrală salvată în `devices_db.json`, care agregă identitatea de bază (`MacAddress`, `Name`, `Vendor`), metadatele de timp (`FirstSeen`, `LastConnected`, `ConnectionCount`, `LastScanMode`) și cele 4 sub-obiecte de mai jos:
* **`ChipsetInfo`**: Date despre controller-ul Bluetooth / Link Manager Protocol (`LmpManufacturerId`, `LmpManufacturerName`, `LmpVersion`, `LmpSubversion`) și identificatorii PnP / Device ID (`DeviceIdSource`, `DeviceIdVendorId`, `DeviceIdVendorName`, `DeviceIdProductId`).
* **`HardwareInfo`**: Identificatori hardware Windows (`HardwareIds`) și informații citite activ prin GATT DIS (`GattManufacturerName`, `HardwareRevision`, `FirmwareRevision`).
* **`SecurityInfo`**: Postura de securitate și conectivitate (`ConnectionType`, `IsPaired`, `ProtectionLevel`, `GattAccess`, `ExposedServices`, `AuditNotes`).
* **`AdvertisementInfo`**: Ultimul instantaneu recepționat în pachetele BLE Advertising (`LastAdvertised`, `LastRssi`, `AddressKind`, `Connectable`, `Companies`, `ServiceUuids`).

---

## 3. Exemplu concret de date observate (Philips TAT3509)

Un aspect important observat la testare este modul în care același dispozitiv fizic folosește două adrese diferite în funcție de transport:
* **Bluetooth Classic (conectat la laptop):** `18:9C:2C:E2:AD:64` (adresă `Public`, prefix OUI `18:9C:2C`).
* **Bluetooth Low Energy (advertising pasiv):** `D1:D3:2C:E2:AD:64` (adresă `Random-Static`, unde primii 2 octeți sunt înlocuiți cu `D1:D3`, iar ultimii 4 octeți `2C:E2:AD:64` rămân identici cu cei ai adresei Classic).

#### Structura înregistrării în `recon_targets.json` / `devices_db.json`
* **`MacAddress`**: `"D1D32CE2AD64"` (adresa BLE normalizată).
* **`Name`**: `"(fara nume)"` (în modul conectat, beacon-ul Google Fast Pair nu include numele dispozitivului în pachetul de advertising).
* **`Vendor`**: `"N/A (adresa random - OUI nu se aplica)"` (primii 3 octeți `D1:D3:2C` nu sunt un OUI IEEE).
* **`Advertisement` / `ServiceUuids`**: `["0000fe2c-0000-1000-8000-00805f9b34fb"]` — UUID-ul serviciului **Google Fast Pair (`0xFE2C`)**, `AddressKind: "Random-Static"`, `LastRssi: -40`, `Connectable: true`.
* **`Hypotheses` (`ReconEngine`)**:
  - **`RuleId`**: `"WHISPERPAIR-GFPS"` (`CVE-2025-36911` — *WhisperPair: Google Fast Pair Pairing-State Bypass*).
  - **`Confidence`**: `"Candidat"` (semnal pasiv confirmat prin UUID-ul `0xFE2C`; necesită verificare activă GATT pentru a testa dacă dispozitivul acceptă *Key-based Pairing* în afara modului de asociere).
* **`Chipset` / `Hardware` / `Security` (câmpuri active)**: `LmpManufacturerName: "Necunoscut"`, `LmpVersion: "Necunoscuta"`, `FirmwareRevision: null`, `GattAccess: null`, `ExposedServices: []` (se populează când rulează `--active-scan`; altfel rămân goale dacă nu se cere sondarea sau dacă aceasta eșuează).[cite: 10, 11, 12]