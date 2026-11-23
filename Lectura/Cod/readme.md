Citind și `Vulnerabilities.docx`, pot răspunde concret.

## Cum funcționează fluxul din `Program_2.cs`

1. **Pornire.** Se citesc opțiunile din linia de comandă (`--scan`, `--connect`, `--fast` etc.).
2. **Faza 1, totul în paralel:**
   - se încarcă `master_oui.txt`, `company_identifiers.yaml` și istoricul JSON;
   - se enumeră device-urile Classic conectate la PC și se interoghează fiecare (RFCOMM, proprietăți Windows);
   - se enumeră device-urile BLE conectate la PC și se interoghează fiecare (servicii GATT, Device Information Service);
   - rulează scan-ul de advertising BLE, 8 secunde implicit, care aduce adresă, tip de adresă, RSSI, nume, company ID, UUID-uri de servicii și dacă device-ul e conectabil.
3. **Faza 1c, opțională.** Pentru device-urile găsite la scan, dar neconectate (de exemplu smart band-ul), poți alege din listă sau folosi `--connect`. Se face doar descoperire GATT, fără pairing.
4. **Faza 2, secvențială.** Rezultatele se combină în `devices_db.json` și se aplică regulile de audit (note de securitate). Device-urile cu adresă rotativă (RPA / non-resolvable) se afișează, dar nu se salvează.

## Verifică și device-urile din jur?

Doar parțial.
- **BLE din jur:** da, prin scan de advertising. Vezi orice device care emite pachete în raza adaptorului, conectat sau nu.
- **Classic din jur:** nu. Nu există inquiry. Device-urile Classic apar doar dacă sunt conectate la acest PC.
- **Paired, dar neconectate și tăcute:** nu apar.
- **„Conectat" înseamnă conectat la PC-ul tău.** Partea asta e inventar al perechilor tale, nu observare a mediului.

## Sunt datele suficiente pentru detecție pasivă?

Pentru **triaj și fingerprinting** da. Pentru **a stabili dacă un device e vulnerabil** nu. Aproape toate vulnerabilitățile din listă depind de chip și de versiunea de firmware sau stivă, iar advertising-ul nu transportă niciuna dintre ele.

| Vulnerabilitate | Ce poate spune acum | Ce lipsește |
|---|---|---|
| **WhisperPair** (Fast Pair) | Candidat, dacă apare serviciul `0xFE2C` în advertising sau UUID-ul `df21fe2c-…` în RFCOMM | Modelul exact și starea patch-ului. Confirmarea cere un test activ. Din câte știu, în modul discoverable service data conține Model ID pe 3 octeți; nu e parsat încă. |
| **Yamaha SR-B30A** (BLE fără autentificare) | Fingerprint după nume și company ID. Cu `--connect`, `GattAccess = Success` pe un device nepereche e un indiciu | Versiunea de firmware (2.40), expusă doar dacă device-ul o dă prin DIS |
| **PerfektBlue** (BlueSDK, mașini) | Aproape nimic: stiva software nu se anunță | Classic inquiry, Class of Device (infotainment auto) și euristici pe nume |
| **Nordic nRF54H20 / nRF52810** | Aproape nimic: una cere acces fizic, cealaltă e DoS în secure element | Identificarea chipului (vezi mai jos). Aici detecția la distanță nu are sens. |
| **Realtek RTL8762** (LL_Length_Req) | Doar slab: OUI-ul indică de obicei producătorul produsului, nu al chipului | Chip și SDK |
| **Cypress PSoC4** (stivă BLE 3.66) | La fel | Versiunea stivei; testul real e activ, pe pairing |
| **MediaTek CVE-2025-20680** | Nimic, e driverul de pe gazdă | Aici merge un **check local**: vendorul și versiunea driverului adaptorului tău Bluetooth. Nu e implementat. |
| **CVE-2025-0093** (Android) | Nimic remote | Nivelul de patch Android, aflat doar local |
| **BlueToolkit / bluesnarfing** | Sunt instrumente și atacuri active, deci etapa de confirmare, nu de detecție | |

Câmpurile LMP din cod ar trebui să dea chipul, dar vendorul chipului și subversion-ul se schimbă între device-uri în pachetul `LL_VERSION_IND` de la conectare. Windows nu expune acel pachet prin API-urile WinRT. Singura cale la nivel de chip e un sniffer extern (de exemplu un dongle nRF52840) sau acces HCI pe Linux.

## Ce ar trebui adăugat

1. **Motor de reguli cu niveluri de încredere.** Acum regulile sunt scrise direct în cod. Ar fi mai bine un `vulnerabilities.json` (id, vendori sau company ID afectați, semnale, versiuni, dovada necesară). Rezultatul ar fi `Candidat`, `Probabil` sau `Neevaluabil fără test activ`, nu „vulnerabil".
2. **Parsare Fast Pair completă:** Model ID, flaguri și starea de pairing mode.
3. **Check local al adaptorului tău**, pentru MediaTek.
4. **Classic inquiry** opțional, pentru device-uri din jur precum mașinile. Tehnic e un scan activ, deși nu conectează.
5. **Urmărire în timp** a device-urilor rotative.
6. **Corectarea potrivirii OUI** pe măști de 28 și 36 de biți, ca producătorul să nu fie atribuit greșit.

Cuvântul „pasiv" are limite: scan-ul în mod `--active-scan` și `--connect` nu mai sunt pasive.

Vrei să încep cu motorul de reguli (`vulnerabilities.json` cu niveluri de încredere) și cu parsarea Fast Pair?