# SDD - Software Design Description

## Arhitectura generala

Reconnaissance Engine -> Vulnerability Assessment Engine -> Reporting Engine

## Pipeline-ul aplicatiei (alpha01)

1. `ConnectedDeviceChecker` - dispozitive deja conectate la gazda (doar afisare).
2. Incarcare in paralel: `master_oui.txt`, `company_identifiers.yaml`, `vulnerabilities.json`, `devices_db.json`.
3. `PassiveDetectionService` - BLE Advertising, clasificare adresa (Public / Random-Static / RPA / NRPA), CompanyIds, ServiceUuids.
4. `ReconEngine` - triaj pe reguli externe, `recon_targets.json`.
5. `ActiveGattProber` - apelat prin `--active-scan` din `Main`; GATT DIS (`0x180A`), `GattAccess`, firmware/hardware.
6. Salvare `devices_db.json` / raport JSON.

## Module

- `Models/ScanOptions.cs` - parsing CLI; `--target` are prioritate peste `--connect`.
- `Models/BluetoothDeviceRecord.cs` - modelul central + snapshot-uri pasive.
- `Data/PassiveLookupStore.cs` - OUI + Bluetooth SIG.
- `Data/DeviceHistoryStore.cs` - persistenta istoricului.
- `Analysis/ReconEngine.cs` - motorul de ipoteze.
- `ActiveDetection/ActiveGattProber.cs` - sondare activa GATT.

## Model de date

`BluetoothTarget` / `BluetoothDeviceRecord` cu: MacAddress, Name, Transport, Vendor, Advertisement, Chipset, Hardware, Security, Hypotheses.

## Stack si mediu

- C# .NET 10, WinRT (`net10.0-windows10.0.19041.0`).
- Alternativa: Python/BlueZ pe Linux.
- Hardware: adaptor Bluetooth standard / dongle nRF52840.
- Simulare: Renode + Zephyr RTOS (`simulare_nordic.resc`).

## Limitari cunoscute

- WinRT nu expune `LL_VERSION_IND`; vendorul real al cipului nu poate fi citit pasiv pe Windows.
- Advertising-ul nu contine versiunea de firmware/stiva; detectia pasiva ofera doar candidati.
- Classic inquiry nu este implementat; doar dispozitivele conectate la gazda apar.
