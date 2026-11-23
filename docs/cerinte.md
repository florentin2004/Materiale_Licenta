# Cerinte si backlog

## Product backlog (`Lectura/obiective.md`)
1. Modul de recunoastere.
2. Evaluare: fingerprinting/CVE + detectie activa.
3. Raportare JSON/PDF.

## Sprinturi
- Sprint 0 (2 sapt.): cerinte, arhitectura, mediu. **Realizat** in `Sprint0.md`.
- Sprint 1 (2-3 sapt.): recunoastere, diagrame, testare pe telefoane/casti/dongle-uri.
- Sprint 2 (3 sapt.): motor de reguli inspirat din YAML-urile BlueToolkit.
- Sprint 3 (2 sapt.): raportare + test end-to-end.

## Factori de risc
- Dependenta de firmware/driverul placii Bluetooth.
- Reproductibilitatea CVE-urilor (multe sunt deja patch-uite).
- Necesitatea hardware-ului dedicat pentru confirmare (HCI/Linux, nRF52840, Ubertooth).

## Directia curenta
De la reproducere CVE-2025-20700 (Airoha RACE) -> Nordic/Renode -> focus pe detectie (conform `CVE/Identity_Shift.docx`).
