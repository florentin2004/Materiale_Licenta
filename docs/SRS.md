# SRS - Software Requirements Specification

## Scop
Software pentru detectia vulnerabilitatilor in Bluetooth BR/EDR si BLE.

## Cerinte utilizator (SDD-01..04)
- SDD-01: scanare autonoma, fara configurare complicata.
- SDD-02: selectia tintei dupa adresa MAC / filtru de nume.
- SDD-03: sumar de securitate pentru dispozitivele analizate.
- SDD-04: export JSON al rezultatelor.

## Cerinte functionale (SRS-01..04)
- SRS-01: Reconnaissance Engine - achizitie pasiva (BLE Advertising / EIR) si activa (SDP/GATT), cu metadate radio: adresa, Company ID, Service UUID, versiune, tip de autentificare.
- SRS-02: Vulnerability Assessment Engine - corelare cu o baza externa de reguli (`vulnerabilities.json`) si generare de ipoteze cu nivel de incredere: `NeevaluabilFaraTestActiv`, `Candidat`, `Probabil`.
- SRS-03: Vulnerability Assessment Engine - evaluare activa controlata, non-distructiva (GATT/RFCOMM/LMP), pentru confirmarea ipotezelor.
- SRS-04: Reporting Engine - serializare in JSON cu stari `Pass` / `Fail` / `Info` si lista de riscuri.

## Cerinte nefunctionale (NFR-01..03)
- NFR-01: modularitate si cuplare slaba; CLI acum, GUI ulterior.
- NFR-02: executie asincrona si rezilienta la timeout-uri.
- NFR-03: teste non-distructive asupra dispozitivelor tinta.

## Criterii de acceptare
- Gasirea a cel putin un dispozitiv real.
- Flux complet: adresa MAC -> obiect tinta -> verificare -> raport.
- JSON valid generat la final.

## Obiective detaliate (C1.1 - C5.2)
1. Knowledge Base: CVE + CVSS + impact + mapare pe nivel (Controller/LMP, Host/L2CAP/SMP/GATT, Application Profiles).
2. Detectie pasiva: fingerprinting fara emisie RF catre tinta.
3. Detectie activa: enumerare SDP/GATT, probing controlat (KNOB, WhisperPair, PBAP/OBEX).
4. Exploatare: mediu hibrid Renode/Zephyr + bench fizic, un exploit demonstrativ.
5. Remediere: patch demonstrativ si re-testare.

> Document derivat din `Sprint0.md`, `obiective_gemini.md` si `Obiective_IVAN.docx`. Sectiunile incomplete se vor marca `TODO`.
