### Structura Product Backlog (Epics & Cerințe)


 **Pasul 1: Modulul de Recunoaștere (Reconnaissance Engine)**
* *Scanare pasivă*: Captarea pachetelor de publicitate (*advertising/broadcast*), extragerea adreselor MAC, a numelui și a UUID-urilor serviciilor expuse (SDP/GATT).


* *Scanare activă (Fingerprinting)*: Interogarea versiunii de Bluetooth suportate, a capacităților hardware/firmware și a suportului pentru mecanisme de securitate (ex. Secure Connections, SSP).




**Pasul 2: Modulul de Evaluare / Detecție a Vulnerabilităților**
* *Detecție bazată pe amprentă (Knowledge Base / CVEs)*: Compararea versiunilor și profilelor detectate cu liste cunoscute de vulnerabilități de stivă/firmware (ex. profil PBAP nesecurizat, stive vulnerabile).


* *Detecție activă la nivel de protocol*: Verificarea configurărilor eronate ale procedurilor de asociere (de exemplu, acceptarea negocierii unei entropii minime de criptare de 1 octet ca în KNOB sau lipsa verificării autenticității).




 **Pasul 3: Modulul de Raportare și Notificare**
* Generarea automată de rapoarte structurate (JSON/PDF) care listează dispozitivele găsite, clasificarea riscurilor și recomandările defensive de remediere.




**Cerințe Non-Funcționale (NFR)**: Modularitate (cuplare slabă pentru a putea adăuga teste noi în format configurabil, ex. YAML), compatibilitate hardware (dongle nRF / interfață Linux BlueZ) și siguranță în execuție (evitarea blocării necontrolate a dispozitivelor țintă).



---

### Planificarea Sprint-urilor (Dezvoltare Incrementală)

Fiecare sprint include etapele de analiză, proiectare detaliată a interfețelor, codare și testare unitară/de integrare.

#### Sprint 0: Pregătire, Cerințe și Arhitectură (2 săptămâni)

**Activități tehnice**:
* Definirea cerințelor software (SRS) și stabilirea criteriilor de acceptare.


* Proiectarea arhitecturii de nivel înalt a framework-ului (mecanism de pipeline: intrare adresă Bluetooth/scan $\rightarrow$ analizor $\rightarrow$ generator raport).


* Configurarea mediului de lucru (subistemul Bluetooth din Linux / instrumente specifice, simulator sau dongle hardware).




* **Livrabil (Definition of Done)**: Documentație inițială de arhitectură și mediu de dezvoltare configurat cu test de conectivitate basic.



#### Sprint 1: Modulul de Reconnaissance (2–3 săptămâni)

**Activități tehnice**:
* *Design*: Diagrame de clasă și de secvență pentru fluxurile de scanare activă și pasivă.


* *Implementare*: Codificarea scanerului pentru descoperirea dispozitivelor din proximitate și extragerea parametrilor (versiune, features, SDP/GATT).


* *Testare*: Verificarea detecției pe dispozitive de test (ex. smartphone, căști, dongle-uri locale).




**Livrabil**: Componentă software autonomă capabilă să descopere dispozitivele din proximitate și să returneze profilul lor tehnic complet.



#### Sprint 2: Motorul de Audit și Evaluare a Vulnerabilităților (3 săptămâni)

**Activități tehnice**:

* *Design*: Proiectarea structurii modulare pentru reguli de securitate (definirea formatului de testare, inspirat din configurațiile YAML din *BlueToolkit*).


* *Implementare*: Realizarea motorului de logică pentru identificarea configurațiilor slabe sau a stivelor vulnerabile.


* *Testare*: Teste unitare pentru fiecare verificare de vulnerabilitate implementată; testare de integrare între modulul de recunoaștere și cel de verificare.




* **Livrabil**: Nucleul sistemului capabil să ia profilul unui dispozitiv și să stabilească automat dacă prezintă indicatori de vulnerabilitate la nivel de protocol.



#### Sprint 3: Modulul de Raportare și Validare de Ansamblu (2 săptămâni)

**Activități tehnice**:
* *Design & Implementare*: Generarea structurată a rezultatelor de audit (format JSON/raport tehnic).


* *Testare de sistem*: Rularea întregului lanț (Scanare $\rightarrow$ Evaluare $\rightarrow$ Raport) într-un scenariu controlat pentru a măsura acuratețea și stabilitatea.




* **Livrabil**: Aplicație complet funcțională capabilă să execute un ciclu cap-coadă de scanare și auditare.



---

### Factori de risc și monitorizare

Pe parcursul desfășurării sprint-urilor, cele mai frecvente riscuri asociate unui astfel de proiect software sunt factorii tehnologici și dependențele hardware (cum ar fi limitările impuse de firmware-ul sau driverele plăcii Bluetooth folosite pentru teste). Structurarea pe sprint-uri permite ajustarea rapidă a modului de scanare sau a tipurilor de verificări fără a compromite întregul proiect de licență.

Ce mediu de execuție intenționezi să folosești cu prioritate pentru acest sistem (o distribuție Linux nativă cu drivere BlueZ, o mașină virtuală sau simulare software)?