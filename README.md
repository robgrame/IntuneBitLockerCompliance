# Intune BitLocker Compliance — diagnostica dettagliata

Soluzione custom per Microsoft Intune (Windows 10/11) che risolve il problema
di **report di non-compliance BitLocker senza dettaglio**: la Compliance Policy
built-in di Intune valuta `RequireDeviceEncryption` in modo binario e non
indica *perché* un dispositivo risulta non conforme (algoritmo errato, % di
cifratura, recovery key non escrowed in Entra ID, ecc.).

La soluzione è organizzata in **due livelli complementari**:

```
Remediations/
  Detect-BitLockerCompliance.ps1     # Intune Remediations - detection
  Remediate-BitLockerCompliance.ps1  # Intune Remediations - safe remediations
CustomCompliance/
  Discover-BitLocker.ps1             # Discovery script (DEVE essere firmato)
  BitLockerComplianceRules.json      # Regole + messaggi IT/EN per Company Portal
```

## Livello A — Intune Remediations (visibilità immediata)

`Detect-BitLockerCompliance.ps1` raccoglie:

- `ProtectionStatus`, `VolumeStatus`, `EncryptionMethod`, `EncryptionPercentage`
- Tipi di key protector presenti + `RecoveryKeyIds`
- `RecoveryKeyEscrowedInEntraId` (verifica via `dsregcmd /status` + EventID 845
  in `Microsoft-Windows-BitLocker/BitLocker Management`)
- Stato TPM (`Get-Tpm`)
- Ultimi errori da `Microsoft-Windows-BitLocker/BitLocker Management`
- Lista `NonComplianceReasons` human-readable

L'output viene scritto sia come righe leggibili sia come singola riga
machine-parsable:

```
BITLOCKER_DIAG={"MountPoint":"C:","ProtectionStatus":"On",...}
```

Quella riga compare nella colonna **Pre-remediation detection output** del
report Intune (Reports → Remediations → seleziona script → Device status),
risolvendo subito il gap di visibilità per il team IT.

`Remediate-BitLockerCompliance.ps1` esegue **solo azioni sicure**:

- `Resume-BitLocker` se la protezione è sospesa su un volume cifrato
- `BackupToAAD-BitLockerKeyProtector` per ogni `RecoveryPassword` non
  escrowed in Entra ID

Non vengono mai eseguiti automaticamente: avvio cifratura, cambio algoritmo,
aggiunta di TPM protector, rotazione/eliminazione di key protector. In quei
casi il Remediate esce con `1` e messaggio esplicito → il device resta
flaggato per intervento manuale.

### Deployment (Remediations)

1. Intune admin center → **Devices → Scripts and remediations → Platform scripts/Remediations → Create**.
2. Detection script: `Detect-BitLockerCompliance.ps1`.
3. Remediation script: `Remediate-BitLockerCompliance.ps1`.
4. Settings: `Run script in 64-bit PowerShell host = Yes`, `Run as system account = Yes`,
   `Enforce script signature check = No` (a meno che gli script non siano firmati).
5. Assign al gruppo dei device target. Schedulare daily.
6. Consultare i risultati: **Reports → Remediations → seleziona script → Device status**,
   colonna *Pre-remediation detection output*. Cercare la riga `BITLOCKER_DIAG=`
   per il JSON completo.

## Livello B — Custom Compliance Settings (compliance ufficiale + UX utente)

`Discover-BitLocker.ps1` restituisce un **singolo JSON flat** conforme allo
schema dei Custom Compliance Settings di Intune. `BitLockerComplianceRules.json`
contiene le regole su ciascun campo + `RemediationStrings` in italiano e inglese
mostrate all'utente finale nel **Company Portal** quando il device è non
compliant.

### Firma dello script di discovery (obbligatoria)

Intune **rifiuta** discovery script non firmati. Esempio con cert di code
signing già in `Cert:\CurrentUser\My`:

```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature `
    -FilePath .\CustomCompliance\Discover-BitLocker.ps1 `
    -Certificate $cert `
    -TimestampServer 'http://timestamp.digicert.com' `
    -HashAlgorithm SHA256
```

Il certificato firmatario (o la sua CA) deve essere distribuito come
**Trusted Publisher / Trusted Root** sui device target (via Intune
Configuration Profile → Certificates).

### Deployment (Custom Compliance)

1. Intune admin center → **Endpoint security → Device compliance → Scripts → Add → Windows 10/11**.
2. Caricare `Discover-BitLocker.ps1` (firmato).
3. **Compliance policies → Create policy → Windows 10/11 → Custom Compliance**.
4. Selezionare lo script appena creato e caricare `BitLockerComplianceRules.json`.
5. Assegnare al gruppo.
6. Sul device l'utente vedrà il titolo/descrizione localizzato per ogni regola
   fallita dentro **Company Portal → Devices → \<device\> → Check status**.

## Schema diagnostico (Custom Compliance, campi flat)

| Campo | Tipo | Note |
|------|------|------|
| MountPoint | String | sempre disco di sistema |
| ProtectionStatus | String | On / Off / Unknown |
| VolumeStatus | String | FullyEncrypted, EncryptionInProgress, ... |
| EncryptionMethod | String | XtsAes256, XtsAes128, Aes256, ... |
| EncryptionPercentage | Int64 | 0-100 |
| KeyProtectorTypes | String | csv (es. "Tpm,RecoveryPassword") |
| HasTpmProtector | Boolean | |
| HasRecoveryPasswordProtector | Boolean | |
| RecoveryKeyEscrowedInEntraId | Boolean | dsregcmd + EventID 845 |
| EntraIdJoined | Boolean | |
| TpmReady | Boolean | |
| NonComplianceReasons | String | concatenati con " \| " |

## Mappa cause di non-compliance → azione

| NonComplianceReasons / regola fallita | Azione lato IT |
|----------------------------------------|----------------|
| `Protection is Off` con `VolumeStatus=FullyEncrypted` | Coperto da Remediate (Resume-BitLocker) |
| `Recovery key not escrowed to Entra ID` | Coperto da Remediate (BackupToAAD); se persiste verificare connettività e join Entra |
| `Missing TPM key protector` | Verificare TPM in firmware, ri-provisionare BitLocker |
| `Missing RecoveryPassword key protector` | Add-BitLockerKeyProtector -RecoveryPasswordProtector (manuale o via script dedicato) |
| `EncryptionMethod` sotto requisito | Pianificare decrypt + re-encrypt (non automatico) |
| `VolumeStatus` non FullyEncrypted | Verificare assegnazione policy di cifratura (Endpoint security → Disk encryption) |

## Privacy

Il diagnostico NON include la recovery password in chiaro: vengono esposti
solo i `KeyProtectorId` (GUID). I dati raccolti restano coerenti con le best
practice di Microsoft per BitLocker reporting.

## Scope supportato

- Windows 10 / Windows 11 client
- Solo volume di sistema (`$env:SystemDrive`)
- Windows Server: fuori scope
